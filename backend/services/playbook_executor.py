"""
Real playbook action executor — every action performs a genuine system operation.
"""
from __future__ import annotations
import socket
import subprocess

import httpx

from backend.config import settings


async def execute_action(action_type: str, target: str, context: dict | None = None) -> dict:
    """
    context can carry:
      hostname   — the affected endpoint hostname (used to target the right Wazuh agent)
      source_ip  — the attacker IP
    """
    ctx = context or {}
    executors = {
        "block_ip":          _block_ip,
        "isolate_endpoint":  _isolate_endpoint,
        "kill_process":      _kill_process,
        "remove_file":       _remove_file,
        "disable_user":      _disable_user,
        "reset_password":    _reset_password,
        "reset_credentials": _reset_credentials,
    }
    fn = executors.get(action_type)
    if not fn:
        return {"success": False, "message": f"Unknown action: {action_type}", "details": {}}
    try:
        return await fn(target, ctx)
    except Exception as e:
        return {"success": False, "message": f"Executor error: {e}", "details": {}}


# ── Wazuh helpers ──────────────────────────────────────────────────────────────

async def _wazuh_token() -> str | None:
    if not settings.WAZUH_ENABLED:
        return None
    try:
        async with httpx.AsyncClient(verify=False, timeout=10) as c:
            r = await c.post(
                f"{settings.WAZUH_URL}/security/user/authenticate",
                auth=(settings.WAZUH_USER, settings.WAZUH_PASSWORD),
            )
            if r.status_code == 200:
                return r.json()["data"]["token"]
    except Exception:
        pass
    return None


async def _wazuh_agent_ids(hostname: str | None = None) -> list[str]:
    """Return agent IDs. If hostname given, returns only matching agent."""
    token = await _wazuh_token()
    if not token:
        return []
    try:
        params: dict = {"limit": 50}
        if hostname:
            params["name"] = hostname
        async with httpx.AsyncClient(verify=False, timeout=10) as c:
            r = await c.get(
                f"{settings.WAZUH_URL}/agents",
                headers={"Authorization": f"Bearer {token}"},
                params=params,
            )
            if r.status_code == 200:
                items = r.json().get("data", {}).get("affected_items", [])
                return [str(a["id"]) for a in items if str(a.get("id", "")) != "000"]
    except Exception:
        pass
    return []


async def _wazuh_active_response(command: str, arguments: list[str],
                                  agent_ids: list[str] | None = None) -> tuple[bool, str]:
    """Send a Wazuh active-response command. Returns (success, message)."""
    token = await _wazuh_token()
    if not token:
        return False, "Wazuh unavailable — check WAZUH_ENABLED and credentials"

    # Wazuh requires explicit numeric agent IDs — "all" is not accepted
    if not agent_ids:
        agent_ids = await _wazuh_agent_ids()
    if not agent_ids:
        return False, "No active Wazuh agents found"

    try:
        params = {"agents_list": ",".join(agent_ids)}
        body = {"command": command, "arguments": arguments}
        async with httpx.AsyncClient(verify=False, timeout=15) as c:
            r = await c.put(
                f"{settings.WAZUH_URL}/active-response",
                headers={"Authorization": f"Bearer {token}"},
                params=params,
                json=body,
            )
            if r.status_code in (200, 201):
                return True, f"command dispatched to {len(agent_ids)} agent(s)"
            return False, f"Wazuh {r.status_code}: {r.text[:200]}"
    except Exception as e:
        return False, f"Wazuh error: {e}"


# ── iptables helper ────────────────────────────────────────────────────────────

def _iptables_block(ip: str) -> tuple[bool, str]:
    errors = []
    for chain, flag in [("INPUT", "-s"), ("OUTPUT", "-d"), ("FORWARD", "-s")]:
        r = subprocess.run(
            ["iptables", "-I", chain, flag, ip, "-j", "DROP"],
            capture_output=True, text=True,
        )
        if r.returncode != 0:
            stderr = r.stderr.strip()
            if "Permission denied" in stderr or "lock file" in stderr:
                return False, "iptables requires root — using Wazuh active-response instead"
            errors.append(stderr)
    if errors:
        return False, " | ".join(errors)
    return True, f"iptables: {ip} blocked on INPUT/OUTPUT/FORWARD"


def _resolve_hostname(hostname: str) -> str | None:
    try:
        return socket.gethostbyname(hostname)
    except Exception:
        return None


# ── Actions ────────────────────────────────────────────────────────────────────

async def _block_ip(ip: str, ctx: dict) -> dict:
    applied, errors = [], []

    ok, msg = _iptables_block(ip)
    if ok:
        applied.append(msg)
    else:
        errors.append(msg)

    if settings.WAZUH_ENABLED:
        ok, msg = await _wazuh_active_response("firewall-drop", ["-", "add", ip])
        if ok:
            applied.append(f"Wazuh active-response: {msg}")
        else:
            errors.append(f"Wazuh: {msg}")

    success = bool(applied)
    return {
        "success": success,
        "message": "; ".join(applied) if applied else "; ".join(errors),
        "details": {"applied": applied, "errors": errors},
    }


async def _isolate_endpoint(hostname: str, ctx: dict) -> dict:
    applied, errors = [], []

    ip = _resolve_hostname(hostname)
    if ip:
        ok, msg = _iptables_block(ip)
        if ok:
            applied.append(f"Host firewall: {hostname} ({ip}) cut off")
        else:
            errors.append(msg)
    else:
        errors.append(f"DNS resolution failed for: {hostname}")

    if settings.WAZUH_ENABLED:
        agent_ids = await _wazuh_agent_ids(hostname)
        if agent_ids:
            target = ip or hostname
            ok, msg = await _wazuh_active_response(
                "firewall-drop", ["-", "add", target], agent_ids
            )
            if ok:
                applied.append(f"Wazuh agent isolation: {msg}")
            else:
                errors.append(f"Wazuh: {msg}")
        else:
            errors.append(f"No Wazuh agent found for hostname: {hostname}")

    success = bool(applied)
    return {
        "success": success,
        "message": "; ".join(applied) if applied else "; ".join(errors),
        "details": {"applied": applied, "errors": errors},
    }


async def _kill_process(process_name: str, ctx: dict) -> dict:
    applied, errors = [], []

    if not settings.WAZUH_ENABLED:
        return {"success": False,
                "message": "Wazuh not enabled — cannot kill process on remote endpoint",
                "details": {}}

    # Target the specific endpoint if we know its hostname
    hostname = ctx.get("hostname")
    agent_ids = await _wazuh_agent_ids(hostname)
    if not agent_ids:
        return {"success": False,
                "message": f"No Wazuh agent found{' for ' + hostname if hostname else ''}",
                "details": {}}

    ok, msg = await _wazuh_active_response(
        "kill-process", ["-", "add", process_name], agent_ids
    )
    if ok:
        applied.append(f"Wazuh kill-process on {hostname or 'agent'}: {msg}")
    else:
        errors.append(f"Wazuh: {msg}")

    success = bool(applied)
    return {
        "success": success,
        "message": "; ".join(applied) if applied else "; ".join(errors),
        "details": {"applied": applied, "errors": errors},
    }


async def _remove_file(file_path: str, ctx: dict) -> dict:
    applied, errors = [], []

    if not settings.WAZUH_ENABLED:
        return {"success": False,
                "message": "Wazuh not enabled — cannot remove file on remote endpoint",
                "details": {}}

    hostname = ctx.get("hostname")
    agent_ids = await _wazuh_agent_ids(hostname)
    if not agent_ids:
        return {"success": False,
                "message": f"No Wazuh agent found{' for ' + hostname if hostname else ''}",
                "details": {}}

    ok, msg = await _wazuh_active_response(
        "delete-file", ["-", "add", file_path], agent_ids
    )
    if ok:
        applied.append(f"Wazuh delete-file on {hostname or 'agent'}: {msg}")
    else:
        errors.append(f"Wazuh: {msg}")

    success = bool(applied)
    return {
        "success": success,
        "message": "; ".join(applied) if applied else "; ".join(errors),
        "details": {"applied": applied, "errors": errors},
    }


async def _disable_user(username: str, ctx: dict) -> dict:
    """
    1. Disable the SentriX platform account (blocks login immediately).
    2. Send Wazuh disable-account to the endpoint (disables the OS-level account).
    """
    applied, errors = [], []

    # ── Step 1: Disable in SentriX database ───────────────────────────────────
    try:
        from backend.database import SessionLocal
        from backend.models.user import User as DBUser
        db = SessionLocal()
        try:
            user = db.query(DBUser).filter(DBUser.username == username).first()
            if user:
                if not user.is_active:
                    applied.append(f"SentriX account '{username}' was already disabled")
                else:
                    user.is_active = False
                    db.commit()
                    applied.append(f"SentriX account '{username}' disabled — login blocked immediately")
            else:
                errors.append(f"No SentriX account found with username '{username}'")
        finally:
            db.close()
    except Exception as e:
        errors.append(f"SentriX DB error: {e}")

    # ── Step 2: Disable OS account via Wazuh active-response ─────────────────
    if settings.WAZUH_ENABLED:
        hostname = ctx.get("hostname")
        agent_ids = await _wazuh_agent_ids(hostname)
        if agent_ids:
            ok, msg = await _wazuh_active_response(
                "disable-account", ["-", "add", username], agent_ids
            )
            if ok:
                applied.append(f"Wazuh OS account disabled on {hostname or 'agent'}: {msg}")
            else:
                errors.append(f"Wazuh: {msg}")
        else:
            errors.append(f"No Wazuh agent found{' for ' + hostname if hostname else ''} — OS account not disabled")

    success = bool(applied)
    return {
        "success": success,
        "message": "; ".join(applied) if applied else "; ".join(errors),
        "details": {"applied": applied, "errors": errors},
    }


async def _reset_password(username: str, ctx: dict) -> dict:
    """
    Disable the SentriX account and lock the OS account.
    The analyst must then set a new password before re-enabling.
    """
    # Reuse disable_user — disabling IS the first step of a password reset
    result = await _disable_user(username, ctx)
    if result["success"]:
        result["message"] += ". Re-enable the account and set a new password via Admin → Users."
    return result


async def _reset_credentials(target: str, ctx: dict) -> dict:
    """Disable SentriX account + lock OS account. Rotate tokens/API keys manually."""
    result = await _disable_user(target, ctx)
    if result["success"]:
        result["message"] += " Rotate any service account tokens and API keys manually."
    return result
