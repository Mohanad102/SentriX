"""
Wazuh alert poller — reads alerts from the Wazuh Manager container via docker exec.
Imports new alerts into SentriX in real time.
"""
import asyncio
import json
import subprocess
import uuid
from datetime import datetime

from backend.config import settings

WAZUH_CONTAINER = "wazuh-manager"
ALERTS_LOG_PATH = "/var/ossec/logs/alerts/alerts.json"


def _build_description(raw: dict, rule: dict) -> str:
    """Build a human-readable description, pulling Windows event fields when full_log is absent."""
    if raw.get("full_log"):
        return raw["full_log"]
    if raw.get("message"):
        return raw["message"]

    # Windows Event Channel alerts — construct from win.* fields
    win  = raw.get("data", {}).get("win", {})
    sys  = win.get("system", {})
    evt  = win.get("eventdata", {})
    parts = []

    event_id = sys.get("eventID")
    provider = sys.get("providerName")
    if event_id:
        parts.append(f"Event ID: {event_id}" + (f" ({provider})" if provider else ""))

    process = evt.get("processName") or evt.get("image") or evt.get("newProcessName")
    if process:
        parts.append(f"Process: {process}")

    user = evt.get("subjectUserName") or evt.get("targetUserName")
    domain = evt.get("subjectDomainName") or evt.get("targetDomainName")
    if user:
        parts.append(f"User: {domain + chr(92) + user if domain else user}")

    obj = evt.get("objectName") or evt.get("targetFilename")
    if obj:
        parts.append(f"Object: {obj}")

    computer = sys.get("computer")
    if computer:
        parts.append(f"Computer: {computer}")

    if parts:
        return "\n".join(parts)

    return rule.get("description", "")


def _level_to_severity(level: int) -> str:
    if level >= 13:
        return "critical"
    if level >= 10:
        return "high"
    if level >= 7:
        return "medium"
    return "low"


def parse_wazuh_alert(raw: dict) -> dict | None:
    rule  = raw.get("rule", {})
    agent = raw.get("agent", {})
    data  = raw.get("data", {})
    level = rule.get("level", 0)

    if level < 3:
        return None

    return {
        "alert_id":    f"WZH-{uuid.uuid4().hex[:8].upper()}",
        "title":       rule.get("description", "Wazuh Alert"),
        "description": _build_description(raw, rule),
        "severity":    _level_to_severity(level),
        "source":      "wazuh",
        "source_ip":   data.get("srcip") or data.get("src_ip"),
        "dest_ip":     data.get("dstip") or data.get("dst_ip"),
        "hostname":    agent.get("name") or raw.get("hostname"),
        "rule_id":     str(rule.get("id", "")),
        "rule_level":  level,
        "category":    (rule.get("groups") or ["unknown"])[0],
        "raw_data":    json.dumps(raw),
    }


async def _docker_available() -> bool:
    try:
        proc = await asyncio.create_subprocess_exec(
            "docker", "inspect", WAZUH_CONTAINER, "--format", "{{.State.Running}}",
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL,
        )
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=5)
        return stdout.decode().strip() == "true"
    except Exception:
        return False


# ── Backfill all existing alerts ──────────────────────────────────────────────
async def backfill_existing_alerts(db) -> int:
    from backend.models.alert import Alert

    if not await _docker_available():
        print("[Wazuh] Container not running — skipping backfill")
        return 0

    try:
        proc = await asyncio.create_subprocess_exec(
            "docker", "exec", WAZUH_CONTAINER, "cat", ALERTS_LOG_PATH,
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL,
        )
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=60)
        lines = stdout.decode().strip().splitlines()
    except Exception as e:
        print(f"[Wazuh] Backfill read error: {e}")
        return 0

    existing = {
        r[0] for r in db.query(Alert.rule_id, Alert.hostname)
        .filter(Alert.source == "wazuh").all()
    }

    count = 0
    for line in lines:
        try:
            raw = json.loads(line)
            alert_data = parse_wazuh_alert(raw)
            if not alert_data:
                continue

            # Deduplicate by rule_id + hostname
            dup_key = (alert_data["rule_id"], alert_data["hostname"])
            if dup_key in existing:
                continue
            existing.add(dup_key)

            alert = Alert(**alert_data)
            ts = raw.get("timestamp")
            if ts:
                try:
                    alert.created_at = datetime.fromisoformat(ts.replace("Z", "+00:00"))
                except Exception:
                    pass

            db.add(alert)
            count += 1
        except Exception:
            continue

    if count:
        db.commit()
        print(f"[Wazuh] Backfilled {count} alerts")
    return count


# ── Real-time tail ────────────────────────────────────────────────────────────
async def _tail_container_log():
    proc = await asyncio.create_subprocess_exec(
        "docker", "exec", WAZUH_CONTAINER, "tail", "-F", "-n", "0", ALERTS_LOG_PATH,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.DEVNULL,
    )
    try:
        while True:
            line = await proc.stdout.readline()
            if not line:
                break
            try:
                raw = json.loads(line.decode().strip())
                alert = parse_wazuh_alert(raw)
                if alert:
                    yield alert
            except (json.JSONDecodeError, Exception):
                continue
    finally:
        proc.kill()


# ── Main polling loop ─────────────────────────────────────────────────────────
async def run_wazuh_poller():
    if not settings.WAZUH_ENABLED:
        return

    from backend.database import SessionLocal

    # Wait for startup
    await asyncio.sleep(10)

    if not _docker_available():
        print("[Wazuh] Container not available — poller exiting")
        return

    # Backfill first
    db = SessionLocal()
    try:
        await backfill_existing_alerts(db)
    finally:
        db.close()

    # Real-time tail
    print("[Wazuh] Starting real-time alert tail...")
    while True:
        try:
            async for alert_data in _tail_container_log():
                db = SessionLocal()
                try:
                    from backend.models.alert import Alert
                    alert = Alert(**alert_data)
                    db.add(alert)
                    db.commit()
                    db.refresh(alert)
                    print(f"[Wazuh] [{alert.severity.upper()}] {alert.title} — {alert.hostname}")
                    asyncio.create_task(_enrich_one(alert.id))
                except Exception:
                    db.rollback()
                finally:
                    db.close()
        except Exception as e:
            print(f"[Wazuh] Poller error: {e} — reconnecting in 10s")
            await asyncio.sleep(10)


async def _enrich_one(alert_id: int):
    from backend.database import SessionLocal
    from backend.models.alert import Alert
    from backend.services.virustotal_service import auto_enrich_alert
    db = SessionLocal()
    try:
        alert = db.query(Alert).filter(Alert.id == alert_id).first()
        if alert:
            await auto_enrich_alert(db, alert)
    except Exception:
        pass
    finally:
        db.close()
