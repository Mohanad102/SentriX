"""
Wazuh alert poller — reads alerts from the Wazuh Manager container via docker exec.
Polls every 30 seconds using a tracked line offset (reliable on Windows).
"""
import asyncio
import json
import uuid
from datetime import datetime

from backend.config import settings

WAZUH_CONTAINER = "wazuh-manager"
ALERTS_LOG_PATH = "/var/ossec/logs/alerts/alerts.json"
POLL_INTERVAL = 10  # seconds


def _build_description(raw: dict, rule: dict) -> str:
    if raw.get("full_log"):
        return raw["full_log"]
    if raw.get("message"):
        return raw["message"]

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
        "_wazuh_id":   raw.get("id", ""),  # unique event ID from Wazuh
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


async def _read_lines_from(offset: int) -> tuple[list[str], int]:
    """Read all lines from alerts.json starting at line `offset` (1-based).
    Returns (new_lines, new_total_line_count)."""
    try:
        if offset > 0:
            cmd = ["docker", "exec", WAZUH_CONTAINER, "awk",
                   f"NR>{offset}", ALERTS_LOG_PATH]
        else:
            cmd = ["docker", "exec", WAZUH_CONTAINER, "cat", ALERTS_LOG_PATH]

        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=60)
        lines = [l for l in stdout.decode(errors="replace").splitlines() if l.strip()]

        # Get current total line count
        wc_proc = await asyncio.create_subprocess_exec(
            "docker", "exec", WAZUH_CONTAINER,
            "wc", "-l", ALERTS_LOG_PATH,
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL,
        )
        wc_out, _ = await asyncio.wait_for(wc_proc.communicate(), timeout=10)
        total = int(wc_out.decode().strip().split()[0])

        return lines, total
    except Exception as e:
        print(f"[Wazuh] Read error: {e}")
        return [], offset


async def _run_workflow(alert_id: int):
    from backend.services.workflow_service import run_auto_workflow
    await run_auto_workflow(alert_id)


async def _run_rules(alert_id: int):
    from backend.routers.rules import evaluate_rules
    from backend.models.alert import Alert
    from backend.database import SessionLocal
    db = SessionLocal()
    try:
        alert = db.query(Alert).filter(Alert.id == alert_id).first()
        if alert:
            evaluate_rules(alert, db, None)
    except Exception as e:
        print(f"[Rules] evaluate error: {e}")
    finally:
        db.close()


def _save_alerts(lines: list[str], seen_ids: set, db) -> int:
    from backend.models.alert import Alert
    count = 0
    for line in lines:
        try:
            raw = json.loads(line.strip())
            alert_data = parse_wazuh_alert(raw)
            if not alert_data:
                continue

            wazuh_id = alert_data.pop("_wazuh_id", "")
            if wazuh_id and wazuh_id in seen_ids:
                continue
            if wazuh_id:
                seen_ids.add(wazuh_id)

            alert = Alert(**alert_data)
            ts = raw.get("timestamp")
            if ts:
                try:
                    alert.created_at = datetime.fromisoformat(ts.replace("Z", "+00:00").replace("+0000", "+00:00"))
                except Exception:
                    pass

            db.add(alert)
            count += 1
        except Exception:
            continue

    if count:
        db.commit()
    return count


async def backfill_existing_alerts(db) -> int:
    if not await _docker_available():
        print("[Wazuh] Container not running — skipping backfill")
        return 0

    print("[Wazuh] Starting backfill...")
    lines, total = await _read_lines_from(0)
    if not lines:
        return 0

    # Collect already-known Wazuh IDs from DB to avoid duplicates
    from backend.models.alert import Alert
    existing_raw = db.query(Alert.raw_data).filter(Alert.source == "wazuh").all()
    seen_ids: set = set()
    for (raw_str,) in existing_raw:
        if raw_str:
            try:
                wid = json.loads(raw_str).get("id", "")
                if wid:
                    seen_ids.add(wid)
            except Exception:
                pass

    count = _save_alerts(lines, seen_ids, db)
    print(f"[Wazuh] Backfilled {count} alerts (total file lines: {total})")
    return count


# ── Main polling loop ─────────────────────────────────────────────────────────
async def run_wazuh_poller():
    if not settings.WAZUH_ENABLED:
        return

    from backend.database import SessionLocal
    from backend.models.alert import Alert

    await asyncio.sleep(10)

    if not await _docker_available():
        print("[Wazuh] Container not available — poller exiting")
        return

    # Backfill and note how many lines existed
    db = SessionLocal()
    try:
        await backfill_existing_alerts(db)
    finally:
        db.close()

    # Get current line count as starting offset
    _, current_line_count = await _read_lines_from(0)
    print(f"[Wazuh] Real-time poll starting at line {current_line_count}, interval={POLL_INTERVAL}s")

    # Build seen_ids from DB for dedup during polling
    db = SessionLocal()
    try:
        existing_raw = db.query(Alert.raw_data).filter(Alert.source == "wazuh").all()
        seen_ids: set = set()
        for (raw_str,) in existing_raw:
            if raw_str:
                try:
                    wid = json.loads(raw_str).get("id", "")
                    if wid:
                        seen_ids.add(wid)
                except Exception:
                    pass
    finally:
        db.close()

    offset = current_line_count

    while True:
        try:
            await asyncio.sleep(POLL_INTERVAL)

            new_lines, new_total = await _read_lines_from(offset)

            if not new_lines:
                # Check if file was rotated (new_total < offset)
                if new_total < offset:
                    print("[Wazuh] Alert log rotated — resetting offset")
                    offset = 0
                continue

            db = SessionLocal()
            try:
                count = _save_alerts(new_lines, seen_ids, db)
                if count > 0:
                    print(f"[Wazuh] Imported {count} new alerts")
                    # Run workflows for new alerts
                    new_alerts = db.query(Alert).filter(
                        Alert.source == "wazuh"
                    ).order_by(Alert.id.desc()).limit(count).all()
                    for a in new_alerts:
                        asyncio.create_task(_run_workflow(a.id))
                        asyncio.create_task(_run_rules(a.id))
            except Exception as e:
                db.rollback()
                print(f"[Wazuh] DB save error: {e}")
            finally:
                db.close()

            offset = new_total

        except Exception as e:
            print(f"[Wazuh] Poller error: {e} — retrying in {POLL_INTERVAL}s")
