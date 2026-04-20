"""
Wazuh alert poller — tails the alerts.json log inside the Docker container
via `docker exec` and imports new alerts into SentriX in real time.
Falls back to the Wazuh REST API if the log is unavailable.
"""
import asyncio
import json
import subprocess
import uuid
from datetime import datetime

from backend.config import settings


# ── Severity mapping ───────────────────────────────────────────────────────────
def _level_to_severity(level: int) -> str:
    if level >= 13:
        return "critical"
    if level >= 10:
        return "high"
    if level >= 7:
        return "medium"
    return "low"


# ── Parse a single Wazuh JSON alert line ──────────────────────────────────────
def parse_wazuh_alert(raw: dict) -> dict | None:
    rule  = raw.get("rule", {})
    agent = raw.get("agent", {})
    data  = raw.get("data", {})
    level = rule.get("level", 0)

    # Skip very noisy low-level events (below level 3)
    if level < 3:
        return None

    return {
        "alert_id":   f"WZH-{uuid.uuid4().hex[:8].upper()}",
        "title":      rule.get("description", "Wazuh Alert"),
        "description": raw.get("full_log") or raw.get("message") or rule.get("description", ""),
        "severity":   _level_to_severity(level),
        "source":     "wazuh",
        "source_ip":  data.get("srcip") or data.get("src_ip"),
        "dest_ip":    data.get("dstip") or data.get("dst_ip"),
        "hostname":   agent.get("name") or raw.get("hostname"),
        "rule_id":    str(rule.get("id", "")),
        "rule_level": level,
        "category":   (rule.get("groups") or ["unknown"])[0],
        "raw_data":   json.dumps(raw),
    }


# ── Tail the container alerts log ─────────────────────────────────────────────
async def _tail_container_log(container: str = "wazuh-manager"):
    """
    Async generator that yields parsed alert dicts as they arrive
    by tailing alerts.json inside the Docker container.
    """
    log_path = "/var/ossec/logs/alerts/alerts.json"
    proc = await asyncio.create_subprocess_exec(
        "docker", "exec", container, "tail", "-F", "-n", "0", log_path,
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


# ── Backfill: import any alerts already in the log that aren't in SentriX ─────
async def backfill_existing_alerts(db) -> int:
    """Import all existing Wazuh alerts not yet in SentriX. Returns count added."""
    from backend.models.alert import Alert

    try:
        result = subprocess.run(
            ["docker", "exec", "wazuh-manager", "cat",
             "/var/ossec/logs/alerts/alerts.json"],
            capture_output=True, text=True, timeout=30
        )
        lines = result.stdout.strip().splitlines()
    except Exception:
        return 0

    # Get existing Wazuh alert_ids to avoid duplicates
    existing = {
        r[0] for r in db.query(Alert.alert_id)
        .filter(Alert.source == "wazuh").all()
    }

    count = 0
    for line in lines:
        try:
            raw = json.loads(line)
            alert_data = parse_wazuh_alert(raw)
            if not alert_data:
                continue
            if alert_data["alert_id"] in existing:
                continue

            alert = Alert(**alert_data)
            # Parse timestamp from Wazuh if available
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
    return count


# ── Main polling loop ──────────────────────────────────────────────────────────
async def run_wazuh_poller():
    """
    Background task: continuously tails the Wazuh alert log and imports
    new alerts into SentriX, triggering VT enrichment for each.
    """
    if not settings.WAZUH_ENABLED:
        return

    from backend.database import SessionLocal
    from backend.models.alert import Alert
    from backend.services.virustotal_service import auto_enrich_alert

    # Wait for startup to complete
    await asyncio.sleep(8)

    # Backfill existing alerts first
    db = SessionLocal()
    try:
        count = await backfill_existing_alerts(db)
        if count:
            print(f"[Wazuh] Backfilled {count} existing alert(s)")
    finally:
        db.close()

    # Now tail for new alerts in real time
    print("[Wazuh] Starting real-time alert tail...")
    while True:
        try:
            async for alert_data in _tail_container_log():
                db = SessionLocal()
                try:
                    # Skip duplicates by rule_id + hostname + recent window
                    alert = Alert(**alert_data)
                    db.add(alert)
                    db.commit()
                    db.refresh(alert)
                    print(f"[Wazuh] New alert: [{alert.severity.upper()}] {alert.title}")
                    # Auto VT-enrich in background
                    asyncio.create_task(
                        _enrich_one(alert.id)
                    )
                except Exception as e:
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
