"""
Wazuh alert poller — reads alerts.json from the shared Docker volume
and imports new alerts into SentriX in real time.
Falls back to the Wazuh REST API if the log file is unavailable.
"""
import asyncio
import json
import os
import uuid
from datetime import datetime

from backend.config import settings


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
        "description": raw.get("full_log") or raw.get("message") or rule.get("description", ""),
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


# ── Tail the alerts.json file from the shared volume ─────────────────────────
async def _tail_log_file():
    """
    Async generator: tails alerts.json from the mounted Wazuh volume.
    Works in Docker Compose (shared volume) or when log path exists locally.
    """
    log_path = settings.WAZUH_ALERTS_LOG

    # Wait for file to appear (Wazuh takes time to start)
    for _ in range(30):
        if os.path.exists(log_path):
            break
        await asyncio.sleep(10)
    else:
        print(f"[Wazuh] Log file not found at {log_path} — giving up")
        return

    proc = await asyncio.create_subprocess_exec(
        "tail", "-F", "-n", "0", log_path,
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


# ── Backfill existing alerts ──────────────────────────────────────────────────
async def backfill_existing_alerts(db) -> int:
    from backend.models.alert import Alert

    log_path = settings.WAZUH_ALERTS_LOG
    if not os.path.exists(log_path):
        return 0

    try:
        with open(log_path, "r", errors="ignore") as f:
            lines = f.read().strip().splitlines()
    except Exception:
        return 0

    existing = {
        r[0] for r in db.query(Alert.alert_id)
        .filter(Alert.source == "wazuh").all()
    }

    count = 0
    for line in lines:
        try:
            raw = json.loads(line)
            alert_data = parse_wazuh_alert(raw)
            if not alert_data or alert_data["alert_id"] in existing:
                continue

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
    return count


# ── Main polling loop ─────────────────────────────────────────────────────────
async def run_wazuh_poller():
    if not settings.WAZUH_ENABLED:
        return

    from backend.database import SessionLocal

    await asyncio.sleep(10)

    db = SessionLocal()
    try:
        count = await backfill_existing_alerts(db)
        if count:
            print(f"[Wazuh] Backfilled {count} existing alert(s)")
    finally:
        db.close()

    print("[Wazuh] Starting real-time alert tail...")
    while True:
        try:
            async for alert_data in _tail_log_file():
                db = SessionLocal()
                try:
                    from backend.models.alert import Alert
                    alert = Alert(**alert_data)
                    db.add(alert)
                    db.commit()
                    db.refresh(alert)
                    print(f"[Wazuh] New alert: [{alert.severity.upper()}] {alert.title}")
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
