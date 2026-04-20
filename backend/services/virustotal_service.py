import re
import httpx
import json
from datetime import datetime
from backend.config import settings

VT_BASE = "https://www.virustotal.com/api/v3"

# ── IOC extraction regexes ─────────────────────────────────────────────────────
_RE_IPV4   = re.compile(r'\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b')
_RE_SHA256 = re.compile(r'\b[a-fA-F0-9]{64}\b')
_RE_SHA1   = re.compile(r'\b[a-fA-F0-9]{40}\b')
_RE_MD5    = re.compile(r'\b[a-fA-F0-9]{32}\b')
_RE_URL    = re.compile(r'https?://[^\s\'"<>]+')
_RE_DOMAIN = re.compile(
    r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)'
    r'+(?:com|net|org|io|gov|edu|mil|int|co|info|biz|onion|ru|cn|de|uk|fr|br|in|jp|au|xyz|top|club|live|online)\b',
    re.IGNORECASE
)

# Noise: skip hex strings that are clearly not network IOCs (rule IDs, colour codes, etc.)
_SKIP_DOMAINS = {'win-dc01', 'workstation', 'file-server', 'web-server', 'firewall'}


def extract_iocs_from_text(text: str) -> list[tuple[str, str]]:
    """Return list of (value, ioc_type) from free text. Deduplicates."""
    if not text:
        return []
    found: dict[str, str] = {}

    for url in _RE_URL.findall(text):
        url = url.rstrip('.,;)')
        found[url] = 'url'

    for ip in _RE_IPV4.findall(text):
        if ip not in found:
            found[ip] = 'ip'

    for h in _RE_SHA256.findall(text):
        if h not in found:
            found[h] = 'hash'

    for h in _RE_SHA1.findall(text):
        if h not in found and h not in found:
            found[h] = 'hash'

    for h in _RE_MD5.findall(text):
        if h not in found:
            found[h] = 'hash'

    for dom in _RE_DOMAIN.findall(text):
        dom = dom.lower()
        if dom not in found and dom not in _SKIP_DOMAINS:
            found[dom] = 'domain'

    return list(found.items())


def extract_all_iocs_from_alert(alert) -> list[tuple[str, str]]:
    """Extract every IOC from all fields of an alert."""
    seen: dict[str, str] = {}

    # Structured fields first
    if alert.source_ip:
        seen[alert.source_ip] = 'ip'
    if alert.dest_ip:
        seen[alert.dest_ip] = 'ip'

    # Free-text fields
    for field in [alert.title, alert.description, alert.raw_data]:
        for value, ioc_type in extract_iocs_from_text(field or ''):
            if value not in seen:
                seen[value] = ioc_type

    return list(seen.items())


# ── VT scanning ────────────────────────────────────────────────────────────────

async def enrich_with_virustotal(value: str, ioc_type: str) -> dict:
    if not settings.VIRUSTOTAL_API_KEY or not settings.VIRUSTOTAL_ENABLED:
        return _mock_vt_response(value, ioc_type)

    headers = {"x-apikey": settings.VIRUSTOTAL_API_KEY}
    endpoint = _get_endpoint(value, ioc_type)

    try:
        async with httpx.AsyncClient(timeout=15) as client:
            resp = await client.get(f"{VT_BASE}/{endpoint}", headers=headers)
            if resp.status_code == 200:
                return _parse_vt_response(resp.json(), ioc_type)
            elif resp.status_code == 404:
                return {"score": "0/0", "is_malicious": False, "report": {"message": "Not found in VirusTotal"}}
            else:
                return _mock_vt_response(value, ioc_type)
    except Exception as e:
        return {"score": "N/A", "is_malicious": None, "report": {"error": str(e)}}


async def enrich_and_store_ioc(db, value: str, ioc_type: str, alert_id: int = None) -> dict:
    """Scan value with VT and persist result to IOC table."""
    from backend.models.ioc import IOC

    is_private = ioc_type == 'ip' and _is_private_ip(value)

    if is_private:
        result = {
            "score": "N/A",
            "is_malicious": None,
            "report": {"note": "Private/internal IP — not submitted to VirusTotal"}
        }
    else:
        result = await enrich_with_virustotal(value, ioc_type)

    existing = db.query(IOC).filter(IOC.value == value).first()
    if existing:
        if not is_private:  # overwrite with real data
            existing.vt_score = result.get("score")
            existing.is_malicious = result.get("is_malicious")
            existing.vt_report = json.dumps(result.get("report", {}))
            existing.enriched = not is_private
            existing.enriched_at = datetime.utcnow()
        if alert_id and not existing.alert_id:
            existing.alert_id = alert_id
    else:
        from backend.models.ioc import IOC as IOCModel
        ioc = IOCModel(
            value=value,
            ioc_type=ioc_type,
            alert_id=alert_id,
            is_malicious=result.get("is_malicious"),
            vt_score=result.get("score"),
            vt_report=json.dumps(result.get("report", {})),
            enriched=not is_private,
            enriched_at=datetime.utcnow() if not is_private else None,
        )
        db.add(ioc)

    db.commit()
    return result


async def auto_enrich_alert(db, alert) -> None:
    """Extract ALL IOCs from an alert and enrich each with VT, then mark the alert done."""
    iocs = extract_all_iocs_from_alert(alert)
    results = []
    for value, ioc_type in iocs:
        try:
            result = await enrich_and_store_ioc(db, value, ioc_type, alert_id=alert.id)
            results.append(result)
        except Exception:
            pass

    alert.vt_enriched = True
    if results:
        malicious_flags = [r.get("is_malicious") for r in results if r.get("is_malicious") is not None]
        alert.vt_malicious = any(malicious_flags) if malicious_flags else None
    db.commit()


async def enrich_pending_iocs(db) -> int:
    """Scan all unenriched public IOCs. Returns count enriched."""
    from backend.models.ioc import IOC

    pending = db.query(IOC).filter(IOC.enriched == False).all()  # noqa: E712
    count = 0
    for ioc in pending:
        if ioc.ioc_type == 'ip' and _is_private_ip(ioc.value):
            continue
        try:
            await enrich_and_store_ioc(db, ioc.value, ioc.ioc_type, alert_id=ioc.alert_id)
            count += 1
        except Exception:
            pass
    return count


# ── Helpers ────────────────────────────────────────────────────────────────────

def _is_private_ip(ip: str) -> bool:
    import ipaddress
    try:
        addr = ipaddress.ip_address(ip)
        return addr.is_private or addr.is_loopback or addr.is_link_local
    except ValueError:
        return False


def _get_endpoint(value: str, ioc_type: str) -> str:
    if ioc_type == "ip":
        return f"ip_addresses/{value}"
    elif ioc_type == "domain":
        return f"domains/{value}"
    elif ioc_type == "url":
        import base64
        url_id = base64.urlsafe_b64encode(value.encode()).decode().strip("=")
        return f"urls/{url_id}"
    elif ioc_type == "hash":
        return f"files/{value}"
    return f"ip_addresses/{value}"


def _parse_vt_response(data: dict, ioc_type: str) -> dict:
    try:
        stats = data["data"]["attributes"]["last_analysis_stats"]
        malicious = stats.get("malicious", 0)
        total = sum(stats.values())
        score = f"{malicious}/{total}"
        is_malicious = malicious > 3
        return {
            "score": score,
            "is_malicious": is_malicious,
            "report": {
                "stats": stats,
                "reputation": data["data"]["attributes"].get("reputation", 0),
            }
        }
    except Exception:
        return {"score": "N/A", "is_malicious": None, "report": data}


def _mock_vt_response(value: str, ioc_type: str) -> dict:
    import hashlib
    seed = int(hashlib.md5(value.encode()).hexdigest(), 16) % 100

    if seed > 70:
        malicious = seed % 30 + 10
        total = 72
        is_malicious = True
    elif seed > 40:
        malicious = seed % 5
        total = 72
        is_malicious = False
    else:
        malicious = 0
        total = 72
        is_malicious = False

    return {
        "score": f"{malicious}/{total}",
        "is_malicious": is_malicious,
        "report": {
            "note": "Mock data - configure VIRUSTOTAL_API_KEY in .env for real results",
            "stats": {
                "malicious": malicious,
                "suspicious": 0,
                "undetected": total - malicious,
                "harmless": 0
            },
            "value": value,
            "type": ioc_type
        }
    }
