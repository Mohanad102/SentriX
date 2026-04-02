import httpx
import json
from backend.config import settings

VT_BASE = "https://www.virustotal.com/api/v3"


async def enrich_with_virustotal(value: str, ioc_type: str) -> dict:
    """
    Enrich an IOC using VirusTotal API.
    Falls back to mock data if API key is not configured.
    """
    if not settings.VIRUSTOTAL_API_KEY or not settings.VIRUSTOTAL_ENABLED:
        return _mock_vt_response(value, ioc_type)

    headers = {"x-apikey": settings.VIRUSTOTAL_API_KEY}
    endpoint = _get_endpoint(value, ioc_type)

    try:
        async with httpx.AsyncClient(timeout=15) as client:
            resp = await client.get(f"{VT_BASE}/{endpoint}", headers=headers)
            if resp.status_code == 200:
                data = resp.json()
                return _parse_vt_response(data, ioc_type)
            elif resp.status_code == 404:
                return {"score": "0/0", "is_malicious": False, "report": {"message": "Not found in VirusTotal"}}
            else:
                return _mock_vt_response(value, ioc_type)
    except Exception as e:
        return {"score": "N/A", "is_malicious": None, "report": {"error": str(e)}}


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
    """Simulated VirusTotal response for demo purposes."""
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
            "note": "Mock data - configure VIRUSTOTAL_API_KEY for real results",
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
