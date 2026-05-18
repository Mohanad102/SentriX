"""TheHive SOAR Integration Service (TheHive 5 v1 API)."""
import httpx
from typing import List, Dict, Optional
from backend.config import settings

SEVERITY_MAP = {"low": 1, "medium": 2, "high": 3, "critical": 4}


def _headers() -> Dict:
    return {
        "Authorization": f"Bearer {settings.THEHIVE_API_KEY}",
        "Content-Type": "application/json",
    }


async def get_status() -> Dict:
    try:
        async with httpx.AsyncClient(timeout=5, verify=False) as client:
            r = await client.get(f"{settings.THEHIVE_URL}/api/v1/status", headers=_headers())
            if r.status_code == 200:
                info = r.json()
                return {
                    "connected": True,
                    "url": settings.THEHIVE_URL,
                    "version": info.get("versions", {}).get("TheHive", "unknown"),
                }
            return {"connected": False, "url": settings.THEHIVE_URL, "error": f"HTTP {r.status_code}"}
    except Exception as e:
        return {"connected": False, "url": settings.THEHIVE_URL, "error": str(e)}


async def list_cases(limit: int = 20, offset: int = 0) -> List[Dict]:
    if not settings.THEHIVE_ENABLED:
        return []
    try:
        async with httpx.AsyncClient(timeout=10, verify=False) as client:
            body = {
                "query": [{"_name": "listCase"}],
                "from": offset,
                "to": offset + limit,
                "sort": ["-_createdAt"],
            }
            r = await client.post(
                f"{settings.THEHIVE_URL}/api/v1/query",
                headers=_headers(),
                json=body,
            )
            if r.status_code == 200:
                return r.json()
    except Exception as e:
        print(f"[TheHive] list_cases error: {e}")
    return []


async def get_case(case_id: str) -> Optional[Dict]:
    if not settings.THEHIVE_ENABLED:
        return None
    try:
        async with httpx.AsyncClient(timeout=10, verify=False) as client:
            r = await client.get(
                f"{settings.THEHIVE_URL}/api/v1/case/{case_id}",
                headers=_headers(),
            )
            if r.status_code == 200:
                return r.json()
    except Exception as e:
        print(f"[TheHive] get_case error: {e}")
    return None


async def create_case(
    title: str,
    description: str,
    severity: int = 2,
    tags: Optional[List[str]] = None,
) -> Optional[Dict]:
    if not settings.THEHIVE_ENABLED:
        return None
    try:
        async with httpx.AsyncClient(timeout=10, verify=False) as client:
            body = {
                "title": title,
                "description": description,
                "severity": severity,
                "tags": tags or ["sentrix"],
                "flag": False,
                "status": "New",
            }
            r = await client.post(
                f"{settings.THEHIVE_URL}/api/v1/case",
                headers=_headers(),
                json=body,
            )
            if r.status_code in (200, 201):
                return r.json()
            print(f"[TheHive] create_case HTTP {r.status_code}: {r.text[:200]}")
    except Exception as e:
        print(f"[TheHive] create_case error: {e}")
    return None


async def create_case_from_alert(alert) -> Optional[Dict]:
    desc = (
        f"**Source:** {alert.source}\n"
        f"**Severity:** {alert.severity}\n"
        f"**Category:** {alert.category or 'N/A'}\n"
        f"**Source IP:** {alert.source_ip or 'N/A'}\n"
        f"**Hostname:** {alert.hostname or 'N/A'}\n\n"
        f"{alert.description or ''}"
    )
    return await create_case(
        title=f"[SentriX Alert] {alert.title}",
        description=desc,
        severity=SEVERITY_MAP.get(alert.severity, 2),
        tags=["sentrix", "alert", alert.source or "unknown"],
    )


async def create_case_from_incident(incident) -> Optional[Dict]:
    desc = (
        f"**Case Number:** {incident.case_number}\n"
        f"**Severity:** {incident.severity}\n"
        f"**Category:** {incident.category or 'N/A'}\n"
        f"**Assigned To:** {incident.assigned_to or 'Unassigned'}\n\n"
        f"{incident.description or ''}"
    )
    return await create_case(
        title=f"[SentriX Incident] {incident.title}",
        description=desc,
        severity=SEVERITY_MAP.get(incident.severity, 2),
        tags=["sentrix", "incident", incident.category or "unknown"],
    )
