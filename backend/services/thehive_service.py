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
    if not settings.THEHIVE_ENABLED:
        return {"connected": False, "url": settings.THEHIVE_URL, "error": "Service disabled — set THEHIVE_ENABLED=true in .env"}
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
        return {"connected": False, "url": settings.THEHIVE_URL, "error": "Connection refused — is TheHive running?"}


async def list_cases(
    limit: int = 20,
    offset: int = 0,
    status: Optional[str] = None,
    severity: Optional[int] = None,
    time_range_hours: Optional[int] = None,
    search: Optional[str] = None,
) -> List[Dict]:
    if not settings.THEHIVE_ENABLED:
        return []
    try:
        import time as _time
        filters = []
        if status:
            filters.append({"_eq": {"_field": "status", "_value": status}})
        if severity:
            filters.append({"_eq": {"_field": "severity", "_value": severity}})
        if time_range_hours:
            cutoff_ms = int((_time.time() - time_range_hours * 3600) * 1000)
            filters.append({"_gte": {"_field": "_createdAt", "_value": cutoff_ms}})
        if search:
            filters.append({"_like": {"_field": "title", "_value": f"*{search}*"}})

        query: list = [{"_name": "listCase"}]
        if len(filters) == 1:
            query.append({"_name": "filter", **filters[0]})
        elif len(filters) > 1:
            query.append({"_name": "filter", "_and": filters})

        async with httpx.AsyncClient(timeout=10, verify=False) as client:
            body = {
                "query": query,
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
            print(f"[TheHive] list_cases HTTP {r.status_code}: {r.text[:300]}")
    except Exception as e:
        print(f"[TheHive] list_cases error: {e}")
    return []


async def delete_case(case_id: str) -> bool:
    if not settings.THEHIVE_ENABLED:
        return False
    try:
        async with httpx.AsyncClient(timeout=10, verify=False) as client:
            r = await client.delete(
                f"{settings.THEHIVE_URL}/api/v1/case/{case_id}",
                headers=_headers(),
            )
            return r.status_code in (200, 204)
    except Exception as e:
        print(f"[TheHive] delete_case error: {e}")
    return False


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
