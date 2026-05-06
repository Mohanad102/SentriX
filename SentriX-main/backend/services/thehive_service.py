"""
TheHive SOAR Integration Service.
Syncs cases with TheHive when enabled.
"""
import httpx
from typing import Optional, Dict
from backend.config import settings


async def create_thehive_case(incident: Dict) -> Optional[str]:
    """Create a case in TheHive from a SentriX incident. Returns TheHive case ID."""
    if not settings.THEHIVE_ENABLED or not settings.THEHIVE_API_KEY:
        return None
    try:
        headers = {
            "Authorization": f"Bearer {settings.THEHIVE_API_KEY}",
            "Content-Type": "application/json"
        }
        severity_map = {"low": 1, "medium": 2, "high": 3, "critical": 4}
        payload = {
            "title": incident.get("title"),
            "description": incident.get("description", ""),
            "severity": severity_map.get(incident.get("severity", "medium"), 2),
            "tags": incident.get("tags", "").split(",") if incident.get("tags") else [],
            "tlp": 2,
            "status": "New"
        }
        async with httpx.AsyncClient(timeout=10) as client:
            resp = await client.post(
                f"{settings.THEHIVE_URL}/api/case",
                json=payload,
                headers=headers
            )
            if resp.status_code == 201:
                return resp.json().get("id")
    except Exception as e:
        print(f"TheHive error: {e}")
    return None


async def get_thehive_case(case_id: str) -> Optional[Dict]:
    if not settings.THEHIVE_ENABLED:
        return None
    try:
        headers = {"Authorization": f"Bearer {settings.THEHIVE_API_KEY}"}
        async with httpx.AsyncClient(timeout=10) as client:
            resp = await client.get(
                f"{settings.THEHIVE_URL}/api/case/{case_id}",
                headers=headers
            )
            if resp.status_code == 200:
                return resp.json()
    except Exception as e:
        print(f"TheHive error: {e}")
    return None


async def submit_cortex_task(observable: str, datatype: str, analyzer: str = "VirusTotal_GetReport_3_1") -> Optional[Dict]:
    """Submit an observable to Cortex for analysis."""
    if not settings.CORTEX_ENABLED or not settings.CORTEX_API_KEY:
        return None
    try:
        headers = {
            "Authorization": f"Bearer {settings.CORTEX_API_KEY}",
            "Content-Type": "application/json"
        }
        payload = {
            "data": observable,
            "dataType": datatype,
            "tlp": 2,
            "analyzerId": analyzer
        }
        async with httpx.AsyncClient(timeout=15) as client:
            resp = await client.post(
                f"{settings.CORTEX_URL}/api/analyzer/{analyzer}/run",
                json=payload,
                headers=headers
            )
            if resp.status_code in (200, 201):
                return resp.json()
    except Exception as e:
        print(f"Cortex error: {e}")
    return None
