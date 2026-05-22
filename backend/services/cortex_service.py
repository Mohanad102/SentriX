"""Cortex Integration Service."""
import httpx
from typing import List, Dict, Optional
from backend.config import settings


def _headers() -> Dict:
    return {
        "Authorization": f"Bearer {settings.CORTEX_API_KEY}",
        "Content-Type": "application/json",
    }


async def get_status() -> Dict:
    if not settings.CORTEX_ENABLED:
        return {"connected": False, "url": settings.CORTEX_URL, "error": "Service disabled — set CORTEX_ENABLED=true in .env"}
    try:
        async with httpx.AsyncClient(timeout=5, verify=False) as client:
            r = await client.get(f"{settings.CORTEX_URL}/api/user/current", headers=_headers())
            if r.status_code == 200:
                info = r.json()
                return {
                    "connected": True,
                    "url": settings.CORTEX_URL,
                    "user": info.get("login", "unknown"),
                }
            return {"connected": False, "url": settings.CORTEX_URL, "error": f"HTTP {r.status_code}"}
    except Exception as e:
        return {"connected": False, "url": settings.CORTEX_URL, "error": "Connection refused — is Cortex running?"}


async def list_analyzers() -> List[Dict]:
    if not settings.CORTEX_ENABLED:
        return []
    try:
        async with httpx.AsyncClient(timeout=10, verify=False) as client:
            r = await client.get(f"{settings.CORTEX_URL}/api/analyzer", headers=_headers())
            if r.status_code == 200:
                return r.json()
    except Exception as e:
        print(f"[Cortex] list_analyzers error: {e}")
    return []


async def run_analyzer(analyzer_id: str, observable: str, data_type: str) -> Optional[Dict]:
    if not settings.CORTEX_ENABLED:
        return None
    try:
        async with httpx.AsyncClient(timeout=15, verify=False) as client:
            body = {
                "data": observable,
                "dataType": data_type,
                "tlp": 2,
                "pap": 2,
                "message": "Submitted by SentriX",
            }
            r = await client.post(
                f"{settings.CORTEX_URL}/api/analyzer/{analyzer_id}/run",
                headers=_headers(),
                json=body,
            )
            if r.status_code in (200, 201):
                return r.json()
            print(f"[Cortex] run_analyzer HTTP {r.status_code}: {r.text[:200]}")
    except Exception as e:
        print(f"[Cortex] run_analyzer error: {e}")
    return None


async def get_job(job_id: str) -> Optional[Dict]:
    if not settings.CORTEX_ENABLED:
        return None
    try:
        async with httpx.AsyncClient(timeout=10, verify=False) as client:
            r = await client.get(f"{settings.CORTEX_URL}/api/job/{job_id}", headers=_headers())
            if r.status_code == 200:
                return r.json()
    except Exception as e:
        print(f"[Cortex] get_job error: {e}")
    return None


async def get_job_report(job_id: str) -> Optional[Dict]:
    if not settings.CORTEX_ENABLED:
        return None
    try:
        async with httpx.AsyncClient(timeout=10, verify=False) as client:
            r = await client.get(f"{settings.CORTEX_URL}/api/job/{job_id}/report", headers=_headers())
            if r.status_code == 200:
                return r.json()
    except Exception as e:
        print(f"[Cortex] get_job_report error: {e}")
    return None
