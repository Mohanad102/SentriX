from fastapi import APIRouter, Depends, HTTPException
from backend.utils.auth import get_current_user
from backend.models.user import User
from backend.config import settings
from backend.services import thehive_service, cortex_service

router = APIRouter(prefix="/api/integrations", tags=["integrations"])


def _admin_only(current_user: User = Depends(get_current_user)):
    if current_user.role != "admin":
        raise HTTPException(status_code=403, detail="Admin only")
    return current_user


@router.get("/settings")
async def get_settings(current_user: User = Depends(_admin_only)):
    return {
        "thehive": {
            "url": settings.THEHIVE_URL,
            "api_key_set": bool(settings.THEHIVE_API_KEY),
            "enabled": settings.THEHIVE_ENABLED,
        },
        "cortex": {
            "url": settings.CORTEX_URL,
            "api_key_set": bool(settings.CORTEX_API_KEY),
            "enabled": settings.CORTEX_ENABLED,
        },
        "wazuh": {
            "url": settings.WAZUH_URL,
            "enabled": settings.WAZUH_ENABLED,
        },
        "virustotal": {
            "api_key_set": bool(settings.VIRUSTOTAL_API_KEY),
            "enabled": settings.VIRUSTOTAL_ENABLED,
        },
        "ai": {
            "model": settings.OPENAI_MODEL,
            "api_key_set": bool(settings.OPENAI_API_KEY),
            "enabled": settings.AI_ENABLED,
        },
    }


@router.post("/test/thehive")
async def test_thehive(current_user: User = Depends(get_current_user)):
    return await thehive_service.get_status()


@router.post("/test/cortex")
async def test_cortex(current_user: User = Depends(get_current_user)):
    return await cortex_service.get_status()


@router.post("/test/wazuh")
async def test_wazuh(current_user: User = Depends(get_current_user)):
    import httpx
    if not settings.WAZUH_ENABLED:
        return {"connected": False, "error": "Wazuh is disabled"}
    try:
        async with httpx.AsyncClient(verify=False, timeout=8) as client:
            r = await client.get(
                f"{settings.WAZUH_URL}/",
                auth=(settings.WAZUH_USER, settings.WAZUH_PASSWORD),
            )
        if r.status_code in (200, 401):
            data = r.json() if r.status_code == 200 else {}
            version = data.get("data", {}).get("api_version") or data.get("api_version", "")
            return {"connected": True, "version": version or "OK"}
        return {"connected": False, "error": f"HTTP {r.status_code}"}
    except Exception as e:
        return {"connected": False, "error": str(e)}


@router.post("/test/virustotal")
async def test_virustotal(current_user: User = Depends(get_current_user)):
    import httpx
    if not settings.VIRUSTOTAL_ENABLED or not settings.VIRUSTOTAL_API_KEY:
        return {"connected": False, "error": "VirusTotal is disabled or API key not set"}
    try:
        async with httpx.AsyncClient(timeout=8) as client:
            r = await client.get(
                "https://www.virustotal.com/api/v3/ip_addresses/8.8.8.8",
                headers={"x-apikey": settings.VIRUSTOTAL_API_KEY},
            )
        if r.status_code == 200:
            return {"connected": True, "version": "API v3"}
        if r.status_code == 401:
            return {"connected": False, "error": "Invalid API key"}
        return {"connected": False, "error": f"HTTP {r.status_code}"}
    except Exception as e:
        return {"connected": False, "error": str(e)}
