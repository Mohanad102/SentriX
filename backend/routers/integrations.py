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
        "abuseipdb": {
            "api_key_set": bool(settings.ABUSEIPDB_API_KEY),
            "enabled": settings.ABUSEIPDB_ENABLED,
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
