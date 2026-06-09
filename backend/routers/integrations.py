from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from pydantic import BaseModel
from typing import Optional
from backend.utils.auth import get_current_user
from backend.models.user import User
from backend.config import settings
from backend.services import thehive_service, cortex_service
from backend.database import get_db

router = APIRouter(prefix="/api/integrations", tags=["integrations"])

_SETTINGS_MAP = {
    "thehive":    {"url": "THEHIVE_URL",    "api_key": "THEHIVE_API_KEY",    "enabled": "THEHIVE_ENABLED"},
    "cortex":     {"url": "CORTEX_URL",     "api_key": "CORTEX_API_KEY",     "enabled": "CORTEX_ENABLED"},
    "wazuh":      {"url": "WAZUH_URL", "username": "WAZUH_USER", "password": "WAZUH_PASSWORD", "enabled": "WAZUH_ENABLED"},
    "virustotal": {"api_key": "VIRUSTOTAL_API_KEY", "enabled": "VIRUSTOTAL_ENABLED"},
    "ai":         {"anthropic_key": "ANTHROPIC_API_KEY", "model": "ANTHROPIC_MODEL", "openai_key": "OPENAI_API_KEY"},
}

_SENSITIVE = {"api_key", "anthropic_key", "openai_key", "password"}


def _upsert(db: Session, service: str, key: str, value: str):
    from backend.models.integration_setting import IntegrationSetting
    row = db.query(IntegrationSetting).filter_by(service=service, key=key).first()
    if row:
        row.value = value
    else:
        db.add(IntegrationSetting(service=service, key=key, value=value))
    db.commit()


def load_db_overrides():
    """Load integration settings from DB into in-memory settings. Called at startup."""
    from backend.models.integration_setting import IntegrationSetting
    from backend.database import SessionLocal
    db = SessionLocal()
    try:
        for row in db.query(IntegrationSetting).all():
            attr = _SETTINGS_MAP.get(row.service, {}).get(row.key)
            if attr and row.value is not None:
                current = getattr(settings, attr, None)
                if isinstance(current, bool):
                    setattr(settings, attr, row.value.lower() in ("true", "1"))
                else:
                    setattr(settings, attr, row.value)
    except Exception as e:
        print(f"[Integration] DB override load failed: {e}")
    finally:
        db.close()


def _ai_provider_name() -> str:
    if settings.ANTHROPIC_API_KEY:
        return "Claude (Anthropic)"
    if settings.OPENAI_API_KEY and settings.AI_ENABLED:
        return "OpenAI"
    return "Demo Mode"


def _ai_model_display() -> str:
    if settings.ANTHROPIC_API_KEY:
        return settings.ANTHROPIC_MODEL
    if settings.OPENAI_API_KEY and settings.AI_ENABLED:
        return settings.OPENAI_MODEL
    return "not configured"


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
            "username": settings.WAZUH_USER,
            "enabled": settings.WAZUH_ENABLED,
        },
        "virustotal": {
            "api_key_set": bool(settings.VIRUSTOTAL_API_KEY),
            "enabled": settings.VIRUSTOTAL_ENABLED,
        },
        "ai": {
            "model": _ai_model_display(),
            "provider": _ai_provider_name(),
            "api_key_set": bool(settings.ANTHROPIC_API_KEY or settings.OPENAI_API_KEY),
            "enabled": bool(settings.ANTHROPIC_API_KEY or (settings.OPENAI_API_KEY and settings.AI_ENABLED)),
        },
    }


class SaveBody(BaseModel):
    url: Optional[str] = None
    api_key: Optional[str] = None
    username: Optional[str] = None
    password: Optional[str] = None
    anthropic_key: Optional[str] = None
    openai_key: Optional[str] = None
    model: Optional[str] = None
    enabled: Optional[bool] = None


@router.post("/save/{service}")
async def save_integration(
    service: str,
    body: SaveBody,
    db: Session = Depends(get_db),
    current_user: User = Depends(_admin_only),
):
    if service not in _SETTINGS_MAP:
        raise HTTPException(status_code=400, detail="Unknown service")

    smap = _SETTINGS_MAP[service]

    for field, value in body.dict(exclude_none=True).items():
        if field not in smap:
            continue
        if field in _SENSITIVE and not str(value).strip():
            continue  # blank = keep current value

        str_val = str(value) if not isinstance(value, bool) else ("true" if value else "false")
        _upsert(db, service, field, str_val)

        attr = smap[field]
        current = getattr(settings, attr, None)
        if isinstance(current, bool):
            setattr(settings, attr, value if isinstance(value, bool) else str(value).lower() in ("true", "1"))
        else:
            setattr(settings, attr, value)

    return {"ok": True}


# ── Test endpoints ──────────────────────────────────────────────────────────────

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


@router.post("/test/ai")
async def test_ai(current_user: User = Depends(get_current_user)):
    if settings.ANTHROPIC_API_KEY:
        try:
            import anthropic
            client = anthropic.AsyncAnthropic(api_key=settings.ANTHROPIC_API_KEY)
            await client.messages.create(
                model=settings.ANTHROPIC_MODEL,
                max_tokens=1,
                messages=[{"role": "user", "content": "ping"}],
            )
            return {"connected": True, "version": settings.ANTHROPIC_MODEL, "provider": "Claude (Anthropic)"}
        except Exception as e:
            err = str(e)
            if "credit" in err.lower() or "billing" in err.lower():
                return {"connected": False, "error": "Insufficient credits — top up at console.anthropic.com"}
            if "invalid" in err.lower() or "auth" in err.lower():
                return {"connected": False, "error": "Invalid API key"}
            return {"connected": False, "error": err[:120]}

    if settings.OPENAI_API_KEY and settings.AI_ENABLED:
        try:
            import httpx
            async with httpx.AsyncClient(timeout=8) as client:
                r = await client.get(
                    "https://api.openai.com/v1/models",
                    headers={"Authorization": f"Bearer {settings.OPENAI_API_KEY}"},
                )
            if r.status_code == 200:
                return {"connected": True, "version": settings.OPENAI_MODEL, "provider": "OpenAI"}
            return {"connected": False, "error": f"OpenAI returned HTTP {r.status_code}"}
        except Exception as e:
            return {"connected": False, "error": str(e)}

    return {"connected": False, "error": "No AI provider configured — add ANTHROPIC_API_KEY to .env"}
