from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from backend.utils.auth import get_current_user
from backend.models.user import User
from backend.services.virustotal_service import enrich_with_virustotal

router = APIRouter(prefix="/api/virustotal", tags=["virustotal"])


class ScanRequest(BaseModel):
    value: str
    ioc_type: str  # ip, domain, url, hash


@router.post("/scan")
async def scan(req: ScanRequest, current_user: User = Depends(get_current_user)):
    if not req.value.strip():
        raise HTTPException(status_code=400, detail="Value is required")
    return await enrich_with_virustotal(req.value.strip(), req.ioc_type)
