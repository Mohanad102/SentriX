from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from backend.utils.auth import get_current_user
from backend.models.user import User
from backend.config import settings
from backend.services import cortex_service

router = APIRouter(prefix="/api/cortex", tags=["cortex"])


class AnalyzeRequest(BaseModel):
    observable: str
    data_type: str   # ip, domain, url, hash, mail, file
    analyzer_id: str


@router.get("/status")
async def cortex_status(current_user: User = Depends(get_current_user)):
    status = await cortex_service.get_status()
    status["enabled"] = settings.CORTEX_ENABLED
    return status


@router.get("/analyzers")
async def list_analyzers(current_user: User = Depends(get_current_user)):
    if not settings.CORTEX_ENABLED:
        raise HTTPException(status_code=503, detail="Cortex integration is not enabled")
    return await cortex_service.list_analyzers()


@router.post("/analyze")
async def analyze(req: AnalyzeRequest, current_user: User = Depends(get_current_user)):
    if not req.observable.strip():
        raise HTTPException(status_code=400, detail="Observable value is required")
    job = await cortex_service.run_analyzer(req.analyzer_id, req.observable.strip(), req.data_type)
    if not job:
        raise HTTPException(status_code=503, detail="Failed to submit job to Cortex — check connection and API key")
    return job


@router.get("/jobs/{job_id}")
async def get_job(job_id: str, current_user: User = Depends(get_current_user)):
    job = await cortex_service.get_job(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    return job


@router.get("/jobs/{job_id}/report")
async def get_job_report(job_id: str, current_user: User = Depends(get_current_user)):
    report = await cortex_service.get_job_report(job_id)
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")
    return report
