from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from typing import Optional, List
from backend.utils.auth import get_current_user
from backend.models.user import User
from backend.config import settings
from backend.services import thehive_service
from backend.database import SessionLocal
from backend.models.alert import Alert
from backend.models.incident import Incident

router = APIRouter(prefix="/api/thehive", tags=["thehive"])


class CreateCaseRequest(BaseModel):
    title: str
    description: str
    severity: str = "medium"
    tags: Optional[List[str]] = None


@router.get("/status")
async def thehive_status(current_user: User = Depends(get_current_user)):
    status = await thehive_service.get_status()
    status["enabled"] = settings.THEHIVE_ENABLED
    return status


@router.get("/cases")
async def list_cases(
    limit: int = 20,
    offset: int = 0,
    current_user: User = Depends(get_current_user),
):
    if not settings.THEHIVE_ENABLED:
        raise HTTPException(status_code=503, detail="TheHive integration is not enabled")
    return await thehive_service.list_cases(limit=limit, offset=offset)


@router.get("/cases/{case_id}")
async def get_case(case_id: str, current_user: User = Depends(get_current_user)):
    if not settings.THEHIVE_ENABLED:
        raise HTTPException(status_code=503, detail="TheHive integration is not enabled")
    case = await thehive_service.get_case(case_id)
    if not case:
        raise HTTPException(status_code=404, detail="Case not found")
    return case


@router.post("/cases")
async def create_case(req: CreateCaseRequest, current_user: User = Depends(get_current_user)):
    case = await thehive_service.create_case(
        title=req.title,
        description=req.description,
        severity=thehive_service.SEVERITY_MAP.get(req.severity, 2),
        tags=req.tags,
    )
    if not case:
        raise HTTPException(status_code=503, detail="Failed to create case in TheHive — check connection and API key")
    return case


@router.post("/cases/from-alert/{alert_id}")
async def push_alert_to_thehive(alert_id: int, current_user: User = Depends(get_current_user)):
    db = SessionLocal()
    try:
        alert = db.query(Alert).filter(Alert.id == alert_id).first()
        if not alert:
            raise HTTPException(status_code=404, detail="Alert not found")
        case = await thehive_service.create_case_from_alert(alert)
        if not case:
            raise HTTPException(status_code=503, detail="Failed to create case in TheHive")
        return case
    finally:
        db.close()


@router.post("/cases/from-incident/{incident_id}")
async def push_incident_to_thehive(incident_id: int, current_user: User = Depends(get_current_user)):
    db = SessionLocal()
    try:
        incident = db.query(Incident).filter(Incident.id == incident_id).first()
        if not incident:
            raise HTTPException(status_code=404, detail="Incident not found")
        case = await thehive_service.create_case_from_incident(incident)
        if not case:
            raise HTTPException(status_code=503, detail="Failed to create case in TheHive")
        # Persist TheHive case ID on the incident
        hive_id = case.get("_id") or case.get("id")
        if hive_id:
            incident.thehive_id = str(hive_id)
            db.commit()
        return case
    finally:
        db.close()
