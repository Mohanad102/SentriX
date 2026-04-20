import json
from fastapi import APIRouter, Depends, HTTPException, Query, BackgroundTasks
from pydantic import BaseModel
from typing import Optional
from sqlalchemy.orm import Session
from backend.database import get_db
from backend.utils.auth import get_current_user
from backend.models.user import User
from backend.models.ioc import IOC
from backend.services.virustotal_service import enrich_with_virustotal, enrich_and_store_ioc, enrich_pending_iocs

router = APIRouter(prefix="/api/virustotal", tags=["virustotal"])


class ScanRequest(BaseModel):
    value: str
    ioc_type: str  # ip, domain, url, hash


def ioc_to_dict(ioc: IOC) -> dict:
    report = {}
    if ioc.vt_report:
        try:
            report = json.loads(ioc.vt_report)
        except Exception:
            pass
    return {
        "id": ioc.id,
        "value": ioc.value,
        "ioc_type": ioc.ioc_type,
        "alert_id": ioc.alert_id,
        "incident_id": ioc.incident_id,
        "is_malicious": ioc.is_malicious,
        "vt_score": ioc.vt_score,
        "report": report,
        "enriched": ioc.enriched,
        "tags": ioc.tags,
        "created_at": ioc.created_at.isoformat() if ioc.created_at else None,
        "enriched_at": ioc.enriched_at.isoformat() if ioc.enriched_at else None,
    }


@router.post("/scan")
async def scan(req: ScanRequest, current_user: User = Depends(get_current_user)):
    if not req.value.strip():
        raise HTTPException(status_code=400, detail="Value is required")
    return await enrich_with_virustotal(req.value.strip(), req.ioc_type)


@router.get("/iocs")
def list_iocs(
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    enriched_only: bool = Query(False),
    malicious_only: bool = Query(False),
    ioc_type: Optional[str] = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    query = db.query(IOC)
    if enriched_only:
        query = query.filter(IOC.enriched == True)  # noqa: E712
    if malicious_only:
        query = query.filter(IOC.is_malicious == True)  # noqa: E712
    if ioc_type:
        query = query.filter(IOC.ioc_type == ioc_type)

    total = query.count()
    items = query.order_by(IOC.created_at.desc()).offset((page - 1) * page_size).limit(page_size).all()
    return {
        "total": total,
        "page": page,
        "page_size": page_size,
        "pages": (total + page_size - 1) // page_size,
        "items": [ioc_to_dict(i) for i in items],
    }


@router.post("/enrich-alert/{alert_id}")
async def enrich_alert(
    alert_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    from backend.models.alert import Alert
    from backend.services.virustotal_service import auto_enrich_alert

    alert = db.query(Alert).filter(Alert.id == alert_id).first()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")

    await auto_enrich_alert(db, alert)
    return {"message": f"Enrichment complete for alert {alert_id}"}


@router.post("/enrich-pending")
async def enrich_pending(
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    count = await enrich_pending_iocs(db)
    return {"message": f"Enriched {count} pending IOC(s)"}


@router.get("/stats")
def vt_stats(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    total = db.query(IOC).count()
    enriched = db.query(IOC).filter(IOC.enriched == True).count()  # noqa: E712
    malicious = db.query(IOC).filter(IOC.is_malicious == True).count()  # noqa: E712
    pending = total - enriched
    return {
        "total": total,
        "enriched": enriched,
        "malicious": malicious,
        "pending": pending,
    }
