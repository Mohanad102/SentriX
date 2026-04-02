from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from pydantic import BaseModel
from typing import Optional
from backend.database import get_db
from backend.models.ioc import IOC
from backend.utils.auth import get_current_user
from backend.models.user import User
from datetime import datetime

router = APIRouter(prefix="/api/ioc", tags=["ioc"])


class IOCCreate(BaseModel):
    value: str
    ioc_type: str  # ip, domain, url, hash, email
    incident_id: Optional[int] = None
    tags: Optional[str] = None


def ioc_to_dict(i: IOC):
    return {
        "id": i.id,
        "value": i.value,
        "ioc_type": i.ioc_type,
        "incident_id": i.incident_id,
        "is_malicious": i.is_malicious,
        "vt_score": i.vt_score,
        "vt_report": i.vt_report,
        "enriched": i.enriched,
        "tags": i.tags,
        "created_at": i.created_at.isoformat() if i.created_at else None,
        "enriched_at": i.enriched_at.isoformat() if i.enriched_at else None,
    }


@router.get("")
def list_iocs(
    incident_id: Optional[int] = None,
    ioc_type: Optional[str] = None,
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    query = db.query(IOC)
    if incident_id:
        query = query.filter(IOC.incident_id == incident_id)
    if ioc_type:
        query = query.filter(IOC.ioc_type == ioc_type)
    total = query.count()
    items = query.order_by(IOC.created_at.desc()).offset((page - 1) * page_size).limit(page_size).all()
    return {"total": total, "items": [ioc_to_dict(i) for i in items]}


@router.post("")
def create_ioc(
    data: IOCCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    ioc = IOC(
        value=data.value,
        ioc_type=data.ioc_type,
        incident_id=data.incident_id,
        tags=data.tags
    )
    db.add(ioc)
    db.commit()
    db.refresh(ioc)
    return ioc_to_dict(ioc)


@router.post("/{ioc_id}/enrich")
async def enrich_ioc(
    ioc_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    ioc = db.query(IOC).filter(IOC.id == ioc_id).first()
    if not ioc:
        raise HTTPException(status_code=404, detail="IOC not found")

    from backend.services.virustotal_service import enrich_with_virustotal
    result = await enrich_with_virustotal(ioc.value, ioc.ioc_type)

    ioc.enriched = True
    ioc.enriched_at = datetime.utcnow()
    ioc.vt_score = result.get("score")
    ioc.vt_report = str(result.get("report", ""))
    ioc.is_malicious = result.get("is_malicious", False)
    db.commit()
    db.refresh(ioc)
    return ioc_to_dict(ioc)


@router.post("/bulk-enrich")
async def bulk_enrich(
    incident_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    iocs = db.query(IOC).filter(IOC.incident_id == incident_id, IOC.enriched == False).all()  # noqa: E712
    if not iocs:
        return {"message": "No unenriched IOCs found", "enriched": 0}

    from backend.services.virustotal_service import enrich_with_virustotal
    enriched_count = 0
    for ioc in iocs:
        try:
            result = await enrich_with_virustotal(ioc.value, ioc.ioc_type)
            ioc.enriched = True
            ioc.enriched_at = datetime.utcnow()
            ioc.vt_score = result.get("score")
            ioc.vt_report = str(result.get("report", ""))
            ioc.is_malicious = result.get("is_malicious", False)
            enriched_count += 1
        except Exception:
            pass
    db.commit()
    return {"message": f"Enriched {enriched_count} IOCs", "enriched": enriched_count}


@router.delete("/{ioc_id}")
def delete_ioc(
    ioc_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    ioc = db.query(IOC).filter(IOC.id == ioc_id).first()
    if not ioc:
        raise HTTPException(status_code=404, detail="IOC not found")
    db.delete(ioc)
    db.commit()
    return {"message": "IOC deleted"}
