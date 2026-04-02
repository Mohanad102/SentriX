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


@router.post("/{ioc_id}/enrich-abuse")
async def enrich_ioc_abuse(
    ioc_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Enrich an IP IOC using AbuseIPDB."""
    from backend.config import settings
    import httpx

    ioc = db.query(IOC).filter(IOC.id == ioc_id).first()
    if not ioc:
        raise HTTPException(status_code=404, detail="IOC not found")
    if ioc.ioc_type != "ip":
        raise HTTPException(status_code=400, detail="AbuseIPDB only supports IP type IOCs")

    api_key = getattr(settings, "ABUSEIPDB_API_KEY", "")
    if not api_key:
        raise HTTPException(status_code=503, detail="AbuseIPDB API key not configured")

    try:
        async with httpx.AsyncClient(timeout=10) as client:
            resp = await client.get(
                "https://api.abuseipdb.com/api/v2/check",
                headers={"Key": api_key, "Accept": "application/json"},
                params={"ipAddress": ioc.value, "maxAgeInDays": 90}
            )
        data = resp.json().get("data", {})
        score = data.get("abuseConfidenceScore", 0)
        ioc.enriched = True
        ioc.enriched_at = datetime.utcnow()
        ioc.vt_score = f"AbuseScore: {score}/100"
        ioc.is_malicious = score >= 50
        ioc.vt_report = str(data)
        db.commit()
        db.refresh(ioc)
        return {**ioc_to_dict(ioc), "abuse_score": score, "country": data.get("countryCode"),
                "isp": data.get("isp"), "total_reports": data.get("totalReports")}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"AbuseIPDB error: {e}")


@router.get("/search")
def search_iocs(
    q: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Search IOCs across all incidents."""
    results = db.query(IOC).filter(IOC.value.ilike(f"%{q}%")).limit(50).all()
    return {"total": len(results), "items": [ioc_to_dict(i) for i in results]}


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
