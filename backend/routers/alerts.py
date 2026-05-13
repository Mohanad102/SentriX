from fastapi import APIRouter, Depends, HTTPException, Query, BackgroundTasks
from sqlalchemy.orm import Session
from sqlalchemy import or_
from pydantic import BaseModel
from typing import Optional, List
from backend.database import get_db, SessionLocal
from backend.models.alert import Alert
from backend.utils.auth import get_current_user
from backend.models.user import User
import uuid
from datetime import datetime

router = APIRouter(prefix="/api/alerts", tags=["alerts"])


class AlertCreate(BaseModel):
    title: str
    description: Optional[str] = None
    severity: str = "medium"
    source_ip: Optional[str] = None
    dest_ip: Optional[str] = None
    hostname: Optional[str] = None
    rule_id: Optional[str] = None
    rule_level: Optional[int] = None
    category: Optional[str] = None
    raw_data: Optional[str] = None


class AlertUpdate(BaseModel):
    status:        Optional[str] = None
    severity:      Optional[str] = None
    incident_id:   Optional[int] = None
    triage_result: Optional[str] = None   # true_positive | false_positive | suspicious
    notes:         Optional[str] = None


def alert_to_dict(a: Alert, is_malicious: bool = None, closed_by: str = None):
    return {
        "id":            a.id,
        "alert_id":      a.alert_id,
        "title":         a.title,
        "description":   a.description,
        "severity":      a.severity,
        "source":        a.source,
        "source_ip":     a.source_ip,
        "dest_ip":       a.dest_ip,
        "hostname":      a.hostname,
        "rule_id":       a.rule_id,
        "rule_level":    a.rule_level,
        "category":      a.category,
        "status":        a.status,
        "raw_data":      a.raw_data,
        "incident_id":   a.incident_id,
        "vt_enriched":   a.vt_enriched or False,
        "is_malicious":  is_malicious,
        "triage_result": a.triage_result,
        "notes":         a.notes,
        "ticket_ref":    a.ticket_ref,
        "closed_by":     closed_by,
        "closed_at":     a.closed_at.isoformat() if a.closed_at else None,
        "created_at":    a.created_at.isoformat() if a.created_at else None,
        "updated_at":    a.updated_at.isoformat() if a.updated_at else None,
    }


@router.get("")
def list_alerts(
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    severity: Optional[str] = None,
    status: Optional[str] = None,
    category: Optional[str] = None,
    search: Optional[str] = None,
    time_range: Optional[str] = None,
    sort_order: Optional[str] = Query("desc", pattern="^(asc|desc)$"),
    hostname: Optional[str] = None,
    hostnames: Optional[str] = None,
    source: Optional[str] = None,
    min_level: Optional[int] = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    query = db.query(Alert)
    if severity:
        query = query.filter(Alert.severity == severity)
    if status:
        query = query.filter(Alert.status == status)
    if category:
        query = query.filter(Alert.category == category)
    if source:
        query = query.filter(Alert.source == source)
    if hostname:
        query = query.filter(Alert.hostname.ilike(f"%{hostname}%"))
    if hostnames:
        names = [h.strip() for h in hostnames.split(",") if h.strip()]
        if names:
            query = query.filter(or_(*[Alert.hostname.ilike(f"%{n}%") for n in names]))
    if search:
        query = query.filter(
            or_(
                Alert.title.ilike(f"%{search}%"),
                Alert.source_ip.ilike(f"%{search}%"),
                Alert.hostname.ilike(f"%{search}%"),
                Alert.alert_id.ilike(f"%{search}%"),
            )
        )
    if min_level is not None:
        query = query.filter(Alert.rule_level >= min_level)
    if time_range:
        from datetime import timedelta
        cutoffs = {"24h": timedelta(hours=24), "7d": timedelta(days=7), "30d": timedelta(days=30)}
        if time_range in cutoffs:
            query = query.filter(Alert.created_at >= datetime.utcnow() - cutoffs[time_range])
    order_col = Alert.created_at.asc() if sort_order == "asc" else Alert.created_at.desc()
    total = query.count()
    alerts = query.order_by(order_col).offset((page - 1) * page_size).limit(page_size).all()

    # Batch-resolve closed_by usernames
    closed_ids = {a.closed_by_id for a in alerts if a.closed_by_id}
    closed_map: dict = {}
    if closed_ids:
        users = db.query(User).filter(User.id.in_(closed_ids)).all()
        closed_map = {u.id: u.username for u in users}

    return {
        "total": total,
        "page": page,
        "page_size": page_size,
        "pages": (total + page_size - 1) // page_size,
        "items": [alert_to_dict(a, a.vt_malicious, closed_map.get(a.closed_by_id)) for a in alerts]
    }


@router.get("/{alert_id}")
def get_alert(
    alert_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    alert = db.query(Alert).filter(Alert.id == alert_id).first()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    closed_by = None
    if alert.closed_by_id:
        u = db.query(User).filter(User.id == alert.closed_by_id).first()
        closed_by = u.username if u else None
    return alert_to_dict(alert, alert.vt_malicious, closed_by)


async def _bg_enrich_alert(alert_id: int):
    """Background task: run VT enrichment for an alert using its own DB session."""
    import asyncio
    from backend.services.virustotal_service import auto_enrich_alert
    db = SessionLocal()
    try:
        alert = db.query(Alert).filter(Alert.id == alert_id).first()
        if alert:
            await auto_enrich_alert(db, alert)
    except Exception:
        pass
    finally:
        db.close()


@router.post("")
async def create_alert(
    data: AlertCreate,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    alert = Alert(
        alert_id=f"ALT-{uuid.uuid4().hex[:8].upper()}",
        title=data.title,
        description=data.description,
        severity=data.severity,
        source="manual",
        source_ip=data.source_ip,
        dest_ip=data.dest_ip,
        hostname=data.hostname,
        rule_id=data.rule_id,
        rule_level=data.rule_level,
        category=data.category,
        raw_data=data.raw_data
    )
    db.add(alert)
    db.commit()
    db.refresh(alert)
    background_tasks.add_task(_bg_enrich_alert, alert.id)
    return alert_to_dict(alert)


@router.patch("/{alert_id}")
def update_alert(
    alert_id: int,
    data: AlertUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    alert = db.query(Alert).filter(Alert.id == alert_id).first()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    if data.status is not None:
        alert.status = data.status
        if data.status == "closed" and not alert.closed_by_id:
            alert.closed_by_id = current_user.id
            alert.closed_at    = datetime.utcnow()
    if data.severity is not None:
        alert.severity = data.severity
    if data.incident_id is not None:
        alert.incident_id = data.incident_id
    if data.triage_result is not None:
        alert.triage_result = data.triage_result
    if data.notes is not None:
        alert.notes = data.notes
    alert.updated_at = datetime.utcnow()
    db.commit()
    db.refresh(alert)
    closed_by = None
    if alert.closed_by_id:
        u = db.query(User).filter(User.id == alert.closed_by_id).first()
        closed_by = u.username if u else None
    return alert_to_dict(alert, alert.vt_malicious, closed_by)


@router.delete("/{alert_id}")
def delete_alert(
    alert_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    alert = db.query(Alert).filter(Alert.id == alert_id).first()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    db.delete(alert)
    db.commit()
    return {"message": "Alert deleted"}


@router.post("/enrich-batch")
async def enrich_batch(
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Trigger background VT enrichment for all unenriched alerts that have a source IP."""
    unenriched = db.query(Alert).filter(
        Alert.vt_enriched == False,
        Alert.source_ip != None,
        Alert.source_ip != ""
    ).all()
    ids = [a.id for a in unenriched]
    for alert_id in ids:
        background_tasks.add_task(_bg_enrich_alert, alert_id)
    return {"queued": len(ids)}


@router.post("/{alert_id}/escalate")
def escalate_to_incident(
    alert_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    from backend.models.incident import Incident
    alert = db.query(Alert).filter(Alert.id == alert_id).first()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")

    import uuid as _uuid
    incident = Incident(
        case_number=f"INC-{_uuid.uuid4().hex[:6].upper()}",
        title=f"Incident from: {alert.title}",
        description=alert.description or alert.title,
        severity=alert.severity,
        category=alert.category,
        assigned_to=current_user.username,
        created_by=current_user.id,
        status="open"
    )
    db.add(incident)
    db.flush()
    alert.incident_id = incident.id
    alert.status = "in_progress"
    db.commit()
    return {"message": "Alert escalated to incident", "incident_id": incident.id, "case_number": incident.case_number}
