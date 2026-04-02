from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from sqlalchemy import or_
from pydantic import BaseModel
from typing import Optional, List
from backend.database import get_db
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
    status: Optional[str] = None
    severity: Optional[str] = None
    incident_id: Optional[int] = None


def alert_to_dict(a: Alert):
    return {
        "id": a.id,
        "alert_id": a.alert_id,
        "title": a.title,
        "description": a.description,
        "severity": a.severity,
        "source": a.source,
        "source_ip": a.source_ip,
        "dest_ip": a.dest_ip,
        "hostname": a.hostname,
        "rule_id": a.rule_id,
        "rule_level": a.rule_level,
        "category": a.category,
        "status": a.status,
        "raw_data": a.raw_data,
        "incident_id": a.incident_id,
        "created_at": a.created_at.isoformat() if a.created_at else None,
        "updated_at": a.updated_at.isoformat() if a.updated_at else None,
    }


@router.get("")
def list_alerts(
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    severity: Optional[str] = None,
    status: Optional[str] = None,
    search: Optional[str] = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    query = db.query(Alert)
    if severity:
        query = query.filter(Alert.severity == severity)
    if status:
        query = query.filter(Alert.status == status)
    if search:
        query = query.filter(
            or_(
                Alert.title.ilike(f"%{search}%"),
                Alert.source_ip.ilike(f"%{search}%"),
                Alert.hostname.ilike(f"%{search}%"),
                Alert.alert_id.ilike(f"%{search}%"),
            )
        )
    total = query.count()
    alerts = query.order_by(Alert.created_at.desc()).offset((page - 1) * page_size).limit(page_size).all()
    return {
        "total": total,
        "page": page,
        "page_size": page_size,
        "pages": (total + page_size - 1) // page_size,
        "items": [alert_to_dict(a) for a in alerts]
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
    return alert_to_dict(alert)


@router.post("")
def create_alert(
    data: AlertCreate,
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
    if data.severity is not None:
        alert.severity = data.severity
    if data.incident_id is not None:
        alert.incident_id = data.incident_id
    alert.updated_at = datetime.utcnow()
    db.commit()
    db.refresh(alert)
    return alert_to_dict(alert)


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
