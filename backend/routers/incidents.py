from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from sqlalchemy import or_
from pydantic import BaseModel
from typing import Optional, List
from backend.database import get_db
from backend.models.incident import Incident, IncidentTask
from backend.utils.auth import get_current_user
from backend.models.user import User
import uuid
from datetime import datetime

router = APIRouter(prefix="/api/incidents", tags=["incidents"])


class IncidentCreate(BaseModel):
    title: str
    description: Optional[str] = None
    severity: str = "medium"
    priority: str = "medium"
    category: Optional[str] = None
    assigned_to: Optional[str] = None
    tags: Optional[str] = None


class IncidentUpdate(BaseModel):
    title: Optional[str] = None
    description: Optional[str] = None
    severity: Optional[str] = None
    priority: Optional[str] = None
    status: Optional[str] = None
    category: Optional[str] = None
    assigned_to: Optional[str] = None
    tags: Optional[str] = None
    ai_summary: Optional[str] = None
    ai_iocs: Optional[str] = None
    ai_recommendations: Optional[str] = None


class TaskCreate(BaseModel):
    title: str
    description: Optional[str] = None
    assigned_to: Optional[str] = None


def incident_to_dict(inc: Incident):
    return {
        "id": inc.id,
        "case_number": inc.case_number,
        "title": inc.title,
        "description": inc.description,
        "severity": inc.severity,
        "status": inc.status,
        "priority": inc.priority,
        "category": inc.category,
        "assigned_to": inc.assigned_to,
        "thehive_id": inc.thehive_id,
        "ai_summary": inc.ai_summary,
        "ai_iocs": inc.ai_iocs,
        "ai_recommendations": inc.ai_recommendations,
        "tags": inc.tags,
        "created_by": inc.created_by,
        "created_at": inc.created_at.isoformat() if inc.created_at else None,
        "updated_at": inc.updated_at.isoformat() if inc.updated_at else None,
        "closed_at": inc.closed_at.isoformat() if inc.closed_at else None,
    }


@router.get("")
def list_incidents(
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    severity: Optional[str] = None,
    status: Optional[str] = None,
    search: Optional[str] = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    query = db.query(Incident)
    if severity:
        query = query.filter(Incident.severity == severity)
    if status:
        query = query.filter(Incident.status == status)
    if search:
        query = query.filter(
            or_(
                Incident.title.ilike(f"%{search}%"),
                Incident.case_number.ilike(f"%{search}%"),
                Incident.assigned_to.ilike(f"%{search}%"),
            )
        )
    total = query.count()
    items = query.order_by(Incident.created_at.desc()).offset((page - 1) * page_size).limit(page_size).all()
    return {
        "total": total,
        "page": page,
        "page_size": page_size,
        "pages": (total + page_size - 1) // page_size,
        "items": [incident_to_dict(i) for i in items]
    }


@router.get("/{incident_id}")
def get_incident(
    incident_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    inc = db.query(Incident).filter(Incident.id == incident_id).first()
    if not inc:
        raise HTTPException(status_code=404, detail="Incident not found")

    tasks = db.query(IncidentTask).filter(IncidentTask.incident_id == incident_id).all()
    from backend.models.alert import Alert
    from backend.models.ioc import IOC
    alerts = db.query(Alert).filter(Alert.incident_id == incident_id).all()
    iocs = db.query(IOC).filter(IOC.incident_id == incident_id).all()

    result = incident_to_dict(inc)
    result["tasks"] = [
        {"id": t.id, "title": t.title, "status": t.status, "assigned_to": t.assigned_to, "result": t.result}
        for t in tasks
    ]
    result["alerts"] = [
        {"id": a.id, "alert_id": a.alert_id, "title": a.title, "severity": a.severity}
        for a in alerts
    ]
    result["iocs"] = [
        {"id": i.id, "value": i.value, "ioc_type": i.ioc_type, "is_malicious": i.is_malicious, "vt_score": i.vt_score}
        for i in iocs
    ]
    return result


@router.post("")
def create_incident(
    data: IncidentCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    incident = Incident(
        case_number=f"INC-{uuid.uuid4().hex[:6].upper()}",
        title=data.title,
        description=data.description,
        severity=data.severity,
        priority=data.priority,
        category=data.category,
        assigned_to=data.assigned_to or current_user.username,
        tags=data.tags,
        created_by=current_user.id
    )
    db.add(incident)
    db.commit()
    db.refresh(incident)
    return incident_to_dict(incident)


@router.patch("/{incident_id}")
def update_incident(
    incident_id: int,
    data: IncidentUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    inc = db.query(Incident).filter(Incident.id == incident_id).first()
    if not inc:
        raise HTTPException(status_code=404, detail="Incident not found")

    for field, value in data.dict(exclude_unset=True).items():
        setattr(inc, field, value)

    if data.status == "closed" and not inc.closed_at:
        inc.closed_at = datetime.utcnow()

    inc.updated_at = datetime.utcnow()
    db.commit()
    db.refresh(inc)
    return incident_to_dict(inc)


@router.delete("/{incident_id}")
def delete_incident(
    incident_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    inc = db.query(Incident).filter(Incident.id == incident_id).first()
    if not inc:
        raise HTTPException(status_code=404, detail="Incident not found")
    db.delete(inc)
    db.commit()
    return {"message": "Incident deleted"}


@router.post("/{incident_id}/tasks")
def add_task(
    incident_id: int,
    data: TaskCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    inc = db.query(Incident).filter(Incident.id == incident_id).first()
    if not inc:
        raise HTTPException(status_code=404, detail="Incident not found")
    task = IncidentTask(
        incident_id=incident_id,
        title=data.title,
        description=data.description,
        assigned_to=data.assigned_to or current_user.username
    )
    db.add(task)
    db.commit()
    db.refresh(task)
    return {"id": task.id, "title": task.title, "status": task.status}


@router.patch("/{incident_id}/tasks/{task_id}")
def update_task(
    incident_id: int,
    task_id: int,
    status: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    task = db.query(IncidentTask).filter(
        IncidentTask.id == task_id,
        IncidentTask.incident_id == incident_id
    ).first()
    if not task:
        raise HTTPException(status_code=404, detail="Task not found")
    task.status = status
    db.commit()
    return {"message": "Task updated"}
