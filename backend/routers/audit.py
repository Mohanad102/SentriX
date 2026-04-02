from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session
from typing import Optional
from backend.database import get_db
from backend.models.audit_log import AuditLog
from backend.models.user import User
from backend.utils.auth import require_admin

router = APIRouter(prefix="/api/audit", tags=["audit"])


def log_to_dict(l: AuditLog):
    return {
        "id": l.id,
        "username": l.username,
        "action": l.action,
        "resource": l.resource,
        "resource_id": l.resource_id,
        "detail": l.detail,
        "ip_address": l.ip_address,
        "created_at": l.created_at.isoformat() if l.created_at else None,
    }


def write_log(db: Session, username: str, action: str,
              resource: str = None, resource_id: str = None,
              detail: str = None, ip_address: str = None, user_id: int = None):
    entry = AuditLog(
        user_id=user_id,
        username=username,
        action=action,
        resource=resource,
        resource_id=str(resource_id) if resource_id else None,
        detail=detail,
        ip_address=ip_address,
    )
    db.add(entry)
    db.commit()


@router.get("")
def list_logs(
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    username: Optional[str] = None,
    action: Optional[str] = None,
    resource: Optional[str] = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_admin)
):
    query = db.query(AuditLog)
    if username:
        query = query.filter(AuditLog.username.ilike(f"%{username}%"))
    if action:
        query = query.filter(AuditLog.action == action)
    if resource:
        query = query.filter(AuditLog.resource == resource)
    total = query.count()
    logs = query.order_by(AuditLog.created_at.desc()).offset((page - 1) * page_size).limit(page_size).all()
    return {
        "total": total,
        "page": page,
        "page_size": page_size,
        "pages": (total + page_size - 1) // page_size,
        "items": [log_to_dict(l) for l in logs]
    }
