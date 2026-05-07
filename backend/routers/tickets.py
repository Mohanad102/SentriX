import uuid
from datetime import datetime
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import or_
from pydantic import BaseModel
from sqlalchemy.orm import Session

from backend.database import get_db
from backend.models.alert import Alert
from backend.models.incident import Incident
from backend.models.ticket import Ticket
from backend.models.user import User
from backend.utils.auth import get_current_user, require_admin

router = APIRouter(prefix="/api/tickets", tags=["tickets"])

# Auto-escalation routing table
ESCALATION_MAP = {
    "low":      "L1 Analyst",
    "medium":   "L2 Analyst",
    "high":     "Incident Response",
    "critical": "Incident Response",
}

VALID_ASSIGNEES = ["L1 Analyst", "L2 Analyst", "Incident Response"]
VALID_STATUSES  = ["open", "in_progress", "escalated", "closed"]


class TicketCreate(BaseModel):
    alert_id:      Optional[int] = None
    title:         str
    description:   Optional[str] = None
    severity:      str = "medium"
    assigned_to:   Optional[str] = None   # if None → auto-escalate by severity
    triage_result: Optional[str] = None   # true_positive | false_positive | suspicious
    notes:         Optional[str] = None


class TicketUpdate(BaseModel):
    status:               Optional[str] = None
    assigned_to:          Optional[str] = None
    notes:                Optional[str] = None
    investigation_notes:  Optional[str] = None
    l2_status:            Optional[str] = None   # under_investigation | contained | escalated_to_ir
    evidence:             Optional[str] = None


def ticket_to_dict(t: Ticket, created_by: str = None) -> dict:
    return {
        "id":                   t.id,
        "ticket_id":            t.ticket_id,
        "alert_id":             t.alert_id,
        "title":                t.title,
        "description":          t.description,
        "severity":             t.severity,
        "status":               t.status,
        "assigned_to":          t.assigned_to,
        "triage_result":        t.triage_result,
        "notes":                t.notes,
        "investigation_notes":  t.investigation_notes,
        "l2_status":            t.l2_status,
        "evidence":             t.evidence,
        "escalated_at":         t.escalated_at.isoformat() if t.escalated_at else None,
        "incident_id":          t.incident_id,
        "resolved_by":          t.resolved_by,
        "resolved_at":          t.resolved_at.isoformat() if t.resolved_at else None,
        "created_by_id":        t.created_by_id,
        "created_by":           created_by,
        "created_at":           t.created_at.isoformat() if t.created_at else None,
        "updated_at":           t.updated_at.isoformat() if t.updated_at else None,
    }


def _resolve_creators(tickets: list, db: Session) -> dict:
    ids = {t.created_by_id for t in tickets if t.created_by_id}
    if not ids:
        return {}
    users = db.query(User).filter(User.id.in_(ids)).all()
    return {u.id: u.username for u in users}


@router.get("")
def list_tickets(
    status:      Optional[str] = None,
    assigned_to: Optional[str] = None,
    severity:    Optional[str] = None,
    page:        int = Query(1, ge=1),
    page_size:   int = Query(20, ge=1, le=100),
    db:          Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    query = db.query(Ticket)
    # L1 analysts see their queue + any ticket they personally created (to track escalations)
    if current_user.role == "soc_analyst_l1":
        query = query.filter(
            or_(
                Ticket.assigned_to == "L1 Analyst",
                Ticket.created_by_id == current_user.id,
            )
        )
    elif assigned_to:
        query = query.filter(Ticket.assigned_to == assigned_to)
    if status:
        query = query.filter(Ticket.status == status)
    if severity:
        query = query.filter(Ticket.severity == severity)
    total   = query.count()
    tickets = query.order_by(Ticket.created_at.desc()).offset((page - 1) * page_size).limit(page_size).all()
    creators = _resolve_creators(tickets, db)
    return {
        "total":     total,
        "page":      page,
        "pages":     (total + page_size - 1) // page_size,
        "items":     [ticket_to_dict(t, creators.get(t.created_by_id)) for t in tickets],
    }


@router.post("")
def create_ticket(
    data:         TicketCreate,
    db:           Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    # Prevent duplicate tickets for the same alert
    if data.alert_id:
        alert = db.query(Alert).filter(Alert.id == data.alert_id).first()
        if alert and alert.ticket_ref:
            raise HTTPException(
                status_code=409,
                detail=f"A ticket already exists for this alert: {alert.ticket_ref}",
            )

    assigned_to = data.assigned_to if data.assigned_to in VALID_ASSIGNEES \
        else ESCALATION_MAP.get(data.severity, "L2 Analyst")

    ticket = Ticket(
        ticket_id=f"TKT-{uuid.uuid4().hex[:8].upper()}",
        alert_id=data.alert_id,
        title=data.title,
        description=data.description,
        severity=data.severity,
        assigned_to=assigned_to,
        triage_result=data.triage_result,
        notes=data.notes,
        created_by_id=current_user.id,
    )
    db.add(ticket)
    db.flush()  # get ticket.ticket_id before committing

    # Back-update the source alert
    if data.alert_id and alert:
        alert.ticket_ref    = ticket.ticket_id
        alert.status        = "in_progress"
        if data.triage_result:
            alert.triage_result = data.triage_result
        if data.notes:
            alert.notes = data.notes

    db.commit()
    db.refresh(ticket)
    return ticket_to_dict(ticket, current_user.username)


@router.get("/{ticket_id}")
def get_ticket(
    ticket_id:    int,
    db:           Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    ticket = db.query(Ticket).filter(Ticket.id == ticket_id).first()
    if not ticket:
        raise HTTPException(status_code=404, detail="Ticket not found")
    creator = None
    if ticket.created_by_id:
        u = db.query(User).filter(User.id == ticket.created_by_id).first()
        creator = u.username if u else None
    return ticket_to_dict(ticket, creator)


@router.patch("/{ticket_id}")
def update_ticket(
    ticket_id:    int,
    data:         TicketUpdate,
    db:           Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    ticket = db.query(Ticket).filter(Ticket.id == ticket_id).first()
    if not ticket:
        raise HTTPException(status_code=404, detail="Ticket not found")

    # L1 analysts can only add notes to tickets in their queue
    if current_user.role == "soc_analyst_l1":
        if ticket.assigned_to != "L1 Analyst":
            raise HTTPException(status_code=403, detail="L1 analysts can only update tickets in the L1 queue")
        if data.notes is not None:
            ticket.notes = data.notes
        ticket.updated_at = datetime.utcnow()
        db.commit()
        db.refresh(ticket)
        return ticket_to_dict(ticket)

    # L2 analysts may only update tickets routed to their queue
    if current_user.role == "soc_analyst_l2" and ticket.assigned_to != "L2 Analyst":
        raise HTTPException(
            status_code=403,
            detail="L2 analysts can only update tickets assigned to the L2 Analyst queue",
        )

    if data.status and data.status in VALID_STATUSES:
        ticket.status = data.status
        if data.status == "closed" and not ticket.resolved_by:
            ticket.resolved_by = current_user.username
            ticket.resolved_at = datetime.utcnow()
    if data.assigned_to and data.assigned_to in VALID_ASSIGNEES:
        ticket.assigned_to = data.assigned_to
    if data.notes is not None:
        ticket.notes = data.notes
    if data.investigation_notes is not None:
        ticket.investigation_notes = data.investigation_notes
    if data.l2_status is not None:
        ticket.l2_status = data.l2_status
    if data.evidence is not None:
        ticket.evidence = data.evidence
    ticket.updated_at = datetime.utcnow()
    db.commit()
    db.refresh(ticket)
    creator = None
    if ticket.created_by_id:
        u = db.query(User).filter(User.id == ticket.created_by_id).first()
        creator = u.username if u else None
    return ticket_to_dict(ticket, creator)


@router.delete("/{ticket_id}")
def delete_ticket(
    ticket_id:    int,
    db:           Session = Depends(get_db),
    current_user: User = Depends(require_admin),
):
    ticket = db.query(Ticket).filter(Ticket.id == ticket_id).first()
    if not ticket:
        raise HTTPException(status_code=404, detail="Ticket not found")
    # Clear ticket_ref on the linked alert
    if ticket.alert_id:
        alert = db.query(Alert).filter(Alert.id == ticket.alert_id).first()
        if alert and alert.ticket_ref == ticket.ticket_id:
            alert.ticket_ref = None
    db.delete(ticket)
    db.commit()
    return {"message": "Ticket deleted"}


@router.post("/{ticket_id}/escalate-ir")
def escalate_to_ir(
    ticket_id:    int,
    db:           Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Escalate ticket to Incident Response queue. L2 and admins only."""
    if current_user.role == "soc_analyst_l1":
        raise HTTPException(status_code=403, detail="L1 analysts cannot escalate to Incident Response")

    ticket = db.query(Ticket).filter(Ticket.id == ticket_id).first()
    if not ticket:
        raise HTTPException(status_code=404, detail="Ticket not found")

    if ticket.assigned_to == "Incident Response":
        raise HTTPException(status_code=409, detail="Ticket is already assigned to Incident Response")

    ticket.assigned_to = "Incident Response"
    ticket.status = "escalated"
    ticket.l2_status = "escalated_to_ir"
    ticket.escalated_at = datetime.utcnow()
    ticket.updated_at = datetime.utcnow()

    # Create a linked incident so it appears in the IR dashboard
    incident = Incident(
        case_number=f"INC-{uuid.uuid4().hex[:6].upper()}",
        title=ticket.title,
        description=ticket.description or "",
        severity=ticket.severity,
        status="open",
        priority=ticket.severity,
        assigned_to=current_user.username,
        tags=f"escalated-from:{ticket.ticket_id}",
        created_by=current_user.id,
    )
    db.add(incident)
    db.flush()

    ticket.incident_id = incident.id
    db.commit()
    db.refresh(ticket)
    creator = None
    if ticket.created_by_id:
        u = db.query(User).filter(User.id == ticket.created_by_id).first()
        creator = u.username if u else None
    return ticket_to_dict(ticket, creator)
