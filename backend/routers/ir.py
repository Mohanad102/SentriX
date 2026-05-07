"""
Incident Response (IR) Module
Provides: playbooks, evidence collection, notifications, IR lifecycle, dashboard stats.
"""
from __future__ import annotations
import json
from datetime import datetime, timedelta
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session

from backend.database import get_db
from backend.models.alert import Alert
from backend.models.evidence import IREvidence
from backend.models.incident import Incident
from backend.models.notification import Notification
from backend.models.playbook import Playbook, PlaybookStep, PlaybookRun
from backend.models.response_action import ResponseAction, ACTION_LABELS, VALID_ACTIONS
from backend.models.user import User
from backend.routers.audit import write_log
from backend.utils.auth import get_current_user, require_not_l1

router = APIRouter(prefix="/api/ir", tags=["incident-response"], dependencies=[Depends(require_not_l1)])

# ── IR Lifecycle ───────────────────────────────────────────────────────────────
IR_LIFECYCLE = ["new", "investigating", "contained", "eradicated", "recovered"]

IR_STATUS_LABELS = {
    "new":           "New",
    "investigating": "Investigating",
    "contained":     "Contained",
    "eradicated":    "Eradicated",
    "recovered":     "Recovered",
}

# ── Built-in Playbooks ─────────────────────────────────────────────────────────
BUILTIN_PLAYBOOKS = [
    {
        "name": "Brute Force Attack Response",
        "description": "Block attacking IP, force password reset, disable compromised account.",
        "category": "brute_force",
        "steps": [
            {"order": 1, "action": "block_ip",        "target_field": "source_ip", "desc": "Block attacking IP at firewall"},
            {"order": 2, "action": "reset_password",  "target_field": "custom",   "desc": "Force password reset on targeted accounts"},
            {"order": 3, "action": "disable_user",    "target_field": "custom",   "desc": "Disable potentially compromised account"},
        ],
    },
    {
        "name": "Malware Infection Response",
        "description": "Isolate infected endpoint, kill malicious process, remove malicious file.",
        "category": "malware",
        "steps": [
            {"order": 1, "action": "isolate_endpoint", "target_field": "hostname", "desc": "Network-isolate infected endpoint via EDR"},
            {"order": 2, "action": "kill_process",     "target_field": "custom",  "desc": "Terminate malicious process"},
            {"order": 3, "action": "remove_file",      "target_field": "custom",  "desc": "Remove and quarantine malicious file"},
        ],
    },
    {
        "name": "Ransomware Emergency Response",
        "description": "Emergency containment — isolate systems, block C2, reset credentials.",
        "category": "ransomware",
        "steps": [
            {"order": 1, "action": "isolate_endpoint",  "target_field": "hostname",  "desc": "Isolate primary affected system"},
            {"order": 2, "action": "block_ip",          "target_field": "source_ip", "desc": "Block C2 IP address at firewall"},
            {"order": 3, "action": "disable_user",      "target_field": "custom",    "desc": "Disable compromised admin account"},
            {"order": 4, "action": "reset_credentials", "target_field": "custom",    "desc": "Reset all administrative credentials"},
        ],
    },
    {
        "name": "Data Exfiltration Response",
        "description": "Block exfiltration channel, isolate source endpoint, reset credentials.",
        "category": "exfiltration",
        "steps": [
            {"order": 1, "action": "block_ip",          "target_field": "source_ip", "desc": "Block source IP of exfiltration"},
            {"order": 2, "action": "isolate_endpoint",  "target_field": "hostname",  "desc": "Isolate source endpoint"},
            {"order": 3, "action": "reset_credentials", "target_field": "custom",    "desc": "Reset credentials on affected system"},
        ],
    },
    {
        "name": "Phishing Attack Response",
        "description": "Disable phished account, force password reset, reset credentials.",
        "category": "phishing",
        "steps": [
            {"order": 1, "action": "disable_user",     "target_field": "custom", "desc": "Disable phished user account"},
            {"order": 2, "action": "reset_password",   "target_field": "custom", "desc": "Force password reset"},
            {"order": 3, "action": "reset_credentials","target_field": "custom", "desc": "Reset all associated credentials"},
        ],
    },
    {
        "name": "Privilege Escalation Response",
        "description": "Revoke elevated access, isolate endpoint, reset admin credentials.",
        "category": "privilege_escalation",
        "steps": [
            {"order": 1, "action": "disable_user",      "target_field": "custom",   "desc": "Disable account with escalated privileges"},
            {"order": 2, "action": "isolate_endpoint",  "target_field": "hostname", "desc": "Isolate affected endpoint"},
            {"order": 3, "action": "reset_credentials", "target_field": "custom",  "desc": "Reset all admin credentials"},
        ],
    },
    {
        "name": "Lateral Movement Response",
        "description": "Block pivot host, disable compromised credentials, isolate affected systems.",
        "category": "lateral_movement",
        "steps": [
            {"order": 1, "action": "block_ip",         "target_field": "source_ip", "desc": "Block lateral movement source IP"},
            {"order": 2, "action": "disable_user",     "target_field": "custom",   "desc": "Disable account used for lateral movement"},
            {"order": 3, "action": "isolate_endpoint", "target_field": "hostname", "desc": "Isolate affected endpoint"},
        ],
    },
]


# ── Schemas ────────────────────────────────────────────────────────────────────

class PlaybookCreate(BaseModel):
    name:        str
    description: Optional[str] = None
    category:    Optional[str] = None
    steps:       list[dict] = []


class PlaybookRunRequest(BaseModel):
    incident_id: int
    targets:     dict[str, str] = {}   # step_key -> target value for "custom" fields


class EvidenceCreate(BaseModel):
    evidence_type: str = "note"
    title:         str
    content:       Optional[str] = None
    source:        Optional[str] = None


class LifecycleUpdate(BaseModel):
    ir_status: str   # new | investigating | contained | eradicated | recovered


class NotifMarkRead(BaseModel):
    ids: list[int] = []


# ── Helpers ────────────────────────────────────────────────────────────────────

def push_notification(db: Session, title: str, message: str,
                      notif_type: str = "info",
                      resource_type: str = None,
                      resource_id=None):
    notif = Notification(
        title=title, message=message, notif_type=notif_type,
        resource_type=resource_type,
        resource_id=str(resource_id) if resource_id else None,
    )
    db.add(notif)


def _resolve_target(target_field: str, incident: Incident, alerts: list[Alert]) -> str | None:
    """Resolve a playbook step target from incident context."""
    if target_field == "source_ip":
        ips = [a.source_ip for a in alerts if a.source_ip]
        return ips[0] if ips else None
    if target_field == "hostname":
        hosts = [a.hostname for a in alerts if a.hostname]
        return hosts[0] if hosts else None
    if target_field == "assigned_to":
        return incident.assigned_to
    return None   # "custom" — caller must supply


def _action_msg(action_type: str, target: str) -> str:
    msgs = {
        "block_ip":          f"Firewall rule created — IP {target} blocked.",
        "disable_user":      f"Account '{target}' disabled in directory services.",
        "isolate_endpoint":  f"Endpoint '{target}' isolated via EDR.",
        "reset_password":    f"Password reset enforced for '{target}'.",
        "kill_process":      f"Process '{target}' terminated on affected endpoint.",
        "remove_file":       f"File '{target}' removed and quarantined.",
        "reset_credentials": f"All credentials for '{target}' reset.",
    }
    return msgs.get(action_type, f"Action executed on '{target}'.")


def _pb_to_dict(pb: Playbook, steps: list[PlaybookStep]) -> dict:
    return {
        "id":          pb.id,
        "name":        pb.name,
        "description": pb.description,
        "category":    pb.category,
        "is_active":   pb.is_active,
        "is_builtin":  pb.is_builtin,
        "created_at":  pb.created_at.isoformat() if pb.created_at else None,
        "steps": [
            {
                "id":              s.id,
                "step_order":      s.step_order,
                "action_type":     s.action_type,
                "action_label":    ACTION_LABELS.get(s.action_type, s.action_type),
                "target_field":    s.target_field,
                "target_override": s.target_override,
                "description":     s.description,
            }
            for s in sorted(steps, key=lambda x: x.step_order)
        ],
    }


def _evidence_to_dict(e: IREvidence) -> dict:
    return {
        "id":            e.id,
        "incident_id":   e.incident_id,
        "evidence_type": e.evidence_type,
        "title":         e.title,
        "content":       e.content,
        "source":        e.source,
        "collected_by":  e.collected_by,
        "collected_at":  e.collected_at.isoformat() if e.collected_at else None,
    }


def _notif_to_dict(n: Notification) -> dict:
    return {
        "id":            n.id,
        "title":         n.title,
        "message":       n.message,
        "notif_type":    n.notif_type,
        "resource_type": n.resource_type,
        "resource_id":   n.resource_id,
        "is_read":       n.is_read,
        "created_at":    n.created_at.isoformat() if n.created_at else None,
    }


# ── Seeding ────────────────────────────────────────────────────────────────────

def seed_builtin_playbooks(db: Session):
    """Ensure all built-in playbooks exist (idempotent)."""
    for pb_def in BUILTIN_PLAYBOOKS:
        existing = db.query(Playbook).filter(
            Playbook.name == pb_def["name"],
            Playbook.is_builtin == True,
        ).first()
        if existing:
            continue
        pb = Playbook(
            name=pb_def["name"],
            description=pb_def["description"],
            category=pb_def["category"],
            is_builtin=True,
            is_active=True,
        )
        db.add(pb)
        db.flush()
        for s in pb_def["steps"]:
            db.add(PlaybookStep(
                playbook_id=pb.id,
                step_order=s["order"],
                action_type=s["action"],
                target_field=s["target_field"],
                target_override=None,
                description=s["desc"],
            ))
    db.commit()


# ── Dashboard ──────────────────────────────────────────────────────────────────

@router.get("/dashboard")
def ir_dashboard(
    db:           Session = Depends(get_db),
    current_user: User    = Depends(get_current_user),
):
    """Aggregated stats for the IR Dashboard."""
    today = datetime.utcnow().replace(hour=0, minute=0, second=0, microsecond=0)

    active_incidents = (
        db.query(Incident)
        .filter(Incident.status.in_(["open", "in_progress"]))
        .order_by(Incident.created_at.desc())
        .limit(50)
        .all()
    )

    actions_today = db.query(ResponseAction).filter(
        ResponseAction.executed_at >= today
    ).count()

    runs_today = db.query(PlaybookRun).filter(
        PlaybookRun.executed_at >= today
    ).count()

    unread_critical = db.query(Notification).filter(
        Notification.is_read == False,
        Notification.notif_type == "critical",
    ).count()

    unread_total = db.query(Notification).filter(
        Notification.is_read == False,
    ).count()

    sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    sorted_incidents = sorted(active_incidents, key=lambda i: sev_order.get(i.severity, 9))

    return {
        "stats": {
            "active_incidents":  len(active_incidents),
            "actions_today":     actions_today,
            "playbooks_today":   runs_today,
            "unread_critical":   unread_critical,
            "unread_total":      unread_total,
        },
        "active_incidents": [
            {
                "id":          inc.id,
                "case_number": inc.case_number,
                "title":       inc.title,
                "severity":    inc.severity,
                "status":      inc.status,
                "ir_status":   inc.ir_status,
                "l2_status":   inc.l2_status,
                "assigned_to": inc.assigned_to,
                "category":    inc.category,
                "created_at":  inc.created_at.isoformat() if inc.created_at else None,
            }
            for inc in sorted_incidents
        ],
    }


# ── IR Lifecycle ───────────────────────────────────────────────────────────────

@router.patch("/incidents/{incident_id}/lifecycle")
def update_lifecycle(
    incident_id:  int,
    data:         LifecycleUpdate,
    db:           Session = Depends(get_db),
    current_user: User    = Depends(get_current_user),
):
    if current_user.role == "soc_analyst_l1":
        raise HTTPException(status_code=403, detail="L1 analysts cannot update IR lifecycle")

    if data.ir_status not in IR_LIFECYCLE:
        raise HTTPException(status_code=400, detail=f"Invalid ir_status. Must be one of: {', '.join(IR_LIFECYCLE)}")

    inc = db.query(Incident).filter(Incident.id == incident_id).first()
    if not inc:
        raise HTTPException(status_code=404, detail="Incident not found")

    inc.ir_status = data.ir_status
    inc.updated_at = datetime.utcnow()

    if data.ir_status == "contained":
        inc.contained_at = datetime.utcnow()
    if data.ir_status == "recovered":
        inc.status = "resolved"
        inc.closed_at = datetime.utcnow()

    write_log(db=db, username=current_user.username, user_id=current_user.id,
              action=f"IR_LIFECYCLE:{data.ir_status.upper()}",
              resource="incident", resource_id=str(incident_id),
              detail=f"IR status → {IR_STATUS_LABELS.get(data.ir_status, data.ir_status)} | {inc.case_number}")

    push_notification(db, title=f"IR Status Update: {inc.case_number}",
                      message=f"{inc.title} → {IR_STATUS_LABELS.get(data.ir_status, data.ir_status)}",
                      notif_type="info", resource_type="incident", resource_id=incident_id)

    db.commit()
    return {"ir_status": data.ir_status, "case_number": inc.case_number, "message": f"IR status updated to {data.ir_status}"}


# ── Playbooks ──────────────────────────────────────────────────────────────────

@router.get("/playbooks")
def list_playbooks(
    db:           Session = Depends(get_db),
    current_user: User    = Depends(get_current_user),
):
    playbooks = db.query(Playbook).filter(Playbook.is_active == True).order_by(Playbook.id).all()
    result = []
    for pb in playbooks:
        steps = db.query(PlaybookStep).filter(PlaybookStep.playbook_id == pb.id).all()
        result.append(_pb_to_dict(pb, steps))
    return {"total": len(result), "items": result}


@router.get("/playbooks/{playbook_id}")
def get_playbook(
    playbook_id:  int,
    db:           Session = Depends(get_db),
    current_user: User    = Depends(get_current_user),
):
    pb = db.query(Playbook).filter(Playbook.id == playbook_id).first()
    if not pb:
        raise HTTPException(status_code=404, detail="Playbook not found")
    steps = db.query(PlaybookStep).filter(PlaybookStep.playbook_id == playbook_id).all()
    return _pb_to_dict(pb, steps)


@router.post("/playbooks")
def create_playbook(
    data:         PlaybookCreate,
    db:           Session = Depends(get_db),
    current_user: User    = Depends(get_current_user),
):
    if current_user.role == "soc_analyst_l1":
        raise HTTPException(status_code=403, detail="L1 analysts cannot create playbooks")

    pb = Playbook(name=data.name, description=data.description,
                  category=data.category, is_builtin=False, is_active=True)
    db.add(pb)
    db.flush()

    for i, s in enumerate(data.steps, 1):
        action = s.get("action_type")
        if action not in VALID_ACTIONS:
            raise HTTPException(status_code=400, detail=f"Invalid action_type: {action}")
        db.add(PlaybookStep(
            playbook_id=pb.id,
            step_order=s.get("step_order", i),
            action_type=action,
            target_field=s.get("target_field", "custom"),
            target_override=s.get("target_override"),
            description=s.get("description"),
        ))

    db.commit()
    db.refresh(pb)
    steps = db.query(PlaybookStep).filter(PlaybookStep.playbook_id == pb.id).all()
    return _pb_to_dict(pb, steps)


@router.post("/playbooks/{playbook_id}/run")
def run_playbook(
    playbook_id:  int,
    data:         PlaybookRunRequest,
    db:           Session = Depends(get_db),
    current_user: User    = Depends(get_current_user),
):
    """
    Execute a playbook against an incident.
    Auto-resolves targets where possible; user supplies targets for 'custom' fields.
    """
    if current_user.role == "soc_analyst_l1":
        raise HTTPException(status_code=403, detail="L1 analysts cannot run playbooks")

    pb = db.query(Playbook).filter(Playbook.id == playbook_id).first()
    if not pb:
        raise HTTPException(status_code=404, detail="Playbook not found")

    incident = db.query(Incident).filter(Incident.id == data.incident_id).first()
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")

    steps = db.query(PlaybookStep).filter(
        PlaybookStep.playbook_id == playbook_id
    ).order_by(PlaybookStep.step_order).all()

    alerts = db.query(Alert).filter(Alert.incident_id == data.incident_id).all()

    executed = []
    skipped  = []

    for step in steps:
        step_key = f"step_{step.step_order}"

        # Resolve target
        target = None
        if step.target_override:
            target = step.target_override
        elif step.target_field == "custom":
            target = data.targets.get(step_key) or data.targets.get(str(step.id))
        else:
            target = _resolve_target(step.target_field, incident, alerts)

        if not target:
            skipped.append({"step": step.step_order, "action": step.action_type, "reason": "no target resolved"})
            continue

        action = ResponseAction(
            incident_id=data.incident_id,
            action_type=step.action_type,
            target=target,
            status="executed",
            notes=step.description,
            executed_by=current_user.username,
        )
        db.add(action)
        db.flush()

        write_log(db=db, username=current_user.username, user_id=current_user.id,
                  action=f"PLAYBOOK_ACTION:{step.action_type.upper()}",
                  resource="incident", resource_id=str(data.incident_id),
                  detail=f"[{pb.name}] Step {step.step_order}: {ACTION_LABELS.get(step.action_type)} → {target}")

        executed.append({
            "step":        step.step_order,
            "action_type": step.action_type,
            "action_label": ACTION_LABELS.get(step.action_type, step.action_type),
            "target":      target,
            "message":     _action_msg(step.action_type, target),
        })

    # Record the run
    run = PlaybookRun(
        playbook_id=playbook_id,
        incident_id=data.incident_id,
        playbook_name=pb.name,
        status="completed" if executed else "failed",
        executed_by=current_user.username,
        results=json.dumps({"executed": executed, "skipped": skipped}),
        actions_count=len(executed),
    )
    db.add(run)

    # Notification
    push_notification(db,
        title=f"Playbook Executed: {pb.name}",
        message=f"{len(executed)} action(s) on {incident.case_number} — {len(skipped)} skipped",
        notif_type="info", resource_type="incident", resource_id=data.incident_id)

    db.commit()

    return {
        "playbook":       pb.name,
        "incident":       incident.case_number,
        "executed_count": len(executed),
        "skipped_count":  len(skipped),
        "executed":       executed,
        "skipped":        skipped,
    }


@router.get("/playbook-runs")
def list_playbook_runs(
    incident_id:  Optional[int] = None,
    limit:        int = 20,
    db:           Session = Depends(get_db),
    current_user: User    = Depends(get_current_user),
):
    query = db.query(PlaybookRun)
    if incident_id:
        query = query.filter(PlaybookRun.incident_id == incident_id)
    runs = query.order_by(PlaybookRun.executed_at.desc()).limit(limit).all()
    return {
        "total": len(runs),
        "items": [
            {
                "id":           r.id,
                "playbook_id":  r.playbook_id,
                "playbook_name":r.playbook_name,
                "incident_id":  r.incident_id,
                "status":       r.status,
                "executed_by":  r.executed_by,
                "actions_count":r.actions_count,
                "executed_at":  r.executed_at.isoformat() if r.executed_at else None,
            }
            for r in runs
        ],
    }


# ── Evidence ───────────────────────────────────────────────────────────────────

@router.get("/evidence/{incident_id}")
def list_evidence(
    incident_id:  int,
    db:           Session = Depends(get_db),
    current_user: User    = Depends(get_current_user),
):
    items = (
        db.query(IREvidence)
        .filter(IREvidence.incident_id == incident_id)
        .order_by(IREvidence.collected_at.desc())
        .all()
    )
    return {"total": len(items), "items": [_evidence_to_dict(e) for e in items]}


@router.post("/evidence/{incident_id}")
def add_evidence(
    incident_id:  int,
    data:         EvidenceCreate,
    db:           Session = Depends(get_db),
    current_user: User    = Depends(get_current_user),
):
    if not db.query(Incident).filter(Incident.id == incident_id).first():
        raise HTTPException(status_code=404, detail="Incident not found")

    ev = IREvidence(
        incident_id=incident_id,
        evidence_type=data.evidence_type,
        title=data.title,
        content=data.content,
        source=data.source,
        collected_by=current_user.username,
    )
    db.add(ev)

    write_log(db=db, username=current_user.username, user_id=current_user.id,
              action="EVIDENCE_COLLECTED",
              resource="incident", resource_id=str(incident_id),
              detail=f"{data.evidence_type.upper()}: {data.title}")

    db.commit()
    db.refresh(ev)
    return _evidence_to_dict(ev)


@router.delete("/evidence/{evidence_id}")
def delete_evidence(
    evidence_id:  int,
    db:           Session = Depends(get_db),
    current_user: User    = Depends(get_current_user),
):
    if current_user.role == "soc_analyst_l1":
        raise HTTPException(status_code=403, detail="L1 analysts cannot delete evidence")
    ev = db.query(IREvidence).filter(IREvidence.id == evidence_id).first()
    if not ev:
        raise HTTPException(status_code=404, detail="Evidence not found")
    db.delete(ev)
    db.commit()
    return {"message": "Evidence deleted"}


# ── Notifications ──────────────────────────────────────────────────────────────

@router.get("/notifications")
def list_notifications(
    unread_only: bool = False,
    limit:       int  = 50,
    db:          Session = Depends(get_db),
    current_user: User   = Depends(get_current_user),
):
    query = db.query(Notification)
    if unread_only:
        query = query.filter(Notification.is_read == False)
    notifs = query.order_by(Notification.created_at.desc()).limit(limit).all()
    unread = db.query(Notification).filter(Notification.is_read == False).count()
    return {
        "unread_count": unread,
        "total": len(notifs),
        "items": [_notif_to_dict(n) for n in notifs],
    }


@router.post("/notifications/read-all")
def mark_all_read(
    db:          Session = Depends(get_db),
    current_user: User   = Depends(get_current_user),
):
    db.query(Notification).filter(Notification.is_read == False).update({"is_read": True})
    db.commit()
    return {"message": "All notifications marked as read"}


@router.patch("/notifications/{notif_id}/read")
def mark_read(
    notif_id:    int,
    db:          Session = Depends(get_db),
    current_user: User   = Depends(get_current_user),
):
    n = db.query(Notification).filter(Notification.id == notif_id).first()
    if not n:
        raise HTTPException(status_code=404, detail="Notification not found")
    n.is_read = True
    db.commit()
    return {"message": "Marked as read"}
