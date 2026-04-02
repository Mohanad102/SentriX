from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from sqlalchemy import and_
from pydantic import BaseModel
from typing import Optional
from datetime import datetime, timedelta
from backend.database import get_db
from backend.models.alert_rule import AlertRule
from backend.models.alert import Alert
from backend.models.user import User
from backend.utils.auth import get_current_user, require_admin

router = APIRouter(prefix="/api/rules", tags=["rules"])


class RuleCreate(BaseModel):
    name: str
    description: Optional[str] = None
    field: str
    operator: str
    value: str
    count: int = 1
    window_mins: int = 5
    action: str = "escalate"
    action_value: Optional[str] = None
    is_active: bool = True


class RuleUpdate(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    field: Optional[str] = None
    operator: Optional[str] = None
    value: Optional[str] = None
    count: Optional[int] = None
    window_mins: Optional[int] = None
    action: Optional[str] = None
    action_value: Optional[str] = None
    is_active: Optional[bool] = None


def rule_to_dict(r: AlertRule):
    return {
        "id": r.id,
        "name": r.name,
        "description": r.description,
        "field": r.field,
        "operator": r.operator,
        "value": r.value,
        "count": r.count,
        "window_mins": r.window_mins,
        "action": r.action,
        "action_value": r.action_value,
        "is_active": r.is_active,
        "created_at": r.created_at.isoformat() if r.created_at else None,
    }


def _matches(alert: Alert, rule: AlertRule) -> bool:
    val = getattr(alert, rule.field, None)
    if val is None:
        return False
    val = str(val).lower()
    rv  = rule.value.lower()
    if rule.operator == "eq":
        return val == rv
    if rule.operator == "contains":
        return rv in val
    if rule.operator in ("gt", "gte", "lt", "lte"):
        try:
            fv, frv = float(val), float(rv)
            return {"gt": fv > frv, "gte": fv >= frv, "lt": fv < frv, "lte": fv <= frv}[rule.operator]
        except ValueError:
            return False
    return False


def evaluate_rules(alert: Alert, db: Session, current_user: User):
    rules = db.query(AlertRule).filter(AlertRule.is_active == True).all()
    for rule in rules:
        if not _matches(alert, rule):
            continue

        # Count matching alerts within the window
        since = datetime.utcnow() - timedelta(minutes=rule.window_mins)
        matching = [
            a for a in db.query(Alert).filter(Alert.created_at >= since).all()
            if _matches(a, rule)
        ]

        if len(matching) >= rule.count:
            if rule.action == "escalate" and not alert.incident_id:
                from backend.models.incident import Incident
                import uuid
                incident = Incident(
                    case_number=f"INC-{uuid.uuid4().hex[:6].upper()}",
                    title=f"[Auto] Rule triggered: {rule.name}",
                    description=(
                        f"Alert auto-escalated by rule: {rule.name}\n"
                        f"Condition: {rule.field} {rule.operator} {rule.value} "
                        f"({rule.count}x in {rule.window_mins}m)"
                    ),
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

            elif rule.action == "set_severity" and rule.action_value:
                alert.severity = rule.action_value
                db.commit()


@router.get("")
def list_rules(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    rules = db.query(AlertRule).order_by(AlertRule.created_at.desc()).all()
    return {"total": len(rules), "items": [rule_to_dict(r) for r in rules]}


@router.post("")
def create_rule(
    data: RuleCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_admin)
):
    rule = AlertRule(**data.model_dump())
    db.add(rule)
    db.commit()
    db.refresh(rule)
    return rule_to_dict(rule)


@router.patch("/{rule_id}")
def update_rule(
    rule_id: int,
    data: RuleUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_admin)
):
    rule = db.query(AlertRule).filter(AlertRule.id == rule_id).first()
    if not rule:
        raise HTTPException(status_code=404, detail="Rule not found")
    for field, val in data.model_dump(exclude_none=True).items():
        setattr(rule, field, val)
    db.commit()
    db.refresh(rule)
    return rule_to_dict(rule)


@router.delete("/{rule_id}")
def delete_rule(
    rule_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_admin)
):
    rule = db.query(AlertRule).filter(AlertRule.id == rule_id).first()
    if not rule:
        raise HTTPException(status_code=404, detail="Rule not found")
    db.delete(rule)
    db.commit()
    return {"message": "Rule deleted"}
