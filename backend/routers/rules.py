import re
import json
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from pydantic import BaseModel
from typing import Optional, List
from datetime import datetime, timedelta
from backend.database import get_db
from backend.models.alert_rule import AlertRule
from backend.models.rule_execution import RuleExecution
from backend.models.alert import Alert
from backend.models.user import User
from backend.utils.auth import get_current_user, require_admin

router = APIRouter(prefix="/api/rules", tags=["rules"])

FIELDS = ["severity", "category", "source_ip", "rule_level", "hostname",
          "title", "description", "rule_id"]

OPERATORS = ["eq", "not_eq", "contains", "not_contains", "gt", "gte", "lt", "lte", "regex"]

ACTIONS = ["escalate", "set_severity", "tag_alert", "notify"]

TEMPLATES = [
    {
        "name": "Critical Alert Auto-Escalate",
        "description": "Immediately escalate any critical severity alert",
        "conditions": [{"field": "severity", "operator": "eq", "value": "critical"}],
        "logic": "AND",
        "count": 1, "window_mins": 1, "action": "escalate", "action_value": None,
    },
    {
        "name": "Brute Force Detection",
        "description": "Escalate when 5+ authentication alerts occur in 5 minutes",
        "conditions": [{"field": "category", "operator": "contains", "value": "authentication"}],
        "logic": "AND",
        "count": 5, "window_mins": 5, "action": "escalate", "action_value": None,
    },
    {
        "name": "High Volume SSH Attacks",
        "description": "Escalate when 10+ SSH-related alerts occur within 10 minutes",
        "conditions": [{"field": "category", "operator": "contains", "value": "syslog"}],
        "logic": "AND",
        "count": 10, "window_mins": 10, "action": "escalate", "action_value": None,
    },
    {
        "name": "Malware Detection Escalate",
        "description": "Escalate any alert mentioning malware in its category",
        "conditions": [{"field": "category", "operator": "contains", "value": "malware"}],
        "logic": "AND",
        "count": 1, "window_mins": 1, "action": "escalate", "action_value": None,
    },
    {
        "name": "High Rule Level → Critical",
        "description": "Promote alerts with Wazuh rule level ≥ 12 to critical severity",
        "conditions": [{"field": "rule_level", "operator": "gte", "value": "12"}],
        "logic": "AND",
        "count": 1, "window_mins": 60, "action": "set_severity", "action_value": "critical",
    },
    {
        "name": "Malware + High Level Escalate",
        "description": "Escalate only when an alert is malware-related AND rule level ≥ 10",
        "conditions": [
            {"field": "category", "operator": "contains", "value": "malware"},
            {"field": "rule_level", "operator": "gte", "value": "10"},
        ],
        "logic": "AND",
        "count": 1, "window_mins": 5, "action": "escalate", "action_value": None,
    },
]


class ConditionItem(BaseModel):
    field: str
    operator: str
    value: str


class RuleCreate(BaseModel):
    name: str
    description: Optional[str] = None
    # Multi-condition (preferred)
    conditions: Optional[List[ConditionItem]] = None
    logic: str = "AND"
    # Single-condition fallback (kept for backward compat)
    field: str = "severity"
    operator: str = "eq"
    value: str = ""
    count: int = 1
    window_mins: int = 5
    action: str = "escalate"
    action_value: Optional[str] = None
    is_active: bool = True


class RuleUpdate(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    conditions: Optional[List[ConditionItem]] = None
    logic: Optional[str] = None
    field: Optional[str] = None
    operator: Optional[str] = None
    value: Optional[str] = None
    count: Optional[int] = None
    window_mins: Optional[int] = None
    action: Optional[str] = None
    action_value: Optional[str] = None
    is_active: Optional[bool] = None


def _get_conditions(rule) -> list:
    """Return the conditions list for a rule, falling back to single field/op/value."""
    if rule.conditions:
        try:
            conds = json.loads(rule.conditions)
            if conds:
                return conds
        except Exception:
            pass
    return [{"field": rule.field, "operator": rule.operator, "value": rule.value}]


def rule_to_dict(r: AlertRule):
    return {
        "id":               r.id,
        "name":             r.name,
        "description":      r.description,
        "conditions":       _get_conditions(r),
        "logic":            r.logic or "AND",
        # Legacy single-condition fields
        "field":            r.field,
        "operator":         r.operator,
        "value":            r.value,
        "count":            r.count,
        "window_mins":      r.window_mins,
        "action":           r.action,
        "action_value":     r.action_value,
        "is_active":        r.is_active,
        "trigger_count":    r.trigger_count or 0,
        "last_triggered_at": r.last_triggered_at.isoformat() if r.last_triggered_at else None,
        "created_at":       r.created_at.isoformat() if r.created_at else None,
    }


def _matches_one(alert: Alert, field: str, operator: str, value: str) -> bool:
    val = getattr(alert, field, None)
    if val is None:
        return False
    val_str = str(val).lower()
    rv = value.lower()

    if operator == "eq":           return val_str == rv
    if operator == "not_eq":       return val_str != rv
    if operator == "contains":     return rv in val_str
    if operator == "not_contains": return rv not in val_str
    if operator == "regex":
        try:
            return bool(re.search(rv, val_str))
        except re.error:
            return False
    if operator in ("gt", "gte", "lt", "lte"):
        try:
            fv, frv = float(val_str), float(rv)
            return {"gt": fv > frv, "gte": fv >= frv, "lt": fv < frv, "lte": fv <= frv}[operator]
        except ValueError:
            return False
    return False


def _matches(alert: Alert, rule) -> bool:
    conditions = _get_conditions(rule)
    logic = (getattr(rule, "logic", None) or "AND").upper()
    results = [_matches_one(alert, c["field"], c["operator"], c["value"]) for c in conditions]
    return all(results) if logic == "AND" else any(results)


def _build_rule_from_create(data: RuleCreate) -> dict:
    conds = [c.model_dump() for c in data.conditions] if data.conditions else None
    if not conds:
        conds = [{"field": data.field, "operator": data.operator, "value": data.value}]
    return {
        "name":         data.name,
        "description":  data.description,
        "field":        conds[0]["field"],
        "operator":     conds[0]["operator"],
        "value":        conds[0]["value"],
        "conditions":   json.dumps(conds),
        "logic":        data.logic or "AND",
        "count":        data.count,
        "window_mins":  data.window_mins,
        "action":       data.action,
        "action_value": data.action_value,
        "is_active":    data.is_active,
    }


def evaluate_rules(alert: Alert, db: Session, current_user=None):
    rules = db.query(AlertRule).filter(AlertRule.is_active == True).all()
    for rule in rules:
        if not _matches(alert, rule):
            continue

        since = datetime.utcnow() - timedelta(minutes=rule.window_mins)
        matching = [
            a for a in db.query(Alert).filter(Alert.created_at >= since).all()
            if _matches(a, rule)
        ]

        if len(matching) < rule.count:
            continue

        action_taken = rule.action
        result = None
        assigned_to = getattr(current_user, "username", "system")
        created_by  = getattr(current_user, "id", None)

        if rule.action == "escalate" and not alert.incident_id:
            from backend.models.incident import Incident
            import uuid
            incident = Incident(
                case_number=f"INC-{uuid.uuid4().hex[:6].upper()}",
                title=f"[Auto] Rule triggered: {rule.name}",
                description=(
                    f"Alert auto-escalated by rule: {rule.name}\n"
                    f"Matched {len(matching)} alert(s) in {rule.window_mins}m"
                ),
                severity=alert.severity,
                category=alert.category,
                assigned_to=assigned_to,
                created_by=created_by,
                status="open"
            )
            db.add(incident)
            db.flush()
            alert.incident_id = incident.id
            alert.status = "in_progress"
            result = f"Created incident {incident.case_number}"
            db.commit()

        elif rule.action == "set_severity" and rule.action_value:
            old = alert.severity
            alert.severity = rule.action_value
            result = f"Severity changed {old} → {rule.action_value}"
            db.commit()

        elif rule.action == "tag_alert" and rule.action_value:
            existing = getattr(alert, "tags", None) or ""
            tags = set(t.strip() for t in existing.split(",") if t.strip())
            tags.add(rule.action_value.strip())
            alert.tags = ",".join(sorted(tags))
            result = f"Tagged alert with '{rule.action_value}'"
            db.commit()

        elif rule.action == "notify":
            try:
                from backend.models.notification import Notification
                notif = Notification(
                    title=f"Rule triggered: {rule.name}",
                    message=f"Alert '{alert.title}' matched rule '{rule.name}'",
                    notif_type="warning",
                    is_read=False,
                )
                db.add(notif)
                result = "Notification created"
                db.commit()
            except Exception:
                result = "Notification skipped (model unavailable)"

        exec_rec = RuleExecution(
            rule_id=rule.id,
            alert_id=alert.id,
            alert_title=alert.title,
            action_taken=action_taken,
            result=result,
        )
        db.add(exec_rec)
        rule.trigger_count = (rule.trigger_count or 0) + 1
        rule.last_triggered_at = datetime.utcnow()
        db.commit()


# ── Routes ────────────────────────────────────────────────────────────────────

@router.get("/templates")
def get_templates(current_user: User = Depends(get_current_user)):
    return {"items": TEMPLATES}


@router.post("/test")
def test_rule(
    data: RuleCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Dry-run a rule definition against recent alerts. Nothing is saved."""
    conds = [c.model_dump() for c in data.conditions] if data.conditions else None
    if not conds:
        conds = [{"field": data.field, "operator": data.operator, "value": data.value}]

    class _TempRule:
        conditions = json.dumps(conds)
        logic      = data.logic or "AND"
        field      = conds[0]["field"]
        operator   = conds[0]["operator"]
        value      = conds[0]["value"]

    temp = _TempRule()
    since = datetime.utcnow() - timedelta(minutes=data.window_mins)
    recent = db.query(Alert).filter(Alert.created_at >= since).all()
    matching = [a for a in recent if _matches(a, temp)]

    return {
        "matching_count":  len(matching),
        "total_in_window": len(recent),
        "would_trigger":   len(matching) >= data.count,
        "threshold":       data.count,
        "window_mins":     data.window_mins,
        "samples": [
            {
                "id":         a.id,
                "title":      a.title,
                "severity":   a.severity,
                "hostname":   a.hostname,
                "created_at": a.created_at.isoformat() if a.created_at else None,
            }
            for a in matching[:5]
        ],
    }


@router.get("")
def list_rules(
    search: Optional[str] = None,
    status: Optional[str] = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    if current_user.role == "soc_analyst_l1":
        raise HTTPException(status_code=403, detail="Access denied")
    q = db.query(AlertRule)
    if search:
        q = q.filter(AlertRule.name.ilike(f"%{search}%"))
    if status == "active":
        q = q.filter(AlertRule.is_active == True)
    elif status == "paused":
        q = q.filter(AlertRule.is_active == False)
    rules = q.order_by(AlertRule.created_at.desc()).all()
    return {"total": len(rules), "items": [rule_to_dict(r) for r in rules]}


@router.post("")
def create_rule(
    data: RuleCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_admin)
):
    rule = AlertRule(**_build_rule_from_create(data))
    db.add(rule)
    db.commit()
    db.refresh(rule)
    return rule_to_dict(rule)


@router.post("/{rule_id}/duplicate")
def duplicate_rule(
    rule_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_admin)
):
    src = db.query(AlertRule).filter(AlertRule.id == rule_id).first()
    if not src:
        raise HTTPException(status_code=404, detail="Rule not found")
    copy = AlertRule(
        name=f"{src.name} (copy)",
        description=src.description,
        field=src.field,
        operator=src.operator,
        value=src.value,
        conditions=src.conditions,
        logic=src.logic,
        count=src.count,
        window_mins=src.window_mins,
        action=src.action,
        action_value=src.action_value,
        is_active=False,
    )
    db.add(copy)
    db.commit()
    db.refresh(copy)
    return rule_to_dict(copy)


@router.get("/{rule_id}/history")
def rule_history(
    rule_id: int,
    limit: int = 50,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    rule = db.query(AlertRule).filter(AlertRule.id == rule_id).first()
    if not rule:
        raise HTTPException(status_code=404, detail="Rule not found")
    execs = (db.query(RuleExecution)
             .filter(RuleExecution.rule_id == rule_id)
             .order_by(RuleExecution.triggered_at.desc())
             .limit(limit).all())
    return {
        "rule_id":   rule_id,
        "rule_name": rule.name,
        "total":     rule.trigger_count or 0,
        "items": [{
            "id":           e.id,
            "alert_id":     e.alert_id,
            "alert_title":  e.alert_title,
            "action_taken": e.action_taken,
            "result":       e.result,
            "triggered_at": e.triggered_at.isoformat() if e.triggered_at else None,
        } for e in execs],
    }


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

    if data.conditions is not None:
        conds = [c.model_dump() for c in data.conditions]
        rule.conditions = json.dumps(conds)
        rule.field    = conds[0]["field"]
        rule.operator = conds[0]["operator"]
        rule.value    = conds[0]["value"]
    elif any(v is not None for v in [data.field, data.operator, data.value]):
        if data.field    is not None: rule.field    = data.field
        if data.operator is not None: rule.operator = data.operator
        if data.value    is not None: rule.value    = data.value
        # Keep conditions JSON in sync with updated first condition
        try:
            existing = json.loads(rule.conditions) if rule.conditions else []
        except Exception:
            existing = []
        if existing:
            existing[0] = {"field": rule.field, "operator": rule.operator, "value": rule.value}
            rule.conditions = json.dumps(existing)

    if data.logic       is not None: rule.logic       = data.logic
    if data.name        is not None: rule.name        = data.name
    if data.description is not None: rule.description = data.description
    if data.count       is not None: rule.count       = data.count
    if data.window_mins is not None: rule.window_mins = data.window_mins
    if data.action      is not None: rule.action      = data.action
    if data.action_value is not None: rule.action_value = data.action_value
    if data.is_active   is not None: rule.is_active   = data.is_active

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
