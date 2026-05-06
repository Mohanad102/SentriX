"""
SOC L2 Investigation Engine
Provides: log correlation, root-cause analysis, response actions, TI lookup.
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
from backend.models.incident import Incident
from backend.models.ioc import IOC
from backend.models.response_action import ResponseAction
from backend.models.user import User
from backend.utils.auth import get_current_user
from backend.routers.audit import write_log

router = APIRouter(prefix="/api/investigation", tags=["investigation"])

# ── RCA Pattern Library ────────────────────────────────────────────────────────
RCA_PATTERNS = [
    {
        "id": "brute_force",
        "label": "Brute Force Attack",
        "mitre_id": "T1110", "mitre_name": "Brute Force",
        "keywords": ["brute force", "failed login", "authentication", "multiple login", "password", "rdp", "ssh"],
        "categories": ["authentication"],
        "description": "Multiple failed authentication attempts from the same or distributed sources indicate a credential-based brute force campaign.",
        "recommended_actions": ["Block source IP at firewall", "Enable account lockout policy", "Enforce MFA on affected accounts", "Review authentication logs for compromised credentials"],
    },
    {
        "id": "phishing",
        "label": "Phishing / Social Engineering",
        "mitre_id": "T1566", "mitre_name": "Phishing",
        "keywords": ["phishing", "email", "social engineering", "spearphishing", "attachment", "invoice", "link"],
        "categories": ["phishing"],
        "description": "Indicators of spear-phishing or email-based social engineering targeting users.",
        "recommended_actions": ["Quarantine malicious emails from mail server", "Revoke compromised credentials", "Notify affected users", "Enable advanced email filtering"],
    },
    {
        "id": "lateral_movement",
        "label": "Lateral Movement",
        "mitre_id": "T1021", "mitre_name": "Remote Services",
        "keywords": ["lateral", "rdp", "smb", "admin share", "pivot", "pass the hash", "unauthorized access"],
        "categories": ["lateral_movement"],
        "description": "Attacker is moving laterally within the network using legitimate remote access protocols.",
        "recommended_actions": ["Isolate affected endpoints", "Disable compromised credentials", "Segment network zones", "Force password reset for impacted accounts"],
    },
    {
        "id": "ransomware",
        "label": "Ransomware Deployment",
        "mitre_id": "T1486", "mitre_name": "Data Encrypted for Impact",
        "keywords": ["ransomware", "encrypt", "locked", "ransom", ".locked", "file server", "mass"],
        "categories": ["ransomware"],
        "description": "Mass file encryption patterns consistent with ransomware deployment. Immediate containment required.",
        "recommended_actions": ["Immediately isolate ALL affected systems", "Disconnect from network", "Preserve forensic images", "Notify management and legal", "Engage IR team"],
    },
    {
        "id": "data_exfiltration",
        "label": "Data Exfiltration",
        "mitre_id": "T1041", "mitre_name": "Exfiltration Over C2 Channel",
        "keywords": ["exfiltration", "data transfer", "large transfer", "upload", "exfil", "sensitive data"],
        "categories": ["exfiltration"],
        "description": "Large or anomalous data transfers to external endpoints indicate active data theft.",
        "recommended_actions": ["Block egress to suspicious IPs immediately", "Engage DLP team", "Identify and scope exfiltrated data", "Notify compliance/legal team"],
    },
    {
        "id": "c2_communication",
        "label": "Command & Control (C2)",
        "mitre_id": "T1071", "mitre_name": "Application Layer Protocol",
        "keywords": ["c2", "command", "control", "beacon", "dns tunnel", "tunneling", "dns", "covert"],
        "categories": ["c2", "network"],
        "description": "Anomalous outbound traffic patterns (e.g., DNS tunneling) suggesting active C2 communication.",
        "recommended_actions": ["Block C2 domains and IPs at DNS and firewall", "Review all outbound traffic", "Check for persistence mechanisms", "Hunt for additional implants"],
    },
    {
        "id": "privilege_escalation",
        "label": "Privilege Escalation",
        "mitre_id": "T1068", "mitre_name": "Exploitation for Privilege Escalation",
        "keywords": ["privilege", "escalation", "uac", "bypass", "admin", "system", "root", "elevated"],
        "categories": ["privilege_escalation"],
        "description": "User gained elevated privileges through exploitation or misconfiguration.",
        "recommended_actions": ["Revoke elevated privileges immediately", "Audit admin account activity", "Apply missing security patches", "Enable privileged access monitoring"],
    },
    {
        "id": "malware_execution",
        "label": "Malware Execution",
        "mitre_id": "T1204", "mitre_name": "User Execution",
        "keywords": ["malware", "trojan", "virus", "payload", "dropper", "backdoor", "powershell", "encoded"],
        "categories": ["malware", "execution"],
        "description": "Malicious software detected running on endpoint. Potential remote access capability.",
        "recommended_actions": ["Quarantine infected endpoint", "Run full AV/EDR scan", "Identify patient zero", "Review network connections from infected host"],
    },
    {
        "id": "persistence",
        "label": "Persistence Mechanism",
        "mitre_id": "T1547", "mitre_name": "Boot or Logon Autostart Execution",
        "keywords": ["persistence", "registry", "run key", "startup", "scheduled task", "cron", "autorun"],
        "categories": ["persistence"],
        "description": "Attacker established persistence mechanisms to survive reboots and maintain access.",
        "recommended_actions": ["Remove persistence artifacts", "Scan for additional backdoors", "Review startup items and scheduled tasks", "Rebuild compromised systems if necessary"],
    },
    {
        "id": "reconnaissance",
        "label": "Reconnaissance / Scanning",
        "mitre_id": "T1046", "mitre_name": "Network Service Scanning",
        "keywords": ["scan", "port scan", "reconnaissance", "nmap", "enumeration", "discovery"],
        "categories": ["network", "recon"],
        "description": "Systematic network scanning or enumeration activity, typically preceding an intrusion attempt.",
        "recommended_actions": ["Block scanning source IP", "Review exposed services", "Enable IDS/IPS signatures", "Document targeted assets for risk assessment"],
    },
]


# ── Schemas ────────────────────────────────────────────────────────────────────

class ActionCreate(BaseModel):
    action_type: str        # block_ip | disable_user | isolate_endpoint | reset_password
    target: str             # IP, username, hostname
    notes: Optional[str] = None


class TILookupRequest(BaseModel):
    value: str
    ioc_type: str           # ip | domain | url | hash
    provider: str = "vt"    # vt | abuse


# ── Helpers ────────────────────────────────────────────────────────────────────

def _score_pattern(pattern: dict, incident: Incident, alerts: list[Alert]) -> int:
    """Return a 0-100 confidence score for a pattern against an incident."""
    score = 0
    text_corpus = " ".join(filter(None, [
        incident.title or "",
        incident.description or "",
        incident.category or "",
        incident.tags or "",
        *[a.title or "" for a in alerts],
        *[a.description or "" for a in alerts],
        *[a.category or "" for a in alerts],
    ])).lower()

    for kw in pattern["keywords"]:
        if kw in text_corpus:
            score += 12

    for cat in pattern["categories"]:
        if cat in text_corpus:
            score += 20

    # Cap at 95
    return min(score, 95)


def action_to_dict(a: ResponseAction) -> dict:
    from backend.models.response_action import ACTION_LABELS
    return {
        "id":          a.id,
        "incident_id": a.incident_id,
        "action_type": a.action_type,
        "action_label": ACTION_LABELS.get(a.action_type, a.action_type),
        "target":      a.target,
        "status":      a.status,
        "notes":       a.notes,
        "executed_by": a.executed_by,
        "executed_at": a.executed_at.isoformat() if a.executed_at else None,
    }


# ── Endpoints ──────────────────────────────────────────────────────────────────

@router.get("/{incident_id}/correlate")
def correlate_events(
    incident_id:  int,
    db:           Session = Depends(get_db),
    current_user: User    = Depends(get_current_user),
):
    """
    Log Correlation Engine.
    Finds alerts related to the incident by shared IP, hostname, and time window.
    Returns an enriched attack timeline.
    """
    incident = db.query(Incident).filter(Incident.id == incident_id).first()
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")

    linked_alerts = db.query(Alert).filter(Alert.incident_id == incident_id).all()

    # Collect unique IPs and hostnames from linked alerts
    ips       = {a.source_ip for a in linked_alerts if a.source_ip}
    hostnames = {a.hostname   for a in linked_alerts if a.hostname}

    # ── IP correlation: other alerts sharing same source IPs ────
    ip_correlated: list[dict] = []
    for ip in ips:
        related = (
            db.query(Alert)
            .filter(Alert.source_ip == ip, Alert.incident_id != incident_id)
            .order_by(Alert.created_at.desc())
            .limit(10)
            .all()
        )
        if related:
            ip_correlated.append({
                "ip":    ip,
                "count": len(related),
                "alerts": [
                    {
                        "id":         a.id,
                        "alert_id":   a.alert_id,
                        "title":      a.title,
                        "severity":   a.severity,
                        "status":     a.status,
                        "category":   a.category,
                        "created_at": a.created_at.isoformat() if a.created_at else None,
                    }
                    for a in related
                ],
            })

    # ── Time correlation: alerts ±2 h around first/last event ──
    time_correlated: list[dict] = []
    if linked_alerts:
        times = [a.created_at for a in linked_alerts if a.created_at]
        if times:
            window_start = min(times) - timedelta(hours=2)
            window_end   = max(times) + timedelta(hours=2)
            nearby = (
                db.query(Alert)
                .filter(
                    Alert.created_at.between(window_start, window_end),
                    Alert.incident_id != incident_id,
                )
                .order_by(Alert.created_at)
                .limit(20)
                .all()
            )
            for a in nearby:
                delta_min = int(
                    (a.created_at - min(times)).total_seconds() / 60
                ) if a.created_at else 0
                sign = "+" if delta_min >= 0 else ""
                time_correlated.append({
                    "id":         a.id,
                    "alert_id":   a.alert_id,
                    "title":      a.title,
                    "severity":   a.severity,
                    "category":   a.category,
                    "created_at": a.created_at.isoformat() if a.created_at else None,
                    "time_delta": f"{sign}{delta_min}m from first event",
                })

    # ── Unified attack timeline ─────────────────────────────────
    timeline_events: list[dict] = []

    if incident.created_at:
        timeline_events.append({
            "time":     incident.created_at.isoformat(),
            "label":    f"Incident opened: {incident.title}",
            "type":     "incident",
            "icon":     "fa-shield-halved",
            "color":    "text-emerald-400",
            "severity": incident.severity,
        })

    for a in linked_alerts:
        if a.created_at:
            timeline_events.append({
                "time":     a.created_at.isoformat(),
                "label":    a.title,
                "type":     "alert",
                "icon":     "fa-bell",
                "color":    "text-orange-400",
                "severity": a.severity,
                "meta":     f"Source: {a.source_ip or '—'}  Host: {a.hostname or '—'}",
            })

    iocs = db.query(IOC).filter(IOC.incident_id == incident_id).all()
    for ioc in iocs:
        if ioc.created_at:
            timeline_events.append({
                "time":     ioc.created_at.isoformat(),
                "label":    f"IOC identified: {ioc.value} ({ioc.ioc_type.upper()})",
                "type":     "ioc",
                "icon":     "fa-fingerprint",
                "color":    "text-purple-400",
                "severity": "critical" if ioc.is_malicious else "low",
            })

    actions = db.query(ResponseAction).filter(ResponseAction.incident_id == incident_id).all()
    for act in actions:
        if act.executed_at:
            timeline_events.append({
                "time":     act.executed_at.isoformat(),
                "label":    f"Action: {act.action_type.replace('_',' ').title()} → {act.target}",
                "type":     "action",
                "icon":     "fa-bolt",
                "color":    "text-yellow-400",
                "severity": "medium",
                "meta":     f"Executed by: {act.executed_by}",
            })

    if incident.closed_at:
        timeline_events.append({
            "time":  incident.closed_at.isoformat(),
            "label": "Incident closed",
            "type":  "incident",
            "icon":  "fa-circle-check",
            "color": "text-gray-400",
            "severity": "low",
        })

    timeline_events.sort(key=lambda e: e["time"])

    # ── Stats ───────────────────────────────────────────────────
    stats: dict = {
        "unique_source_ips":     len(ips),
        "unique_hostnames":      len(hostnames),
        "linked_alerts":         len(linked_alerts),
        "ip_correlated_alerts":  sum(g["count"] for g in ip_correlated),
        "time_correlated_alerts": len(time_correlated),
        "total_timeline_events": len(timeline_events),
    }
    if linked_alerts:
        times = [a.created_at for a in linked_alerts if a.created_at]
        if len(times) > 1:
            duration = (max(times) - min(times)).total_seconds() / 3600
            stats["attack_duration_hours"] = round(duration, 1)
            stats["attack_start"] = min(times).isoformat()
            stats["attack_end"]   = max(times).isoformat()

    return {
        "ip_correlated":    ip_correlated,
        "time_correlated":  time_correlated,
        "attack_timeline":  timeline_events,
        "stats":            stats,
    }


@router.get("/{incident_id}/root-cause")
def root_cause_analysis(
    incident_id:  int,
    db:           Session = Depends(get_db),
    current_user: User    = Depends(get_current_user),
):
    """
    Rule-based Root Cause Analysis.
    Scores each known attack pattern against incident data and returns ranked hypotheses.
    """
    incident = db.query(Incident).filter(Incident.id == incident_id).first()
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")

    alerts = db.query(Alert).filter(Alert.incident_id == incident_id).all()

    hypotheses = []
    for pattern in RCA_PATTERNS:
        confidence = _score_pattern(pattern, incident, alerts)
        if confidence > 0:
            hypotheses.append({
                "id":          pattern["id"],
                "label":       pattern["label"],
                "mitre_id":    pattern["mitre_id"],
                "mitre_name":  pattern["mitre_name"],
                "confidence":  confidence,
                "description": pattern["description"],
                "recommended_actions": pattern["recommended_actions"],
            })

    hypotheses.sort(key=lambda h: h["confidence"], reverse=True)
    top = hypotheses[:5]

    primary = top[0] if top else None
    summary = (
        f"Primary threat: {primary['label']} ({primary['mitre_id']}) "
        f"with {primary['confidence']}% confidence."
        if primary else
        "Insufficient data for root cause determination. Add more alerts to this incident."
    )

    return {
        "hypotheses": top,
        "summary":    summary,
        "analyzed_alerts": len(alerts),
        "generated_at": datetime.utcnow().isoformat(),
    }


@router.get("/{incident_id}/actions")
def list_actions(
    incident_id:  int,
    db:           Session = Depends(get_db),
    current_user: User    = Depends(get_current_user),
):
    """List all response actions executed on this incident."""
    incident = db.query(Incident).filter(Incident.id == incident_id).first()
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")

    actions = (
        db.query(ResponseAction)
        .filter(ResponseAction.incident_id == incident_id)
        .order_by(ResponseAction.executed_at.desc())
        .all()
    )
    return {"total": len(actions), "items": [action_to_dict(a) for a in actions]}


@router.post("/{incident_id}/actions")
def execute_action(
    incident_id:  int,
    data:         ActionCreate,
    db:           Session = Depends(get_db),
    current_user: User    = Depends(get_current_user),
):
    """
    Execute a Response Action on the incident.
    Simulated enforcement — logged and linked to incident.
    L2 analysts and admins only.
    """
    if current_user.role == "soc_analyst_l1":
        raise HTTPException(status_code=403, detail="L1 analysts cannot execute response actions")

    incident = db.query(Incident).filter(Incident.id == incident_id).first()
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")

    from backend.models.response_action import VALID_ACTIONS
    if data.action_type not in VALID_ACTIONS:
        raise HTTPException(status_code=400, detail=f"Invalid action_type. Must be one of: {', '.join(VALID_ACTIONS)}")

    action = ResponseAction(
        incident_id=incident_id,
        action_type=data.action_type,
        target=data.target,
        status="executed",
        notes=data.notes,
        executed_by=current_user.username,
    )
    db.add(action)
    db.flush()

    # Audit log
    from backend.models.response_action import ACTION_LABELS
    write_log(
        db=db,
        username=current_user.username,
        user_id=current_user.id,
        action=f"RESPONSE_ACTION:{data.action_type.upper()}",
        resource="incident",
        resource_id=str(incident_id),
        detail=f"{ACTION_LABELS.get(data.action_type, data.action_type)}: {data.target} | Case: {incident.case_number}",
    )

    db.commit()
    db.refresh(action)

    return {
        **action_to_dict(action),
        "message": _build_action_message(data.action_type, data.target),
    }


def _build_action_message(action_type: str, target: str) -> str:
    msgs = {
        "block_ip":          f"Firewall rule created — IP {target} is now blocked.",
        "disable_user":      f"Account {target} disabled in directory services.",
        "isolate_endpoint":  f"Endpoint {target} isolated from network via EDR.",
        "reset_password":    f"Password reset enforced for account {target}.",
        "kill_process":      f"Process '{target}' terminated on affected endpoint.",
        "remove_file":       f"Malicious file '{target}' removed and quarantined.",
        "reset_credentials": f"All credentials for '{target}' have been reset.",
    }
    return msgs.get(action_type, f"Action executed on {target}.")


@router.post("/ti-lookup")
async def ti_lookup(
    data:         TILookupRequest,
    db:           Session = Depends(get_db),
    current_user: User    = Depends(get_current_user),
):
    """
    Quick Threat Intelligence lookup with DB caching (24h TTL).
    Supports VirusTotal (all IOC types) and AbuseIPDB (IP only).
    """
    value    = data.value.strip()
    ioc_type = data.ioc_type
    provider = data.provider

    # Check cache (IOC table)
    cached = db.query(IOC).filter(IOC.value == value).first()
    if cached and cached.enriched and cached.enriched_at:
        age_hours = (datetime.utcnow() - cached.enriched_at).total_seconds() / 3600
        if age_hours < 24:
            return {
                "source": "cache",
                "value":  value,
                "type":   ioc_type,
                "is_malicious": cached.is_malicious,
                "score":        cached.vt_score,
                "report":       cached.vt_report,
                "cached_at":    cached.enriched_at.isoformat(),
            }

    # Live lookup
    if provider == "abuse" and ioc_type == "ip":
        from backend.config import settings
        import httpx
        api_key = getattr(settings, "ABUSEIPDB_API_KEY", "")
        if not api_key:
            result = {"error": "AbuseIPDB not configured — set ABUSEIPDB_API_KEY in .env"}
        else:
            try:
                async with httpx.AsyncClient(timeout=10) as client:
                    resp = await client.get(
                        "https://api.abuseipdb.com/api/v2/check",
                        headers={"Key": api_key, "Accept": "application/json"},
                        params={"ipAddress": value, "maxAgeInDays": 90},
                    )
                d = resp.json().get("data", {})
                score = d.get("abuseConfidenceScore", 0)
                result = {
                    "abuse_score": score,
                    "is_malicious": score >= 50,
                    "country": d.get("countryCode"),
                    "isp": d.get("isp"),
                    "total_reports": d.get("totalReports", 0),
                    "last_reported": d.get("lastReportedAt"),
                }
            except Exception as e:
                result = {"error": str(e)}
    else:
        from backend.services.virustotal_service import enrich_with_virustotal
        vt = await enrich_with_virustotal(value, ioc_type)
        result = {
            "score":       vt.get("score"),
            "is_malicious": vt.get("is_malicious"),
            "report":      vt.get("report", {}),
        }

    # Cache result
    if cached:
        cached.enriched    = True
        cached.enriched_at = datetime.utcnow()
        cached.vt_score    = str(result.get("score") or result.get("abuse_score", "N/A"))
        cached.is_malicious = result.get("is_malicious")
        cached.vt_report   = json.dumps(result)
    else:
        new_ioc = IOC(
            value=value,
            ioc_type=ioc_type,
            enriched=True,
            enriched_at=datetime.utcnow(),
            is_malicious=result.get("is_malicious"),
            vt_score=str(result.get("score") or result.get("abuse_score", "N/A")),
            vt_report=json.dumps(result),
        )
        db.add(new_ioc)

    db.commit()

    return {
        "source":       provider,
        "value":        value,
        "type":         ioc_type,
        "is_malicious": result.get("is_malicious"),
        "score":        result.get("score") or result.get("abuse_score"),
        "report":       result,
    }


