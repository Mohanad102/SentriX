from fastapi import APIRouter, Depends, HTTPException, Response
from sqlalchemy.orm import Session
from typing import Optional
from backend.database import get_db
from backend.models.incident import Incident
from backend.models.alert import Alert
from backend.models.ioc import IOC
from backend.utils.auth import get_current_user
from backend.models.user import User
from datetime import datetime
import json

router = APIRouter(prefix="/api/reports", tags=["reports"])


def build_incident_report(inc: Incident, alerts, iocs) -> dict:
    return {
        "report_type": "Incident Report",
        "generated_at": datetime.utcnow().isoformat(),
        "case_number": inc.case_number,
        "title": inc.title,
        "severity": inc.severity,
        "status": inc.status,
        "priority": inc.priority,
        "category": inc.category,
        "assigned_to": inc.assigned_to,
        "created_at": inc.created_at.isoformat() if inc.created_at else None,
        "closed_at": inc.closed_at.isoformat() if inc.closed_at else None,
        "description": inc.description,
        "ai_summary": inc.ai_summary,
        "ai_iocs": inc.ai_iocs,
        "ai_recommendations": inc.ai_recommendations,
        "alerts": [
            {
                "alert_id": a.alert_id,
                "title": a.title,
                "severity": a.severity,
                "source_ip": a.source_ip,
                "hostname": a.hostname,
                "created_at": a.created_at.isoformat() if a.created_at else None
            }
            for a in alerts
        ],
        "iocs": [
            {
                "value": i.value,
                "type": i.ioc_type,
                "is_malicious": i.is_malicious,
                "vt_score": i.vt_score
            }
            for i in iocs
        ]
    }


@router.get("/incident/{incident_id}")
def get_incident_report(
    incident_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    inc = db.query(Incident).filter(Incident.id == incident_id).first()
    if not inc:
        raise HTTPException(status_code=404, detail="Incident not found")
    alerts = db.query(Alert).filter(Alert.incident_id == incident_id).all()
    iocs = db.query(IOC).filter(IOC.incident_id == incident_id).all()
    return build_incident_report(inc, alerts, iocs)


@router.get("/incident/{incident_id}/export/json")
def export_incident_json(
    incident_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    inc = db.query(Incident).filter(Incident.id == incident_id).first()
    if not inc:
        raise HTTPException(status_code=404, detail="Incident not found")
    alerts = db.query(Alert).filter(Alert.incident_id == incident_id).all()
    iocs = db.query(IOC).filter(IOC.incident_id == incident_id).all()
    report = build_incident_report(inc, alerts, iocs)
    content = json.dumps(report, indent=2, ensure_ascii=False)
    return Response(
        content=content,
        media_type="application/json",
        headers={"Content-Disposition": f"attachment; filename=report_{inc.case_number}.json"}
    )


@router.get("/incident/{incident_id}/export/txt")
def export_incident_txt(
    incident_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    inc = db.query(Incident).filter(Incident.id == incident_id).first()
    if not inc:
        raise HTTPException(status_code=404, detail="Incident not found")
    alerts = db.query(Alert).filter(Alert.incident_id == incident_id).all()
    iocs = db.query(IOC).filter(IOC.incident_id == incident_id).all()

    lines = [
        "=" * 60,
        "           SENTRIX - INCIDENT REPORT",
        "=" * 60,
        f"Generated:     {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')} UTC",
        f"Case Number:   {inc.case_number}",
        f"Title:         {inc.title}",
        f"Severity:      {inc.severity.upper()}",
        f"Status:        {inc.status.upper()}",
        f"Priority:      {inc.priority.upper()}",
        f"Assigned To:   {inc.assigned_to or 'Unassigned'}",
        f"Created:       {inc.created_at.strftime('%Y-%m-%d %H:%M:%S') if inc.created_at else 'N/A'}",
        "",
        "-" * 60,
        "DESCRIPTION",
        "-" * 60,
        inc.description or "No description provided.",
        "",
    ]

    if inc.ai_summary:
        lines += ["-" * 60, "AI ANALYSIS SUMMARY", "-" * 60, inc.ai_summary, ""]
    if inc.ai_iocs:
        lines += ["-" * 60, "IDENTIFIED IOCs", "-" * 60, inc.ai_iocs, ""]
    if inc.ai_recommendations:
        lines += ["-" * 60, "RECOMMENDATIONS", "-" * 60, inc.ai_recommendations, ""]

    if alerts:
        lines += ["-" * 60, "RELATED ALERTS", "-" * 60]
        for a in alerts:
            lines.append(f"  [{a.severity.upper()}] {a.alert_id} - {a.title}")
            if a.source_ip:
                lines.append(f"    Source IP: {a.source_ip}")

    if iocs:
        lines += ["", "-" * 60, "INDICATORS OF COMPROMISE", "-" * 60]
        for i in iocs:
            status_str = "MALICIOUS" if i.is_malicious else ("CLEAN" if i.is_malicious is False else "UNKNOWN")
            lines.append(f"  [{i.ioc_type.upper()}] {i.value} - {status_str} (VT: {i.vt_score or 'N/A'})")

    lines += ["", "=" * 60, "END OF REPORT", "=" * 60]
    content = "\n".join(lines)

    return Response(
        content=content,
        media_type="text/plain",
        headers={"Content-Disposition": f"attachment; filename=report_{inc.case_number}.txt"}
    )


@router.get("/summary")
def get_summary_report(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    from sqlalchemy import func
    alert_by_sev = db.query(Alert.severity, func.count(Alert.id)).group_by(Alert.severity).all()
    inc_by_status = db.query(Incident.status, func.count(Incident.id)).group_by(Incident.status).all()
    malicious_iocs = db.query(IOC).filter(IOC.is_malicious == True).count()  # noqa: E712

    return {
        "generated_at": datetime.utcnow().isoformat(),
        "total_alerts": db.query(Alert).count(),
        "alerts_by_severity": {sev: cnt for sev, cnt in alert_by_sev},
        "total_incidents": db.query(Incident).count(),
        "incidents_by_status": {st: cnt for st, cnt in inc_by_status},
        "total_iocs": db.query(IOC).count(),
        "malicious_iocs": malicious_iocs
    }
