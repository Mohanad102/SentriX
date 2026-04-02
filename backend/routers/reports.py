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


@router.get("/incident/{incident_id}/export/pdf")
def export_incident_pdf(
    incident_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    from reportlab.lib.pagesizes import A4
    from reportlab.lib import colors
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import cm
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable
    from reportlab.lib.enums import TA_CENTER, TA_LEFT
    import io

    inc = db.query(Incident).filter(Incident.id == incident_id).first()
    if not inc:
        raise HTTPException(status_code=404, detail="Incident not found")
    alerts = db.query(Alert).filter(Alert.incident_id == incident_id).all()
    iocs   = db.query(IOC).filter(IOC.incident_id == incident_id).all()

    buf = io.BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=A4, leftMargin=2*cm, rightMargin=2*cm,
                            topMargin=2*cm, bottomMargin=2*cm)
    styles = getSampleStyleSheet()

    SEV_COLORS = {
        "critical": colors.HexColor("#ef4444"),
        "high":     colors.HexColor("#f97316"),
        "medium":   colors.HexColor("#eab308"),
        "low":      colors.HexColor("#22c55e"),
    }
    sev_color = SEV_COLORS.get(inc.severity, colors.grey)

    title_style   = ParagraphStyle("title", fontSize=20, textColor=colors.HexColor("#10b981"),
                                   alignment=TA_CENTER, spaceAfter=6, fontName="Helvetica-Bold")
    sub_style     = ParagraphStyle("sub",   fontSize=10, textColor=colors.grey, alignment=TA_CENTER, spaceAfter=12)
    heading_style = ParagraphStyle("h2",    fontSize=13, textColor=colors.HexColor("#10b981"),
                                   fontName="Helvetica-Bold", spaceBefore=14, spaceAfter=4)
    body_style    = ParagraphStyle("body",  fontSize=9,  textColor=colors.HexColor("#374151"),
                                   leading=14, spaceAfter=6)

    story = [
        Paragraph("SentriX — Incident Report", title_style),
        Paragraph(f"Generated: {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}", sub_style),
        HRFlowable(width="100%", thickness=1, color=colors.HexColor("#10b981")),
        Spacer(1, 10),
    ]

    # Meta table
    meta = [
        ["Case Number", inc.case_number,     "Status",   inc.status.upper()],
        ["Severity",    inc.severity.upper(), "Priority", (inc.priority or "N/A").upper()],
        ["Category",    inc.category or "N/A","Assigned", inc.assigned_to or "Unassigned"],
        ["Created",     inc.created_at.strftime("%Y-%m-%d %H:%M") if inc.created_at else "N/A", "", ""],
    ]
    t = Table(meta, colWidths=[3.5*cm, 6*cm, 3.5*cm, 4*cm])
    t.setStyle(TableStyle([
        ("BACKGROUND", (0,0), (0,-1), colors.HexColor("#f3f4f6")),
        ("BACKGROUND", (2,0), (2,-1), colors.HexColor("#f3f4f6")),
        ("FONTNAME",   (0,0), (0,-1), "Helvetica-Bold"),
        ("FONTNAME",   (2,0), (2,-1), "Helvetica-Bold"),
        ("FONTSIZE",   (0,0), (-1,-1), 9),
        ("GRID",       (0,0), (-1,-1), 0.5, colors.HexColor("#e5e7eb")),
        ("ROWBACKGROUNDS", (0,0), (-1,-1), [colors.white, colors.HexColor("#f9fafb")]),
        ("TEXTCOLOR", (1,0), (1,0), sev_color),
        ("FONTNAME",  (1,0), (1,0), "Helvetica-Bold"),
    ]))
    story += [Paragraph("Incident Details", heading_style), t, Spacer(1, 8)]

    # Title & Description
    story += [
        Paragraph(f"<b>{inc.title}</b>", ParagraphStyle("it", fontSize=11, textColor=colors.HexColor("#111827"), spaceAfter=4)),
        Paragraph(inc.description or "No description.", body_style),
    ]

    # AI sections
    for label, content in [("AI Summary", inc.ai_summary), ("Recommendations", inc.ai_recommendations)]:
        if content:
            story += [Paragraph(label, heading_style),
                      HRFlowable(width="100%", thickness=0.5, color=colors.HexColor("#d1fae5")),
                      Paragraph(content.replace("\n", "<br/>"), body_style)]

    # Alerts table
    if alerts:
        story.append(Paragraph(f"Related Alerts ({len(alerts)})", heading_style))
        ah = [["Alert ID", "Title", "Severity", "Source IP", "Time"]]
        for a in alerts:
            ah.append([
                a.alert_id or "",
                (a.title or "")[:45],
                (a.severity or "").upper(),
                a.source_ip or "",
                a.created_at.strftime("%Y-%m-%d %H:%M") if a.created_at else ""
            ])
        at = Table(ah, colWidths=[2.5*cm, 7*cm, 2*cm, 3*cm, 3*cm])
        at.setStyle(TableStyle([
            ("BACKGROUND", (0,0), (-1,0), colors.HexColor("#10b981")),
            ("TEXTCOLOR",  (0,0), (-1,0), colors.white),
            ("FONTNAME",   (0,0), (-1,0), "Helvetica-Bold"),
            ("FONTSIZE",   (0,0), (-1,-1), 8),
            ("GRID",       (0,0), (-1,-1), 0.4, colors.HexColor("#e5e7eb")),
            ("ROWBACKGROUNDS", (0,1), (-1,-1), [colors.white, colors.HexColor("#f0fdf4")]),
        ]))
        story.append(at)

    # IOCs table
    if iocs:
        story.append(Paragraph(f"Indicators of Compromise ({len(iocs)})", heading_style))
        ih = [["Type", "Value", "Status", "VT Score"]]
        for i in iocs:
            status = "MALICIOUS" if i.is_malicious else ("CLEAN" if i.is_malicious is False else "UNKNOWN")
            ih.append([(i.ioc_type or "").upper(), i.value or "", status, i.vt_score or "N/A"])
        it = Table(ih, colWidths=[2.5*cm, 9*cm, 3*cm, 3*cm])
        it.setStyle(TableStyle([
            ("BACKGROUND", (0,0), (-1,0), colors.HexColor("#10b981")),
            ("TEXTCOLOR",  (0,0), (-1,0), colors.white),
            ("FONTNAME",   (0,0), (-1,0), "Helvetica-Bold"),
            ("FONTSIZE",   (0,0), (-1,-1), 8),
            ("GRID",       (0,0), (-1,-1), 0.4, colors.HexColor("#e5e7eb")),
            ("ROWBACKGROUNDS", (0,1), (-1,-1), [colors.white, colors.HexColor("#f0fdf4")]),
        ]))
        story.append(it)

    doc.build(story)
    buf.seek(0)
    return Response(
        content=buf.read(),
        media_type="application/pdf",
        headers={"Content-Disposition": f"attachment; filename=report_{inc.case_number}.pdf"}
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
