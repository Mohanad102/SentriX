from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from sqlalchemy import func
from backend.database import get_db
from backend.models.alert import Alert
from backend.models.incident import Incident
from backend.models.ioc import IOC
from backend.utils.auth import get_current_user
from backend.models.user import User
from datetime import datetime, timedelta

router = APIRouter(prefix="/api/dashboard", tags=["dashboard"])


@router.get("/stats")
def get_dashboard_stats(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    total_alerts = db.query(Alert).count()
    open_alerts = db.query(Alert).filter(Alert.status == "open").count()
    critical_alerts = db.query(Alert).filter(Alert.severity == "critical").count()
    high_alerts = db.query(Alert).filter(Alert.severity == "high").count()

    total_incidents = db.query(Incident).count()
    open_incidents = db.query(Incident).filter(Incident.status == "open").count()
    in_progress_incidents = db.query(Incident).filter(Incident.status == "in_progress").count()
    resolved_incidents = db.query(Incident).filter(Incident.status == "resolved").count()

    total_iocs = db.query(IOC).count()
    malicious_iocs = db.query(IOC).filter(IOC.is_malicious == True).count()  # noqa: E712

    # Alerts in last 24h
    last_24h = datetime.utcnow() - timedelta(hours=24)
    alerts_24h = db.query(Alert).filter(Alert.created_at >= last_24h).count()

    return {
        "alerts": {
            "total": total_alerts,
            "open": open_alerts,
            "critical": critical_alerts,
            "high": high_alerts,
            "last_24h": alerts_24h
        },
        "incidents": {
            "total": total_incidents,
            "open": open_incidents,
            "in_progress": in_progress_incidents,
            "resolved": resolved_incidents
        },
        "iocs": {
            "total": total_iocs,
            "malicious": malicious_iocs
        }
    }


@router.get("/alerts-by-severity")
def get_alerts_by_severity(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    results = db.query(Alert.severity, func.count(Alert.id)).group_by(Alert.severity).all()
    return {sev: count for sev, count in results}


@router.get("/alerts-over-time")
def get_alerts_over_time(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    # Last 7 days
    days = []
    for i in range(6, -1, -1):
        day = datetime.utcnow() - timedelta(days=i)
        start = day.replace(hour=0, minute=0, second=0, microsecond=0)
        end = start + timedelta(days=1)
        count = db.query(Alert).filter(Alert.created_at >= start, Alert.created_at < end).count()
        days.append({"date": start.strftime("%Y-%m-%d"), "count": count})
    return days


@router.get("/recent-alerts")
def get_recent_alerts(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    alerts = (
        db.query(Alert)
        .order_by(Alert.created_at.desc())
        .limit(10)
        .all()
    )
    return [
        {
            "id": a.id,
            "alert_id": a.alert_id,
            "title": a.title,
            "severity": a.severity,
            "source_ip": a.source_ip,
            "hostname": a.hostname,
            "status": a.status,
            "created_at": a.created_at.isoformat() if a.created_at else None
        }
        for a in alerts
    ]


@router.get("/incidents-by-status")
def get_incidents_by_status(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    results = db.query(Incident.status, func.count(Incident.id)).group_by(Incident.status).all()
    return {status: count for status, count in results}


@router.get("/top-categories")
def get_top_categories(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    results = (
        db.query(Alert.category, func.count(Alert.id))
        .filter(Alert.category != None)  # noqa: E711
        .group_by(Alert.category)
        .order_by(func.count(Alert.id).desc())
        .limit(5)
        .all()
    )
    return [{"category": cat, "count": cnt} for cat, cnt in results]
