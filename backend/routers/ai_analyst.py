from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from sqlalchemy import func
from pydantic import BaseModel
from typing import Optional
from backend.database import get_db
from backend.models.ioc import ChatMessage, IOC
from backend.models.incident import Incident
from backend.models.alert import Alert
from backend.utils.auth import get_current_user
from backend.models.user import User
import uuid

router = APIRouter(prefix="/api/ai", tags=["ai"])


class ChatRequest(BaseModel):
    message: str
    session_id: Optional[str] = None
    incident_id: Optional[int] = None


class AnalysisRequest(BaseModel):
    incident_id: int


@router.post("/chat")
async def chat(
    req: ChatRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    session_id = req.session_id or str(uuid.uuid4())

    # Load chat history for this session (last 10 messages)
    history = db.query(ChatMessage).filter(
        ChatMessage.session_id == session_id
    ).order_by(ChatMessage.created_at.desc()).limit(10).all()
    history = list(reversed(history))

    # Save user message
    user_msg = ChatMessage(
        session_id=session_id,
        role="user",
        content=req.message,
        incident_context=req.incident_id
    )
    db.add(user_msg)
    db.flush()

    # Collect real-time system stats from DB
    alert_by_sev = dict(
        db.query(Alert.severity, func.count(Alert.id)).group_by(Alert.severity).all()
    )
    inc_by_status = dict(
        db.query(Incident.status, func.count(Incident.id)).group_by(Incident.status).all()
    )
    system_stats = {
        "total_alerts": db.query(Alert).count(),
        "open_alerts": db.query(Alert).filter(Alert.status == "open").count(),
        "critical_alerts": alert_by_sev.get("critical", 0),
        "high_alerts": alert_by_sev.get("high", 0),
        "medium_alerts": alert_by_sev.get("medium", 0),
        "low_alerts": alert_by_sev.get("low", 0),
        "alerts_by_severity": alert_by_sev,
        "total_incidents": db.query(Incident).count(),
        "open_incidents": inc_by_status.get("open", 0),
        "in_progress_incidents": inc_by_status.get("in_progress", 0),
        "resolved_incidents": inc_by_status.get("resolved", 0),
        "incidents_by_status": inc_by_status,
        "total_iocs": db.query(IOC).count(),
        "malicious_iocs": db.query(IOC).filter(IOC.is_malicious == True).count(),  # noqa: E712
    }

    # Get incident context if provided
    incident_context = None
    if req.incident_id:
        inc = db.query(Incident).filter(Incident.id == req.incident_id).first()
        if inc:
            inc_alerts = db.query(Alert).filter(Alert.incident_id == req.incident_id).all()
            inc_iocs = db.query(IOC).filter(IOC.incident_id == req.incident_id).all()
            incident_context = {
                "case_number": inc.case_number,
                "title": inc.title,
                "severity": inc.severity,
                "status": inc.status,
                "description": inc.description,
                "alerts": [{"title": a.title, "severity": a.severity, "category": a.category, "source_ip": a.source_ip} for a in inc_alerts],
                "iocs": [{"value": i.value, "type": i.ioc_type, "malicious": i.is_malicious, "score": i.vt_score} for i in inc_iocs],
            }

    from backend.services.rag_service import get_ai_response
    response = await get_ai_response(
        query=req.message,
        history=[(m.role, m.content) for m in history],
        incident_context=incident_context,
        system_stats=system_stats
    )

    # Save assistant response
    assistant_msg = ChatMessage(
        session_id=session_id,
        role="assistant",
        content=response
    )
    db.add(assistant_msg)
    db.commit()

    return {
        "session_id": session_id,
        "response": response
    }


@router.post("/analyze-incident")
async def analyze_incident(
    req: AnalysisRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    inc = db.query(Incident).filter(Incident.id == req.incident_id).first()
    if not inc:
        raise HTTPException(status_code=404, detail="Incident not found")

    from backend.models.alert import Alert
    from backend.models.ioc import IOC
    alerts = db.query(Alert).filter(Alert.incident_id == req.incident_id).all()
    iocs = db.query(IOC).filter(IOC.incident_id == req.incident_id).all()

    context = {
        "case_number": inc.case_number,
        "title": inc.title,
        "severity": inc.severity,
        "description": inc.description,
        "alerts": [{"title": a.title, "category": a.category, "source_ip": a.source_ip} for a in alerts],
        "iocs": [{"value": i.value, "type": i.ioc_type, "malicious": i.is_malicious, "score": i.vt_score} for i in iocs]
    }

    from backend.services.rag_service import analyze_incident_with_rag
    result = await analyze_incident_with_rag(context)

    # Save analysis back to incident
    inc.ai_summary = result.get("summary", "")
    inc.ai_iocs = result.get("iocs", "")
    inc.ai_recommendations = result.get("recommendations", "")
    db.commit()

    return result


@router.get("/chat-history/{session_id}")
def get_chat_history(
    session_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    messages = db.query(ChatMessage).filter(
        ChatMessage.session_id == session_id
    ).order_by(ChatMessage.created_at.asc()).all()
    return [
        {
            "role": m.role,
            "content": m.content,
            "created_at": m.created_at.isoformat() if m.created_at else None
        }
        for m in messages
    ]


@router.delete("/chat-history/{session_id}")
def clear_chat_history(
    session_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    db.query(ChatMessage).filter(ChatMessage.session_id == session_id).delete()
    db.commit()
    return {"message": "Chat history cleared"}
