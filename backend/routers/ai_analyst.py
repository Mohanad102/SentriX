import json
import uuid

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import StreamingResponse
from sqlalchemy import func
from sqlalchemy.orm import Session
from pydantic import BaseModel
from typing import Optional

from backend.database import get_db
from backend.models.alert import Alert
from backend.models.incident import Incident
from backend.models.ioc import ChatMessage, IOC
from backend.models.user import User
from backend.utils.auth import get_current_user, require_not_l1

router = APIRouter(prefix="/api/ai", tags=["ai"], dependencies=[Depends(require_not_l1)])


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


@router.get("/model-info")
def model_info(current_user: User = Depends(get_current_user)):
    from backend.services.rag_service import get_active_model
    from backend.services.knowledge_base import knowledge_base
    return {"model": get_active_model(), "kb_docs": knowledge_base.doc_count}


@router.post("/kb/rebuild")
def rebuild_kb(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    from backend.services.knowledge_base import knowledge_base
    count = knowledge_base.build(db)
    return {"status": "ok", "docs_indexed": count}


@router.post("/chat/stream")
async def chat_stream(
    req: ChatRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Streaming version of /chat — returns text/event-stream chunks."""
    session_id = req.session_id or str(uuid.uuid4())

    # Load history before we return the StreamingResponse
    history_rows = (
        db.query(ChatMessage)
        .filter(ChatMessage.session_id == session_id)
        .order_by(ChatMessage.created_at.desc())
        .limit(10)
        .all()
    )
    history = [(m.role, m.content) for m in reversed(history_rows)]

    # Save user message now (synchronous, before streaming)
    db.add(ChatMessage(session_id=session_id, role="user", content=req.message, incident_context=req.incident_id))
    db.commit()

    # Build system stats
    alert_by_sev = dict(db.query(Alert.severity, func.count(Alert.id)).group_by(Alert.severity).all())
    inc_by_status = dict(db.query(Incident.status, func.count(Incident.id)).group_by(Incident.status).all())
    system_stats = {
        "total_alerts":          db.query(Alert).count(),
        "open_alerts":           db.query(Alert).filter(Alert.status == "open").count(),
        "critical_alerts":       alert_by_sev.get("critical", 0),
        "high_alerts":           alert_by_sev.get("high", 0),
        "medium_alerts":         alert_by_sev.get("medium", 0),
        "low_alerts":            alert_by_sev.get("low", 0),
        "total_incidents":       db.query(Incident).count(),
        "open_incidents":        inc_by_status.get("open", 0),
        "in_progress_incidents": inc_by_status.get("in_progress", 0),
        "resolved_incidents":    inc_by_status.get("resolved", 0),
        "total_iocs":            db.query(IOC).count(),
        "malicious_iocs":        db.query(IOC).filter(IOC.is_malicious == True).count(),  # noqa: E712
    }

    # Incident context
    incident_context = None
    if req.incident_id:
        inc = db.query(Incident).filter(Incident.id == req.incident_id).first()
        if inc:
            inc_alerts = db.query(Alert).filter(Alert.incident_id == req.incident_id).all()
            inc_iocs   = db.query(IOC).filter(IOC.incident_id == req.incident_id).all()
            incident_context = {
                "case_number": inc.case_number,
                "title":       inc.title,
                "severity":    inc.severity,
                "status":      inc.status,
                "description": inc.description,
                "alerts": [{"title": a.title, "severity": a.severity, "category": a.category, "source_ip": a.source_ip} for a in inc_alerts],
                "iocs":   [{"value": i.value, "type": i.ioc_type, "malicious": i.is_malicious, "score": i.vt_score} for i in inc_iocs],
            }

    from backend.services.rag_service import get_ai_response_stream

    async def generate():
        chunks: list[str] = []
        # Send session_id first so the frontend can persist it
        yield f"data: {json.dumps({'session_id': session_id})}\n\n"
        try:
            async for chunk in get_ai_response_stream(req.message, history, incident_context, system_stats):
                chunks.append(chunk)
                yield f"data: {json.dumps({'chunk': chunk})}\n\n"
        except Exception as e:
            yield f"data: {json.dumps({'error': str(e)})}\n\n"
        finally:
            # Persist the complete assistant message
            full_response = "".join(chunks)
            if full_response:
                from backend.database import SessionLocal
                save_db = SessionLocal()
                try:
                    save_db.add(ChatMessage(session_id=session_id, role="assistant", content=full_response))
                    save_db.commit()
                except Exception:
                    pass
                finally:
                    save_db.close()
            yield f"data: {json.dumps({'done': True})}\n\n"

    return StreamingResponse(
        generate(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )
