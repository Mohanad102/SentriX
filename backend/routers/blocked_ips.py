from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from pydantic import BaseModel
from typing import Optional
from datetime import datetime

from backend.database import get_db
from backend.models.blocked_ip import BlockedIP
from backend.utils.auth import require_admin

router = APIRouter(prefix="/api/blocked-ips", tags=["blocked-ips"])


class BlockIPRequest(BaseModel):
    ip: str
    reason: Optional[str] = None


def to_dict(b: BlockedIP):
    return {
        "id": b.id,
        "ip": b.ip,
        "reason": b.reason,
        "blocked_by": b.blocked_by,
        "blocked_at": b.blocked_at.isoformat() if b.blocked_at else None,
    }


@router.get("")
def list_blocked(db: Session = Depends(get_db), _=Depends(require_admin)):
    items = db.query(BlockedIP).order_by(BlockedIP.blocked_at.desc()).all()
    return {"items": [to_dict(b) for b in items], "total": len(items)}


@router.post("")
def block_ip(body: BlockIPRequest, db: Session = Depends(get_db), current_user=Depends(require_admin)):
    existing = db.query(BlockedIP).filter(BlockedIP.ip == body.ip).first()
    if existing:
        raise HTTPException(status_code=409, detail="IP is already blocked")
    entry = BlockedIP(ip=body.ip, reason=body.reason, blocked_by=current_user.username)
    db.add(entry)
    db.commit()
    db.refresh(entry)
    return to_dict(entry)


@router.delete("/{entry_id}")
def unblock_ip(entry_id: int, db: Session = Depends(get_db), _=Depends(require_admin)):
    entry = db.query(BlockedIP).filter(BlockedIP.id == entry_id).first()
    if not entry:
        raise HTTPException(status_code=404, detail="Not found")
    db.delete(entry)
    db.commit()
    return {"ok": True}
