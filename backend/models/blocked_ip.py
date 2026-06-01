from sqlalchemy import Column, Integer, String, DateTime
from datetime import datetime
from backend.database import Base


class BlockedIP(Base):
    __tablename__ = "blocked_ips"

    id = Column(Integer, primary_key=True, index=True)
    ip = Column(String, unique=True, nullable=False, index=True)
    reason = Column(String, nullable=True)
    blocked_by = Column(String, nullable=True)
    blocked_at = Column(DateTime, default=datetime.utcnow)
