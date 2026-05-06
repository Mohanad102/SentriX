from sqlalchemy import Column, Integer, String, DateTime, Text, Boolean, ForeignKey
from sqlalchemy.sql import func
from backend.database import Base


class IOC(Base):
    __tablename__ = "iocs"

    id = Column(Integer, primary_key=True, index=True)
    value = Column(String, nullable=False, index=True)
    ioc_type = Column(String, nullable=False)  # ip, domain, url, hash, email
    incident_id = Column(Integer, ForeignKey("incidents.id"), nullable=True)
    alert_id = Column(Integer, nullable=True)
    is_malicious = Column(Boolean, nullable=True)
    vt_score = Column(String, nullable=True)  # e.g. "45/72"
    vt_report = Column(Text, nullable=True)
    enriched = Column(Boolean, default=False)
    tags = Column(String, nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    enriched_at = Column(DateTime(timezone=True), nullable=True)


class ChatMessage(Base):
    __tablename__ = "chat_messages"

    id = Column(Integer, primary_key=True, index=True)
    session_id = Column(String, index=True)
    role = Column(String)  # user, assistant
    content = Column(Text)
    incident_context = Column(Integer, nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
