from sqlalchemy import Column, Integer, String, DateTime, Text, ForeignKey
from sqlalchemy.sql import func
from backend.database import Base


class Incident(Base):
    __tablename__ = "incidents"

    id = Column(Integer, primary_key=True, index=True)
    case_number = Column(String, unique=True, index=True)
    title = Column(String, nullable=False)
    description = Column(Text)
    severity = Column(String, default="medium")  # low, medium, high, critical
    status = Column(String, default="open")  # open, in_progress, resolved, closed
    priority = Column(String, default="medium")  # low, medium, high, critical
    category = Column(String, nullable=True)
    assigned_to = Column(String, nullable=True)
    thehive_id = Column(String, nullable=True)
    ai_summary = Column(Text, nullable=True)
    ai_iocs = Column(Text, nullable=True)
    ai_recommendations = Column(Text, nullable=True)
    tags = Column(String, nullable=True)
    created_by = Column(Integer, ForeignKey("users.id"), nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())
    closed_at = Column(DateTime(timezone=True), nullable=True)


class IncidentTask(Base):
    __tablename__ = "incident_tasks"

    id = Column(Integer, primary_key=True, index=True)
    incident_id = Column(Integer, ForeignKey("incidents.id"))
    title = Column(String, nullable=False)
    description = Column(Text)
    status = Column(String, default="pending")  # pending, in_progress, completed
    assigned_to = Column(String, nullable=True)
    cortex_job_id = Column(String, nullable=True)
    result = Column(Text, nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
