from sqlalchemy import Column, Integer, String, DateTime, Text
from sqlalchemy.sql import func
from backend.database import Base


class Ticket(Base):
    __tablename__ = "tickets"

    id = Column(Integer, primary_key=True, index=True)
    ticket_id = Column(String, unique=True, index=True)          # TKT-XXXXXXXX
    alert_id = Column(Integer, nullable=True)                    # source alert (int id)
    title = Column(String, nullable=False)
    description = Column(Text, nullable=True)
    severity = Column(String, default="medium")                  # low, medium, high, critical
    status = Column(String, default="open")                      # open, in_progress, escalated, closed
    assigned_to = Column(String, nullable=False)                 # L1 Analyst | L2 Analyst | Incident Response
    triage_result = Column(String, nullable=True)                # true_positive | false_positive | suspicious
    notes = Column(Text, nullable=True)
    investigation_notes = Column(Text, nullable=True)
    l2_status = Column(String, nullable=True)                    # under_investigation | contained | escalated_to_ir
    evidence = Column(Text, nullable=True)
    escalated_at = Column(DateTime(timezone=True), nullable=True)
    created_by_id = Column(Integer, nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())
