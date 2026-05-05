from sqlalchemy import Column, Integer, String, DateTime, Text, Float, Boolean
from sqlalchemy.sql import func
from backend.database import Base


class Alert(Base):
    __tablename__ = "alerts"

    id = Column(Integer, primary_key=True, index=True)
    alert_id = Column(String, unique=True, index=True)
    title = Column(String, nullable=False)
    description = Column(Text)
    severity = Column(String, default="medium")  # low, medium, high, critical
    source = Column(String, default="wazuh")  # wazuh, manual
    source_ip = Column(String, nullable=True)
    dest_ip = Column(String, nullable=True)
    hostname = Column(String, nullable=True)
    rule_id = Column(String, nullable=True)
    rule_level = Column(Integer, nullable=True)
    category = Column(String, nullable=True)
    status = Column(String, default="open")  # open, in_progress, closed, false_positive
    raw_data = Column(Text, nullable=True)
    incident_id = Column(Integer, nullable=True)
    vt_enriched = Column(Boolean, default=False, nullable=True)
    vt_malicious = Column(Boolean, nullable=True)
    # Triage fields (set by L1 analyst)
    triage_result = Column(String, nullable=True)   # true_positive | false_positive | suspicious
    notes = Column(Text, nullable=True)
    ticket_ref = Column(String, nullable=True)       # TKT-XXXXXXXX — set when a ticket is created
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())
