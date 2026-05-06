from sqlalchemy import Column, Integer, String, DateTime, Text, Float
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
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())
