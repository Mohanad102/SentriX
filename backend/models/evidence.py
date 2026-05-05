from sqlalchemy import Column, Integer, String, DateTime, Text, ForeignKey
from sqlalchemy.sql import func
from backend.database import Base

EVIDENCE_TYPES = ["log", "ip_address", "file_hash", "network_capture", "process_list", "screenshot", "note"]


class IREvidence(Base):
    __tablename__ = "ir_evidence"

    id            = Column(Integer, primary_key=True, index=True)
    incident_id   = Column(Integer, ForeignKey("incidents.id"), nullable=False)
    evidence_type = Column(String, nullable=False, default="note")
    title         = Column(String, nullable=False)
    content       = Column(Text, nullable=True)
    source        = Column(String, nullable=True)    # tool / system where collected
    collected_by  = Column(String, nullable=True)
    collected_at  = Column(DateTime(timezone=True), server_default=func.now())
