from sqlalchemy import Column, Integer, String, Boolean, DateTime, Text
from sqlalchemy.sql import func
from backend.database import Base


class AlertRule(Base):
    __tablename__ = "alert_rules"

    id          = Column(Integer, primary_key=True, index=True)
    name        = Column(String, nullable=False)
    description = Column(Text, nullable=True)
    field       = Column(String, nullable=False)   # source_ip, category, rule_level, severity
    operator    = Column(String, nullable=False)   # eq, contains, gt, lt, gte
    value       = Column(String, nullable=False)
    count       = Column(Integer, default=1)       # trigger after N occurrences
    window_mins = Column(Integer, default=5)       # within X minutes
    action      = Column(String, default="escalate")  # escalate, set_severity
    action_value= Column(String, nullable=True)    # e.g. "critical"
    is_active   = Column(Boolean, default=True)
    created_at  = Column(DateTime(timezone=True), server_default=func.now())
    updated_at  = Column(DateTime(timezone=True), onupdate=func.now())
