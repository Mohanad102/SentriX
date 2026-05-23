from sqlalchemy import Column, Integer, String, DateTime, ForeignKey, Text
from sqlalchemy.sql import func
from backend.database import Base


class RuleExecution(Base):
    __tablename__ = "rule_executions"

    id           = Column(Integer, primary_key=True, index=True)
    rule_id      = Column(Integer, ForeignKey("alert_rules.id", ondelete="CASCADE"), nullable=False, index=True)
    alert_id     = Column(Integer, nullable=True)
    alert_title  = Column(String, nullable=True)
    action_taken = Column(String, nullable=False)
    result       = Column(Text, nullable=True)
    triggered_at = Column(DateTime(timezone=True), server_default=func.now())
