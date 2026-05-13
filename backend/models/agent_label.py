from sqlalchemy import Column, String, DateTime
from datetime import datetime
from backend.database import Base


class AgentLabel(Base):
    __tablename__ = "agent_labels"

    agent_id    = Column(String, primary_key=True, index=True)
    label       = Column(String, nullable=False)
    updated_at  = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
