from sqlalchemy import Column, Integer, String, DateTime, Text
from sqlalchemy.sql import func
from backend.database import Base


class AuditLog(Base):
    __tablename__ = "audit_logs"

    id         = Column(Integer, primary_key=True, index=True)
    user_id    = Column(Integer, nullable=True)
    username   = Column(String, nullable=True)
    action     = Column(String, nullable=False)   # CREATE, UPDATE, DELETE, LOGIN, etc.
    resource   = Column(String, nullable=True)    # alert, incident, user, ioc
    resource_id= Column(String, nullable=True)
    detail     = Column(Text, nullable=True)
    ip_address = Column(String, nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
