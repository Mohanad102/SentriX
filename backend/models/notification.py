from sqlalchemy import Column, Integer, String, DateTime, Text, Boolean
from sqlalchemy.sql import func
from backend.database import Base


class Notification(Base):
    __tablename__ = "notifications"

    id            = Column(Integer, primary_key=True, index=True)
    title         = Column(String, nullable=False)
    message       = Column(Text, nullable=True)
    notif_type    = Column(String, default="info")    # info | warning | critical
    resource_type = Column(String, nullable=True)     # incident | ticket | action
    resource_id   = Column(String, nullable=True)
    is_read       = Column(Boolean, default=False)
    created_at    = Column(DateTime(timezone=True), server_default=func.now())
