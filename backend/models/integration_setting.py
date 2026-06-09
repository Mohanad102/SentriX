from sqlalchemy import Column, Integer, String, Text, UniqueConstraint
from backend.database import Base


class IntegrationSetting(Base):
    __tablename__ = "integration_settings"
    id = Column(Integer, primary_key=True, index=True)
    service = Column(String(50), nullable=False)
    key = Column(String(100), nullable=False)
    value = Column(Text, nullable=True)

    __table_args__ = (UniqueConstraint("service", "key", name="uq_int_svc_key"),)
