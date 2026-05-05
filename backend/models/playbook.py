from sqlalchemy import Column, Integer, String, DateTime, Text, Boolean, ForeignKey
from sqlalchemy.sql import func
from backend.database import Base


class Playbook(Base):
    __tablename__ = "playbooks"

    id          = Column(Integer, primary_key=True, index=True)
    name        = Column(String, nullable=False)
    description = Column(Text, nullable=True)
    category    = Column(String, nullable=True)   # brute_force | malware | ransomware | phishing | etc.
    is_active   = Column(Boolean, default=True)
    is_builtin  = Column(Boolean, default=False)
    created_at  = Column(DateTime(timezone=True), server_default=func.now())


class PlaybookStep(Base):
    __tablename__ = "playbook_steps"

    id              = Column(Integer, primary_key=True, index=True)
    playbook_id     = Column(Integer, ForeignKey("playbooks.id"), nullable=False)
    step_order      = Column(Integer, nullable=False, default=1)
    action_type     = Column(String, nullable=False)
    target_field    = Column(String, nullable=True)    # source_ip | hostname | custom
    target_override = Column(String, nullable=True)    # hard-coded target (overrides field lookup)
    description     = Column(String, nullable=True)


class PlaybookRun(Base):
    __tablename__ = "playbook_runs"

    id            = Column(Integer, primary_key=True, index=True)
    playbook_id   = Column(Integer, ForeignKey("playbooks.id"), nullable=True)
    incident_id   = Column(Integer, ForeignKey("incidents.id"), nullable=False)
    playbook_name = Column(String, nullable=True)
    status        = Column(String, default="completed")   # completed | partial | failed
    executed_by   = Column(String, nullable=True)
    executed_at   = Column(DateTime(timezone=True), server_default=func.now())
    results       = Column(Text, nullable=True)           # JSON summary
    actions_count = Column(Integer, default=0)
