from sqlalchemy import Column, Integer, String, DateTime, Text, ForeignKey
from sqlalchemy.sql import func
from backend.database import Base


ACTION_LABELS = {
    "block_ip":           "Block IP Address",
    "disable_user":       "Disable User Account",
    "isolate_endpoint":   "Isolate Endpoint",
    "reset_password":     "Force Password Reset",
    "kill_process":       "Kill Process",
    "remove_file":        "Remove Malicious File",
    "reset_credentials":  "Reset Credentials",
}

VALID_ACTIONS = set(ACTION_LABELS.keys())


class ResponseAction(Base):
    __tablename__ = "response_actions"

    id          = Column(Integer, primary_key=True, index=True)
    incident_id = Column(Integer, ForeignKey("incidents.id"), nullable=True)
    action_type = Column(String, nullable=False)   # block_ip | disable_user | isolate_endpoint | reset_password
    target      = Column(String, nullable=False)   # IP, username, hostname
    status      = Column(String, default="executed")  # executed | failed | pending
    notes       = Column(Text, nullable=True)
    executed_by = Column(String, nullable=True)
    executed_at = Column(DateTime(timezone=True), server_default=func.now())
