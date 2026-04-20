from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from backend.config import settings

engine = create_engine(
    settings.DATABASE_URL,
    connect_args={"check_same_thread": False}
)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def init_db():
    from backend.models import user, alert, incident, ioc, audit_log, alert_rule  # noqa: F401
    Base.metadata.create_all(bind=engine)
    _run_migrations()


def _run_migrations():
    """Apply lightweight schema migrations for SQLite (ADD COLUMN only)."""
    migrations = [
        "ALTER TABLE alerts ADD COLUMN vt_enriched BOOLEAN DEFAULT 0",
        "ALTER TABLE iocs ADD COLUMN enriched_at DATETIME",
        "ALTER TABLE alerts ADD COLUMN vt_malicious BOOLEAN",
    ]
    with engine.connect() as conn:
        for sql in migrations:
            try:
                conn.execute(_text(sql))
                conn.commit()
            except Exception:
                pass  # column already exists


def _text(sql: str):
    from sqlalchemy import text
    return text(sql)
