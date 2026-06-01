from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
import asyncio
import os

from backend.database import init_db
from backend.routers import auth, alerts, incidents, ioc, dashboard, ai_analyst, reports, users, audit, rules, virustotal, tickets, investigation, ir, agents, thehive, cortex, integrations, blocked_ips

app = FastAPI(
    title="SentriX API",
    description="AI-Driven SOC Platform",
    version="1.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


class IPBlockMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        # X-Forwarded-For is set by proxies (Codespace, nginx, etc.)
        forwarded_for = request.headers.get("x-forwarded-for")
        client_ip = forwarded_for.split(",")[0].strip() if forwarded_for else (request.client.host if request.client else None)

        if client_ip:
            try:
                from backend.database import SessionLocal
                from backend.models.blocked_ip import BlockedIP
                db = SessionLocal()
                try:
                    blocked = db.query(BlockedIP).filter(BlockedIP.ip == client_ip).first()
                finally:
                    db.close()
                if blocked:
                    return JSONResponse(status_code=403, content={"detail": "Access denied."})
            except Exception:
                pass

        return await call_next(request)


app.add_middleware(IPBlockMiddleware)

# API Routers
app.include_router(auth.router)
app.include_router(alerts.router)
app.include_router(incidents.router)
app.include_router(ioc.router)
app.include_router(dashboard.router)
app.include_router(ai_analyst.router)
app.include_router(reports.router)
app.include_router(users.router)
app.include_router(audit.router)
app.include_router(rules.router)
app.include_router(virustotal.router)
app.include_router(tickets.router)
app.include_router(investigation.router)
app.include_router(ir.router)
app.include_router(agents.router)
app.include_router(thehive.router)
app.include_router(cortex.router)
app.include_router(integrations.router)
app.include_router(blocked_ips.router)

# Serve frontend static files
frontend_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), "frontend")
static_path = os.path.join(frontend_path, "static")

if os.path.exists(static_path):
    app.mount("/static", StaticFiles(directory=static_path), name="static")


@app.get("/", include_in_schema=False)
def root():
    index_file = os.path.join(frontend_path, "index.html")
    return FileResponse(index_file)


@app.get("/{page}.html", include_in_schema=False)
def serve_page(page: str):
    file_path = os.path.join(frontend_path, f"{page}.html")
    if os.path.exists(file_path):
        return FileResponse(file_path)
    from fastapi import HTTPException
    raise HTTPException(status_code=404, detail="Page not found")


@app.on_event("startup")
async def startup_event():
    init_db()
    _seed_data()
    _seed_ir_data()
    # Start Wazuh poller in background if enabled
    from backend.config import settings
    if settings.WAZUH_ENABLED:
        from backend.services.wazuh_poller import run_wazuh_poller
        asyncio.create_task(run_wazuh_poller())
        print("[Wazuh] Poller scheduled")


def _seed_ir_data():
    from backend.database import SessionLocal
    from backend.routers.ir import seed_builtin_playbooks
    db = SessionLocal()
    try:
        seed_builtin_playbooks(db)
    except Exception as e:
        print(f"IR seed error: {e}")
    finally:
        db.close()


def _seed_data():
    """Create default admin and analyst users on first run."""
    from backend.database import SessionLocal
    from backend.models.user import User
    from backend.utils.auth import get_password_hash

    db = SessionLocal()
    try:
        if not db.query(User).filter(User.username == "admin").first():
            db.add(User(
                username="admin",
                email="admin@sentrix.local",
                full_name="System Administrator",
                hashed_password=get_password_hash("admin123"),
                role="admin"
            ))

        if not db.query(User).filter(User.username == "analyst").first():
            db.add(User(
                username="analyst",
                email="analyst@sentrix.local",
                full_name="SOC Analyst",
                hashed_password=get_password_hash("analyst123"),
                role="soc_analyst_l2"
            ))

        db.commit()
    except Exception as e:
        db.rollback()
        print(f"Seed error: {e}")
    finally:
        db.close()
