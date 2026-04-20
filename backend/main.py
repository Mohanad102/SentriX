from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, Response
import os

from backend.database import init_db
from backend.routers import auth, alerts, incidents, ioc, dashboard, ai_analyst, reports, users, audit, rules, virustotal

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

# Serve frontend static files
frontend_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), "frontend")
static_path = os.path.join(frontend_path, "static")

if os.path.exists(static_path):
    app.mount("/static", StaticFiles(directory=static_path), name="static")


NO_CACHE_HEADERS = {
    "Cache-Control": "no-cache, no-store, must-revalidate",
    "Pragma": "no-cache",
    "Expires": "0",
}


@app.get("/", include_in_schema=False)
def root():
    index_file = os.path.join(frontend_path, "index.html")
    return FileResponse(index_file, headers=NO_CACHE_HEADERS)


SIDEBAR_INJECT = '<script src="/static/js/sidebar.js?v=2"></script>'

@app.get("/{page}.html", include_in_schema=False)
def serve_page(page: str):
    from fastapi import HTTPException
    from fastapi.responses import HTMLResponse
    file_path = os.path.join(frontend_path, f"{page}.html")
    if not os.path.exists(file_path):
        raise HTTPException(status_code=404, detail="Page not found")
    with open(file_path, encoding="utf-8") as f:
        html = f.read()
    if SIDEBAR_INJECT not in html:
        html = html.replace("</body>", f"  {SIDEBAR_INJECT}\n</body>")
    return HTMLResponse(content=html, headers=NO_CACHE_HEADERS)


@app.on_event("startup")
async def startup_event():
    init_db()
    _seed_users()
    import asyncio
    asyncio.create_task(_periodic_vt_enrichment())
    # asyncio.create_task(_start_wazuh_poller())


# async def _start_wazuh_poller():
#     from backend.services.wazuh_poller import run_wazuh_poller
#     await run_wazuh_poller()


async def _periodic_vt_enrichment():
    """
    Background worker that runs every 2 minutes.
    Processes every alert that hasn't been VT-enriched yet — extracts ALL IOCs
    (IPs, domains, URLs, hashes) from every text field and scans each one.
    Also re-scans any IOC records that are still marked unenriched.
    """
    import asyncio
    from backend.database import SessionLocal
    from backend.services.virustotal_service import enrich_pending_iocs, auto_enrich_alert
    from backend.models.alert import Alert

    await asyncio.sleep(5)  # brief delay so startup seeding finishes first

    while True:
        db = SessionLocal()
        try:
            # Process all alerts not yet enriched, in batches of 50
            unenriched = (
                db.query(Alert)
                .filter((Alert.vt_enriched == False) | (Alert.vt_enriched == None))  # noqa: E712
                .order_by(Alert.created_at.desc())
                .limit(50)
                .all()
            )
            for alert in unenriched:
                await auto_enrich_alert(db, alert)

            # Also sweep any individual IOC records still pending
            await enrich_pending_iocs(db)
        except Exception:
            pass
        finally:
            db.close()

        await asyncio.sleep(120)  # 2 minutes


def _seed_users():
    """Create default user accounts on first run. No fake alerts or demo data."""
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
                role="analyst"
            ))
        db.commit()
    except Exception as e:
        db.rollback()
        print(f"Seed users error: {e}")
    finally:
        db.close()
