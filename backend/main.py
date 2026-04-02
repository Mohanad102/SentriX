from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
import os

from backend.database import init_db
from backend.routers import auth, alerts, incidents, ioc, dashboard, ai_analyst, reports

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
def startup_event():
    init_db()
    _seed_data()


def _seed_data():
    """Create default admin user and demo data on first run."""
    from backend.database import SessionLocal
    from backend.models.user import User
    from backend.utils.auth import get_password_hash
    from backend.models.alert import Alert
    from backend.models.incident import Incident
    from backend.models.ioc import IOC
    import uuid
    from datetime import datetime, timedelta
    import random

    db = SessionLocal()
    try:
        # Create admin user
        if not db.query(User).filter(User.username == "admin").first():
            admin = User(
                username="admin",
                email="admin@sentrix.local",
                full_name="System Administrator",
                hashed_password=get_password_hash("admin123"),
                role="admin"
            )
            db.add(admin)

        # Create analyst user
        if not db.query(User).filter(User.username == "analyst").first():
            analyst = User(
                username="analyst",
                email="analyst@sentrix.local",
                full_name="SOC Analyst",
                hashed_password=get_password_hash("analyst123"),
                role="analyst"
            )
            db.add(analyst)

        db.flush()

        # Only seed demo data if no alerts exist
        if db.query(Alert).count() == 0:
            demo_alerts = [
                {"title": "Brute Force Attack Detected", "severity": "high", "category": "authentication",
                 "source_ip": "185.220.101.45", "hostname": "WIN-DC01", "rule_id": "5712", "rule_level": 10,
                 "description": "Multiple failed SSH/RDP login attempts from external IP 185.220.101.45"},
                {"title": "Malware Detected - Trojan.GenericKD", "severity": "critical", "category": "malware",
                 "source_ip": "10.0.0.25", "hostname": "WORKSTATION-04", "rule_id": "1002", "rule_level": 14,
                 "description": "Antivirus detected Trojan.GenericKD malware on endpoint. File quarantined."},
                {"title": "Suspicious PowerShell Execution", "severity": "high", "category": "execution",
                 "source_ip": "10.0.0.12", "hostname": "WORKSTATION-02", "rule_id": "91201", "rule_level": 11,
                 "description": "PowerShell executed with encoded command: -EncodedCommand SQBFAFgA..."},
                {"title": "Port Scan Detected from External IP", "severity": "medium", "category": "network",
                 "source_ip": "203.0.113.50", "hostname": "FIREWALL-01", "rule_id": "1001", "rule_level": 8,
                 "description": "Network scan detected targeting ports 22, 80, 443, 3389, 8080"},
                {"title": "Unauthorized Access Attempt - Admin Share", "severity": "high", "category": "lateral_movement",
                 "source_ip": "10.0.0.55", "hostname": "SERVER-02", "rule_id": "18107", "rule_level": 10,
                 "description": "Attempt to access ADMIN$ share from unauthorized workstation"},
                {"title": "Data Exfiltration Attempt Detected", "severity": "critical", "category": "exfiltration",
                 "source_ip": "10.0.0.25", "dest_ip": "198.51.100.77", "hostname": "WORKSTATION-04",
                 "rule_id": "87001", "rule_level": 13,
                 "description": "Large data transfer detected to external IP. Possible data exfiltration."},
                {"title": "Ransomware Activity Indicators", "severity": "critical", "category": "ransomware",
                 "source_ip": "10.0.0.33", "hostname": "FILE-SERVER-01", "rule_id": "87900", "rule_level": 15,
                 "description": "Mass file encryption detected. Multiple files renamed with .locked extension."},
                {"title": "DNS Tunneling Detected", "severity": "medium", "category": "c2",
                 "source_ip": "10.0.0.15", "hostname": "WORKSTATION-05", "rule_id": "64001", "rule_level": 9,
                 "description": "Unusual DNS query volume and entropy suggesting DNS tunneling C2 communication"},
                {"title": "Failed Login - Multiple Accounts", "severity": "medium", "category": "authentication",
                 "source_ip": "192.168.1.100", "hostname": "WIN-DC01", "rule_id": "18152", "rule_level": 7,
                 "description": "10+ failed login attempts across different user accounts from same source"},
                {"title": "Suspicious Registry Modification", "severity": "high", "category": "persistence",
                 "source_ip": "10.0.0.22", "hostname": "WORKSTATION-03", "rule_id": "17101", "rule_level": 11,
                 "description": "Registry Run key modified: HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"},
                {"title": "CVE-2024-1234 Exploitation Attempt", "severity": "critical", "category": "exploit",
                 "source_ip": "91.108.56.145", "dest_ip": "10.0.0.80", "hostname": "WEB-SERVER-01",
                 "rule_id": "99001", "rule_level": 14,
                 "description": "Remote code execution attempt targeting web server via known CVE"},
                {"title": "Privilege Escalation Detected", "severity": "high", "category": "privilege_escalation",
                 "source_ip": "10.0.0.12", "hostname": "WORKSTATION-02", "rule_id": "5501", "rule_level": 12,
                 "description": "User account gained SYSTEM privileges via UAC bypass technique"},
            ]

            base_time = datetime.utcnow() - timedelta(days=6)
            statuses = ["open", "open", "open", "in_progress", "closed"]
            for i, a in enumerate(demo_alerts):
                alert = Alert(
                    alert_id=f"ALT-{uuid.uuid4().hex[:8].upper()}",
                    title=a["title"],
                    description=a["description"],
                    severity=a["severity"],
                    source="wazuh",
                    source_ip=a.get("source_ip"),
                    dest_ip=a.get("dest_ip"),
                    hostname=a.get("hostname"),
                    rule_id=a.get("rule_id"),
                    rule_level=a.get("rule_level"),
                    category=a.get("category"),
                    status=random.choice(statuses),
                    created_at=base_time + timedelta(hours=i * 12 + random.randint(0, 8))
                )
                db.add(alert)

        # Seed incidents
        if db.query(Incident).count() == 0:
            demo_incidents = [
                {
                    "title": "Ransomware Outbreak - File Server Compromise",
                    "severity": "critical",
                    "status": "in_progress",
                    "priority": "critical",
                    "category": "ransomware",
                    "assigned_to": "analyst",
                    "description": "Multiple endpoints reporting ransomware activity. FILE-SERVER-01 has been isolated. Mass file encryption detected with .locked extension.",
                    "tags": "ransomware,critical,file-server",
                    "ai_summary": "Critical ransomware incident affecting FILE-SERVER-01. Evidence of lateral movement from WORKSTATION-04. Immediate containment required.",
                    "ai_recommendations": "1. Isolate FILE-SERVER-01 immediately\n2. Disconnect from network\n3. Notify management\n4. Begin forensic investigation"
                },
                {
                    "title": "APT Campaign - Credential Harvesting",
                    "severity": "high",
                    "status": "open",
                    "priority": "high",
                    "category": "apt",
                    "assigned_to": "admin",
                    "description": "Advanced persistent threat indicators detected. Multiple workstations showing signs of credential dumping and lateral movement.",
                    "tags": "apt,credential-theft,lateral-movement"
                },
                {
                    "title": "Web Server SQL Injection Attack",
                    "severity": "high",
                    "status": "resolved",
                    "priority": "high",
                    "category": "web_attack",
                    "assigned_to": "analyst",
                    "description": "SQL injection attempts detected against WEB-SERVER-01. Database queries show evidence of data extraction attempts.",
                    "tags": "sql-injection,web-attack",
                    "ai_summary": "SQL injection attack targeting web application database. Attacker attempted to extract user credentials table.",
                    "ai_recommendations": "1. Patch web application\n2. Review WAF rules\n3. Check database access logs\n4. Reset compromised credentials"
                },
                {
                    "title": "Phishing Campaign - Executive Targeting",
                    "severity": "medium",
                    "status": "open",
                    "priority": "medium",
                    "category": "phishing",
                    "assigned_to": "analyst",
                    "description": "Spear phishing emails targeting C-level executives detected. Emails contain malicious attachment mimicking invoice.",
                    "tags": "phishing,spearphishing,social-engineering"
                },
            ]

            admin_user = db.query(User).filter(User.username == "admin").first()
            base_time = datetime.utcnow() - timedelta(days=5)
            for i, inc_data in enumerate(demo_incidents):
                incident = Incident(
                    case_number=f"INC-{uuid.uuid4().hex[:6].upper()}",
                    title=inc_data["title"],
                    description=inc_data["description"],
                    severity=inc_data["severity"],
                    status=inc_data["status"],
                    priority=inc_data["priority"],
                    category=inc_data["category"],
                    assigned_to=inc_data["assigned_to"],
                    tags=inc_data.get("tags"),
                    ai_summary=inc_data.get("ai_summary"),
                    ai_recommendations=inc_data.get("ai_recommendations"),
                    created_by=admin_user.id if admin_user else None,
                    created_at=base_time + timedelta(hours=i * 24)
                )
                db.add(incident)

            db.flush()

            # Add demo IOCs for first incident
            first_incident = db.query(Incident).first()
            if first_incident:
                iocs = [
                    IOC(value="198.51.100.77", ioc_type="ip", incident_id=first_incident.id,
                        is_malicious=True, vt_score="52/72", enriched=True),
                    IOC(value="malware-c2.darkweb.onion", ioc_type="domain", incident_id=first_incident.id,
                        is_malicious=True, vt_score="61/72", enriched=True),
                    IOC(value="44d88612fea8a8f36de82e1278abb02f", ioc_type="hash", incident_id=first_incident.id,
                        is_malicious=True, vt_score="68/72", enriched=True),
                    IOC(value="10.0.0.25", ioc_type="ip", incident_id=first_incident.id,
                        is_malicious=False, vt_score="0/72", enriched=True),
                ]
                for ioc_item in iocs:
                    db.add(ioc_item)

        db.commit()
    except Exception as e:
        db.rollback()
        print(f"Seed data error: {e}")
    finally:
        db.close()
