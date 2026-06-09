# SentriX — AI-Driven SOC Platform

SentriX is a Security Operations Center (SOC) platform built for real-time alert monitoring, incident response, threat intelligence, and AI-assisted analysis.

---

## Requirements

- Python 3.10 or higher
- pip
- Git

---

## Installation & Setup

### 1. Clone the repository

```bash
git clone https://github.com/Mohanad102/SentriX.git
cd SentriX
```

### 2. Create a virtual environment

**Windows (PowerShell):**
```powershell
python -m venv venv
.\venv\Scripts\Activate
```

**Linux / macOS:**
```bash
python3 -m venv venv
source venv/bin/activate
```

### 3. Install dependencies

```bash
pip install -r backend/requirements.txt
```

### 4. Configure environment variables

```bash
# Windows
copy .env.example .env

# Linux / macOS
cp .env.example .env
```

Then open `.env` and set at minimum:

```env
SECRET_KEY=any-long-random-string-here
WAZUH_PASSWORD=wazuh
```

> The rest of the integrations (Wazuh, TheHive, VirusTotal, etc.) are disabled by default and can be enabled later.

---

## Running the Application

### Start the server

```bash
python run.py
```

The server will start on `http://localhost:8000`

### Default login credentials

| Field | Value |
|-------|-------|
| Username | `admin` |
| Password | `admin123` |

### Useful URLs

| Page | URL |
|------|-----|
| Dashboard | http://localhost:8000 |
| API Docs (Swagger) | http://localhost:8000/docs |

---

## Running the Device Monitor

The monitor agent runs on any machine you want to watch. It detects suspicious processes, network connections, file changes, brute-force attempts, and more — and sends real alerts to the SentriX dashboard.

**Install monitor dependencies:**
```bash
pip install psutil requests
```

**Start the monitor** (in a separate terminal while the server is running):
```bash
python monitor.py
```

> Make sure SentriX is running on `localhost:8000` before starting the monitor.

---

## Stopping the Application

Press `Ctrl+C` in the terminal running `run.py`.

**Or forcefully on Linux:**
```bash
pkill -f "run.py|uvicorn"
```

**Or on Windows (PowerShell):**
```powershell
Stop-Process -Name python
```

---

## Project Structure

```
SentriX/
├── backend/
│   ├── main.py              # FastAPI app entry point
│   ├── config.py            # Environment settings
│   ├── database.py          # SQLite database setup
│   ├── models/              # Database models
│   ├── routers/             # API route handlers
│   ├── services/            # Integration services (Wazuh, TheHive, etc.)
│   └── utils/               # Auth helpers
├── frontend/
│   ├── dashboard.html       # Main SOC dashboard
│   ├── alerts.html          # Alert management
│   ├── incidents.html       # Incident response
│   ├── tickets.html         # Ticket queue
│   ├── rules.html           # Detection rules
│   ├── users.html           # User management
│   ├── integrations.html    # Integration settings
│   ├── ai_analyst.html      # AI-assisted analysis
│   ├── virustotal.html      # Malware / IOC lookup
│   ├── agents.html          # Agent management
│   └── static/              # CSS, JS, images
├── monitor.py               # Device monitoring agent
├── run.py                   # Application launcher
├── .env.example             # Environment variable template
└── docker-compose.yml       # Docker setup (optional)
```

---

## Optional: Run with Docker

```bash
docker-compose up -d
```

---

## User Roles

| Role | Access |
|------|--------|
| `admin` | Full access to all features |
| `manager` | Dashboard, alerts, incidents, reports |
| `soc_analyst_l1` | Alerts, tickets, basic dashboard |
| `soc_analyst_l2` | L2 queue, investigations, AI analyst |
| `incident_responder` | IR dashboard, playbooks, SOAR actions |
