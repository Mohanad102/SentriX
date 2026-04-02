#!/usr/bin/env python3
"""
SentriX Device Monitor
Monitors the device and sends real alerts to the SentriX platform.
"""

import psutil
import requests
import socket
import os
import time
import json
import hashlib
from datetime import datetime

# ─── Configuration ────────────────────────────────────────────
API_URL   = "https://miniature-space-capybara-w65p479x5pgcwjw-8000.app.github.dev"
USERNAME  = "admin"
PASSWORD  = "admin123"
INTERVAL  = 30        # seconds between each scan
HOSTNAME  = socket.gethostname()

# Suspicious process names to watch for
SUSPICIOUS_PROCESSES = [
    "nmap", "masscan", "hydra", "sqlmap", "metasploit", "msfconsole",
    "nc", "netcat", "socat", "tcpdump", "wireshark", "aircrack",
    "hashcat", "john", "mimikatz", "cobalt", "empire"
]

# Suspicious remote ports and their known associations
SUSPICIOUS_PORTS = {
    4444:  "Metasploit default",
    1337:  "Common backdoor",
    31337: "Elite backdoor",
    12345: "NetBus RAT",
    5555:  "Android ADB / RAT",
    6667:  "IRC (C2 common)",
    9001:  "Tor relay",
    9050:  "Tor SOCKS proxy",
}

# Sensitive files to monitor for changes
WATCHED_FILES = [
    "/etc/passwd",
    "/etc/shadow",
    "/etc/hosts",
    "/etc/sudoers",
    "/root/.ssh/authorized_keys",
]

# ─── State ────────────────────────────────────────────────────
_state = {
    "token": None,
    "prev_connections": set(),
    "prev_processes": set(),
    "file_hashes": {},
    "prev_cpu_alert": 0,
    "sent_alerts": set(),   # deduplication cache
}


# ─── Authentication ───────────────────────────────────────────
def login():
    try:
        resp = requests.post(
            f"{API_URL}/api/auth/login",
            data={"username": USERNAME, "password": PASSWORD},
            timeout=5
        )
        if resp.ok:
            _state["token"] = resp.json()["access_token"]
            print(f"[+] Logged in as {USERNAME}")
            return True
    except Exception as e:
        print(f"[!] Failed to connect to SentriX: {e}")
    return False


def get_headers():
    return {"Authorization": f"Bearer {_state['token']}"}


# ─── Send Alert ───────────────────────────────────────────────
def send_alert(title, description, severity, category,
               source_ip=None, dest_ip=None, rule_id=None, rule_level=None, raw_data=None):

    # Deduplicate: skip if same alert was already sent this session
    key = hashlib.md5(f"{title}{source_ip}{dest_ip}".encode()).hexdigest()
    if key in _state["sent_alerts"]:
        return
    _state["sent_alerts"].add(key)
    if len(_state["sent_alerts"]) > 500:
        _state["sent_alerts"].clear()

    payload = {
        "title": title,
        "description": description,
        "severity": severity,
        "category": category,
        "hostname": HOSTNAME,
        "source_ip": source_ip,
        "dest_ip": dest_ip,
        "rule_id": rule_id,
        "rule_level": rule_level,
        "raw_data": raw_data,
    }

    try:
        resp = requests.post(
            f"{API_URL}/api/alerts",
            headers=get_headers(),
            json=payload,
            timeout=5
        )
        if resp.status_code == 401:
            login()
        elif resp.ok:
            ts = datetime.now().strftime("%H:%M:%S")
            print(f"[{ts}] Alert sent: [{severity.upper()}] {title}")
    except Exception as e:
        print(f"[!] Failed to send alert: {e}")


# ─── 1. Suspicious Process Detection ─────────────────────────
def check_suspicious_processes():
    current = set()
    for proc in psutil.process_iter(["pid", "name", "username", "cmdline", "create_time"]):
        try:
            name = proc.info["name"].lower()
            cmdline = " ".join(proc.info.get("cmdline") or []).lower()
            for sus in SUSPICIOUS_PROCESSES:
                if sus in name or sus in cmdline:
                    key = f"{sus}_{proc.pid}"
                    current.add(key)
                    if key not in _state["prev_processes"]:
                        send_alert(
                            title=f"Suspicious Process Detected: {proc.info['name']}",
                            description=(
                                f"A suspicious process was detected on the system.\n"
                                f"PID: {proc.pid} | User: {proc.info['username']}\n"
                                f"Command: {cmdline[:200]}"
                            ),
                            severity="high",
                            category="execution",
                            rule_id="MON-001",
                            rule_level=10,
                            raw_data=json.dumps({"pid": proc.pid, "name": proc.info["name"], "cmd": cmdline[:500]}),
                        )
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass
    _state["prev_processes"] = current


# ─── 2. Network Connection Monitoring ────────────────────────
def check_network_connections():
    current = set()
    try:
        conns = psutil.net_connections(kind="inet")
    except psutil.AccessDenied:
        return

    for conn in conns:
        if conn.status != "ESTABLISHED":
            continue
        if not conn.raddr:
            continue

        rip, rport = conn.raddr.ip, conn.raddr.port
        lip   = conn.laddr.ip   if conn.laddr else None
        lport = conn.laddr.port if conn.laddr else None

        key = f"{lip}:{lport}->{rip}:{rport}"
        current.add(key)

        if key in _state["prev_connections"]:
            continue

        if rport in SUSPICIOUS_PORTS:
            send_alert(
                title=f"Connection to Suspicious Port: {rport}",
                description=(
                    f"Active connection to a known suspicious port.\n"
                    f"From: {lip}:{lport} -> To: {rip}:{rport}\n"
                    f"Reason: {SUSPICIOUS_PORTS[rport]}"
                ),
                severity="critical",
                category="c2",
                source_ip=lip,
                dest_ip=rip,
                rule_id="MON-002",
                rule_level=14,
                raw_data=json.dumps({"local": f"{lip}:{lport}", "remote": f"{rip}:{rport}"}),
            )
        elif not rip.startswith(("127.", "10.", "192.168.", "172.")):
            send_alert(
                title=f"New Outbound Connection -> {rip}:{rport}",
                description=(
                    f"New connection established to an external IP address.\n"
                    f"From: {lip}:{lport} -> To: {rip}:{rport}"
                ),
                severity="low",
                category="network",
                source_ip=lip,
                dest_ip=rip,
                rule_id="MON-003",
                rule_level=4,
                raw_data=json.dumps({"local": f"{lip}:{lport}", "remote": f"{rip}:{rport}"}),
            )

    _state["prev_connections"] = current


# ─── 3. CPU / RAM Usage ───────────────────────────────────────
def check_resource_usage():
    cpu = psutil.cpu_percent(interval=1)
    ram = psutil.virtual_memory().percent
    now = time.time()

    if cpu > 90 and (now - _state["prev_cpu_alert"]) > 300:
        _state["prev_cpu_alert"] = now

        top_procs = sorted(
            psutil.process_iter(["name", "cpu_percent"]),
            key=lambda p: p.info.get("cpu_percent") or 0,
            reverse=True
        )[:5]
        top_names = [p.info["name"] for p in top_procs if p.info.get("name")]

        send_alert(
            title=f"High CPU Usage Detected: {cpu:.0f}%",
            description=(
                f"CPU usage reached {cpu:.1f}% and RAM {ram:.1f}%.\n"
                f"Top processes: {', '.join(top_names)}\n"
                f"Possible cryptominer or denial-of-service activity."
            ),
            severity="high" if cpu > 95 else "medium",
            category="execution",
            rule_id="MON-004",
            rule_level=8,
            raw_data=json.dumps({"cpu": cpu, "ram": ram, "top_processes": top_names}),
        )


# ─── 4. Sensitive File Integrity Monitoring ───────────────────
def init_file_hashes():
    for path in WATCHED_FILES:
        if os.path.exists(path):
            try:
                with open(path, "rb") as f:
                    _state["file_hashes"][path] = hashlib.md5(f.read()).hexdigest()
            except PermissionError:
                _state["file_hashes"][path] = None


def check_file_changes():
    for path in WATCHED_FILES:
        if not os.path.exists(path):
            continue
        try:
            with open(path, "rb") as f:
                current_hash = hashlib.md5(f.read()).hexdigest()
        except PermissionError:
            continue

        prev_hash = _state["file_hashes"].get(path)
        if prev_hash is None:
            _state["file_hashes"][path] = current_hash
            continue

        if current_hash != prev_hash:
            _state["file_hashes"][path] = current_hash
            send_alert(
                title=f"Sensitive File Modified: {path}",
                description=(
                    f"A sensitive system file was modified.\n"
                    f"File: {path}\n"
                    f"Previous hash: {prev_hash}\n"
                    f"Current hash:  {current_hash}"
                ),
                severity="critical",
                category="persistence",
                rule_id="MON-005",
                rule_level=13,
                raw_data=json.dumps({"file": path, "old_hash": prev_hash, "new_hash": current_hash}),
            )


# ─── 5. Logged-in User Monitoring ────────────────────────────
_prev_users = set()

def check_logged_in_users():
    global _prev_users
    try:
        current_users = set()
        for u in psutil.users():
            current_users.add(f"{u.name}@{u.terminal or 'console'}")

        new_users = current_users - _prev_users
        for u in new_users:
            send_alert(
                title=f"New User Session Detected: {u}",
                description=f"A new user session was opened on the system: {u}",
                severity="medium",
                category="authentication",
                rule_id="MON-006",
                rule_level=6,
                raw_data=json.dumps({"user_session": u}),
            )
        _prev_users = current_users
    except Exception:
        pass


# ─── Main Loop ────────────────────────────────────────────────
def main():
    print("=" * 55)
    print("  SentriX Device Monitor")
    print(f"  Host    : {HOSTNAME}")
    print(f"  Interval: {INTERVAL}s")
    print("=" * 55)

    if not login():
        print("[!] Make sure SentriX is running on localhost:8000")
        return

    init_file_hashes()
    print(f"[+] Watching {len(WATCHED_FILES)} sensitive files")
    print(f"[+] Watching {len(SUSPICIOUS_PROCESSES)} suspicious process names")
    print(f"[+] Watching {len(SUSPICIOUS_PORTS)} suspicious ports")
    print("[+] Monitoring started... (Ctrl+C to stop)\n")

    while True:
        try:
            check_suspicious_processes()
            check_network_connections()
            check_resource_usage()
            check_file_changes()
            check_logged_in_users()
            time.sleep(INTERVAL)
        except KeyboardInterrupt:
            print("\n[!] Monitor stopped.")
            break
        except Exception as e:
            print(f"[!] Error: {e}")
            time.sleep(5)


if __name__ == "__main__":
    main()
