#!/usr/bin/env python3
"""
SentriX Device Monitor
Monitors the device and sends real alerts to the SentriX platform.
"""

import psutil
import requests
import socket
import os
import re
import time
import json
import hashlib
import subprocess
from datetime import datetime

# ─── Configuration ────────────────────────────────────────────
API_URL   = "http://localhost:8000"
USERNAME  = "admin"
PASSWORD  = "admin123"
INTERVAL  = 30
HOSTNAME  = socket.gethostname()

SUSPICIOUS_PROCESSES = [
    "nmap", "masscan", "hydra", "sqlmap", "metasploit", "msfconsole",
    "nc", "netcat", "socat", "tcpdump", "wireshark", "aircrack",
    "hashcat", "john", "mimikatz", "cobalt", "empire"
]

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

WATCHED_FILES = [
    "/etc/passwd",
    "/etc/shadow",
    "/etc/hosts",
    "/etc/sudoers",
    "/root/.ssh/authorized_keys",
]

AUTH_LOG_PATHS = [
    "/var/log/auth.log",
    "/var/log/secure",
    "/var/log/syslog",
]

# ─── State ────────────────────────────────────────────────────
_state = {
    "token": None,
    "prev_connections": set(),
    "prev_processes": set(),
    "file_hashes": {},
    "prev_cpu_alert": 0,
    "sent_alerts": set(),
    "auth_log_pos": {},       # file path -> last read position
    "crontab_hash": None,
    "prev_open_ports": set(),
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
    for proc in psutil.process_iter(["pid", "name", "username", "cmdline", "exe", "ppid"]):
        try:
            name    = proc.info["name"].lower()
            cmdline = " ".join(proc.info.get("cmdline") or []).lower()
            exe     = proc.info.get("exe") or ""
            ppid    = proc.info.get("ppid")

            # Resolve parent process name
            parent_name = ""
            try:
                if ppid:
                    parent_name = psutil.Process(ppid).name()
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass

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
                                f"Parent: {parent_name} (PPID: {ppid})\n"
                                f"Path: {exe}\n"
                                f"Command: {cmdline[:300]}"
                            ),
                            severity="high",
                            category="execution",
                            rule_id="MON-001",
                            rule_level=10,
                            raw_data=json.dumps({
                                "pid": proc.pid,
                                "name": proc.info["name"],
                                "exe": exe,
                                "ppid": ppid,
                                "parent": parent_name,
                                "cmd": cmdline[:500]
                            }),
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
            psutil.process_iter(["name", "cpu_percent", "pid", "username"]),
            key=lambda p: p.info.get("cpu_percent") or 0,
            reverse=True
        )[:5]
        top_info = [
            {"name": p.info["name"], "pid": p.info["pid"],
             "cpu": p.info.get("cpu_percent"), "user": p.info.get("username")}
            for p in top_procs if p.info.get("name")
        ]
        top_names = [x["name"] for x in top_info]

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
            raw_data=json.dumps({"cpu": cpu, "ram": ram, "top_processes": top_info}),
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


# ─── 6. SSH / Auth Log Monitoring ────────────────────────────
def init_auth_log():
    for path in AUTH_LOG_PATHS:
        if os.path.exists(path):
            try:
                _state["auth_log_pos"][path] = os.path.getsize(path)
            except Exception:
                pass


def check_auth_logs():
    failed_pattern    = re.compile(r"Failed password for (?:invalid user )?(\S+) from (\S+) port (\d+)")
    accepted_pattern  = re.compile(r"Accepted (?:password|publickey) for (\S+) from (\S+) port (\d+)")
    invalid_pattern   = re.compile(r"Invalid user (\S+) from (\S+)")
    sudo_pattern      = re.compile(r"sudo:\s+(\S+) : .*COMMAND=(.*)")

    for path, start_pos in list(_state["auth_log_pos"].items()):
        if not os.path.exists(path):
            continue
        try:
            with open(path, "r", errors="ignore") as f:
                f.seek(start_pos)
                new_lines = f.read()
                _state["auth_log_pos"][path] = f.tell()

            if not new_lines:
                continue

            # Count failed logins per IP
            failed_ips = {}
            for match in failed_pattern.finditer(new_lines):
                user, ip, port = match.groups()
                failed_ips[ip] = failed_ips.get(ip, 0) + 1

            for ip, count in failed_ips.items():
                severity = "critical" if count >= 10 else "high" if count >= 5 else "medium"
                send_alert(
                    title=f"SSH Failed Login Attempts: {count} from {ip}",
                    description=(
                        f"{count} failed SSH login attempt(s) detected.\n"
                        f"Source IP: {ip}\n"
                        f"Log file: {path}"
                    ),
                    severity=severity,
                    category="authentication",
                    source_ip=ip,
                    rule_id="MON-007",
                    rule_level=8 if count < 5 else 12,
                    raw_data=json.dumps({"ip": ip, "count": count, "log": path}),
                )

            # Successful logins
            for match in accepted_pattern.finditer(new_lines):
                user, ip, port = match.groups()
                send_alert(
                    title=f"Successful SSH Login: {user} from {ip}",
                    description=(
                        f"SSH login accepted.\n"
                        f"User: {user} | Source IP: {ip}:{port}\n"
                        f"Log file: {path}"
                    ),
                    severity="low",
                    category="authentication",
                    source_ip=ip,
                    rule_id="MON-008",
                    rule_level=3,
                    raw_data=json.dumps({"user": user, "ip": ip, "port": port}),
                )

            # Invalid users
            for match in invalid_pattern.finditer(new_lines):
                user, ip = match.groups()
                send_alert(
                    title=f"Invalid SSH User Attempt: {user} from {ip}",
                    description=(
                        f"SSH login attempt with non-existent username.\n"
                        f"Username: {user} | Source IP: {ip}"
                    ),
                    severity="medium",
                    category="authentication",
                    source_ip=ip,
                    rule_id="MON-009",
                    rule_level=6,
                    raw_data=json.dumps({"user": user, "ip": ip}),
                )

            # Sudo usage
            for match in sudo_pattern.finditer(new_lines):
                user, command = match.groups()
                send_alert(
                    title=f"Sudo Command Executed by: {user}",
                    description=(
                        f"A user executed a command with sudo privileges.\n"
                        f"User: {user}\n"
                        f"Command: {command.strip()}"
                    ),
                    severity="medium",
                    category="privilege_escalation",
                    rule_id="MON-010",
                    rule_level=7,
                    raw_data=json.dumps({"user": user, "command": command.strip()}),
                )

        except Exception as e:
            print(f"[!] Error reading {path}: {e}")


# ─── 7. Crontab Change Detection ─────────────────────────────
def get_crontab_snapshot():
    content = ""
    # System crontabs
    for cron_dir in ["/etc/cron.d", "/etc/cron.daily", "/etc/cron.hourly",
                     "/etc/cron.weekly", "/etc/cron.monthly"]:
        if os.path.isdir(cron_dir):
            for f in os.listdir(cron_dir):
                fpath = os.path.join(cron_dir, f)
                try:
                    with open(fpath, "r", errors="ignore") as fh:
                        content += fh.read()
                except Exception:
                    pass
    # /etc/crontab
    if os.path.exists("/etc/crontab"):
        try:
            with open("/etc/crontab", "r", errors="ignore") as f:
                content += f.read()
        except Exception:
            pass
    # User crontabs
    try:
        result = subprocess.run(["crontab", "-l"], capture_output=True, text=True, timeout=3)
        content += result.stdout
    except Exception:
        pass
    return hashlib.md5(content.encode()).hexdigest()


def init_crontab():
    _state["crontab_hash"] = get_crontab_snapshot()


def check_crontab_changes():
    current_hash = get_crontab_snapshot()
    if _state["crontab_hash"] and current_hash != _state["crontab_hash"]:
        _state["crontab_hash"] = current_hash
        send_alert(
            title="Crontab Modification Detected",
            description=(
                "A scheduled task (crontab) was added, modified, or removed.\n"
                "This may indicate persistence mechanism installation.\n"
                "Check: /etc/crontab, /etc/cron.d/, and user crontabs."
            ),
            severity="high",
            category="persistence",
            rule_id="MON-011",
            rule_level=11,
            raw_data=json.dumps({"prev_hash": _state["crontab_hash"], "new_hash": current_hash}),
        )
    _state["crontab_hash"] = current_hash


# ─── 8. Open Port Scan Detection (new listening ports) ────────
def check_open_ports():
    current_ports = set()
    try:
        for conn in psutil.net_connections(kind="inet"):
            if conn.status == "LISTEN" and conn.laddr:
                current_ports.add(conn.laddr.port)
    except psutil.AccessDenied:
        return

    if not _state["prev_open_ports"]:
        _state["prev_open_ports"] = current_ports
        return

    new_ports = current_ports - _state["prev_open_ports"]
    for port in new_ports:
        severity = "critical" if port in SUSPICIOUS_PORTS else "medium"
        reason = SUSPICIOUS_PORTS.get(port, "Newly opened listening port")
        send_alert(
            title=f"New Listening Port Detected: {port}",
            description=(
                f"A new port has started listening on this system.\n"
                f"Port: {port}\n"
                f"Note: {reason}\n"
                f"This may indicate a backdoor or new service."
            ),
            severity=severity,
            category="network",
            rule_id="MON-012",
            rule_level=9 if severity == "critical" else 6,
            raw_data=json.dumps({"port": port, "note": reason}),
        )

    _state["prev_open_ports"] = current_ports


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
    init_auth_log()
    init_crontab()

    print(f"[+] Watching {len(WATCHED_FILES)} sensitive files")
    print(f"[+] Watching {len(SUSPICIOUS_PROCESSES)} suspicious process names")
    print(f"[+] Watching {len(SUSPICIOUS_PORTS)} suspicious ports")
    print(f"[+] Watching auth logs: {[p for p in AUTH_LOG_PATHS if os.path.exists(p)]}")
    print(f"[+] Crontab monitoring enabled")
    print(f"[+] Open port monitoring enabled")
    print("[+] Monitoring started... (Ctrl+C to stop)\n")

    while True:
        try:
            check_suspicious_processes()
            check_network_connections()
            check_resource_usage()
            check_file_changes()
            check_logged_in_users()
            check_auth_logs()
            check_crontab_changes()
            check_open_ports()
            time.sleep(INTERVAL)
        except KeyboardInterrupt:
            print("\n[!] Monitor stopped.")
            break
        except Exception as e:
            print(f"[!] Error: {e}")
            time.sleep(5)


if __name__ == "__main__":
    main()
