#!/usr/bin/env python3
"""
SentriX Device Monitor
يراقب الجهاز ويرسل alerts حقيقية للتطبيق تلقائياً
"""

import psutil
import requests
import socket
import os
import time
import json
import hashlib
from datetime import datetime

# ─── الإعدادات ───────────────────────────────────────────────
API_URL      = "http://localhost:8000"
USERNAME     = "admin"
PASSWORD     = "admin123"
INTERVAL     = 30        # ثانية بين كل فحص
HOSTNAME     = socket.gethostname()

# العمليات المشبوهة للمراقبة
SUSPICIOUS_PROCESSES = [
    "nmap", "masscan", "hydra", "sqlmap", "metasploit", "msfconsole",
    "nc", "netcat", "socat", "tcpdump", "wireshark", "aircrack",
    "hashcat", "john", "mimikatz", "cobalt", "empire"
]

# المنافذ المشبوهة (خارج الاستخدام العادي)
SUSPICIOUS_PORTS = {
    4444: "Metasploit default",
    1337: "Common backdoor",
    31337: "Elite backdoor",
    12345: "NetBus RAT",
    5555: "Android ADB / RAT",
    6667: "IRC (C2 common)",
    9001: "Tor relay",
    9050: "Tor SOCKS proxy",
}

# الملفات الحساسة للمراقبة
WATCHED_FILES = [
    "/etc/passwd",
    "/etc/shadow",
    "/etc/hosts",
    "/etc/sudoers",
    "/root/.ssh/authorized_keys",
]

# ─── الحالة السابقة (للمقارنة) ───────────────────────────────
_state = {
    "token": None,
    "prev_connections": set(),
    "prev_processes": set(),
    "file_hashes": {},
    "prev_cpu_alert": 0,
    "sent_alerts": set(),   # لتجنب التكرار
}


# ─── المصادقة ─────────────────────────────────────────────────
def login():
    try:
        resp = requests.post(
            f"{API_URL}/api/auth/login",
            data={"username": USERNAME, "password": PASSWORD},
            timeout=5
        )
        if resp.ok:
            _state["token"] = resp.json()["access_token"]
            print(f"[✓] تم تسجيل الدخول كـ {USERNAME}")
            return True
    except Exception as e:
        print(f"[!] فشل الاتصال بالتطبيق: {e}")
    return False


def get_headers():
    return {"Authorization": f"Bearer {_state['token']}"}


# ─── إرسال Alert ─────────────────────────────────────────────
def send_alert(title, description, severity, category,
               source_ip=None, dest_ip=None, rule_id=None, rule_level=None, raw_data=None):

    # تجنب إرسال نفس الـ alert مرتين في نفس الدقيقة
    key = hashlib.md5(f"{title}{source_ip}{dest_ip}".encode()).hexdigest()
    if key in _state["sent_alerts"]:
        return
    _state["sent_alerts"].add(key)
    # نظف القائمة كل 500 عنصر
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
            print(f"[{ts}] 🔔 Alert أُرسل: [{severity.upper()}] {title}")
    except Exception as e:
        print(f"[!] خطأ في إرسال alert: {e}")


# ─── 1. مراقبة العمليات المشبوهة ─────────────────────────────
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
                            title=f"عملية مشبوهة: {proc.info['name']}",
                            description=(
                                f"تم اكتشاف عملية مشبوهة على الجهاز.\n"
                                f"PID: {proc.pid} | المستخدم: {proc.info['username']}\n"
                                f"الأمر: {cmdline[:200]}"
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


# ─── 2. مراقبة الاتصالات الشبكية ─────────────────────────────
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
        lip = conn.laddr.ip if conn.laddr else None
        lport = conn.laddr.port if conn.laddr else None

        key = f"{lip}:{lport}->{rip}:{rport}"
        current.add(key)

        if key in _state["prev_connections"]:
            continue

        # منفذ مشبوه؟
        if rport in SUSPICIOUS_PORTS:
            send_alert(
                title=f"اتصال بمنفذ مشبوه: {rport}",
                description=(
                    f"اتصال نشط بمنفذ مشبوه.\n"
                    f"من: {lip}:{lport} → إلى: {rip}:{rport}\n"
                    f"السبب: {SUSPICIOUS_PORTS[rport]}"
                ),
                severity="critical",
                category="c2",
                source_ip=lip,
                dest_ip=rip,
                rule_id="MON-002",
                rule_level=14,
                raw_data=json.dumps({"local": f"{lip}:{lport}", "remote": f"{rip}:{rport}"}),
            )

        # اتصال خارجي جديد (غير local)
        elif not rip.startswith(("127.", "10.", "192.168.", "172.")):
            send_alert(
                title=f"اتصال خارجي جديد → {rip}:{rport}",
                description=(
                    f"اتصال جديد بعنوان IP خارجي.\n"
                    f"من: {lip}:{lport} → إلى: {rip}:{rport}"
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


# ─── 3. مراقبة استخدام CPU/RAM ───────────────────────────────
def check_resource_usage():
    cpu = psutil.cpu_percent(interval=1)
    ram = psutil.virtual_memory().percent
    now = time.time()

    if cpu > 90 and (now - _state["prev_cpu_alert"]) > 300:
        _state["prev_cpu_alert"] = now

        # أعلى 5 عمليات استهلاكاً
        top_procs = sorted(
            psutil.process_iter(["name", "cpu_percent"]),
            key=lambda p: p.info.get("cpu_percent") or 0,
            reverse=True
        )[:5]
        top_names = [p.info["name"] for p in top_procs if p.info.get("name")]

        send_alert(
            title=f"استخدام CPU مرتفع جداً: {cpu:.0f}%",
            description=(
                f"استخدام CPU وصل {cpu:.1f}% وRAM {ram:.1f}%.\n"
                f"أعلى العمليات: {', '.join(top_names)}\n"
                f"قد يكون دليلاً على Cryptominer أو هجوم."
            ),
            severity="high" if cpu > 95 else "medium",
            category="execution",
            rule_id="MON-004",
            rule_level=8,
            raw_data=json.dumps({"cpu": cpu, "ram": ram, "top_processes": top_names}),
        )


# ─── 4. مراقبة الملفات الحساسة ───────────────────────────────
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
                title=f"تغيير في ملف حساس: {path}",
                description=(
                    f"تم اكتشاف تعديل على ملف حساس في النظام.\n"
                    f"الملف: {path}\n"
                    f"الـ Hash السابق: {prev_hash}\n"
                    f"الـ Hash الجديد: {current_hash}"
                ),
                severity="critical",
                category="persistence",
                rule_id="MON-005",
                rule_level=13,
                raw_data=json.dumps({"file": path, "old_hash": prev_hash, "new_hash": current_hash}),
            )


# ─── 5. مراقبة المستخدمين المسجلين دخولاً ───────────────────
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
                title=f"مستخدم جديد سجّل دخوله: {u}",
                description=f"تم اكتشاف جلسة مستخدم جديدة على الجهاز: {u}",
                severity="medium",
                category="authentication",
                rule_id="MON-006",
                rule_level=6,
                raw_data=json.dumps({"user_session": u}),
            )
        _prev_users = current_users
    except Exception:
        pass


# ─── الحلقة الرئيسية ─────────────────────────────────────────
def main():
    print("=" * 55)
    print("  SentriX Device Monitor")
    print(f"  الجهاز: {HOSTNAME}")
    print(f"  الفحص كل: {INTERVAL} ثانية")
    print("=" * 55)

    if not login():
        print("[!] تأكد أن التطبيق يعمل على localhost:8000")
        return

    init_file_hashes()
    print(f"[✓] مراقبة {len(WATCHED_FILES)} ملف حساس")
    print(f"[✓] مراقبة {len(SUSPICIOUS_PROCESSES)} نوع عملية مشبوهة")
    print(f"[✓] مراقبة {len(SUSPICIOUS_PORTS)} منفذ مشبوه")
    print("[✓] بدأت المراقبة... (Ctrl+C للإيقاف)\n")

    while True:
        try:
            check_suspicious_processes()
            check_network_connections()
            check_resource_usage()
            check_file_changes()
            check_logged_in_users()
            time.sleep(INTERVAL)
        except KeyboardInterrupt:
            print("\n[!] تم إيقاف المراقبة.")
            break
        except Exception as e:
            print(f"[!] خطأ: {e}")
            time.sleep(5)


if __name__ == "__main__":
    main()
