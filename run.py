#!/usr/bin/env python3
"""SentriX — AI-Driven SOC Platform — Entry Point"""
import uvicorn
import sys
import os
import subprocess
import re
import time
import threading
import json

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

TUNNEL_STATE_FILE = "/tmp/sentrix_tunnels.json"
BORE_BINARY = "/usr/local/bin/bore"


def _find_bore():
    for path in [BORE_BINARY, "/tmp/bore", "bore"]:
        if os.path.isfile(path) and os.access(path, os.X_OK):
            return path
    return None


FIXED_PORTS = {1514: 11514, 1515: 11515, 55000: 55000}


def _start_bore_tunnel(bore_bin, local_port):
    """Start a bore tunnel and return (process, public_port)."""
    cmd = [bore_bin, "local", str(local_port), "--to", "bore.pub"]
    if local_port in FIXED_PORTS:
        cmd += ["--port", str(FIXED_PORTS[local_port])]
    proc = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    # Read lines until we find the port
    for _ in range(30):
        line = proc.stdout.readline()
        if not line:
            break
        m = re.search(r"bore\.pub:(\d+)", line)
        if m:
            return proc, int(m.group(1))
    return proc, None


def _save_tunnel_state(port_1514, port_1515):
    state = {"port_1514": port_1514, "port_1515": port_1515, "host": "bore.pub"}
    with open(TUNNEL_STATE_FILE, "w") as f:
        json.dump(state, f)
    print(f"  Wazuh tunnel: bore.pub:{port_1514} (agent) / bore.pub:{port_1515} (enroll)")


def _drain(proc):
    """Keep reading stdout so the process doesn't block."""
    try:
        for _ in proc.stdout:
            pass
    except Exception:
        pass


def _start_and_watch(bore_bin, local_port, port_slot):
    """Start a bore tunnel and restart it automatically if it dies."""
    while True:
        proc, public_port = _start_bore_tunnel(bore_bin, local_port)
        if public_port:
            # Update the saved state with the new port
            try:
                state = {}
                if os.path.exists(TUNNEL_STATE_FILE):
                    with open(TUNNEL_STATE_FILE) as f:
                        state = json.load(f)
                state[port_slot] = public_port
                state["host"] = "bore.pub"
                with open(TUNNEL_STATE_FILE, "w") as f:
                    json.dump(state, f)
                print(f"  [Bore] Port {local_port} → bore.pub:{public_port}")
            except Exception:
                pass
            # Drain until process dies
            _drain(proc)
            proc.wait()
            print(f"  [Bore] Tunnel for port {local_port} died — restarting...")
        else:
            print(f"  [Bore] Failed to get port for {local_port} — retrying in 10s")
        time.sleep(10)


def _keepalive_loop():
    """Ping localhost every 4 minutes to prevent Codespaces inactivity shutdown."""
    import urllib.request
    while True:
        time.sleep(240)
        try:
            urllib.request.urlopen("http://localhost:8000/api/dashboard/stats", timeout=5)
        except Exception:
            pass


def start_bore_tunnels():
    bore_bin = _find_bore()
    if not bore_bin:
        print("  [Bore] Binary not found — skipping tunnel setup")
        return

    # Kill any existing bore processes
    subprocess.run(["pkill", "-f", "bore local"], capture_output=True)
    time.sleep(1)

    print("  Starting Wazuh tunnels via bore (with auto-restart watchdog)...")
    threading.Thread(target=_start_and_watch, args=(bore_bin, 1514, "port_1514"), daemon=True).start()
    threading.Thread(target=_start_and_watch, args=(bore_bin, 1515, "port_1515"), daemon=True).start()
    threading.Thread(target=_start_and_watch, args=(bore_bin, 55000, "port_55000"), daemon=True).start()
    # Give tunnels time to connect before server starts
    time.sleep(6)


if __name__ == "__main__":
    print("=" * 60)
    print("  SentriX — AI-Driven SOC Platform")
    print("  Applied Science Private University")
    print("=" * 60)
    print("  Starting server on http://localhost:8000")
    print("  API Docs: http://localhost:8000/docs")
    print("  Default Login: admin / admin123")
    print("=" * 60)

    start_bore_tunnels()

    threading.Thread(target=_keepalive_loop, daemon=True).start()
    print("  Keep-alive: pinging localhost every 4 min to prevent inactivity stop")

    uvicorn.run(
        "backend.main:app",
        host="0.0.0.0",
        port=8000,
        reload=True,
        log_level="info"
    )
