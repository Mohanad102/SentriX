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


def _start_bore_tunnel(bore_bin, local_port):
    """Start a bore tunnel and return (process, public_port)."""
    proc = subprocess.Popen(
        [bore_bin, "local", str(local_port), "--to", "bore.pub"],
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


def start_bore_tunnels():
    bore_bin = _find_bore()
    if not bore_bin:
        print("  [Bore] Binary not found — skipping tunnel setup")
        return

    # Kill any existing bore processes
    subprocess.run(["pkill", "-f", "bore local"], capture_output=True)
    time.sleep(1)

    print("  Starting Wazuh tunnels via bore...")
    proc1, port_1514 = _start_bore_tunnel(bore_bin, 1514)
    proc2, port_1515 = _start_bore_tunnel(bore_bin, 1515)

    if port_1514 and port_1515:
        _save_tunnel_state(port_1514, port_1515)
        # Drain stdout in background so processes don't block
        threading.Thread(target=_drain, args=(proc1,), daemon=True).start()
        threading.Thread(target=_drain, args=(proc2,), daemon=True).start()
    else:
        print("  [Bore] Failed to get tunnel ports")


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

    uvicorn.run(
        "backend.main:app",
        host="0.0.0.0",
        port=8000,
        reload=True,
        log_level="info"
    )
