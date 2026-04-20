"""
alert_system.py — Alert Delivery  (FIXED v2)
==============================================
Handles all alert output:
  1. Terminal   — ANSI colour-coded banners
  2. File       — appended to alerts.json (JSON-Lines)
  3. SSE        — pushed to dashboard browsers in real-time

FIX: Alerts use  "ip"  as the key, not "attacker_ip".
     dashboard.py /api/attacker_ips and /api/incidents read "ip".
"""

import json
import threading
from datetime import datetime
from queue    import Queue
from typing   import Any, Dict, List

from storage import append_alert

# ─── ANSI colours ─────────────────────────────────────────────────────────────
_RESET = "\033[0m"
_BOLD  = "\033[1m"
_COLORS = {
    "CRITICAL": "\033[1;31m",
    "HIGH":     "\033[31m",
    "MEDIUM":   "\033[33m",
    "LOW":      "\033[36m",
    "INFO":     "\033[37m",
}
_ICONS = {
    "CRITICAL": "🚨",
    "HIGH":     "⚠️ ",
    "MEDIUM":   "🔶",
    "LOW":      "🔷",
    "INFO":     "ℹ️ ",
}

# ─── SSE client registry ──────────────────────────────────────────────────────
_sse_clients: List[Queue] = []
_sse_lock = threading.Lock()


def register_sse_client(q: Queue) -> None:
    with _sse_lock:
        _sse_clients.append(q)


def unregister_sse_client(q: Queue) -> None:
    with _sse_lock:
        if q in _sse_clients:
            _sse_clients.remove(q)


def _broadcast_sse(alert: Dict[str, Any]) -> None:
    payload = f"data: {json.dumps(alert, default=str)}\n\n"
    with _sse_lock:
        dead = []
        for q in _sse_clients:
            try:
                q.put_nowait(payload)
            except Exception:
                dead.append(q)
        for q in dead:
            _sse_clients.remove(q)


# ─── ANSI setup ───────────────────────────────────────────────────────────────
def _enable_ansi() -> None:
    try:
        import ctypes
        ctypes.windll.kernel32.SetConsoleMode(
            ctypes.windll.kernel32.GetStdHandle(-11), 7
        )
    except Exception:
        pass

_enable_ansi()


# ─── Terminal rendering ───────────────────────────────────────────────────────

def _print_alert(alert: Dict[str, Any]) -> None:
    sev   = alert.get("severity", "INFO")
    color = _COLORS.get(sev, _COLORS["INFO"])
    icon  = _ICONS.get(sev, "·")
    ts    = alert.get("timestamp", datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    rule  = alert.get("rule", "—")
    desc  = alert.get("description", "—")
    eid   = alert.get("event_id", "—")
    mitre = alert.get("mitre", "")
    ip    = alert.get("ip", "")

    sep = "═" * 66
    print(f"\n{color}{sep}{_RESET}")
    print(f"{color}{_BOLD}  {icon}  [{sev}]  {rule.upper().replace('_', ' ')}{_RESET}")
    print(f"{color}{sep}{_RESET}")
    print(f"{color}  🕒 Time      : {ts}{_RESET}")
    print(f"{color}  🆔 Event ID  : {eid}{_RESET}")
    if ip:
        print(f"{color}  🌐 Attacker IP: {ip}{_RESET}")
    if mitre:
        print(f"{color}  🎯 MITRE     : {mitre}{_RESET}")
    print(f"{color}  📝 Detail    : {desc}{_RESET}")

    skip = {"rule", "severity", "description", "timestamp", "saved_at",
            "event_id", "mitre", "ip", "user"}
    for k, v in alert.items():
        if k not in skip and v:
            label = k.replace("_", " ").title()
            print(f"{color}  📌 {label:<13}: {v}{_RESET}")
    print(f"{color}{sep}{_RESET}\n")


# ─── Public API ───────────────────────────────────────────────────────────────

def fire_alert(alert: Dict[str, Any]) -> None:
    """Print to terminal, save to alerts.json, broadcast via SSE."""
    _print_alert(alert)
    append_alert(alert)
    _broadcast_sse(alert)
