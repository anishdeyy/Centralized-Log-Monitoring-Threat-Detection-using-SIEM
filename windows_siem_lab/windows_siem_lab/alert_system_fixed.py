"""alert_system.py — Alert Delivery with Rate Limiting
=========================================
Handles all alert output:
  1. Terminal — ANSI colour-coded banners
  2. File — appended to alerts.json (JSON-Lines)
  3. SSE — broadcast to connected dashboards in real-time
  
Key improvements:
  • Rate limiting to prevent alert spam
  • Deduplication using IP + event_id
  • Smooth dashboard updates
"""

import json
import threading
import time
from collections import defaultdict
from datetime import datetime, timedelta
from queue import Queue
from typing import Any, Dict, List, Optional

from storage import append_alert

# ─── Configuration ────────────────────────────────────────────────────────────
# After this duration, the same alert can fire again from same IP
ALERT_DEDUP_WINDOW = 60  # seconds

# Max alerts to fire per 10-second window (prevents spam)
RATE_LIMIT_THRESHOLD = 10
RATE_LIMIT_WINDOW = 10


# ─── ANSI colours ────────────────────────────────────────────────────────────
_RESET = "\033[0m"
_BOLD = "\033[1m"

_COLORS: Dict[str, str] = {
    "CRITICAL": "\033[1;31m",  # bold red
    "HIGH": "\033[31m",  # red
    "MEDIUM": "\033[33m",  # yellow
    "LOW": "\033[36m",  # cyan
    "INFO": "\033[37m",  # light grey
}

_ICONS: Dict[str, str] = {
    "CRITICAL": "🚨",
    "HIGH": "⚠️ ",
    "MEDIUM": "🔶",
    "LOW": "🔷",
    "INFO": "ℹ️ ",
}

# ─── SSE broadcast infrastructure ─────────────────────────────────────────────
_sse_clients: List[Queue] = []
_sse_lock = threading.Lock()

# ─── Deduplication and rate limiting ──────────────────────────────────────────
_alert_history: Dict[str, float] = {}  # key=(rule, ip) → last_fire_time
_history_lock = threading.Lock()

_rate_limit_window: List[float] = []  # timestamps of recent alerts
_rate_limit_lock = threading.Lock()


def register_sse_client(q: Queue) -> None:
    """Called by Flask SSE endpoint when browser connects."""
    with _sse_lock:
        _sse_clients.append(q)


def unregister_sse_client(q: Queue) -> None:
    """Called by Flask SSE endpoint when browser disconnects."""
    with _sse_lock:
        if q in _sse_clients:
            _sse_clients.remove(q)


def _broadcast_sse(alert: Dict[str, Any]) -> None:
    """Push alert to all connected SSE clients (non-blocking)."""
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


def _check_rate_limit() -> bool:
    """Check if we've exceeded alert rate limit (returns True if OK to send)."""
    with _rate_limit_lock:
        now = time.time()
        # Remove old entries outside the window
        _rate_limit_window[:] = [
            t for t in _rate_limit_window
            if now - t < RATE_LIMIT_WINDOW
        ]
        
        if len(_rate_limit_window) >= RATE_LIMIT_THRESHOLD:
            return False  # Rate limited
        
        _rate_limit_window.append(now)
        return True


def _check_deduplication(rule: str, ip: str) -> bool:
    """
    Check if this alert was already fired recently from same IP.
    Returns True if OK to fire (not a duplicate).
    """
    key = f"{rule}:{ip or 'unknown'}"
    
    with _history_lock:
        now = time.time()
        last_fire = _alert_history.get(key, 0)
        
        if now - last_fire > ALERT_DEDUP_WINDOW:
            _alert_history[key] = now
            return True  # OK to fire
        
        return False  # Duplicate — skip


def _enable_ansi() -> None:
    """Enable ANSI escape codes in Windows console."""
    try:
        import ctypes
        kernel32 = ctypes.windll.kernel32
        kernel32.SetConsoleMode(kernel32.GetStdHandle(-11), 7)
    except Exception:
        pass


_enable_ansi()


def _print_alert(alert: Dict[str, Any]) -> None:
    """Render colour-coded alert banner to stdout."""
    sev = alert.get("severity", "INFO").upper()
    rule = alert.get("rule", "unknown")
    desc = alert.get("description", "")
    attacker_ip = alert.get("attacker_ip", "")
    user = alert.get("user", "")
    
    color = _COLORS.get(sev, _RESET)
    icon = _ICONS.get(sev, "ℹ️ ")
    
    banner = (
        f"\n{color}{_BOLD}"
        f"  {icon} [{sev}] {rule.upper()}\n"
        f"{_RESET}{color}"
        f"     → {desc[:100]}\n"
    )
    
    if attacker_ip and attacker_ip != "-":
        banner += f"     → Attacker: {attacker_ip}\n"
    
    if user and user != "SYSTEM":
        banner += f"     → User: {user}\n"
    
    banner += f"{_RESET}\n"
    
    print(banner)


def fire_alert(alert: Dict[str, Any]) -> None:
    """
    Fire an alert through all channels (terminal, file, SSE).
    
    Applies deduplication and rate limiting to prevent spam.
    """
    # Extract dedup key
    rule = alert.get("rule", "unknown")
    attacker_ip = alert.get("attacker_ip", "")
    
    # Check deduplication
    if not _check_deduplication(rule, attacker_ip):
        return  # Already fired recently
    
    # Check rate limiting
    if not _check_rate_limit():
        return  # Rate limited — skip this alert
    
    # Add timestamp if missing
    alert.setdefault("timestamp", datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    
    # Print to terminal
    try:
        _print_alert(alert)
    except Exception as e:
        print(f"  Error printing alert: {e}")
    
    # Write to disk
    try:
        append_alert(alert)
    except Exception as e:
        print(f"  Error appending alert: {e}")
    
    # Broadcast to dashboards
    try:
        _broadcast_sse(alert)
    except Exception as e:
        print(f"  Error broadcasting SSE: {e}")
