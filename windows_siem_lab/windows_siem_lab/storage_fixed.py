"""storage.py — Persistence Layer with Correlation
================================
Saves parsed logs and alerts to disk, with functions for:
  • Quick retrieval (last 100 logs, alerts)
  • Summary statistics (KPI cards)
  • Top attacking IPs (with frequency + rules)
  • Correlated incidents (grouped by IP)
"""

import json
import os
from collections import Counter, defaultdict
from datetime import datetime
from typing import Any, Dict, List, Tuple

PARSED_LOG_FILE = "parsed_logs.json"
ALERTS_FILE = "alerts.json"

# Thread-safe writes
import threading
_log_lock = threading.Lock()
_alert_lock = threading.Lock()


def _write(filepath: str, record: Dict[str, Any], lock: threading.Lock) -> None:
    """Append one JSON-Lines record to filepath (thread-safe)."""
    with lock:
        with open(filepath, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(record, default=str) + "\n")


def _read(filepath: str) -> List[Dict[str, Any]]:
    """Read all records from JSON-Lines file. Skip corrupted lines."""
    if not os.path.exists(filepath):
        return []
    records = []
    with open(filepath, "r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if line:
                try:
                    records.append(json.loads(line))
                except json.JSONDecodeError:
                    pass
    return records


# ─── Public write API ─────────────────────────────────────────────────────────

def append_parsed_log(parsed: Dict[str, Any]) -> None:
    """Persist a normalised log event."""
    _write(PARSED_LOG_FILE, parsed, _log_lock)


def append_alert(alert: Dict[str, Any]) -> None:
    """Persist an alert with saved_at timestamp."""
    alert.setdefault("saved_at", datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    _write(ALERTS_FILE, alert, _alert_lock)


# ─── Public read API ──────────────────────────────────────────────────────────

def load_parsed_logs() -> List[Dict[str, Any]]:
    """Return all stored parsed log events."""
    return _read(PARSED_LOG_FILE)


def load_alerts() -> List[Dict[str, Any]]:
    """Return all stored alerts."""
    return _read(ALERTS_FILE)


def get_recent_logs(limit: int = 60) -> List[Dict[str, Any]]:
    """Return last N parsed logs (newest first)."""
    logs = load_parsed_logs()
    return list(reversed(logs[-limit:]))


def get_recent_alerts(limit: int = 80) -> List[Dict[str, Any]]:
    """Return last N alerts (newest first)."""
    alerts = load_alerts()
    return list(reversed(alerts[-limit:]))


# ─── Correlation logic ────────────────────────────────────────────────────────

def get_top_attacker_ips(limit: int = 10) -> List[Dict[str, Any]]:
    """
    Return top attacking IPs sorted by frequency.
    Each entry includes: ip, alert_count, rule_counts, user_targets.
    
    CRITICAL FIX: Uses 'attacker_ip' field from alerts.
    """
    alerts = load_alerts()
    
    ip_data: Dict[str, Dict[str, Any]] = defaultdict(lambda: {
        "alert_count": 0,
        "rules": defaultdict(int),
        "users": set(),
    })
    
    for alert in alerts:
        ip = alert.get("attacker_ip", "") or alert.get("ip", "")
        if not ip or ip == "-":
            continue
        
        data = ip_data[ip]
        data["alert_count"] += 1
        
        rule = alert.get("rule", "unknown")
        data["rules"][rule] += 1
        
        user = alert.get("user", "")
        if user:
            data["users"].add(user)
    
    # Convert to list and sort by frequency
    result = []
    for ip, data in sorted(ip_data.items(), key=lambda x: x[1]["alert_count"], reverse=True)[:limit]:
        result.append({
            "ip": ip,
            "alert_count": data["alert_count"],
            "top_rules": [
                {"rule": r, "count": c}
                for r, c in sorted(data["rules"].items(), key=lambda x: x[1], reverse=True)[:3]
            ],
            "user_targets": list(data["users"])[:5],
            "user_count": len(data["users"]),
        })
    
    return result


def get_correlated_incidents(limit: int = 50) -> List[Dict[str, Any]]:
    """
    Group alerts by attacker IP into "incidents".
    Each incident shows: IP, start/end time, alert count, rules triggered, users targeted.
    
    CRITICAL FIX: Uses 'attacker_ip' field.
    """
    alerts = load_alerts()
    
    incidents: Dict[str, Dict[str, Any]] = defaultdict(lambda: {
        "ip": "",
        "first_alert": "",
        "last_alert": "",
        "alert_count": 0,
        "rules": set(),
        "users": set(),
        "severity_max": "INFO",
        "critical_count": 0,
    })
    
    severity_order = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
    
    for alert in alerts:
        ip = alert.get("attacker_ip", "") or alert.get("ip", "")
        if not ip or ip == "-":
            continue
        
        incident = incidents[ip]
        incident["ip"] = ip
        
        ts = alert.get("timestamp", "")
        if not incident["first_alert"] or ts < incident["first_alert"]:
            incident["first_alert"] = ts
        if ts > incident["last_alert"]:
            incident["last_alert"] = ts
        
        incident["alert_count"] += 1
        
        rule = alert.get("rule", "")
        if rule:
            incident["rules"].add(rule)
        
        user = alert.get("user", "")
        if user:
            incident["users"].add(user)
        
        sev = alert.get("severity", "INFO")
        if severity_order.get(sev, 0) > severity_order.get(incident["severity_max"], 0):
            incident["severity_max"] = sev
        
        if sev == "CRITICAL":
            incident["critical_count"] += 1
    
    # Convert to list and sort by alert count
    result = []
    for ip, incident in sorted(incidents.items(), key=lambda x: x[1]["alert_count"], reverse=True)[:limit]:
        result.append({
            "ip": ip,
            "first_alert": incident["first_alert"],
            "last_alert": incident["last_alert"],
            "alert_count": incident["alert_count"],
            "critical_count": incident["critical_count"],
            "severity_max": incident["severity_max"],
            "rules": list(incident["rules"]),
            "users": list(incident["users"])[:5],
            "duration_seconds": _calculate_duration(incident["first_alert"], incident["last_alert"]),
        })
    
    return result


def _calculate_duration(start_ts: str, end_ts: str) -> int:
    """Calculate seconds between two timestamps."""
    try:
        fmt = "%Y-%m-%d %H:%M:%S"
        start = datetime.strptime(start_ts, fmt)
        end = datetime.strptime(end_ts, fmt)
        return int((end - start).total_seconds())
    except:
        return 0


def get_stats() -> Dict[str, Any]:
    """
    Compute dashboard summary statistics.
    """
    logs = load_parsed_logs()
    alerts = load_alerts()
    
    # Severity counts
    severity_counts = defaultdict(int)
    for alert in alerts:
        sev = alert.get("severity", "INFO").upper()
        severity_counts[sev] += 1
    
    # Top attacking IPs
    top_ips = get_top_attacker_ips(limit=5)
    attacker_ips = [ip_data["ip"] for ip_data in top_ips]
    
    # Event type distribution
    event_type_counts = defaultdict(int)
    for log in logs:
        event_type = log.get("event_type", "unknown")
        event_type_counts[event_type] += 1
    
    return {
        "total_logs": len(logs),
        "total_alerts": len(alerts),
        "critical_alerts": severity_counts.get("CRITICAL", 0),
        "high_alerts": severity_counts.get("HIGH", 0),
        "medium_alerts": severity_counts.get("MEDIUM", 0),
        "severity_breakdown": dict(severity_counts),
        "attacker_ip_count": len(set(
            a.get("attacker_ip", "") or a.get("ip", "")
            for a in alerts
            if a.get("attacker_ip", "") or a.get("ip", "")
        )),
        "top_attacker_ips": attacker_ips,
        "event_type_breakdown": dict(event_type_counts),
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    }


def get_timeline_alerts(limit_minutes: int = 60) -> List[Dict[str, Any]]:
    """
    Return alerts grouped per minute for last N minutes.
    Used for timeline chart on dashboard.
    """
    alerts = load_alerts()
    
    # Group by minute
    minute_counts = defaultdict(lambda: {"critical": 0, "high": 0, "medium": 0, "low": 0})
    
    for alert in alerts:
        ts = alert.get("timestamp", "")
        if ts:
            # Round to minute
            minute_key = ts[:16]  # YYYY-MM-DD HH:MM
            sev = alert.get("severity", "INFO").lower()
            if sev in minute_counts[minute_key]:
                minute_counts[minute_key][sev] += 1
    
    # Convert to list, sorted
    result = []
    for minute, counts in sorted(minute_counts.items())[-limit_minutes:]:
        result.append({
            "minute": minute,
            **counts
        })
    
    return result


def clear_all() -> None:
    """Wipe both log files (use with caution)."""
    try:
        open(PARSED_LOG_FILE, "w").close()
        print(f"  Cleared {PARSED_LOG_FILE}")
    except:
        pass
    
    try:
        open(ALERTS_FILE, "w").close()
        print(f"  Cleared {ALERTS_FILE}")
    except:
        pass
