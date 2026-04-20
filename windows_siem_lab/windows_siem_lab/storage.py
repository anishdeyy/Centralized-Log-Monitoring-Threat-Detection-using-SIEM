"""
storage.py — Persistence Layer  (FIXED v2)
============================================
JSON-Lines persistence for parsed logs and alerts.

FIXES IN THIS VERSION
---------------------
1. top_ips now counts from ALERTS (not just parsed_logs), reading the "ip" field.
   Previously it only counted events where event_id==4624 AND logon_type=="3",
   reading "source_ip" — that field doesn't exist post-normalisation, so
   the counter was always 0.

2. Backward-compatible: reads "ip" OR "source_ip" when scanning existing files
   so old alerts.json / parsed_logs.json from before the fix still work.

3. timeline_data returns per-severity counts for the stacked bar chart.
"""

import json
import os
import threading
from collections import Counter
from datetime    import datetime
from typing      import Any, Dict, List

PARSED_LOG_FILE = "parsed_logs.json"
ALERTS_FILE     = "alerts.json"

_log_lock   = threading.Lock()
_alert_lock = threading.Lock()


# ─── Internal helpers ─────────────────────────────────────────────────────────

def _write(filepath: str, record: Dict[str, Any], lock: threading.Lock) -> None:
    with lock:
        with open(filepath, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(record, default=str) + "\n")


def _read(filepath: str) -> List[Dict[str, Any]]:
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


def _get_ip(record: dict) -> str:
    """
    Read IP from a record, checking both "ip" (new) and "source_ip" (old)
    and "attacker_ip" (older alerts) for backward compatibility.
    """
    ip = (
        record.get("ip") or
        record.get("source_ip") or
        record.get("attacker_ip") or
        ""
    )
    # Discard placeholder values
    if ip in ("-", "no-ip", "unknown", "None", ""):
        return ""
    return str(ip).strip()


# ─── Public write API ─────────────────────────────────────────────────────────

def append_parsed_log(parsed: Dict[str, Any]) -> None:
    _write(PARSED_LOG_FILE, parsed, _log_lock)


def append_alert(alert: Dict[str, Any]) -> None:
    alert.setdefault("saved_at", datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    _write(ALERTS_FILE, alert, _alert_lock)


# ─── Public read API ──────────────────────────────────────────────────────────

def load_parsed_logs() -> List[Dict[str, Any]]:
    return _read(PARSED_LOG_FILE)


def load_alerts() -> List[Dict[str, Any]]:
    return _read(ALERTS_FILE)


def get_stats() -> Dict[str, Any]:
    """
    Compute dashboard summary statistics.

    top_ips — counted from ALERTS (not raw logs), using the "ip" field.
    This ensures only IPs that actually triggered detection rules appear
    in the "Top Attacking IPs" panel.
    """
    logs   = load_parsed_logs()
    alerts = load_alerts()

    sev_counts  = Counter()
    eid_counts  = Counter()
    user_counts = Counter()

    for log in logs:
        sev_counts[log.get("severity", "INFO")]  += 1
        eid_counts[log.get("event_id", 0)]       += 1
        user = log.get("user", "")
        if user and user not in ("SYSTEM", ""):
            user_counts[user] += 1

    # ── Count attacking IPs from ALERTS ─────────────────────────────────────
    # An IP is an "attacker IP" if it appears in a fired alert.
    ip_counts         = Counter()
    alert_rule_counts = Counter()
    alert_sev_counts  = Counter()
    timeline_detail   = {}

    for a in alerts:
        ip = _get_ip(a)
        if ip:
            ip_counts[ip] += 1
        alert_rule_counts[a.get("rule", "unknown")] += 1
        alert_sev_counts[a.get("severity", "INFO")]  += 1

        # Timeline bucket by minute
        bucket = (a.get("timestamp") or "")[:16]   # "YYYY-MM-DD HH:MM"
        if bucket:
            if bucket not in timeline_detail:
                timeline_detail[bucket] = {
                    "time": bucket.split(" ")[-1],
                    "CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0,
                }
            sev = a.get("severity", "INFO")
            timeline_detail[bucket][sev] = timeline_detail[bucket].get(sev, 0) + 1

    timeline = [
        v for k, v in sorted(timeline_detail.items())[-60:]
    ]

    return {
        "total_logs":      len(logs),
        "total_alerts":    len(alerts),
        "severity_counts": dict(sev_counts),
        "event_id_counts": {str(k): v for k, v in eid_counts.most_common(20)},
        "top_ips":         ip_counts.most_common(10),
        "top_users":       user_counts.most_common(10),
        "alerts_by_rule":  dict(alert_rule_counts),
        "alerts_by_sev":   dict(alert_sev_counts),
        "recent_alerts":   alerts[-50:],
        "timeline_data":   timeline,
    }


# ─── Utility ──────────────────────────────────────────────────────────────────

def clear_all() -> None:
    for f in (PARSED_LOG_FILE, ALERTS_FILE):
        if os.path.exists(f):
            os.remove(f)
            print(f"  [Storage] Deleted {f}")


def file_sizes() -> Dict[str, str]:
    result = {}
    for name, path in [("parsed_logs", PARSED_LOG_FILE), ("alerts", ALERTS_FILE)]:
        if os.path.exists(path):
            sz = os.path.getsize(path)
            if sz > 1_048_576:
                result[name] = f"{sz/1_048_576:.1f} MB"
            elif sz > 1024:
                result[name] = f"{sz/1024:.1f} KB"
            else:
                result[name] = f"{sz} B"
        else:
            result[name] = "not created yet"
    return result
