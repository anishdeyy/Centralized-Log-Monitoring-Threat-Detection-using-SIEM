"""parser_module.py — Log Normaliser with IP Extraction Fix
===================================
Converts raw event dicts from windows_agent into a clean, unified schema.
"""

from datetime import datetime
from typing import Any, Dict, Optional

# ─── Event type labels ────────────────────────────────────────────────────────
EVENT_TYPE_LABELS: Dict[str, str] = {
    "successful_login": "Successful Logon",
    "failed_login": "Failed Logon",
    "logoff": "User Logoff",
    "explicit_cred_logon": "Logon with Explicit Credentials",
    "privilege_assigned": "Special Privileges Assigned",
    "suspicious_process": "Suspicious Process Launched",
    "process_created": "New Process Created",
    "service_installed": "New Service Installed",
    "account_lockout": "Account Locked Out",
    "powershell_script": "PowerShell Script Block",
    "audit_log_cleared": "Audit Log Cleared",
    "account_created": "User Account Created",
    "account_deleted": "User Account Deleted",
    "generic": "Generic System Event",
}

# ─── Logon type codes → labels ────────────────────────────────────────────────
LOGON_TYPE_LABELS: Dict[str, str] = {
    "2": "Interactive",
    "3": "Network",
    "4": "Batch",
    "5": "Service",
    "7": "Unlock",
    "8": "NetworkCleartext",
    "9": "NewCredentials",
    "10": "RemoteInteractive (RDP)",
    "11": "CachedInteractive",
}

# ─── Logon type → risk rating ────────────────────────────────────────────────
LOGON_TYPE_RISK: Dict[str, str] = {
    "2": "LOW",
    "3": "MEDIUM",
    "4": "LOW",
    "5": "LOW",
    "7": "MEDIUM",
    "8": "HIGH",
    "9": "HIGH",
    "10": "MEDIUM",
    "11": "LOW",
}

# ─── Severity ordering ────────────────────────────────────────────────────────
SEVERITY_ORDER = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}


def severity_int(sev: str) -> int:
    """Return 0–4 numeric severity (useful for sorting/filtering)."""
    return SEVERITY_ORDER.get(str(sev).upper(), 0)


def _clean_ts(ts: str) -> str:
    """Ensure timestamp is formatted as 'YYYY-MM-DD HH:MM:SS'."""
    if isinstance(ts, str) and len(ts) >= 19:
        try:
            # Try to parse various formats
            if 'T' in ts:
                dt = datetime.fromisoformat(ts.replace('Z', '+00:00').split('.')[0])
            else:
                dt = datetime.strptime(ts[:19], "%Y-%m-%d %H:%M:%S")
            return dt.strftime("%Y-%m-%d %H:%M:%S")
        except (ValueError, TypeError):
            pass
    
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def normalise(raw: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """
    Normalise raw event dict from windows_agent into unified SIEM record.
    Returns None if input is not a valid dict.
    
    CRITICAL FIX: Maps 'source_ip' from windows_agent to 'ip' in output.
    """
    if not isinstance(raw, dict):
        return None
    
    # ── Core field extraction ──────────────────────────────────────────
    ts = _clean_ts(raw.get("timestamp", ""))
    event_id = int(raw.get("event_id", 0))
    channel = str(raw.get("channel", "Unknown"))
    source = str(raw.get("source", "Unknown"))
    computer = str(raw.get("computer", "Unknown"))
    event_type = str(raw.get("event_type", "generic"))
    severity = str(raw.get("severity", "INFO")).upper()
    user = str(raw.get("user", "SYSTEM"))
    
    # ── CRITICAL FIX: Map 'source_ip' from agent to 'ip' in output ────
    # windows_agent produces 'source_ip', but downstream expects 'ip'
    source_ip = raw.get("source_ip", "") or raw.get("ip", "")
    ip = str(source_ip).strip() if source_ip else ""
    
    process = str(raw.get("process_name", "")).lower()
    cmdline = str(raw.get("cmdline", "")).lower()
    logon_type = str(raw.get("logon_type", "")).strip()
    privileges = str(raw.get("privileges", ""))
    message = str(raw.get("message", ""))[:500]
    inserts = raw.get("raw_inserts", [])
    
    # ── Enrichment ─────────────────────────────────────────────────────
    logon_label = LOGON_TYPE_LABELS.get(logon_type, logon_type)
    logon_risk = LOGON_TYPE_RISK.get(logon_type, "INFO")
    type_label = EVENT_TYPE_LABELS.get(
        event_type, event_type.replace("_", " ").title()
    )
    
    return {
        "timestamp": ts,
        "event_id": event_id,
        "channel": channel,
        "source": source,
        "computer": computer,
        "event_type": event_type,
        "event_type_label": type_label,
        "severity": severity,
        "severity_int": severity_int(severity),
        "user": user,
        "ip": ip,  # ← STANDARDIZED FIELD NAME
        "source_ip": ip,  # ← COMPATIBILITY ALIAS
        "process_name": process,
        "cmdline": cmdline,
        "logon_type": logon_type,
        "logon_type_label": logon_label,
        "logon_risk": logon_risk,
        "privileges": privileges,
        "message": message,
        "raw_inserts": inserts[:10],
    }
