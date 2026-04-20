"""
parser_module.py — Log Normaliser  (FIXED v2)
===============================================
Normalises raw event dicts from windows_agent into the SIEM's unified schema.

FIXES IN THIS VERSION
---------------------
1. IP field: reads  raw.get("ip") or raw.get("source_ip")  — handles both the
   old "source_ip" key (in existing alerts.json / parsed_logs.json) and the
   corrected "ip" key produced by the fixed windows_agent.

2. All output records use  "ip"  as the canonical key.  detector.py, storage.py,
   and dashboard.py all read "ip" consistently.

Output schema (every field always present)
------------------------------------------
{
  "timestamp":         "2024-06-01 14:30:22",
  "event_id":          4625,
  "channel":           "Security",
  "source":            "Microsoft-Windows-Security-Auditing",
  "computer":          "DESKTOP-LAB",
  "event_type":        "failed_login",
  "event_type_label":  "Failed Logon",
  "severity":          "MEDIUM",
  "severity_int":      2,
  "user":              "labuser",
  "ip":                "192.168.56.102",   ← always "ip", never "source_ip"
  "process_name":      "",
  "cmdline":           "",
  "logon_type":        "3",
  "logon_type_label":  "Network",
  "logon_risk":        "MEDIUM",
  "privileges":        "",
  "message":           "An account failed to log on …",
  "raw_inserts":       […],
}
"""

from datetime import datetime
from typing   import Any, Dict, Optional

# ─── Human-readable event type labels ────────────────────────────────────────
EVENT_TYPE_LABELS: Dict[str, str] = {
    "successful_login":    "Successful Logon",
    "failed_login":        "Failed Logon",
    "logoff":              "User Logoff",
    "explicit_cred_logon": "Logon with Explicit Credentials",
    "registry_modified":   "Registry Value Modified",
    "object_access":       "Object Access Attempt",
    "privilege_assigned":  "Special Privileges Assigned",
    "suspicious_process":  "Suspicious Process Launched",
    "process_created":     "New Process Created",
    "service_installed":   "New Service Installed",
    "account_created":     "User Account Created",
    "account_deleted":     "User Account Deleted",
    "account_lockout":     "Account Locked Out",
    "group_member_added":  "Member Added to Security Group",
    "audit_log_cleared":   "Audit Log Cleared",
    "powershell_script":   "PowerShell Script Block",
    "generic":             "Generic System Event",
}

# ─── Logon type codes ─────────────────────────────────────────────────────────
LOGON_TYPE_LABELS: Dict[str, str] = {
    "2":  "Interactive",
    "3":  "Network",
    "4":  "Batch",
    "5":  "Service",
    "7":  "Unlock",
    "8":  "NetworkCleartext",
    "9":  "NewCredentials",
    "10": "RemoteInteractive (RDP)",
    "11": "CachedInteractive",
}

# Logon type → implied risk
LOGON_TYPE_RISK: Dict[str, str] = {
    "2":  "LOW",
    "3":  "MEDIUM",   # Network — SMB / WinRM / Impacket
    "4":  "LOW",
    "5":  "LOW",
    "7":  "MEDIUM",
    "8":  "HIGH",     # Cleartext password over network
    "9":  "HIGH",     # NewCredentials — used in PTH
    "10": "MEDIUM",   # RDP
    "11": "LOW",
}

# ─── Severity ordering ────────────────────────────────────────────────────────
SEVERITY_ORDER = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}


def severity_int(sev: str) -> int:
    """Return 0–4 numeric severity."""
    return SEVERITY_ORDER.get(str(sev).upper(), 0)


# ─────────────────────────────────────────────────────────────────────────────
# Main normalisation function
# ─────────────────────────────────────────────────────────────────────────────

def normalise(raw: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """
    Normalise a raw event dict from windows_agent into a unified SIEM record.

    KEY FIX: Reads IP from  raw["ip"]  OR  raw["source_ip"]  (backward-
    compatible with existing data files that used the old key name).
    Always outputs  "ip"  in the result.

    Returns None if input is not a valid dict.
    """
    if not isinstance(raw, dict):
        return None

    ts         = _clean_ts(raw.get("timestamp", ""))
    event_id   = int(raw.get("event_id", 0))
    channel    = str(raw.get("channel",    "Unknown"))
    source     = str(raw.get("source",     "Unknown"))
    computer   = str(raw.get("computer",   "Unknown"))
    event_type = str(raw.get("event_type", "generic"))
    severity   = str(raw.get("severity",   "INFO")).upper()
    user       = str(raw.get("user",       "SYSTEM"))

    # ── IP: read from "ip" (new) OR "source_ip" (old) ────────────────────
    ip = str(
        raw.get("ip") or
        raw.get("source_ip") or
        ""
    ).strip()
    # Discard placeholder values written by old code
    if ip in ("-", "no-ip", "unknown", "None"):
        ip = ""

    process    = str(raw.get("process_name", ""))
    cmdline    = str(raw.get("cmdline",    ""))
    logon_type = str(raw.get("logon_type", "")).strip()
    privileges = str(raw.get("privileges", ""))
    message    = str(raw.get("message",    ""))[:500]
    inserts    = raw.get("raw_inserts", [])

    logon_label = LOGON_TYPE_LABELS.get(logon_type, logon_type)
    logon_risk  = LOGON_TYPE_RISK.get(logon_type, "INFO")
    type_label  = EVENT_TYPE_LABELS.get(
        event_type, event_type.replace("_", " ").title()
    )

    return {
        "timestamp":        ts,
        "event_id":         event_id,
        "channel":          channel,
        "source":           source,
        "computer":         computer,
        "event_type":       event_type,
        "event_type_label": type_label,
        "severity":         severity,
        "severity_int":     severity_int(severity),
        "user":             user,
        "ip":               ip,       # ← canonical key
        "process_name":     process,
        "cmdline":          cmdline,
        "logon_type":       logon_type,
        "logon_type_label": logon_label,
        "logon_risk":       logon_risk,
        "privileges":       privileges,
        "message":          message,
        "raw_inserts":      inserts[:10],
    }


def _clean_ts(ts: str) -> str:
    """Ensure timestamp is 'YYYY-MM-DD HH:MM:SS'."""
    if not ts:
        return datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    try:
        datetime.strptime(ts[:19], "%Y-%m-%d %H:%M:%S")
        return ts[:19]
    except ValueError:
        pass
    for fmt in ("%a %b %d %H:%M:%S %Y", "%m/%d/%Y %H:%M:%S", "%d/%m/%Y %H:%M:%S"):
        try:
            return datetime.strptime(ts.strip(), fmt).strftime("%Y-%m-%d %H:%M:%S")
        except ValueError:
            continue
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")

