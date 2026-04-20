"""detection_rules.py — Detection Engine with Improved Rules and Correlation
================================
Rule-based threat detection for Windows SIEM.

Key improvements:
  • Fix IP extraction — all rules use 'ip' field consistently
  • Proper state management for correlation
  • Support all required attacks (Kali brute-force, PowerShell attacks, etc.)
  • Rate limiting built in
  • Correlation logic for incidents by IP
"""

import time
from collections import defaultdict
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional

from alert_system import fire_alert

# ─── Tunable thresholds ──────────────────────────────────────────────────────
BRUTE_FORCE_THRESHOLD = 5
BRUTE_FORCE_WINDOW = 60

PRIV_ESC_REPEAT_THRESHOLD = 3
PRIV_ESC_WINDOW = 120

LATERAL_MOVE_THRESHOLD = 3
LATERAL_MOVE_WINDOW = 120

RAPID_USER_THRESHOLD = 4
RAPID_USER_WINDOW = 60

ACCOUNT_ENUM_THRESHOLD = 3
ACCOUNT_ENUM_WINDOW = 120

FAIL_BEFORE_SUCCESS_WINDOW = 300

# ─── MITRE ATT&CK tactic mapping ──────────────────────────────────────────────
MITRE_MAP: Dict[str, str] = {
    "brute_force": "T1110 — Credential Access",
    "account_lockout": "T1110 — Credential Access",
    "success_after_failures": "T1078 — Valid Accounts",
    "privilege_escalation": "T1068 — Privilege Escalation",
    "privilege_escalation_sequence": "T1548 — Abuse Elevation Control",
    "suspicious_process": "T1059 — Command & Scripting Interpreter",
    "encoded_powershell": "T1059.001 — PowerShell",
    "pass_the_hash": "T1550.002 — Pass the Hash",
    "lateral_movement": "T1021 — Remote Services",
    "admin_tool_abuse": "T1569 — System Services",
    "service_installed": "T1543.003 — Windows Service",
    "audit_log_cleared": "T1070.001 — Clear Event Logs",
    "account_enumeration": "T1087 — Account Discovery",
    "rapid_user_switching": "T1078 — Valid Accounts",
}


def _epoch(ts_str: str) -> float:
    """Convert 'YYYY-MM-DD HH:MM:SS' to Unix epoch."""
    try:
        return datetime.strptime(ts_str, "%Y-%m-%d %H:%M:%S").timestamp()
    except (ValueError, TypeError):
        return time.time()


# ─── Detection Rules ──────────────────────────────────────────────────────────

def rule_brute_force(entry: Dict, state: Dict) -> Optional[Dict]:
    """
    Detect brute-force login attacks.
    Trigger: Failed network logon (4625, logon_type=3).
    
    Supports: Kali hydra, impacket attacks
    """
    if entry.get("event_id") != 4625:
        return None
    
    logon_type = entry.get("logon_type", "")
    if logon_type not in ("3", "10"):  # Network or RDP
        return None
    
    ip = entry.get("ip", "") or entry.get("source_ip", "")
    if not ip or ip == "-":
        return None
    
    return {
        "rule": "brute_force",
        "severity": "HIGH",
        "event_id": 4625,
        "user": entry.get("user"),
        "attacker_ip": ip,
        "mitre": MITRE_MAP["brute_force"],
        "description": f"Failed network logon from {ip}",
    }


def rule_account_lockout(entry: Dict, state: Dict) -> Optional[Dict]:
    """
    Alert on account lockout (Event 4740).
    Usually result of brute-force attack.
    """
    if entry.get("event_id") != 4740:
        return None
    
    ip = entry.get("ip", "") or entry.get("source_ip", "")
    
    return {
        "rule": "account_lockout",
        "severity": "HIGH",
        "event_id": 4740,
        "user": entry.get("user"),
        "attacker_ip": ip,
        "mitre": MITRE_MAP["account_lockout"],
        "description": f"Account locked out: {entry.get('user')} (likely brute-force)",
    }


def rule_success_after_failures(entry: Dict, state: Dict) -> Optional[Dict]:
    """
    Detect successful login AFTER multiple failures.
    Hallmark of successful brute-force or credential-stuffing.
    
    Trigger: 4624 success for user with ≥3 failures in past 5 min.
    """
    # Track failures
    if entry.get("event_type") == "failed_login":
        user = entry.get("user", "unknown")
        now = _epoch(entry.get("timestamp", ""))
        fl = state.setdefault("fail_log", {}).setdefault(user, [])
        fl.append(now)
        state["fail_log"][user] = [
            t for t in fl if now - t <= FAIL_BEFORE_SUCCESS_WINDOW
        ]
        return None
    
    if entry.get("event_id") != 4624:
        return None
    
    user = entry.get("user", "unknown")
    fails = state.get("fail_log", {}).get(user, [])
    
    if len(fails) >= 3:
        ip = entry.get("ip", "") or entry.get("source_ip", "")
        alert = {
            "rule": "success_after_failures",
            "severity": "CRITICAL",
            "event_id": 4624,
            "user": user,
            "attacker_ip": ip,
            "failure_count": len(fails),
            "mitre": MITRE_MAP["success_after_failures"],
            "description": f"SUCCESS after {len(fails)} failures for {user}",
        }
        # Clear the counter
        if user in state.get("fail_log", {}):
            del state["fail_log"][user]
        return alert
    
    return None


def rule_privilege_escalation(entry: Dict, state: Dict) -> Optional[Dict]:
    """
    Detect privilege escalation (Event 4672).
    Alert on dangerous privileges like SeDebugPrivilege.
    """
    if entry.get("event_id") != 4672:
        return None
    
    privs = entry.get("privileges", "") or ""
    user = entry.get("user", "unknown")
    
    dangerous = {
        "SeDebugPrivilege",
        "SeImpersonatePrivilege",
        "SeTcbPrivilege",
        "SeBackupPrivilege",
        "SeRestorePrivilege",
    }
    
    sev = "CRITICAL" if any(p in privs for p in dangerous) else "HIGH"
    
    return {
        "rule": "privilege_escalation",
        "severity": sev,
        "event_id": 4672,
        "user": user,
        "privileges": privs[:200],
        "attacker_ip": entry.get("ip", "") or entry.get("source_ip", ""),
        "mitre": MITRE_MAP["privilege_escalation"],
        "description": f"Privilege escalation [{sev}]: {user} assigned privs",
    }


def rule_privilege_escalation_sequence(
    entry: Dict, state: Dict
) -> Optional[Dict]:
    """
    Detect REPEATED privilege assignments.
    Trigger: ≥3 privilege events (4672) for same user in 120 seconds.
    """
    if entry.get("event_id") != 4672:
        return None
    
    user = entry.get("user", "unknown")
    now = _epoch(entry.get("timestamp", ""))
    
    priv_seq = state.setdefault("priv_seq", {})
    hits = priv_seq.setdefault(user, [])
    hits.append(now)
    priv_seq[user] = [t for t in hits if now - t <= PRIV_ESC_WINDOW]
    
    count = len(priv_seq[user])
    if count >= PRIV_ESC_REPEAT_THRESHOLD:
        if count % PRIV_ESC_REPEAT_THRESHOLD == 0:  # Fire every N triggers
            return {
                "rule": "privilege_escalation_sequence",
                "severity": "CRITICAL",
                "event_id": 4672,
                "user": user,
                "count": count,
                "attacker_ip": entry.get("ip", "") or entry.get("source_ip", ""),
                "mitre": MITRE_MAP["privilege_escalation_sequence"],
                "description": f"REPEATED priv escalation: {user} ({count} events in {PRIV_ESC_WINDOW}s)",
            }
    
    return None


def rule_suspicious_process(entry: Dict, state: Dict) -> Optional[Dict]:
    """
    Alert on suspicious process execution (Event 4688).
    Includes PowerShell, CMD, PSExec, Mimikatz, etc.
    """
    if entry.get("event_type") != "suspicious_process":
        return None
    
    proc = entry.get("process_name", "").lower()
    user = entry.get("user", "unknown")
    cmdline = (entry.get("cmdline") or "").lower()
    
    # Check for malicious command-line indicators
    cmdline_iocs = [
        "bypass", "-enc", "encodedcommand", "invoke-expression",
        "iex(", "downloadstring", "webclient", "hidden",
        "invoke-mimikatz", "sekurlsa", "-nop", "reflection",
        "whoami", "systeminfo", "tasklist"
    ]
    
    critical = any(ioc in cmdline for ioc in cmdline_iocs)
    sev = "CRITICAL" if critical else "HIGH"
    
    return {
        "rule": "suspicious_process",
        "severity": sev,
        "event_id": 4688,
        "user": user,
        "process": proc,
        "attacker_ip": entry.get("ip", "") or entry.get("source_ip", ""),
        "mitre": MITRE_MAP["suspicious_process"],
        "description": f"Suspicious process: {proc} by {user} ({sev})",
    }


def rule_encoded_powershell(entry: Dict, state: Dict) -> Optional[Dict]:
    """
    Detect base64-encoded or obfuscated PowerShell.
    Event 4688 (process creation) or 4104 (PowerShell Script Block).
    """
    event_id = entry.get("event_id")
    if event_id not in (4688, 4104):
        return None
    
    cmdline = (entry.get("cmdline") or entry.get("message") or "").lower()
    
    indicators = [
        "-enc", "-encodedcommand", "bypass", "hidden",
        "invoke-expression", "iex ", "iex(", "scriptblock",
        "conversion.frombase64string", "decompressstring",
    ]
    
    if not any(ind in cmdline for ind in indicators):
        return None
    
    user = entry.get("user", "unknown")
    ip = entry.get("ip", "") or entry.get("source_ip", "")
    
    return {
        "rule": "encoded_powershell",
        "severity": "CRITICAL",
        "event_id": event_id,
        "user": user,
        "attacker_ip": ip,
        "mitre": MITRE_MAP["encoded_powershell"],
        "description": f"Encoded PowerShell command detected from {user}",
    }


def rule_pass_the_hash(entry: Dict, state: Dict) -> Optional[Dict]:
    """
    Detect Pass-the-Hash attacks (Event 4648).
    Logon with explicit credentials using NTLM hash.
    """
    if entry.get("event_id") != 4648:
        return None
    
    ip = entry.get("ip", "") or entry.get("source_ip", "")
    user = entry.get("user", "unknown")
    
    return {
        "rule": "pass_the_hash",
        "severity": "CRITICAL",
        "event_id": 4648,
        "user": user,
        "attacker_ip": ip,
        "mitre": MITRE_MAP["pass_the_hash"],
        "description": f"Pass-the-Hash suspected: explicit credential use from {ip}",
    }


def rule_lateral_movement(entry: Dict, state: Dict) -> Optional[Dict]:
    """
    Detect lateral movement (Event 4624).
    Trigger: ≥3 network logins (type 3) from same IP in 120 seconds.
    
    Supports: SMB, WinRM, Impacket lateral movement
    """
    if entry.get("event_id") != 4624:
        return None
    
    logon_type = entry.get("logon_type", "")
    if logon_type != "3":  # Network logons only
        return None
    
    ip = entry.get("ip", "") or entry.get("source_ip", "")
    if not ip or ip == "-":
        return None
    
    now = _epoch(entry.get("timestamp", ""))
    lateral = state.setdefault("lateral_move", {}).setdefault(ip, [])
    lateral.append(now)
    state["lateral_move"][ip] = [t for t in lateral if now - t <= LATERAL_MOVE_WINDOW]
    
    count = len(state["lateral_move"][ip])
    if count >= LATERAL_MOVE_THRESHOLD:
        if count % LATERAL_MOVE_THRESHOLD == 0:  # Fire every N triggers
            return {
                "rule": "lateral_movement",
                "severity": "HIGH",
                "event_id": 4624,
                "attacker_ip": ip,
                "logon_count": count,
                "user": entry.get("user", "unknown"),
                "mitre": MITRE_MAP["lateral_movement"],
                "description": f"Lateral movement from {ip}: {count} network logins in {LATERAL_MOVE_WINDOW}s",
            }
    
    return None


def rule_admin_tool_abuse(entry: Dict, state: Dict) -> Optional[Dict]:
    """
    Detect abuse of admin tools (Event 4688).
    PSExec, PsExecSvc, net, tasklist, whoami, etc.
    """
    if entry.get("event_id") != 4688:
        return None
    
    proc = entry.get("process_name", "").lower()
    
    admin_tools = {"psexec", "tasklist", "whoami", "nltest", "dsquery", 
                   "net", "net1", "sc", "reg", "ipconfig", "netstat", "at"}
    
    if not any(tool in proc for tool in admin_tools):
        return None
    
    user = entry.get("user", "unknown")
    ip = entry.get("ip", "") or entry.get("source_ip", "")
    
    return {
        "rule": "admin_tool_abuse",
        "severity": "HIGH",
        "event_id": 4688,
        "user": user,
        "process": proc,
        "attacker_ip": ip,
        "mitre": MITRE_MAP["admin_tool_abuse"],
        "description": f"Admin tool abuse: {proc} by {user}",
    }


def rule_service_installed(entry: Dict, state: Dict) -> Optional[Dict]:
    """
    Detect new service installation (Event 4697 or 7045).
    Common persistence mechanism.
    """
    if entry.get("event_id") not in (4697, 7045):
        return None
    
    user = entry.get("user", "unknown")
    
    return {
        "rule": "service_installed",
        "severity": "HIGH",
        "event_id": entry.get("event_id"),
        "user": user,
        "attacker_ip": entry.get("ip", "") or entry.get("source_ip", ""),
        "mitre": MITRE_MAP["service_installed"],
        "description": f"New service installed by {user}",
    }


def rule_audit_log_cleared(entry: Dict, state: Dict) -> Optional[Dict]:
    """
    Detect audit log clear (Event 1102).
    Anti-forensics / cover tracks.
    """
    if entry.get("event_id") != 1102:
        return None
    
    user = entry.get("user", "unknown")
    
    return {
        "rule": "audit_log_cleared",
        "severity": "CRITICAL",
        "event_id": 1102,
        "user": user,
        "attacker_ip": entry.get("ip", "") or entry.get("source_ip", ""),
        "mitre": MITRE_MAP["audit_log_cleared"],
        "description": f"AUDIT LOG CLEARED by {user} — anti-forensics detected",
    }


def rule_account_enumeration(entry: Dict, state: Dict) -> Optional[Dict]:
    """
    Detect account enumeration (Event 4625).
    Trigger: ≥3 failed logins with different usernames from same IP in 120 seconds.
    """
    if entry.get("event_id") != 4625:
        return None
    
    ip = entry.get("ip", "") or entry.get("source_ip", "")
    if not ip or ip == "-":
        return None
    
    user = entry.get("user", "unknown")
    now = _epoch(entry.get("timestamp", ""))
    
    enum_map = state.setdefault("account_enum", {}).setdefault(ip, {})
    enum_map.setdefault(user, []).append(now)
    
    # Clean old entries
    for u in list(enum_map.keys()):
        enum_map[u] = [t for t in enum_map[u] if now - t <= ACCOUNT_ENUM_WINDOW]
        if not enum_map[u]:
            del enum_map[u]
    
    unique_users = len(enum_map)
    if unique_users >= ACCOUNT_ENUM_THRESHOLD:
        users_list = ", ".join(list(enum_map.keys())[:5])
        return {
            "rule": "account_enumeration",
            "severity": "MEDIUM",
            "event_id": 4625,
            "attacker_ip": ip,
            "unique_users": unique_users,
            "mitre": MITRE_MAP["account_enumeration"],
            "description": f"Account enumeration from {ip}: {unique_users} unique users ({users_list}...)",
        }
    
    return None


def rule_rapid_user_switching(entry: Dict, state: Dict) -> Optional[Dict]:
    """
    Detect rapid user switching (Event 4624).
    Trigger: ≥4 distinct users logged in within 60 seconds.
    """
    if entry.get("event_id") != 4624:
        return None
    
    user = entry.get("user", "unknown")
    now = _epoch(entry.get("timestamp", ""))
    
    users = state.setdefault("rapid_users", {})
    while users and now - users[0][0] > RAPID_USER_WINDOW:
        users.pop(0)
    
    if user not in [u for _, u in users]:
        users.append((now, user))
    
    unique_count = len(set(u for _, u in users))
    if unique_count >= RAPID_USER_THRESHOLD:
        user_list = ", ".join(set(u for _, u in users)[:5])
        return {
            "rule": "rapid_user_switching",
            "severity": "MEDIUM",
            "event_id": 4624,
            "user_count": unique_count,
            "attacker_ip": entry.get("ip", "") or entry.get("source_ip", ""),
            "mitre": MITRE_MAP["rapid_user_switching"],
            "description": f"Rapid user switching: {unique_count} unique users in {RAPID_USER_WINDOW}s ({user_list}...)",
        }
    
    return None


# ─── Rule execution engine ────────────────────────────────────────────────────

RULES = [
    rule_brute_force,
    rule_account_lockout,
    rule_success_after_failures,
    rule_privilege_escalation,
    rule_privilege_escalation_sequence,
    rule_suspicious_process,
    rule_encoded_powershell,
    rule_pass_the_hash,
    rule_lateral_movement,
    rule_admin_tool_abuse,
    rule_service_installed,
    rule_audit_log_cleared,
    rule_account_enumeration,
    rule_rapid_user_switching,
]


class DetectionEngine:
    """Main detection engine."""
    
    def __init__(self):
        self.state: Dict[str, Any] = {
            "fail_log": {},
            "priv_seq": {},
            "lateral_move": {},
            "account_enum": {},
            "rapid_users": [],
        }
    
    def evaluate(self, entry: Dict[str, Any]) -> None:
        """Evaluate one log entry against all rules."""
        for rule in RULES:
            alert = rule(entry, self.state)
            if alert:
                # Add metadata
                alert.setdefault("timestamp", entry.get("timestamp"))
                alert.setdefault("computer", entry.get("computer"))
                alert.setdefault("channel", entry.get("channel"))
                fire_alert(alert)
