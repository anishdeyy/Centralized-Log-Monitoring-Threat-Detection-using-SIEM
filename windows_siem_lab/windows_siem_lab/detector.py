"""
detector.py — Detection Engine  (FIXED v2)
============================================
Rule-based threat detection.

FIXES IN THIS VERSION
---------------------
1. All rules now read  entry.get("ip")  — the unified field from parser_module.
   Old references to  entry.get("source_ip")  are removed.

2. All alert dicts now use  "ip"  as the key (not "attacker_ip").
   storage.py, dashboard.py, and the incidents endpoint all read "ip".

3. lateral_movement rule fixed: reads "ip" not "source_ip".

4. New rule: encoded_powershell — detects -enc / bypass / iex patterns.

5. MITRE ATT&CK tactic labels included in every alert.

Detection Rules
---------------
Rule                        Trigger                        Severity
────────────────────────────────────────────────────────────────────────
brute_force                 ≥5 failed logins / 60 s        HIGH
account_lockout             Event 4740                     HIGH
success_after_failures      4624 after ≥3 failures         CRITICAL
privilege_escalation        Event 4672 (dangerous privs)   CRITICAL
privilege_escalation_seq    ≥3 priv events / 120 s         CRITICAL
suspicious_process          Event 4688 known-bad process   HIGH
encoded_powershell          4688/4104 -enc/bypass/iex       CRITICAL
pass_the_hash               Event 4648 explicit creds      CRITICAL
lateral_movement            ≥3 network logons / 120 s      HIGH
admin_tool_abuse            4688 admin tools               HIGH
service_installed           Event 4697 / 7045              HIGH
audit_log_cleared           Event 1102                     CRITICAL
account_enumeration         ≥3 usernames / IP / 120 s      MEDIUM
rapid_user_switching        ≥4 users logged in / 60 s      MEDIUM
"""

import time
from collections import defaultdict
from dataclasses import dataclass, field
from datetime    import datetime
from typing      import Any, Callable, Dict, List, Optional

from alert_system import fire_alert

# ─── Thresholds ───────────────────────────────────────────────────────────────
BRUTE_FORCE_THRESHOLD       = 5
BRUTE_FORCE_WINDOW          = 60
PRIV_ESC_REPEAT_THRESHOLD   = 3
PRIV_ESC_WINDOW             = 120
LATERAL_MOVE_THRESHOLD      = 3
LATERAL_MOVE_WINDOW         = 120
RAPID_USER_THRESHOLD        = 4
RAPID_USER_WINDOW           = 60
ACCOUNT_ENUM_THRESHOLD      = 3
ACCOUNT_ENUM_WINDOW         = 120
FAIL_BEFORE_SUCCESS_WINDOW  = 300

# ─── MITRE ATT&CK tactic labels ──────────────────────────────────────────────
MITRE: Dict[str, str] = {
    "brute_force":                   "T1110 — Credential Access",
    "account_lockout":               "T1110 — Credential Access",
    "success_after_failures":        "T1078 — Valid Accounts",
    "privilege_escalation":          "T1068 — Privilege Escalation",
    "privilege_escalation_sequence": "T1548 — Abuse Elevation Control",
    "suspicious_process":            "T1059 — Command & Scripting",
    "encoded_powershell":            "T1059.001 — PowerShell",
    "pass_the_hash":                 "T1550.002 — Pass the Hash",
    "lateral_movement":              "T1021 — Remote Services",
    "admin_tool_abuse":              "T1569 — System Services",
    "service_installed":             "T1543.003 — Windows Service",
    "audit_log_cleared":             "T1070.001 — Clear Event Logs",
    "account_enumeration":           "T1087 — Account Discovery",
    "rapid_user_switching":          "T1078 — Valid Accounts",
}


# ─────────────────────────────────────────────────────────────────────────────
# Utility
# ─────────────────────────────────────────────────────────────────────────────

def _epoch(ts: str) -> float:
    try:
        return datetime.strptime(ts, "%Y-%m-%d %H:%M:%S").timestamp()
    except (ValueError, TypeError):
        return time.time()


# ─────────────────────────────────────────────────────────────────────────────
# Rule implementations
# ─────────────────────────────────────────────────────────────────────────────

def rule_brute_force(entry: Dict, state: Dict) -> Optional[Dict]:
    """≥5 failed logins from same IP+user within 60 s."""
    if entry.get("event_type") != "failed_login":
        return None
    user = entry.get("user", "unknown")
    ip   = entry.get("ip") or "no-ip"     # ← "ip" (fixed)
    now  = _epoch(entry.get("timestamp", ""))
    key  = f"{user}:{ip}"
    hits = state["brute"].setdefault(key, [])
    hits.append(now)
    state["brute"][key] = [t for t in hits if now - t <= BRUTE_FORCE_WINDOW]
    count = len(state["brute"][key])
    if count >= BRUTE_FORCE_THRESHOLD and count % 5 == 0:
        return {
            "rule":        "brute_force",
            "severity":    "HIGH",
            "event_id":    4625,
            "user":        user,
            "ip":          ip,
            "count":       count,
            "mitre":       MITRE["brute_force"],
            "description": (
                f"BRUTE FORCE: {count} failed logins for '{user}' "
                f"from {ip} in {BRUTE_FORCE_WINDOW}s"
            ),
        }
    return None


def rule_account_lockout(entry: Dict, state: Dict) -> Optional[Dict]:
    """Alert on Event 4740 — account locked out."""
    if entry.get("event_id") != 4740:
        return None
    return {
        "rule":        "account_lockout",
        "severity":    "HIGH",
        "event_id":    4740,
        "user":        entry.get("user"),
        "ip":          entry.get("ip") or "",   # ← "ip"
        "mitre":       MITRE["account_lockout"],
        "description": (
            f"ACCOUNT LOCKED OUT: '{entry.get('user')}' — "
            f"result of brute-force attack."
        ),
    }


def rule_success_after_failures(entry: Dict, state: Dict) -> Optional[Dict]:
    """Successful login (4624) after ≥3 failures in last 5 min."""
    if entry.get("event_type") == "failed_login":
        user = entry.get("user", "unknown")
        now  = _epoch(entry.get("timestamp", ""))
        fl   = state["fail_log"].setdefault(user, [])
        fl.append(now)
        state["fail_log"][user] = [
            t for t in fl if now - t <= FAIL_BEFORE_SUCCESS_WINDOW
        ]
        return None
    if entry.get("event_type") != "successful_login":
        return None
    user     = entry.get("user", "unknown")
    now      = _epoch(entry.get("timestamp", ""))
    failures = [
        t for t in state["fail_log"].get(user, [])
        if now - t <= FAIL_BEFORE_SUCCESS_WINDOW
    ]
    if len(failures) >= 3:
        state["fail_log"][user] = []
        return {
            "rule":        "success_after_failures",
            "severity":    "CRITICAL",
            "event_id":    "4625→4624",
            "user":        user,
            "ip":          entry.get("ip") or "",   # ← "ip"
            "fail_count":  len(failures),
            "mitre":       MITRE["success_after_failures"],
            "description": (
                f"POSSIBLE BREACH: '{user}' logged in after "
                f"{len(failures)} failures — brute-force may have succeeded."
            ),
        }
    return None


def rule_privilege_escalation(entry: Dict, state: Dict) -> Optional[Dict]:
    """Event 4672 — special privileges assigned."""
    if entry.get("event_id") != 4672:
        return None
    user   = entry.get("user", "unknown")
    privs  = entry.get("privileges", "")
    dangerous = {
        "SeDebugPrivilege", "SeTcbPrivilege", "SeImpersonatePrivilege",
        "SeAssignPrimaryTokenPrivilege", "SeLoadDriverPrivilege",
        "SeTakeOwnershipPrivilege", "SeBackupPrivilege",
    }
    sev = "CRITICAL" if any(p in privs for p in dangerous) else "HIGH"
    return {
        "rule":        "privilege_escalation",
        "severity":    sev,
        "event_id":    4672,
        "user":        user,
        "ip":          entry.get("ip") or "",
        "privileges":  privs[:200] if privs else "—",
        "mitre":       MITRE["privilege_escalation"],
        "description": (
            f"PRIVILEGE ESCALATION [{sev}]: '{user}' assigned special privileges. "
            f"Privs: {privs[:80] if privs else 'unknown'}"
        ),
    }


def rule_privilege_escalation_sequence(entry: Dict, state: Dict) -> Optional[Dict]:
    """≥3 privilege events (4672) for same user in 120 s."""
    if entry.get("event_id") != 4672:
        return None
    user = entry.get("user", "unknown")
    now  = _epoch(entry.get("timestamp", ""))
    hits = state["priv_seq"].setdefault(user, [])
    hits.append(now)
    state["priv_seq"][user] = [t for t in hits if now - t <= PRIV_ESC_WINDOW]
    count = len(state["priv_seq"][user])
    if count >= PRIV_ESC_REPEAT_THRESHOLD and count % PRIV_ESC_REPEAT_THRESHOLD == 0:
        return {
            "rule":        "privilege_escalation_sequence",
            "severity":    "CRITICAL",
            "event_id":    4672,
            "user":        user,
            "ip":          entry.get("ip") or "",
            "count":       count,
            "mitre":       MITRE["privilege_escalation_sequence"],
            "description": (
                f"REPEATED PRIV ESCALATION: '{user}' triggered {count} "
                f"privilege events in {PRIV_ESC_WINDOW}s — possible malware."
            ),
        }
    return None


def rule_suspicious_process(entry: Dict, state: Dict) -> Optional[Dict]:
    """Event 4688 with a known-bad process name."""
    if entry.get("event_type") != "suspicious_process":
        return None
    proc    = entry.get("process_name", "unknown")
    user    = entry.get("user", "unknown")
    cmdline = (entry.get("cmdline") or entry.get("message", "")).lower()
    cmdline_iocs = [
        "bypass", "-enc", "encodedcommand", "invoke-expression",
        "iex(", "downloadstring", "webclient", "hidden",
        "invoke-mimikatz", "sekurlsa", "-nop", "reflection",
    ]
    critical = any(ioc in cmdline for ioc in cmdline_iocs)
    sev = "CRITICAL" if critical else "HIGH"
    return {
        "rule":        "suspicious_process",
        "severity":    sev,
        "event_id":    4688,
        "user":        user,
        "ip":          entry.get("ip") or "",
        "process":     proc,
        "mitre":       MITRE["suspicious_process"],
        "description": (
            f"SUSPICIOUS PROCESS: '{proc}' by '{user}'. "
            + ("Command-line IOC detected." if critical
               else "Known high-risk executable.")
        ),
    }


def rule_encoded_powershell(entry: Dict, state: Dict) -> Optional[Dict]:
    """
    Detect encoded or obfuscated PowerShell.
    Fires on Event 4688 (process creation) and Event 4104 (script block).
    Requires command-line logging to be enabled (auditpol + registry key).
    """
    eid     = entry.get("event_id")
    cmdline = (entry.get("cmdline") or entry.get("message", "")).lower()
    proc    = (entry.get("process_name") or "").lower()
    if eid not in (4688, 4104):
        return None
    if eid == 4688 and "powershell" not in proc:
        return None
    encoding_iocs = ["-enc", "-encodedcommand", "encodedcommand"]
    obfuscation_iocs = [
        "iex(", "iex (", "invoke-expression", "-noprofile",
        "bypass", "downloadstring", "webclient", "downloadfile",
        "invoke-mimikatz", "sekurlsa", "frombase64string",
        "reflection.assembly", "system.net.webclient",
    ]
    is_encoded    = any(ioc in cmdline for ioc in encoding_iocs)
    is_obfuscated = any(ioc in cmdline for ioc in obfuscation_iocs)
    if not (is_encoded or is_obfuscated):
        return None
    sev  = "CRITICAL" if is_encoded else "HIGH"
    kind = "ENCODED" if is_encoded else "OBFUSCATED"
    return {
        "rule":        "encoded_powershell",
        "severity":    sev,
        "event_id":    eid,
        "user":        entry.get("user"),
        "ip":          entry.get("ip") or "",
        "process":     proc,
        "ioc_type":    kind,
        "mitre":       MITRE["encoded_powershell"],
        "description": (
            f"MALICIOUS POWERSHELL [{kind}]: '{proc}' by "
            f"'{entry.get('user')}'. Review command line immediately."
        ),
    }


def rule_pass_the_hash(entry: Dict, state: Dict) -> Optional[Dict]:
    """Event 4648 — explicit credential logon (pass-the-hash indicator)."""
    if entry.get("event_id") != 4648:
        return None
    user = entry.get("user", "")
    skip = {"SYSTEM", "LOCAL SERVICE", "NETWORK SERVICE", "ANONYMOUS LOGON", ""}
    if user.upper() in skip:
        return None
    ip = entry.get("ip") or ""
    return {
        "rule":        "pass_the_hash",
        "severity":    "CRITICAL",
        "event_id":    4648,
        "user":        user,
        "ip":          ip,
        "mitre":       MITRE["pass_the_hash"],
        "description": (
            f"PASS-THE-HASH / LATERAL MOVEMENT: Explicit credentials used "
            f"by '{user}'. Source IP: {ip or 'unknown'}"
        ),
    }


def rule_lateral_movement(entry: Dict, state: Dict) -> Optional[Dict]:
    """
    ≥3 network logons (type 3) from the same source IP within 120 s.
    Classic pattern for Impacket psexec/wmiexec/smbexec.
    """
    if entry.get("event_type") != "successful_login":
        return None
    logon_type = str(entry.get("logon_type", "")).strip()
    if logon_type != "3":
        return None
    ip  = entry.get("ip") or "no-ip"   # ← "ip" (fixed)
    now = _epoch(entry.get("timestamp", ""))
    hits = state["lateral"].setdefault(ip, [])
    hits.append(now)
    state["lateral"][ip] = [t for t in hits if now - t <= LATERAL_MOVE_WINDOW]
    count = len(state["lateral"][ip])
    if count >= LATERAL_MOVE_THRESHOLD and count % LATERAL_MOVE_THRESHOLD == 0:
        return {
            "rule":        "lateral_movement",
            "severity":    "HIGH",
            "event_id":    4624,
            "ip":          ip,
            "user":        entry.get("user"),
            "count":       count,
            "logon_type":  "3 (Network)",
            "mitre":       MITRE["lateral_movement"],
            "description": (
                f"LATERAL MOVEMENT: {count} network logons (Type 3) from "
                f"{ip} in {LATERAL_MOVE_WINDOW}s — possible PsExec/WMIExec."
            ),
        }
    return None


def rule_admin_tool_abuse(entry: Dict, state: Dict) -> Optional[Dict]:
    """Event 4688 with a known admin/attack tool."""
    if entry.get("event_id") != 4688:
        return None
    ADMIN_TOOLS = {
        "psexec.exe", "psexesvc.exe", "wmic.exe", "sc.exe", "reg.exe",
        "at.exe", "schtasks.exe", "net.exe", "net1.exe",
        "nltest.exe", "dsquery.exe", "csvde.exe", "ldifde.exe",
    }
    proc = (entry.get("process_name") or "").lower().strip()
    if not any(tool in proc for tool in ADMIN_TOOLS):
        return None
    return {
        "rule":        "admin_tool_abuse",
        "severity":    "HIGH",
        "event_id":    4688,
        "user":        entry.get("user"),
        "ip":          entry.get("ip") or "",
        "process":     proc,
        "mitre":       MITRE["admin_tool_abuse"],
        "description": (
            f"ADMIN TOOL: '{proc}' run by '{entry.get('user')}'. "
            f"Commonly abused for lateral movement / enumeration."
        ),
    }


def rule_service_installed(entry: Dict, state: Dict) -> Optional[Dict]:
    """Events 4697 / 7045 — new service installed."""
    if entry.get("event_id") not in (4697, 7045):
        return None
    inserts = entry.get("raw_inserts", [])
    svc     = inserts[0] if inserts else "unknown"
    return {
        "rule":        "service_installed",
        "severity":    "HIGH",
        "event_id":    entry.get("event_id"),
        "user":        entry.get("user"),
        "ip":          entry.get("ip") or "",
        "service":     svc,
        "mitre":       MITRE["service_installed"],
        "description": (
            f"SERVICE INSTALLED: '{svc}' by '{entry.get('user')}'. "
            f"Attackers install services for persistence or code execution."
        ),
    }


def rule_audit_log_cleared(entry: Dict, state: Dict) -> Optional[Dict]:
    """Event 1102 — Windows Security audit log cleared."""
    if entry.get("event_id") != 1102:
        return None
    return {
        "rule":        "audit_log_cleared",
        "severity":    "CRITICAL",
        "event_id":    1102,
        "user":        entry.get("user"),
        "ip":          entry.get("ip") or "",
        "mitre":       MITRE["audit_log_cleared"],
        "description": (
            f"AUDIT LOG CLEARED by '{entry.get('user')}'. "
            f"CRITICAL — attacker may be covering tracks."
        ),
    }


def rule_account_enumeration(entry: Dict, state: Dict) -> Optional[Dict]:
    """≥3 distinct usernames tried from same IP in 120 s."""
    if entry.get("event_type") != "failed_login":
        return None
    ip   = entry.get("ip") or "no-ip"    # ← "ip"
    user = entry.get("user", "unknown")
    now  = _epoch(entry.get("timestamp", ""))
    bucket = state["enum"].setdefault(ip, {})
    bucket[user] = now
    state["enum"][ip] = {
        u: t for u, t in bucket.items()
        if now - t <= ACCOUNT_ENUM_WINDOW
    }
    unique = len(state["enum"][ip])
    if unique >= ACCOUNT_ENUM_THRESHOLD and unique % ACCOUNT_ENUM_THRESHOLD == 0:
        return {
            "rule":        "account_enumeration",
            "severity":    "MEDIUM",
            "event_id":    4625,
            "ip":          ip,
            "users_tried": list(state["enum"][ip].keys()),
            "count":       unique,
            "mitre":       MITRE["account_enumeration"],
            "description": (
                f"ACCOUNT ENUMERATION: {unique} distinct usernames tried "
                f"from {ip} in {ACCOUNT_ENUM_WINDOW}s."
            ),
        }
    return None


def rule_rapid_user_switching(entry: Dict, state: Dict) -> Optional[Dict]:
    """≥4 distinct users logged in within 60 s."""
    if entry.get("event_type") != "successful_login":
        return None
    user = entry.get("user", "unknown")
    now  = _epoch(entry.get("timestamp", ""))
    state["rapid_users"][user] = now
    state["rapid_users"] = {
        u: t for u, t in state["rapid_users"].items()
        if now - t <= RAPID_USER_WINDOW
    }
    unique = len(state["rapid_users"])
    if unique >= RAPID_USER_THRESHOLD and unique % RAPID_USER_THRESHOLD == 0:
        return {
            "rule":        "rapid_user_switching",
            "severity":    "MEDIUM",
            "event_id":    4624,
            "ip":          entry.get("ip") or "",
            "users":       list(state["rapid_users"].keys()),
            "count":       unique,
            "mitre":       MITRE["rapid_user_switching"],
            "description": (
                f"RAPID USER SWITCHING: {unique} distinct accounts logged in "
                f"within {RAPID_USER_WINDOW}s — possible credential stuffing."
            ),
        }
    return None


# ─────────────────────────────────────────────────────────────────────────────
# Incident Correlator
# ─────────────────────────────────────────────────────────────────────────────

SEV_ORDER = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]


@dataclass
class Incident:
    """Correlated attack chain from a single source IP."""
    ip:             str
    start_time:     str
    alerts:         list = field(default_factory=list)
    rules_fired:    set  = field(default_factory=set)
    severity:       str  = "INFO"
    users_targeted: set  = field(default_factory=set)
    INCIDENT_WINDOW: int = 600   # 10 minutes

    def add(self, alert: dict) -> None:
        self.alerts.append(alert)
        self.rules_fired.add(alert.get("rule", "unknown"))
        if alert.get("user"):
            self.users_targeted.add(alert["user"])
        cur = SEV_ORDER.index(self.severity) if self.severity in SEV_ORDER else 0
        new = SEV_ORDER.index(alert.get("severity", "INFO")) \
            if alert.get("severity", "INFO") in SEV_ORDER else 0
        if new > cur:
            self.severity = alert["severity"]

    def to_dict(self) -> dict:
        return {
            "ip":             self.ip,
            "start_time":     self.start_time,
            "end_time":       self.alerts[-1].get("timestamp", "") if self.alerts else "",
            "alert_count":    len(self.alerts),
            "rules_fired":    sorted(self.rules_fired),
            "tactics":        [MITRE.get(r, r) for r in self.rules_fired],
            "severity":       self.severity,
            "users_targeted": sorted(self.users_targeted),
        }


class IncidentCorrelator:
    """Groups alerts by source IP and time window into incidents."""

    def __init__(self):
        self._incidents: Dict[str, Incident] = {}

    def ingest(self, alert: dict) -> Incident:
        ip  = alert.get("ip") or "unknown"
        now = _epoch(alert.get("timestamp", ""))
        if ip in self._incidents:
            inc = self._incidents[ip]
            if inc.alerts:
                last = _epoch(inc.alerts[-1].get("timestamp", ""))
                if now - last > Incident.INCIDENT_WINDOW:
                    del self._incidents[ip]
        if ip not in self._incidents:
            self._incidents[ip] = Incident(
                ip=ip, start_time=alert.get("timestamp", "")
            )
        self._incidents[ip].add(alert)
        return self._incidents[ip]

    def active_incidents(self) -> List[dict]:
        return [inc.to_dict() for inc in self._incidents.values()]


# ─────────────────────────────────────────────────────────────────────────────
# Detection Engine
# ─────────────────────────────────────────────────────────────────────────────

class DetectionEngine:
    """
    Maintains detection state and a registry of rule functions.
    Call  evaluate(parsed_entry)  for every incoming log record.
    """

    def __init__(self) -> None:
        self._state: Dict[str, Any] = {
            "brute":       defaultdict(list),
            "fail_log":    defaultdict(list),
            "priv_seq":    defaultdict(list),
            "enum":        defaultdict(dict),
            "rapid_users": {},
            "lateral":     defaultdict(list),
        }
        self.correlator = IncidentCorrelator()
        self._rules: List[tuple] = [
            ("brute_force",                   rule_brute_force),
            ("account_lockout",               rule_account_lockout),
            ("success_after_failures",        rule_success_after_failures),
            ("privilege_escalation",          rule_privilege_escalation),
            ("privilege_escalation_sequence", rule_privilege_escalation_sequence),
            ("suspicious_process",            rule_suspicious_process),
            ("encoded_powershell",            rule_encoded_powershell),
            ("pass_the_hash",                 rule_pass_the_hash),
            ("lateral_movement",              rule_lateral_movement),
            ("admin_tool_abuse",              rule_admin_tool_abuse),
            ("service_installed",             rule_service_installed),
            ("audit_log_cleared",             rule_audit_log_cleared),
            ("account_enumeration",           rule_account_enumeration),
            ("rapid_user_switching",          rule_rapid_user_switching),
        ]

    def add_rule(self, name: str, fn: Callable) -> None:
        for i, (n, _) in enumerate(self._rules):
            if n == name:
                self._rules[i] = (name, fn)
                return
        self._rules.append((name, fn))

    def evaluate(self, entry: Dict[str, Any]) -> List[Dict]:
        fired = []
        ts    = entry.get("timestamp", datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
        for name, fn in self._rules:
            try:
                alert = fn(entry, self._state)
                if alert:
                    alert["timestamp"] = ts
                    # Ensure ip is always set in alert
                    alert.setdefault("ip", entry.get("ip", ""))
                    alert.setdefault("user", entry.get("user", ""))
                    fire_alert(alert)
                    incident = self.correlator.ingest(alert)
                    if len(incident.rules_fired) >= 3:
                        print(
                            f"\n  [INCIDENT] {incident.ip} — "
                            f"{len(incident.rules_fired)} rules: "
                            f"{', '.join(sorted(incident.rules_fired))}"
                        )
                    fired.append(alert)
            except Exception as exc:
                print(f"  [Detector] Rule '{name}' error: {exc}")
        return fired
