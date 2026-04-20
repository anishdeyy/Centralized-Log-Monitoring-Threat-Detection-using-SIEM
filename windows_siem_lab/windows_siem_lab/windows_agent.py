"""
windows_agent.py — Windows Event Log Agent  (FIXED v2)
========================================================
Reads REAL Windows Event Logs using pywin32.

FIXES IN THIS VERSION
---------------------
1. IP extraction now runs for ALL logon events (4624, 4625, 4648, 4740, …)
   not just for 4625.  Uses StringInserts index 18/19 where Windows stores
   "Source Network Address" — exactly what PowerShell shows.

2. All events now store the IP under the unified key  "ip"  (not "source_ip").
   parser_module, detector, storage, and dashboard all read "ip".

3. Complete EVENT_META table — all 16 event IDs are covered.

4. Noise filter:
   - Event 4703 (token rights adjusted) is silently dropped
   - Event 4688 from known-benign processes (svchost, python, MicrosoftEdge,
     conhost, WmiPrvSE, etc.) is silently dropped
   - Rate-limiter: identical (event_id, user, ip) triplets are throttled
     to at most 1 record per 5 s to prevent dashboard flooding

5. All debug  print("RAW INSERTS:", ...)  statements removed.
"""

import queue
import re
import threading
import time
from collections import defaultdict
from datetime    import datetime
from typing      import Any, Dict, Generator, List, Optional

# ── pywin32 import ────────────────────────────────────────────────────────────
try:
    import win32evtlog
    import win32evtlogutil
    import pywintypes
    HAS_PYWIN32 = True
except ImportError:
    HAS_PYWIN32 = False

# ─── Configuration ────────────────────────────────────────────────────────────
POLL_INTERVAL        = 2.0    # seconds between ReadEventLog() calls
RATE_LIMIT_WINDOW    = 5.0    # seconds — identical events de-duplicated within window
MAX_QUEUE_SIZE       = 1000   # internal queue cap

# ─── Complete EVENT_META table ────────────────────────────────────────────────
# Every event ID we care about.  Unknown IDs fall to ("generic", "INFO").
EVENT_META: Dict[int, Dict[str, str]] = {
    4624: {"event_type": "successful_login",    "severity": "INFO"},
    4625: {"event_type": "failed_login",         "severity": "MEDIUM"},
    4634: {"event_type": "logoff",               "severity": "INFO"},
    4648: {"event_type": "explicit_cred_logon",  "severity": "HIGH"},
    4657: {"event_type": "registry_modified",    "severity": "MEDIUM"},
    4663: {"event_type": "object_access",        "severity": "LOW"},
    4672: {"event_type": "privilege_assigned",   "severity": "HIGH"},
    4688: {"event_type": "process_created",      "severity": "LOW"},
    4697: {"event_type": "service_installed",    "severity": "HIGH"},
    4720: {"event_type": "account_created",      "severity": "MEDIUM"},
    4726: {"event_type": "account_deleted",      "severity": "MEDIUM"},
    4740: {"event_type": "account_lockout",      "severity": "HIGH"},
    4756: {"event_type": "group_member_added",   "severity": "HIGH"},
    7045: {"event_type": "service_installed",    "severity": "HIGH"},
    1102: {"event_type": "audit_log_cleared",    "severity": "CRITICAL"},
    4104: {"event_type": "powershell_script",    "severity": "MEDIUM"},
}

# ─── Suspicious processes (Event 4688 elevation) ──────────────────────────────
SUSPICIOUS_PROCESSES = {
    "powershell.exe", "cmd.exe",     "wscript.exe",  "cscript.exe",
    "mshta.exe",      "regsvr32.exe","rundll32.exe", "certutil.exe",
    "bitsadmin.exe",  "wmic.exe",    "net.exe",      "net1.exe",
    "at.exe",         "schtasks.exe","psexec.exe",   "psexesvc.exe",
    "mimikatz.exe",   "whoami.exe",  "nltest.exe",   "dsquery.exe",
    "sc.exe",         "reg.exe",
}

# ─── Benign processes — 4688 events for these are dropped (noise filter) ─────
BENIGN_PROCESSES = {
    "svchost.exe",        "conhost.exe",        "python.exe",
    "python3.exe",        "pythonw.exe",        "microsoftedge.exe",
    "msedge.exe",         "wmiprvse.exe",       "taskhostw.exe",
    "runtimebroker.exe",  "searchindexer.exe",  "searchprotocolhost.exe",
    "dllhost.exe",        "sihost.exe",         "fontdrvhost.exe",
    "dwm.exe",            "explorer.exe",       "ctfmon.exe",
    "backgroundtaskhost.exe", "smartscreen.exe","sppsvc.exe",
    "msdtc.exe",          "lsass.exe",          "services.exe",
    "csrss.exe",          "wininit.exe",        "winlogon.exe",
    "system",             "audiodg.exe",        "audioses.dll",
}

# ─── Event IDs to drop entirely ───────────────────────────────────────────────
DROPPED_EVENT_IDS = {
    4703,   # Token rights adjusted — extremely noisy, low value
    4658,   # Handle to object closed
    4656,   # Handle to object requested (too noisy)
    5379,   # Credential Manager credentials read — constant noise
    4798,   # User's local group membership enumerated
    4799,   # Security-enabled local group membership was enumerated
}

# ─── IPv4 regex ───────────────────────────────────────────────────────────────
_IPV4_RE = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')


# ─────────────────────────────────────────────────────────────────────────────
# Rate limiter — prevents identical event bursts flooding the queue
# ─────────────────────────────────────────────────────────────────────────────

class _RateLimiter:
    """
    Allows at most 1 pass per (event_id, user, ip) key per RATE_LIMIT_WINDOW.
    This stops Kali brute-force from sending 200 identical 4625 records/sec
    into the dashboard while still triggering detection rules.
    """
    def __init__(self, window: float = RATE_LIMIT_WINDOW):
        self._seen:   Dict[tuple, float] = {}
        self._window: float = window
        self._lock = threading.Lock()

    def allow(self, event_id: int, user: str, ip: str) -> bool:
        key = (event_id, user or "", ip or "")
        now = time.time()
        with self._lock:
            last = self._seen.get(key, 0.0)
            if now - last >= self._window:
                self._seen[key] = now
                # Periodic cleanup — remove entries older than 60 s
                if len(self._seen) > 5000:
                    cutoff = now - 60
                    self._seen = {k: v for k, v in self._seen.items()
                                  if v > cutoff}
                return True
        return False


_rate_limiter = _RateLimiter()


# ─────────────────────────────────────────────────────────────────────────────
# Internal helpers
# ─────────────────────────────────────────────────────────────────────────────

def _safe_insert(inserts: List[str], idx: int) -> str:
    """Return StringInserts[idx] safely, or empty string."""
    try:
        v = inserts[idx]
        return v.strip() if v else ""
    except IndexError:
        return ""


def _extract_user(inserts: List[str], event_id: int) -> str:
    """
    Extract the username from StringInserts.
    Known positions per Event ID, with fallback to DOMAIN\\user scan.
    """
    known = {
        4624: 5, 4625: 5, 4634: 1,
        4648: 1, 4672: 1, 4688: 1,
        4720: 0, 4726: 0, 4740: 0,
        4697: 0, 1102: 1,
    }
    if event_id in known:
        val = _safe_insert(inserts, known[event_id])
        if val and val not in ("-", "SYSTEM", ""):
            return val
    # Fallback: DOMAIN\user format
    for ins in inserts:
        if ins and "\\" in ins:
            part = ins.split("\\")[-1].strip()
            if part and part not in ("-", "SYSTEM", ""):
                return part
    return "SYSTEM"


def _extract_ip(inserts: List[str], message: str) -> str:
    """
    Extract the source IP address from a Windows event.

    Windows stores "Source Network Address" at StringInsert positions 18/19
    for logon events (4624, 4625, 4648, 4740).  We check those positions
    first, then scan all inserts, then fall back to the formatted message.

    This is what PowerShell's Get-WinEvent shows as:
        Network Information:
            Source Network Address: 192.168.56.102

    Returns "" if no valid routable IP is found.
    """
    def _is_valid(ip: str) -> bool:
        if not ip or ip in ("-", "::1", "::", "-", "LOCAL"):
            return False
        if ip.startswith(("127.", "0.", "169.254.", "::")):
            return False
        return True

    # 1. Check known positions first (fastest, most accurate)
    for idx in (18, 19, 12, 13, 14, 20, 21):
        val = _safe_insert(inserts, idx)
        if not val:
            continue
        # Direct IP check
        if _is_valid(val) and _IPV4_RE.fullmatch(val.strip()):
            return val.strip()
        # Regex inside the value
        m = _IPV4_RE.search(val)
        if m and _is_valid(m.group()):
            return m.group()

    # 2. Scan all inserts
    for ins in inserts:
        m = _IPV4_RE.search(ins or "")
        if m and _is_valid(m.group()):
            return m.group()

    # 3. Parse the formatted message for "Source Network Address: X.X.X.X"
    #    This is the EXACT same field PowerShell shows.
    if message:
        patterns = [
            r'Source Network Address[:\s]+([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})',
            r'Network Address[:\s]+([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})',
            r'Workstation Name[:\s]+.*?([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})',
        ]
        for pattern in patterns:
            m = re.search(pattern, message, re.IGNORECASE)
            if m and _is_valid(m.group(1)):
                return m.group(1)

        # Fallback: any IPv4 in the message
        m = _IPV4_RE.search(message)
        if m and _is_valid(m.group()):
            return m.group()

    return ""


def _ts_to_str(ts_obj) -> str:
    """Convert a pywintypes datetime to 'YYYY-MM-DD HH:MM:SS'."""
    try:
        return ts_obj.Format("%Y-%m-%d %H:%M:%S")
    except Exception:
        return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def _record_to_dict(record, channel: str) -> Optional[Dict[str, Any]]:
    """
    Convert a raw pywin32 EVENTLOGRECORD into a structured dict.

    Returns None for events that should be silently dropped (noise filter).
    All downstream modules use the field  "ip"  (unified key).
    """
    event_id = record.EventID & 0xFFFF

    # ── Noise filter: drop useless event IDs entirely ─────────────────────
    if event_id in DROPPED_EVENT_IDS:
        return None

    meta     = EVENT_META.get(event_id, {"event_type": "generic", "severity": "INFO"})
    inserts: List[str] = list(record.StringInserts or [])

    # ── Format the human-readable message ─────────────────────────────────
    try:
        message = win32evtlogutil.SafeFormatMessage(record, channel)
    except Exception:
        message = " | ".join(str(s) for s in inserts)

    # ── Extract user and IP ────────────────────────────────────────────────
    user = _extract_user(inserts, event_id)

    # IP extraction: run for ALL logon/account events, not just 4625
    ip = ""
    if event_id in (4624, 4625, 4648, 4740, 4634, 4756, 4720):
        ip = _extract_ip(inserts, message)

    # ── Noise filter: drop benign 4688 (process creation) events ──────────
    if event_id == 4688:
        proc_raw = (_safe_insert(inserts, 5) or
                    _safe_insert(inserts, 4) or
                    _safe_insert(inserts, 6) or "").lower()
        # Extract just the executable name from full path
        proc_name = proc_raw.split("\\")[-1].strip()
        if proc_name in BENIGN_PROCESSES:
            return None

    # ── Rate limiting — drop duplicates in short bursts ───────────────────
    # Allow brute-force to pass through (detection needs the count), but
    # smooth the rate so the dashboard doesn't get flooded.
    # We allow up to 1 identical (event_id, user, ip) per RATE_LIMIT_WINDOW.
    # Exception: events with different IPs always pass (each IP is distinct).
    if not _rate_limiter.allow(event_id, user, ip):
        return None

    # ── Build the structured record ────────────────────────────────────────
    entry: Dict[str, Any] = {
        "timestamp":     _ts_to_str(record.TimeGenerated),
        "event_id":      event_id,
        "channel":       channel,
        "source":        record.SourceName,
        "computer":      record.ComputerName,
        "record_number": record.RecordNumber,
        "event_type":    meta["event_type"],
        "severity":      meta["severity"],
        "user":          user,
        "ip":            ip,          # ← unified field name used by all modules
        "message":       (message or "")[:600],
        "raw_inserts":   inserts[:14],
        "process_name":  "",
        "logon_type":    "",
        "privileges":    "",
        "cmdline":       "",
    }

    # ── Per-event enrichment ───────────────────────────────────────────────
    if event_id == 4688:
        proc = (_safe_insert(inserts, 5) or
                _safe_insert(inserts, 4) or "").lower()
        proc_name = proc.split("\\")[-1]
        cmd  = (_safe_insert(inserts, 8) or
                _safe_insert(inserts, 9) or "").lower()
        entry["process_name"] = proc_name
        entry["cmdline"]      = cmd
        if proc_name in SUSPICIOUS_PROCESSES:
            entry["severity"]   = "HIGH"
            entry["event_type"] = "suspicious_process"

    elif event_id in (4624, 4625, 4648):
        entry["logon_type"] = _safe_insert(inserts, 8)

    elif event_id == 4672:
        entry["privileges"] = _safe_insert(inserts, 2)

    elif event_id == 4104:
        script = _safe_insert(inserts, 2)
        entry["message"]  = (script or message or "")[:800]
        entry["cmdline"]  = (script or "").lower()

    return entry


# ─────────────────────────────────────────────────────────────────────────────
# Single-channel tail generator
# ─────────────────────────────────────────────────────────────────────────────

def _tail_channel(channel: str) -> Generator[Dict[str, Any], None, None]:
    """Open *channel* and yield every NEW event record as a dict."""
    if not HAS_PYWIN32:
        return

    try:
        handle = win32evtlog.OpenEventLog(None, channel)
    except Exception as exc:
        print(f"  [Agent] Cannot open '{channel}': {exc}")
        print("          TIP: Run as Administrator for the Security channel.")
        return

    try:
        total  = win32evtlog.GetNumberOfEventLogRecords(handle)
        oldest = win32evtlog.GetOldestEventLogRecord(handle)
        cursor = oldest + total
    except Exception:
        cursor = 0

    print(f"  [Agent] Monitoring '{channel}'  (start cursor #{cursor})")

    flags = (win32evtlog.EVENTLOG_FORWARDS_READ |
             win32evtlog.EVENTLOG_SEEK_READ)

    while True:
        try:
            events = win32evtlog.ReadEventLog(handle, flags, cursor)
        except pywintypes.error as err:
            if err.winerror in (1, 38, 87):   # EOF — no new records
                time.sleep(POLL_INTERVAL)
                continue
            print(f"  [Agent] ReadEventLog error on '{channel}': {err}")
            time.sleep(POLL_INTERVAL)
            continue
        except Exception as err:
            print(f"  [Agent] Unexpected error on '{channel}': {err}")
            time.sleep(POLL_INTERVAL)
            continue

        if events:
            try:
                for record in events:
                    cursor = record.RecordNumber + 1
                    entry = _record_to_dict(record, channel)
                    if entry is not None:      # None = filtered out
                        yield entry
            except Exception as err:
                print(f"  [Agent] Error processing event on '{channel}': {err}")
                # Continue to next batch, don't update cursor to avoid skipping
        else:
            time.sleep(POLL_INTERVAL)


# ─────────────────────────────────────────────────────────────────────────────
# Public API — multi-channel event stream
# ─────────────────────────────────────────────────────────────────────────────

def stream_events(
    channels: Optional[List[str]] = None
) -> Generator[Dict[str, Any], None, None]:
    """
    Yield Windows Event Log records from ALL specified channels in real-time.
    One daemon thread per channel; results merge through a shared Queue.

    Usage:
        for event in stream_events(["Security", "System"]):
            process(event)
    """
    if channels is None:
        channels = [
            "Security",
            "System",
            "Microsoft-Windows-PowerShell/Operational",
        ]

    q: queue.Queue = queue.Queue(maxsize=MAX_QUEUE_SIZE)

    def _worker(ch: str) -> None:
        for evt in _tail_channel(ch):
            try:
                q.put_nowait(evt)
            except queue.Full:
                pass   # drop when queue is full — better than blocking

    for ch in channels:
        t = threading.Thread(
            target=_worker, args=(ch,),
            daemon=True, name=f"siem-{ch}"
        )
        t.start()

    while True:
        try:
            yield q.get(timeout=1.0)
        except queue.Empty:
            continue
