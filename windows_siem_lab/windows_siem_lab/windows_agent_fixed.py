"""windows_agent.py — Windows Event Log Agent with XML IP Extraction
============================================
Reads REAL Windows Event Logs using pywin32.

Key improvements:
  • XML parsing to extract IPs reliably (not guessing StringInserts)
  • Support IP extraction for all logon events (4624, 4625, 4648)
  • Proper filtering of noisy events
  • Clean, structured output dict
"""

import queue
import re
import threading
import time
import xml.etree.ElementTree as ET
from datetime import datetime
from typing import Any, Dict, Generator, List, Optional

try:
    import win32evtlog
    import win32evtlogutil
    import pywintypes
    HAS_PYWIN32 = True
except ImportError:
    HAS_PYWIN32 = False

# ─── Configuration ────────────────────────────────────────────────────────────
POLL_INTERVAL = 2.0
BATCH_SIZE = 200

# ─── Event-ID metadata table ─────────────────────────────────────────────────
EVENT_META: Dict[int, Dict[str, str]] = {
    4624: {"event_type": "successful_login", "severity": "INFO"},
    4625: {"event_type": "failed_login", "severity": "MEDIUM"},
    4634: {"event_type": "logoff", "severity": "INFO"},
    4648: {"event_type": "explicit_cred_logon", "severity": "HIGH"},
    4672: {"event_type": "privilege_assigned", "severity": "HIGH"},
    4688: {"event_type": "process_created", "severity": "LOW"},
    4697: {"event_type": "service_installed", "severity": "HIGH"},
    4720: {"event_type": "account_created", "severity": "MEDIUM"},
    4726: {"event_type": "account_deleted", "severity": "MEDIUM"},
    4740: {"event_type": "account_lockout", "severity": "HIGH"},
    4756: {"event_type": "group_member_added", "severity": "MEDIUM"},
    7045: {"event_type": "service_installed", "severity": "HIGH"},
    1102: {"event_type": "audit_log_cleared", "severity": "CRITICAL"},
    4104: {"event_type": "powershell_script", "severity": "MEDIUM"},
}

# ─── Processes that always raise severity ────────────────────────────────────
SUSPICIOUS_PROCESSES = {
    "powershell.exe", "cmd.exe", "wscript.exe", "cscript.exe",
    "mshta.exe", "regsvr32.exe", "rundll32.exe", "certutil.exe",
    "bitsadmin.exe", "wmic.exe", "net.exe", "net1.exe",
    "at.exe", "schtasks.exe", "psexec.exe", "psexesvc.exe",
    "mimikatz.exe", "whoami.exe", "nltest.exe", "dsquery.exe",
    "sc.exe", "reg.exe", "ipconfig.exe", "netstat.exe",
}

# ─── Noise filtering ─────────────────────────────────────────────────────────
# Events to skip entirely
SKIP_EVENT_IDS = {4703}  # Privilege Use — too noisy

# Processes to skip on 4688
NOISE_PROCESSES = {
    "python.exe", "svchost.exe", "dwm.exe", "explorer.exe",
    "taskhostw.exe", "conhost.exe", "backgroundtaskhost.exe",
    "TiWorker.exe", "wininit.exe", "services.exe",
}

# ─── Regex helpers ──────────────────────────────────────────────────────────
_IPV4_RE = re.compile(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b')


def _extract_ip_from_xml(xml_str: str) -> str:
    """
    Extract source IP from Windows event XML by parsing EventData fields.
    
    Common fields:
      - IpAddress (4625, 4624)
      - SourceIp (various events)
      - ClientAddress
    """
    if not xml_str:
        return ""
    
    try:
        root = ET.fromstring(xml_str)
        
        # Define namespace
        ns = {'Event': 'http://schemas.microsoft.com/win/2004/08/events/event'}
        
        # Try to find EventData
        event_data = root.find('.//Event:EventData', ns)
        if event_data is None:
            event_data = root.find('.//EventData')
        
        if event_data is not None:
            # Look for known IP fields
            for data_elem in event_data.findall('Data'):
                name = data_elem.get('Name', '').lower()
                value = (data_elem.text or "").strip()
                
                # Check field names
                if any(x in name for x in ['ipaddress', 'sourceip', 'clientaddress', 
                                           'source network', 'workstation']):
                    ip = _validate_ip(value)
                    if ip:
                        return ip
            
            # Fallback: check all Data elements for IP-like values
            for data_elem in event_data.findall('Data'):
                value = (data_elem.text or "").strip()
                ip = _validate_ip(value)
                if ip:
                    return ip
    
    except Exception as e:
        # Silently continue if XML parsing fails
        pass
    
    # Last resort: regex search
    match = _IPV4_RE.search(xml_str)
    if match:
        ip = _validate_ip(match.group())
        if ip:
            return ip
    
    return ""


def _validate_ip(ip: str) -> str:
    """Return IP if valid, else empty string. Reject loopback, multicast, etc."""
    if not ip or not re.match(r'^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$', ip):
        return ""
    
    parts = [int(x) for x in ip.split('.')]
    if any(p > 255 for p in parts):
        return ""
    
    # Reject loopback, unspecified, link-local, multicast, broadcast
    if ip.startswith(('127.', '0.', '169.254.', '224.', '255.')):
        return ""
    
    return ip if ip != "-" else ""


def _safe_insert(inserts: List[str], idx: int) -> str:
    """Return StringInsert[idx] safely, or empty string."""
    try:
        v = inserts[idx]
        return v.strip() if v else ""
    except IndexError:
        return ""


def _extract_user(inserts: List[str], event_id: int) -> str:
    """Extract username from StringInserts (event-ID specific positions)."""
    known_positions = {
        4624: 5, 4625: 5, 4634: 1, 4648: 1, 4672: 1, 4688: 1,
        4720: 0, 4726: 0, 4740: 0, 4697: 0, 1102: 1, 7045: 0,
    }
    
    if event_id in known_positions:
        val = _safe_insert(inserts, known_positions[event_id])
        if val and val not in ("-", "SYSTEM", ""):
            return val
    
    # Fallback: scan for DOMAIN\user format
    for ins in inserts:
        if ins and "\\" in ins:
            return ins.split("\\")[-1]
    
    return "SYSTEM"


def _ts_to_str(ts_obj) -> str:
    """Convert pywintypes datetime to 'YYYY-MM-DD HH:MM:SS'."""
    try:
        return ts_obj.Format("%Y-%m-%d %H:%M:%S")
    except Exception:
        return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def _record_to_dict(record, channel: str) -> Optional[Dict[str, Any]]:
    """
    Convert raw pywin32 EVENTLOGRECORD to normalized dict.
    Returns None if event should be filtered out.
    """
    event_id = record.EventID & 0xFFFF
    
    # Skip noisy events entirely
    if event_id in SKIP_EVENT_IDS:
        return None
    
    meta = EVENT_META.get(event_id, {"event_type": "generic", "severity": "INFO"})
    inserts: List[str] = list(record.StringInserts or [])
    
    # Filter noisy 4688 events
    if event_id == 4688:
        proc = str(inserts).lower() if inserts else ""
        if any(noise in proc for noise in NOISE_PROCESSES):
            return None
    
    # Get user
    user = _extract_user(inserts, event_id)
    
    # Get message
    try:
        message = win32evtlogutil.SafeFormatMessage(record, channel)
    except Exception:
        message = ""
    
    # Extract IP from XML event data
    try:
        xml_str = record.StringInserts[-1] if record.StringInserts else ""
        if not xml_str or not xml_str.startswith('<'):
            # Try to get raw event XML
            flags = win32evtlog.EVENTLOG_FORWARDS_READ
            handle = win32evtlog.OpenEventLog(None, channel)
            try:
                events = win32evtlog.ReadEventLog(handle, flags, record.RecordNumber)
                if events:
                    xml_str = events[0].get('Data', '')
            except:
                pass
            finally:
                try:
                    win32evtlog.CloseEventLog(handle)
                except:
                    pass
    except:
        xml_str = ""
    
    # First try XML extraction, then fallback to message
    source_ip = _extract_ip_from_xml(xml_str) or _extract_ip_from_xml(message or "")
    
    # For login events, try to extract from message as backup
    if not source_ip and event_id in (4624, 4625, 4648):
        match = _IPV4_RE.search(message or "")
        if match:
            source_ip = _validate_ip(match.group())
    
    entry: Dict[str, Any] = {
        "timestamp": _ts_to_str(record.TimeGenerated),
        "event_id": event_id,
        "channel": channel,
        "source": record.SourceName,
        "computer": record.ComputerName,
        "record_number": record.RecordNumber,
        "event_type": meta["event_type"],
        "severity": meta["severity"],
        "user": user,
        "source_ip": source_ip,
        "message": (message or "")[:600],
        "raw_inserts": inserts[:12],
        "process_name": "",
        "logon_type": "",
        "privileges": "",
        "cmdline": "",
    }
    
    # Event-specific enrichment
    if event_id == 4688:
        proc = _safe_insert(inserts, 5) or _safe_insert(inserts, 4)
        cmd = _safe_insert(inserts, 8) or _safe_insert(inserts, 9)
        entry["process_name"] = proc.lower()
        entry["cmdline"] = cmd.lower()
        if any(sp in proc.lower() for sp in SUSPICIOUS_PROCESSES):
            entry["severity"] = "HIGH"
            entry["event_type"] = "suspicious_process"
    
    elif event_id in (4624, 4625, 4648):
        entry["logon_type"] = _safe_insert(inserts, 8)
    
    elif event_id == 4672:
        entry["privileges"] = _safe_insert(inserts, 2)
    
    elif event_id == 4104:
        script = _safe_insert(inserts, 2)
        entry["message"] = (script or message or "")[:800]
        entry["cmdline"] = (script or "").lower()
    
    return entry


def _tail_channel(channel: str) -> Generator[Dict[str, Any], None, None]:
    """Open channel and yield every NEW event record as a dict."""
    if not HAS_PYWIN32:
        return
    
    try:
        handle = win32evtlog.OpenEventLog(None, channel)
    except Exception as exc:
        print(f"  [Agent] Cannot open '{channel}': {exc}")
        print("         TIP: Run as Administrator for the Security channel.")
        return
    
    # Position cursor at the last existing record
    try:
        total = win32evtlog.GetNumberOfEventLogRecords(handle)
        oldest = win32evtlog.GetOldestEventLogRecord(handle)
        cursor = oldest + total
    except Exception:
        cursor = 0
    
    print(f"  [Agent] Monitoring '{channel}'  (cursor #{cursor})")
    
    flags = (win32evtlog.EVENTLOG_FORWARDS_READ |
             win32evtlog.EVENTLOG_SEEK_READ)
    
    while True:
        try:
            events = win32evtlog.ReadEventLog(handle, flags, cursor)
            if events:
                for event in events:
                    record = event
                    result = _record_to_dict(record, channel)
                    if result:
                        yield result
                    cursor = event.RecordNumber + 1
            else:
                time.sleep(POLL_INTERVAL)
        except Exception as e:
            print(f"  [Agent] Error reading {channel}: {e}")
            time.sleep(POLL_INTERVAL)


def stream_events(channels: list) -> Generator[Dict[str, Any], None, None]:
    """
    Merge streams from multiple channels (Security, System, PowerShell…).
    Runs indefinitely; yields events from any channel as they arrive.
    """
    if not HAS_PYWIN32:
        return
    
    # Queue to merge channels
    q: queue.Queue = queue.Queue()
    
    # Start one daemon thread per channel
    for channel in channels:
        def _thread_tail(ch=channel):
            for event in _tail_channel(ch):
                q.put(event)
        
        t = threading.Thread(target=_thread_tail, daemon=True)
        t.start()
    
    # Merge all channels via queue
    while True:
        try:
            event = q.get(timeout=1)
            yield event
        except queue.Empty:
            # No events in past 1 second — keep thread alive
            pass
