"""main.py — Windows SIEM Entry Point (FIXED VERSION)
====================================
Starts the Windows Event Log agent and routes events through:
  windows_agent → parser_module → detection_rules → alerts → storage

Key fixes:
  • Uses fixed modules with proper IP extraction
  • Clean pipeline with no field mapping issues
  • Proper rate limiting and deduplication in alerts
"""

import argparse
import sys
import threading
import time

# ─── ASCII Banner ────────────────────────────────────────────────────────────
BANNER = r"""
 ____  _  _____  __  __      ____  ___ _____ __  __
/ ___|(_)| ____||  \/  |    / ___|_ _| ____|  \/  |
\___ \| ||  _|  | |\/| |    \___ \| ||  _| | |\/| |
 ___) | || |___ | |  | |     ___) | || |___| |  | |
|____/|_||_____||_|  |_|    |____/___|_____|_|  |_|

  Windows Host-Based SIEM  ·  Real Event Logs  ·  No Cloud
  ─────────────────────────────────────────────────────────
  Agent   : pywin32 (Security / System / PowerShell)
  Parser  : JSON normalisation with proper IP extraction
  Detector: 14+ rules with correlation
  UI      : Flask dashboard  →  http://127.0.0.1:5000

  🚀 FIXES APPLIED:
     ✓ Attacker IP extracted from event XML
     ✓ Dashboard noise filtered (python.exe, svchost.exe)
     ✓ Rate limiting & deduplication enabled
     ✓ Top Attacking IPs working
     ✓ Correlated Incidents working
"""

RULES_SUMMARY = """
  Active Detection Rules
  ──────────────────────────────────────────────────────────────────
  Rule                        Event IDs              Severity
  ──────────────────────────────────────────────────────────────────
  brute_force                 4625 (failed logon)    HIGH
  account_lockout             4740                   HIGH
  success_after_failures      4624 after 4625s       CRITICAL
  privilege_escalation        4672 (privs)           CRITICAL
  privilege_escalation_seq    4672 repeated          CRITICAL
  suspicious_process          4688 (process)         HIGH
  encoded_powershell          4688 / 4104 (-enc)     CRITICAL
  pass_the_hash               4648 (explicit creds)  CRITICAL
  lateral_movement            4624 type-3 burst      HIGH
  admin_tool_abuse            4688 admin tools       HIGH
  service_installed           4697 / 7045            HIGH
  audit_log_cleared           1102                   CRITICAL
  account_enumeration         4625 many users        MEDIUM
  rapid_user_switching        multiple 4624s         MEDIUM
  ──────────────────────────────────────────────────────────────────

  Supports:
    ✓ Kali Linux brute-force (hydra, impacket)
    ✓ Pass-the-hash (PTH, mimikatz)
    ✓ SMB/WinRM lateral movement
    ✓ PowerShell encoded commands
    ✓ Privilege escalation detection
    ✓ Account enumeration
"""


def _start_dashboard_thread():
    """Launch Flask dashboard in background daemon thread."""
    try:
        from dashboard_fixed import app
        print("  [Dashboard] Starting at http://127.0.0.1:5000 …")
        app.run(host="0.0.0.0", port=5000, debug=False,
                use_reloader=False, threaded=True)
    except ImportError:
        print("  [Dashboard] Flask not installed — skipping (pip install flask)")
    except Exception as exc:
        print(f"  [Dashboard] Failed to start: {exc}")


def run_siem(channels: list):
    """
    Main SIEM loop — reads real Windows Event Logs and processes every event.
    
    Pipeline: raw → normalise() → append_parsed_log() → engine.evaluate()
    """
    try:
        from windows_agent_fixed import stream_events, HAS_PYWIN32
    except ImportError:
        print("\n  ERROR: windows_agent_fixed.py not found in project folder.")
        sys.exit(1)
    
    if not HAS_PYWIN32:
        print("\n  ERROR: pywin32 is not installed or not on Windows.")
        print("  Install it:  pip install pywin32")
        print("               python -m pywin32_postinstall -install")
        print("  Then re-run this script as Administrator.\n")
        sys.exit(1)
    
    from parser_module_fixed import normalise
    from detection_rules_fixed import DetectionEngine
    from storage_fixed import append_parsed_log
    
    engine = DetectionEngine()
    count = 0
    
    print(f"\n  Monitoring channels : {channels}")
    print("  Press Ctrl-C to stop.\n")
    print("  " + "─" * 58)
    
    for raw in stream_events(channels):
        parsed = normalise(raw)
        if parsed is None:
            continue
        
        append_parsed_log(parsed)
        engine.evaluate(parsed)
        
        count += 1
        # Heartbeat every 200 events
        if count % 200 == 0:
            print(f"  [SIEM] {count:,} events processed …")


def main():
    parser = argparse.ArgumentParser(
        description="Windows SIEM — reads real Windows Event Logs"
    )
    parser.add_argument(
        "--channels", nargs="+",
        default=["Security", "System", "Microsoft-Windows-PowerShell/Operational"],
        metavar="CHANNEL",
        help="Event Log channels to monitor (default: Security System PowerShell)"
    )
    parser.add_argument(
        "--dashboard", action="store_true",
        help="Also launch the Flask web dashboard on port 5000"
    )
    args = parser.parse_args()
    
    print(BANNER)
    print(RULES_SUMMARY)
    print("  Mode : LIVE  (reading real Windows Event Logs)")
    print("  NOTE : Must run as Administrator for the Security channel")
    print()
    
    # Clear previous runs
    open("parsed_logs.json", "w").close()
    open("alerts.json", "w").close()
    
    # Start dashboard if requested
    if args.dashboard:
        t = threading.Thread(target=_start_dashboard_thread, daemon=True)
        t.start()
        time.sleep(1)
    
    try:
        run_siem(args.channels)
    except KeyboardInterrupt:
        print("\n\n  SIEM stopped by user (Ctrl-C).")
        print("  Logs saved  →  parsed_logs.json")
        print("  Alerts saved →  alerts.json")
        print("  Dashboard   →  python dashboard_fixed.py")
        print()
        sys.exit(0)


if __name__ == "__main__":
    main()
