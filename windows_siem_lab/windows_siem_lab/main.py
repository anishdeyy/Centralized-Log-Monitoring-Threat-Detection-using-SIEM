"""
main.py — Windows SIEM Entry Point
====================================
Starts the Windows Event Log agent and routes every event through:
    windows_agent → parser_module → detector → alert_system → storage

Run:
    python main.py                        # Live mode (requires pywin32 + Admin)
    python main.py --channels Security    # Monitor Security log only
    python main.py --dashboard            # Also launch the Flask dashboard

Requires:
    pip install pywin32 flask
    python -m pywin32_postinstall -install
    Run as Administrator (needed for Security channel)
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
  Agent   : pywin32  (Security / System / PowerShell)
  Parser  : JSON normalisation
  Detector: 14 rules  (brute force → audit log clear)
  UI      : Flask dashboard  →  http://127.0.0.1:5000
"""

RULES_SUMMARY = """
  Active Detection Rules
  ──────────────────────────────────────────────────────────────────
  Rule                        Trigger                        Severity
  ──────────────────────────────────────────────────────────────────
  brute_force                 ≥5 failed logins / 60 s        HIGH
  account_lockout             Event 4740                     HIGH
  success_after_failures      4624 after ≥3 failures         CRITICAL
  privilege_escalation        Event 4672 (dangerous privs)   CRITICAL
  privilege_escalation_seq    ≥3 priv events / 120 s         CRITICAL
  suspicious_process          Event 4688 known-bad proc      HIGH
  encoded_powershell          4688 -enc / bypass / iex       CRITICAL
  pass_the_hash               Event 4648 explicit creds      CRITICAL
  lateral_movement            ≥3 network logons / 120 s      HIGH
  admin_tool_abuse            4688 admin/hacking tool        HIGH
  service_installed           Event 4697 / 7045              HIGH
  audit_log_cleared           Event 1102                     CRITICAL
  account_enumeration         ≥3 usernames / IP / 120 s      MEDIUM
  rapid_user_switching        ≥4 users logged in / 60 s      MEDIUM
  ──────────────────────────────────────────────────────────────────
"""


def _start_dashboard_thread():
    """Launch Flask dashboard in a background daemon thread."""
    try:
        from dashboard import app
        print("  [Dashboard] Starting at http://127.0.0.1:5000 …")
        # use_reloader=False is required when running inside a thread
        app.run(host="0.0.0.0", port=5000, debug=False,
                use_reloader=False, threaded=True)
    except ImportError:
        print("  [Dashboard] Flask not installed — skipping (pip install flask)")
    except Exception as exc:
        print(f"  [Dashboard] Failed to start: {exc}")


def run_siem(channels: list):
    """
    Main SIEM loop — reads real Windows Event Logs and processes every event.

    Pipeline per event:
        raw dict  →  normalise()  →  append_parsed_log()  →  engine.evaluate()
    """
    try:
        from windows_agent import stream_events, HAS_PYWIN32
    except ImportError:
        print("\n  ERROR: windows_agent.py not found in project folder.")
        sys.exit(1)

    if not HAS_PYWIN32:
        print("\n  ERROR: pywin32 is not installed or not on Windows.")
        print("  Install it:  pip install pywin32")
        print("               python -m pywin32_postinstall -install")
        print("  Then re-run this script as Administrator.\n")
        sys.exit(1)

    from parser_module import normalise
    from detector      import DetectionEngine
    from storage       import append_parsed_log

    engine = DetectionEngine()
    count  = 0

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
        # Print a heartbeat line every 200 events so the user knows it's alive
        if count % 200 == 0:
            print(f"  [SIEM] {count:,} events processed …")


def main():
    parser = argparse.ArgumentParser(
        description="Windows SIEM — reads real Windows Event Logs"
    )
    parser.add_argument(
        "--channels", nargs="+",
        default=["Security", "System",
                 "Microsoft-Windows-PowerShell/Operational"],
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

    # Clear previous logs for fresh dashboard
    open("parsed_logs.json", "w").close()
    open("alerts.json", "w").close()

    # Optionally start the dashboard in the background
    if args.dashboard:
        t = threading.Thread(target=_start_dashboard_thread, daemon=True)
        t.start()
        time.sleep(1)  # give Flask a moment to bind

    try:
        run_siem(args.channels)
    except KeyboardInterrupt:
        print("\n\n  SIEM stopped by user (Ctrl-C).")
        print("  Logs saved  →  parsed_logs.json")
        print("  Alerts saved →  alerts.json")
        print("  Dashboard   →  python dashboard.py")
        print()
        sys.exit(0)


if __name__ == "__main__":
    main()
