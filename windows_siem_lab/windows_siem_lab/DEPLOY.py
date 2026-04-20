#!/usr/bin/env python3
"""
DEPLOYMENT ASSISTANT for Windows SIEM FIXED

This script automates the deployment of the fixed SIEM codebase.
Run this to replace original files with fixed versions.
"""

import shutil
import os
from pathlib import Path

def main():
    print("\n" + "="*70)
    print("  🚀 Windows SIEM — FIXED VERSION DEPLOYMENT")
    print("="*70 + "\n")
    
    base_dir = Path(".")
    
    # Files to replace
    replacements = {
        "windows_agent_fixed.py": "windows_agent.py",
        "parser_module_fixed.py": "parser_module.py",
        "detection_rules_fixed.py": "detector.py",
        "alert_system_fixed.py": "alert_system.py",
        "storage_fixed.py": "storage.py",
        "dashboard_fixed.py": "dashboard.py",
        "main_fixed.py": "main.py",
    }
    
    print("📦 Step 1: Backing up original files...\n")
    backup_dir = base_dir / "backup_original"
    backup_dir.mkdir(exist_ok=True)
    
    for target_file in replacements.values():
        src = base_dir / target_file
        if src.exists():
            dst = backup_dir / target_file
            shutil.copy(src, dst)
            print(f"   ✓ Backed up: {target_file}")
    
    print(f"\n   📁 Backups saved to: {backup_dir}\n")
    
    print("🔧 Step 2: Deploying FIXED versions...\n")
    
    for fixed_file, target_file in replacements.items():
        src = base_dir / fixed_file
        dst = base_dir / target_file
        
        if src.exists():
            shutil.copy(src, dst)
            print(f"   ✓ Deployed: {fixed_file} → {target_file}")
        else:
            print(f"   ⚠ Not found: {fixed_file}")
    
    print("\n" + "="*70)
    print("  ✅ DEPLOYMENT COMPLETE!")
    print("="*70 + "\n")
    
    print("📋 QUICK START (Run as Administrator):\n")
    print("   1. Open PowerShell as ADMINISTRATOR")
    print("   2. cd 'c:\\Users\\Nitro 5\\Downloads\\windows_siem_lab\\windows_siem_lab'")
    print("   3. python main.py --dashboard\n")
    
    print("🌐 Dashboard:")
    print("   http://127.0.0.1:5000\n")
    
    print("🎯 FIXES APPLIED:\n")
    print("   ✅ Attacker IP extraction — XML parsing from Windows events")
    print("   ✅ Dashboard noise filtered — removed python.exe, svchost.exe")
    print("   ✅ Rate limiting enabled — prevents alert spam (10/10s)")
    print("   ✅ Deduplication enabled — same rule from same IP (60s window)")
    print("   ✅ Top Attacking IPs now working — populated correctly")
    print("   ✅ Correlated Incidents working — grouped by attacker IP")
    print("   ✅ All detection rules improved — proper IP field handling\n")
    
    print("📊 DETECTION RULES:\n")
    rules = [
        ("brute_force", "4625 failed network logons", "HIGH"),
        ("account_lockout", "4740 account locked out", "HIGH"),
        ("success_after_failures", "4624 after 3+ fails", "CRITICAL"),
        ("privilege_escalation", "4672 dangerous privs", "CRITICAL"),
        ("privilege_escalation_sequence", "4672 repeated x3", "CRITICAL"),
        ("suspicious_process", "4688 PowerShell/CMD/etc", "HIGH"),
        ("encoded_powershell", "4688/4104 -enc/-bypass", "CRITICAL"),
        ("pass_the_hash", "4648 explicit creds", "CRITICAL"),
        ("lateral_movement", "4624 type-3 burst x3", "HIGH"),
        ("admin_tool_abuse", "4688 admin tools", "HIGH"),
        ("service_installed", "4697/7045 new service", "HIGH"),
        ("audit_log_cleared", "1102 anti-forensics", "CRITICAL"),
        ("account_enumeration", "4625 3+ users from IP", "MEDIUM"),
        ("rapid_user_switching", "4624 4+ users in 60s", "MEDIUM"),
    ]
    
    for rule, trigger, severity in rules:
        print(f"   • {rule:30} → {trigger:40} [{severity}]")
    
    print("\n📝 FIELD MAPPING (Fixed):\n")
    print("   windows_agent.py produces:    'source_ip'")
    print("   parser_module.py outputs:     'ip' and 'source_ip' (alias)")
    print("   detection rules use:          'ip' (consistent)")
    print("   dashboard API returns:        'ip', 'attacker_ip'\n")
    
    print("🧪 TEST ATTACKS:\n")
    print("   # Brute-force attempt (4625)")
    print("   runas /user:invaliduser cmd.exe")
    print("   [enter any password → fails]\n")
    
    print("   # Process creation event (4688)")
    print("   powershell -Command Get-Process\n")
    
    print("   # Encoded PowerShell command (CRITICAL)")
    print("   powershell -enc JABwAHIAbwBjAGUAcwBzAGUAcwA=\n")
    
    print("📁 FILE STRUCTURE:\n")
    print("   windows_agent.py         ← XML IP extraction")
    print("   parser_module.py         ← Field mapping fix")
    print("   detector.py              ← All 14 detection rules")
    print("   alert_system.py          ← Rate limiting + dedup")
    print("   storage.py               ← Correlation logic")
    print("   dashboard.py             ← Updated endpoints")
    print("   main.py                  ← Entry point\n")
    
    print("💡 KEY IMPROVEMENTS:\n")
    print("   1. IP Extraction: Uses XML parsing from event data, not StringInserts")
    print("   2. Noise Filtering: 4703 events skipped, python.exe filtered")
    print("   3. Rate Limiting: 10 alerts per 10 seconds max")
    print("   4. Deduplication: Same rule from same IP only fires every 60s")
    print("   5. Correlation: Top IPs + Incidents grouped automatically")
    print("   6. Field Consistency: All code uses 'ip' field\n")
    
    print("="*70 + "\n")

if __name__ == "__main__":
    main()
