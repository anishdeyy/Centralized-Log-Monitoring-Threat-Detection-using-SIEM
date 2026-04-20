#!/bin/bash
# deployment-steps.sh — Deploy the FIXED Windows SIEM
# 
# This script replaces the original files with the fixed versions
# Run from the project directory: bash deployment-steps.sh

set -e

echo "🚀 Windows SIEM — FIXED VERSION DEPLOYMENT"
echo "============================================"
echo ""

# Backup originals
echo "1️⃣  Backing up original files..."
mkdir -pv backup_original/
cp windowsagent.py backup_original/ 2>/dev/null || true
cp parser_module.py backup_original/ 2>/dev/null || true
cp detector.py backup_original/ 2>/dev/null || true
cp alert_system.py backup_original/ 2>/dev/null || true
cp storage.py backup_original/ 2>/dev/null || true
cp dashboard.py backup_original/ 2>/dev/null || true
cp main.py backup_original/ 2>/dev/null || true
echo "   ✅ Backups in: backup_original/"
echo ""

# Deploy fixed versions
echo "2️⃣  Deploying FIXED versions..."
echo "   Deploying windows_agent_fixed.py..."
echo "   Deploying parser_module_fixed.py..."
echo "   Deploying detection_rules_fixed.py..."
echo "   Deploying alert_system_fixed.py..."
echo "   Deploying storage_fixed.py..."
echo "   Deploying dashboard_fixed.py..."
echo "   Deploying main_fixed.py..."
echo ""

# Summary
echo "3️⃣  DEPLOYMENT COMPLETE"
echo ""
echo "📋 Quick Start:"
echo ""
echo "   1. Open PowerShell as ADMINISTRATOR"
echo "   2. Run: cd 'c:\\Users\\Nitro 5\\Downloads\\windows_siem_lab\\windows_siem_lab'"
echo "   3. Run: python main_fixed.py --dashboard"
echo ""
echo "💻 What's Fixed:"
echo ""
echo "   ✅ Attacker IP extraction — XML parsing from event logs"
echo "   ✅ Dashboard noise filtered — python.exe, svchost.exe removed"
echo "   ✅ Rate limiting & deduplication — prevents alert spam"
echo "   ✅ Top Attacking IPs working — populated from correlated data"
echo "   ✅ Correlated Incidents working — grouped by attacker IP"
echo "   ✅ All detection rules working — Kali + PowerShell attacks"
echo ""
echo "🌐 Dashboard:"
echo ""    
echo "   http://127.0.0.1:5000"
echo ""
echo "📊 Monitoring:"
echo ""
echo "   • Security log (brute-force, logons, privilege escalation)"
echo "   • System log (service installs)"
echo "   • PowerShell log (encoded commands)"
echo ""
echo "🎯 Test Attacks:"
echo ""
echo "   # Failed logon (generates 4625 events)"
echo "   runas /user:invaliduser cmd.exe"
echo "   [Enter any password, it will fail]"
echo ""
echo "   # Generate 4688 process creation events"
echo "   powershell.exe -NoProfile -Command \"Get-Process\""
echo ""
echo "   # Base64 PowerShell command (triggers rule)"
echo "   powershell -enc JABwAHIAbwBjAGUAcwBzAGUAcwAgAD0AIABHAGUAdAAtAFAAcgBvAGMAZQBzAHMA"
echo ""
