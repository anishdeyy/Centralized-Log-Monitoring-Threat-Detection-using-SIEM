# 🛡️ WINDOWS SIEM — PRODUCTION FIXED VERSION

Complete, working local Python SIEM for Windows with **proper IP extraction**, **clean dashboard**, and **working correlation**.

---

## 🚀 QUICK START

### 1. Open PowerShell as ADMINISTRATOR
```powershell
# Right-click PowerShell → "Run as Administrator"
```

### 2. Navigate to Project
```powershell
cd "C:\Users\Nitro 5\Downloads\windows_siem_lab\windows_siem_lab"
```

### 3. Run the SIEM
```powershell
python main_fixed.py --dashboard
```

### 4. Open Dashboard
```
http://127.0.0.1:5000
```

### 5. Test Attack
```powershell
# Generate failed logon events (4625)
runas /user:invaliduser cmd.exe
# Enter any password → press Enter (will fail)
```

**Expected Result:**
- Dashboard shows attacker IP: `192.168.56.101` (or your IP)
- Alert fires: "Failed network logon"
- Top Attacking IPs card shows the IP
- Correlated Incident created

---

## ✅ WHAT'S FIXED

### Issue 1: Attacker IP showing as "-"
**FIXED** ✓
- XML extraction from Windows event logs
- Works for all login events (4624, 4625, 4648)
- IPs visible in dashboard alerts and events

### Issue 2: Dashboard flooded with noise
**FIXED** ✓
- Event 4703 completely filtered
- python.exe, svchost.exe, dwm.exe removed
- Dashboard is clean and readable

### Issue 3: Alert spam (updates too fast)
**FIXED** ✓
- Rate limiting: max 10 alerts per 10 seconds
- Deduplication: same rule from same IP only fires once per 60s
- Dashboard smooth, not unreadable

### Issue 4: Top Attacking IPs always empty
**FIXED** ✓
- Correlation logic implemented
- Aggregates alerts by IP
- Shows rules triggered and users targeted

### Issue 5: Correlated Incidents always empty
**FIXED** ✓
- Groups alerts by source IP
- Shows timeline (first → last alert)
- Tracks severity, rules, users
- Updates every 5 seconds

---

## 📂 FILE STRUCTURE

```
windows_siem_lab/
├── windows_agent_fixed.py       ← XML IP extraction + noise filtering
├── parser_module_fixed.py       ← Field mapping ('source_ip' → 'ip')
├── detection_rules_fixed.py     ← All 14 rules (improved)
├── alert_system_fixed.py        ← Rate limiting + deduplication
├── storage_fixed.py             ← Correlation + incident grouping
├── dashboard_fixed.py           ← Flask UI with fixed backend
├── main_fixed.py                ← Entry point
├── parsed_logs.json             ← All parsed events (auto-created)
├── alerts.json                  ← All alerts (auto-created)
├── FIXES_EXPLAINED.md           ← Detailed technical explanation
├── DEPLOYMENT_STEPS.md          ← Deployment guide
└── DEPLOY.py                    ← Automated deployment script
```

---

## 🎯 14 DETECTION RULES

| Rule | Event IDs | Trigger | Severity |
|------|-----------|---------|----------|
| brute_force | 4625 | Network logon failures | HIGH |
| account_lockout | 4740 | Account locked | HIGH |
| success_after_failures | 4624 | Login after 3+ failures | CRITICAL |
| privilege_escalation | 4672 | Dangerous privileges assigned | HIGH/CRITICAL |
| privilege_escalation_sequence | 4672 | 3+ priv events in 120s | CRITICAL |
| suspicious_process | 4688 | PowerShell, CMD, PSExec, etc. | HIGH |
| encoded_powershell | 4688/4104 | PowerShell with -enc, bypass, hidden | CRITICAL |
| pass_the_hash | 4648 | Explicit credential use | CRITICAL |
| lateral_movement | 4624 | 3+ network logons from IP in 120s | HIGH |
| admin_tool_abuse | 4688 | Admin tools (tasklist, whoami, net) | HIGH |
| service_installed | 4697/7045 | New service creation | HIGH |
| audit_log_cleared | 1102 | Event log cleared | CRITICAL |
| account_enumeration | 4625 | 3+ failed logins, different users | MEDIUM |
| rapid_user_switching | 4624 | 4+ unique users logged in 60s | MEDIUM |

---

## 🧪 TEST ATTACKS

### Test 1: Brute Force (4625)
```powershell
# Generates failed logon events
runas /user:user1 cmd.exe
# [Enter wrong password]
runis /user:user2 cmd.exe
# [Enter wrong password]
# ... repeat 3+ times
```
**Expected:** HIGH alert, IP showing, repeated attempts detected

### Test 2: Admin Tool Abuse (4688)
```powershell
# Generates 4688 with suspicious process
powershell -Command "whoami; tasklist"
```
**Expected:** HIGH alert, PowerShell command visible

### Test 3: Encoded PowerShell (4104/4688)
```powershell
# Base64 encoded command
powershell -enc JABwAHIAbwBjAGUAcwBzAGUAcwAgAD0AIABHAGUAdAAtAFAAcgBvAGMAZQBzAHMA
```
**Expected:** CRITICAL alert, encoded PowerShell detected

---

## 📊 DASHBOARD FEATURES

### KPI Cards
- 📋 Total Logs — parsed events
- 🔔 Total Alerts — fired alerts
- 🚨 Critical Alerts
- ⚠️ High Alerts
- 🎯 Attacker IPs — unique source IPs

### Charts
- 📈 Attack Timeline — alerts per minute (60 min window)
- 🍩 Alert Severity — CRITICAL/HIGH/MEDIUM breakdown

### Tables
- 🎯 Top Attacking IPs — with rules triggered + users
- 🔗 Correlated Incidents — alerts grouped by IP
- 🔔 Recent Alerts — last 80 alerts with details
- 📋 Recent Events — last 60 log events

### Real-Time
- ⚡ Live updates every 1-5 seconds
- 🌐 SSE stream (Server-Sent Events)
- 📍 New alerts appear instantly

---

## 🔌 API ENDPOINTS

```
GET /                      → Main dashboard page
GET /api/stats            → KPI summary (json)
GET /api/alerts           → Last 100 alerts
GET /api/logs             → Last 100 events
GET /api/attacker_ips     → Top attacking IPs
GET /api/incidents        → Correlated incidents by IP
GET /api/timeline         → Alerts per minute (60 min)
GET /api/stream           → SSE real-time alert stream
```

**Example:**
```bash
curl http://127.0.0.1:5000/api/stats | jq
curl http://127.0.0.1:5000/api/attacker_ips | jq
curl http://127.0.0.1:5000/api/incidents | jq
```

---

## ⚙️ CONFIGURATION

### Rate Limiting
File: `alert_system_fixed.py`
```python
ALERT_DEDUP_WINDOW = 60  # seconds (same rule+IP)
RATE_LIMIT_THRESHOLD = 10  # max alerts
RATE_LIMIT_WINDOW = 10  # per 10 seconds
```

### Noise Filtering
File: `windows_agent_fixed.py`
```python
SKIP_EVENT_IDS = {4703}  # Skip entirely

NOISE_PROCESSES = {
    "python.exe", "svchost.exe", "dwm.exe",
    # Add more to skip...
}
```

### Detection Thresholds
File: `detection_rules_fixed.py`
```python
BRUTE_FORCE_THRESHOLD = 5  # failed logins
LATERAL_MOVE_THRESHOLD = 3  # network logons
ACCOUNT_ENUM_THRESHOLD = 3  # unique users
RAPID_USER_THRESHOLD = 4  # concurrent users
```

---

## 🔐 WINDOWS AUDIT POLICY SETUP

Enable all required audit logs (PowerShell as Admin):

```powershell
auditpol /set /category:"Account Logon" /success:enable /failure:enable
auditpol /set /category:"Logon/Logoff" /success:enable /failure:enable
auditpol /set /category:"Account Management" /success:enable /failure:enable
auditpol /set /category:"Detailed Tracking" /success:enable /failure:enable
auditpol /set /category:"System" /success:enable /failure:enable
auditpol /set /category:"Privilege Use" /success:enable /failure:enable

# Enable command-line logging
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" `
  /v ProcessCreationIncludeCmdLine_Enabled /t REG_DWORD /d 1 /f

# Enable PowerShell Script Block Logging
$p = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"
New-Item -Path $p -Force | Out-Null
Set-ItemProperty -Path $p -Name EnableScriptBlockLogging -Value 1
```

---

## 📝 DATA FILES

Both use JSON-Lines format (one JSON object per line):

### parsed_logs.json
Every normalized Windows Event Log record:
```json
{
  "timestamp": "2024-06-01 14:30:22",
  "event_id": 4625,
  "channel": "Security",
  "event_type": "failed_login",
  "user": "labuser",
  "ip": "192.168.56.102",
  "message": "An account failed to log on..."
}
```

### alerts.json
Every alert that fired:
```json
{
  "rule": "brute_force",
  "severity": "HIGH",
  "event_id": 4625,
  "user": "labuser",
  "attacker_ip": "192.168.56.102",
  "description": "Failed network logon from 192.168.56.102",
  "saved_at": "2024-06-01 14:30:22"
}
```

---

## 🐛 TROUBLESHOOTING

### "Access Denied" on Security log
**Solution:** Run PowerShell as Administrator
```powershell
# Check status
auditpol /get /category:*
```

### IPs still showing as "-"
**Verify:**
1. Running as Administrator (required for Security log)
2. Using `main_fixed.py --dashboard` (not original main.py)
3. Check parsed_logs.json for 'ip' field

### Dashboard at localhost:5000 won't load
**Check:**
```powershell
netstat -ano | findstr :5000
```
If port in use, kill process or restart Windows

### No events appearing
**Verify:**
1. Administrator mode ✓
2. Audit policies enabled ✓
3. SIEM running ✓
4. Generate test events (failed login) ✓

**Check logs:**
```bash
dir parsed_logs.json alerts.json
type parsed_logs.json | head -5  # PowerShell
```

---

## 🎓 ATTACK SCENARIOS

### Scenario 1: Kali Brute Force
```bash
# From Kali Linux
hydra -L users.txt -P pass.txt -t 4 smb://192.168.56.101
```
**Detected:** brute_force (HIGH), account_enumeration (MEDIUM), success_after_failures (CRITICAL if one succeeds)

### Scenario 2: Mimikatz Credential Theft
```powershell
# PowerShell
Invoke-Mimikatz -Command '"lsadump::sam"' -Verbose
```
**Detected:** suspicious_process (HIGH), encoded_powershell (CRITICAL)

### Scenario 3: Lateral Movement (SMB)
```powershell
# From attacker machine
psexec \\target-pc -u admin -p pass cmd.exe
```
**Detected:** lateral_movement (HIGH), privilege_escalation (CRITICAL)

### Scenario 4: Anti-Forensics
```powershell
# Clear event logs
Clear-EventLog -LogName Security
```
**Detected:** audit_log_cleared (CRITICAL)

---

## 📚 TECHNICAL DOCUMENTATION

See detailed explanations:
- **FIXES_EXPLAINED.md** — Technical details of all fixes
- **DEPLOYMENT_STEPS.md** — Step-by-step deployment

---

## 📦 DEPENDENCIES

```
pywin32>=306       # Windows Event Log API
flask>=3.0         # Web dashboard
```

Install:
```powershell
pip install -r requirements.txt
python -m pywin32_postinstall -install
```

---

## 🚢 DEPLOYMENT OPTIONS

### Option 1: Use Fixed Versions (Recommended)
```powershell
cd 'C:\Users\Nitro 5\Downloads\windows_siem_lab\windows_siem_lab'
python main_fixed.py --dashboard
```

### Option 2: Automated Deployment
```powershell
python DEPLOY.py
python main.py --dashboard
```

### Option 3: Separate Terminals
```powershell
# Terminal 1
python main_fixed.py

# Terminal 2
python dashboard_fixed.py
```

---

## 🎯 VERIFICATION CHECKLIST

- [ ] Running as Administrator
- [ ] main_fixed.py launched
- [ ] Dashboard loads at http://127.0.0.1:5000
- [ ] KPI cards showing numbers
- [ ] parsed_logs.json has >0 events
- [ ] Test attack generates alert
- [ ] Attacker IP visible in Recent Alerts
- [ ] Attacker IP visible in Top Attacking IPs
- [ ] Incident appears in Correlated Incidents
- [ ] Timeline chart has bars
- [ ] No python.exe entries in logs

---

## 🤝 SUPPORT

For issues, check FIXES_EXPLAINED.md for technical details on each component.

---

**Status:** ✅ Production Ready — All Issues Fixed

