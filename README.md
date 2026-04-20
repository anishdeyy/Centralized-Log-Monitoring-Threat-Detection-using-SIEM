# 🛡️ Windows SIEM — Python Host-Based Security Monitor

A local, Python-only SIEM that reads **real Windows Event Logs** and detects
real attacks (brute force, privilege escalation, pass-the-hash, etc.) from
tools like Hydra or Impacket running on Kali Linux.

---

## Quick Start

### 1. Install dependencies

```
pip install -r requirements.txt
python -m pywin32_postinstall -install
```

### 2. Run as Administrator

> The **Security** log requires Administrator rights.

```
# Terminal 1 — start the SIEM engine + dashboard together
python main.py --dashboard

# OR run them separately:
# Terminal 1  →  python main.py
# Terminal 2  →  python dashboard.py
```

### 3. Open the dashboard

```
http://127.0.0.1:5000
```

---

## Project Structure

```
windows_siem_lab/
├── main.py           ← Entry point — starts SIEM engine
├── windows_agent.py  ← Reads real Windows Event Logs (pywin32)
├── parser_module.py  ← Normalises raw events into clean JSON
├── detector.py       ← 14 detection rules + incident correlator
├── alert_system.py   ← Terminal alerts + SSE broadcast to dashboard
├── storage.py        ← JSON-Lines persistence (parsed_logs.json, alerts.json)
├── dashboard.py      ← Flask web dashboard (SSE + Chart.js)
├── requirements.txt  ← pip dependencies
└── README.md
```

---

## Detection Rules

| Rule | Event IDs | Severity |
|------|-----------|----------|
| Brute Force | 4625 repeated | HIGH |
| Account Lockout | 4740 | HIGH |
| Success After Failures | 4624 after 4625s | CRITICAL |
| Privilege Escalation | 4672 (dangerous privs) | CRITICAL |
| Privilege Escalation Sequence | 4672 repeated | CRITICAL |
| Suspicious Process | 4688 known-bad process | HIGH |
| Encoded PowerShell | 4688/4104 with -enc/iex | CRITICAL |
| Pass the Hash | 4648 explicit creds | CRITICAL |
| Lateral Movement | 4624 type-3 burst | HIGH |
| Admin Tool Abuse | 4688 admin tools | HIGH |
| Service Installed | 4697/7045 | HIGH |
| Audit Log Cleared | 1102 | CRITICAL |
| Account Enumeration | 4625 many usernames | MEDIUM |
| Rapid User Switching | multiple 4624s | MEDIUM |

---

## Windows Setup (Required Before Running)

### Enable audit policies (PowerShell as Admin):
```powershell
auditpol /set /category:"Account Logon"      /success:enable /failure:enable
auditpol /set /category:"Logon/Logoff"       /success:enable /failure:enable
auditpol /set /category:"Account Management" /success:enable /failure:enable
auditpol /set /category:"Detailed Tracking"  /success:enable /failure:enable
auditpol /set /category:"System"             /success:enable /failure:enable
auditpol /set /category:"Privilege Use"      /success:enable /failure:enable
```

### Enable command-line logging (needed for encoded PS detection):
```powershell
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" /v ProcessCreationIncludeCmdLine_Enabled /t REG_DWORD /d 1 /f
```

### Enable PowerShell Script Block Logging:
```powershell
$p = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"
New-Item -Path $p -Force
Set-ItemProperty -Path $p -Name EnableScriptBlockLogging -Value 1
```

---

## Output Files

| File | Contents |
|------|----------|
| `parsed_logs.json` | Every normalised Windows Event Log record |
| `alerts.json` | Every alert that fired, with rule + MITRE tactic |

Both files use JSON-Lines format (one JSON object per line).

---

## Dashboard Features

- 📊 **KPI cards** — total logs, alerts, critical/high/medium counts, attacker IPs
- 📈 **Attack timeline** — alerts per minute stacked bar chart (Chart.js)
- 🍩 **Severity donut** — proportion of alerts by severity
- 🎯 **Attacker IPs** — top attacking IPs with rules triggered and users targeted
- 🔗 **Incidents** — alerts grouped by source IP into correlated incidents
- 🔔 **Alerts table** — last 80 alerts with rule, MITRE tactic, description
- 📋 **Events table** — last 60 raw log events
- ⚡ **Real-time SSE** — alerts appear instantly without page refresh
- 🍞 **Toast popups** — floating notification for each new alert

---

*For academic use — educational cybersecurity project.*
