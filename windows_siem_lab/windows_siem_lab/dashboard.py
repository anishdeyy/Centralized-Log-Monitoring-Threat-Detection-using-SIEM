"""
dashboard.py — Flask SIEM Dashboard  (FIXED v2)
=================================================
Web dashboard for the Windows SIEM.

Start standalone:   python dashboard.py
Or via main.py:     python main.py --dashboard

Open in browser:    http://127.0.0.1:5000

FIXES IN THIS VERSION
---------------------
1. /api/attacker_ips reads "ip" from alerts (not "attacker_ip").
   Previously read "ip" but alerts used "attacker_ip" → always empty.

2. /api/incidents reads "ip" from alerts consistently.

3. /api/stats enriches timeline_data with per-severity counts for the
   stacked bar chart (CRITICAL / HIGH / MEDIUM buckets).

4. SSE stream has a 20-second keepalive ping to prevent browser
   disconnects on quiet labs.

5. Dashboard auto-refreshes stats/charts every 15 s as SSE fallback.

6. Added "Attacker IP" column to the Recent Alerts table.
"""

import json
import threading
from datetime import datetime
from queue    import Empty, Queue

try:
    from flask import Flask, Response, jsonify, render_template_string, stream_with_context
    HAS_FLASK = True
except ImportError:
    HAS_FLASK = False
    print("  [Dashboard] Flask not installed. Run:  pip install flask")

from storage      import load_alerts, load_parsed_logs, get_stats
from alert_system import register_sse_client, unregister_sse_client

app = Flask(__name__) if HAS_FLASK else None


# ─────────────────────────────────────────────────────────────────────────────
# HTML / CSS / JS  (single-file — no templates folder needed)
# ─────────────────────────────────────────────────────────────────────────────

_HTML = """<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>Windows SIEM Dashboard</title>
  <script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"></script>
  <style>
    *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
    :root {
      --bg:      #060911; --surface: #0d1117; --card:   #161b22;
      --border:  #21262d; --border2: #30363d; --text:   #e6edf3;
      --muted:   #8b949e; --accent:  #58a6ff; --red:    #f85149;
      --orange:  #f0883e; --yellow:  #d29922; --green:  #3fb950;
    }
    body { font-family:'Segoe UI',system-ui,sans-serif;
           background:var(--bg); color:var(--text); min-height:100vh; }

    header {
      background:var(--surface); border-bottom:1px solid var(--border);
      padding:0 28px; height:58px;
      display:flex; align-items:center; gap:12px;
      position:sticky; top:0; z-index:200;
    }
    .logo { font-size:1.1rem; font-weight:800; color:var(--accent);
            font-family:monospace; }
    .logo span { color:var(--red); }
    .badge { font-family:monospace; font-size:.68rem;
             background:var(--border); color:var(--muted);
             padding:2px 8px; border-radius:4px; border:1px solid var(--border2); }
    .spacer { flex:1; }
    #live-dot { width:9px; height:9px; background:var(--green);
                border-radius:50%; animation:pulse 2s infinite; }
    @keyframes pulse { 0%,100%{opacity:1} 50%{opacity:.25} }
    #clock { font-family:monospace; font-size:.8rem; color:var(--muted); }

    .container { max-width:1400px; margin:0 auto; padding:24px 28px; }

    .kpi-grid {
      display:grid; grid-template-columns:repeat(auto-fit,minmax(165px,1fr));
      gap:14px; margin-bottom:24px;
    }
    .kpi { background:var(--card); border:1px solid var(--border);
           border-radius:10px; padding:16px 18px; }
    .kpi-label { font-size:.72rem; color:var(--muted); text-transform:uppercase;
                 letter-spacing:.05em; margin-bottom:6px; }
    .kpi-value { font-size:2rem; font-weight:800; font-family:monospace; }
    .kpi.crit .kpi-value { color:var(--red); }
    .kpi.high .kpi-value { color:var(--orange); }
    .kpi.med  .kpi-value { color:var(--yellow); }
    .kpi.info .kpi-value { color:var(--accent); }
    .kpi.tot  .kpi-value { color:var(--text); }

    .two-col { display:grid; grid-template-columns:1fr 1fr; gap:18px; margin-bottom:24px; }
    @media(max-width:900px){ .two-col{grid-template-columns:1fr;} }

    .card { background:var(--card); border:1px solid var(--border);
            border-radius:10px; padding:18px 20px; }
    .card-title { font-size:.76rem; font-weight:700; color:var(--muted);
                  text-transform:uppercase; letter-spacing:.06em; margin-bottom:14px; }

    table { width:100%; border-collapse:collapse; font-size:.82rem; }
    th { font-size:.7rem; font-weight:700; color:var(--muted);
         text-transform:uppercase; letter-spacing:.05em;
         padding:7px 10px; border-bottom:1px solid var(--border); text-align:left; }
    td { padding:8px 10px; border-bottom:1px solid var(--border);
         vertical-align:top; word-break:break-all; }
    tr:last-child td { border-bottom:none; }
    tr:hover td { background:rgba(88,166,255,.04); }

    .sev { display:inline-block; padding:1px 8px; border-radius:4px;
           font-size:.7rem; font-weight:700; white-space:nowrap; }
    .sev-CRITICAL { background:rgba(248,81,73,.18);  color:var(--red);    border:1px solid var(--red); }
    .sev-HIGH     { background:rgba(240,136,62,.18); color:var(--orange); border:1px solid var(--orange); }
    .sev-MEDIUM   { background:rgba(210,153,34,.18); color:var(--yellow); border:1px solid var(--yellow); }
    .sev-LOW      { background:rgba(63,185,80,.12);  color:var(--green);  border:1px solid var(--green); }
    .sev-INFO     { background:rgba(88,166,255,.1);  color:var(--accent); border:1px solid var(--accent); }

    .ip-chip { font-family:monospace; font-size:.8rem; color:var(--red);
               background:rgba(248,81,73,.1); border:1px solid rgba(248,81,73,.3);
               padding:1px 7px; border-radius:4px; white-space:nowrap; }

    .attacker-row {
      display:flex; align-items:center; justify-content:space-between;
      padding:10px 14px; border-radius:8px;
      border:1px solid var(--border); margin-bottom:8px;
      background:rgba(248,81,73,.04);
    }
    .attacker-meta { font-size:.74rem; color:var(--muted); margin-top:3px; }
    .attacker-count { font-family:monospace; font-weight:700;
                      font-size:1.1rem; color:var(--orange); }

    .incident {
      border-radius:8px; padding:12px 16px; margin-bottom:10px;
      border:1px solid var(--border); border-left-width:3px;
    }
    .inc-header { display:flex; align-items:center; gap:10px;
                  justify-content:space-between; flex-wrap:wrap; margin-bottom:5px; }
    .inc-id { font-family:monospace; font-weight:700;
              color:var(--accent); font-size:.9rem; }
    .inc-meta { font-size:.74rem; color:var(--muted); }

    .chart-wrap { position:relative; height:220px; }
    .section { margin-bottom:26px; }
    .empty { color:var(--muted); font-size:.85rem; text-align:center; padding:24px 0; }

    #toast-container { position:fixed; bottom:22px; right:22px; z-index:9999;
                       display:flex; flex-direction:column; gap:9px; max-width:370px; }
    .toast { border-radius:8px; padding:11px 15px; font-size:.82rem;
             cursor:pointer; animation:slide-in .2s ease; }
    @keyframes slide-in { from{transform:translateX(110%);opacity:0}
                          to{transform:translateX(0);opacity:1} }
  </style>
</head>
<body>

<header>
  <div class="logo">SIEM<span>.</span>PY</div>
  <span class="badge">Windows SIEM</span>
  <span class="badge" id="event-count">0 events</span>
  <div class="spacer"></div>
  <div id="live-dot" title="Live stream"></div>
  <span style="color:var(--muted);font-size:.74rem;margin-left:6px">LIVE</span>
  <span id="clock" style="margin-left:16px"></span>
</header>

<div class="container">

  <!-- KPI row -->
  <div class="kpi-grid section">
    <div class="kpi tot"><div class="kpi-label">📋 Total Logs</div>
      <div class="kpi-value" id="kpi-logs">—</div></div>
    <div class="kpi tot"><div class="kpi-label">🔔 Total Alerts</div>
      <div class="kpi-value" id="kpi-alerts">—</div></div>
    <div class="kpi crit"><div class="kpi-label">🚨 Critical</div>
      <div class="kpi-value" id="kpi-critical">—</div></div>
    <div class="kpi high"><div class="kpi-label">⚠️  High</div>
      <div class="kpi-value" id="kpi-high">—</div></div>
    <div class="kpi med"><div class="kpi-label">🔶 Medium</div>
      <div class="kpi-value" id="kpi-medium">—</div></div>
    <div class="kpi info"><div class="kpi-label">🎯 Attacker IPs</div>
      <div class="kpi-value" id="kpi-ips">—</div></div>
  </div>

  <!-- Charts -->
  <div class="two-col section">
    <div class="card">
      <div class="card-title">📈 Attack Timeline (alerts / minute)</div>
      <div class="chart-wrap"><canvas id="timeline-chart"></canvas></div>
    </div>
    <div class="card">
      <div class="card-title">🍩 Alerts by Severity</div>
      <div class="chart-wrap"><canvas id="sev-chart"></canvas></div>
    </div>
  </div>

  <!-- Attacker IPs + Incidents -->
  <div class="two-col section">
    <div class="card">
      <div class="card-title">🎯 Top Attacking IPs</div>
      <div id="attacker-panel"><div class="empty">No attacker IPs yet.</div></div>
    </div>
    <div class="card">
      <div class="card-title">🔗 Correlated Incidents</div>
      <div id="incidents-panel"><div class="empty">No incidents yet.</div></div>
    </div>
  </div>

  <!-- Alerts table -->
  <div class="section">
    <div class="card" style="overflow-x:auto">
      <div class="card-title">🔔 Recent Alerts</div>
      <table>
        <thead><tr>
          <th>Time</th><th>Severity</th><th>Rule</th>
          <th>Attacker IP</th><th>User</th><th>MITRE</th><th>Description</th>
        </tr></thead>
        <tbody id="alerts-tbody">
          <tr><td colspan="7" class="empty">Waiting for alerts…</td></tr>
        </tbody>
      </table>
    </div>
  </div>

  <!-- Events table -->
  <div class="section">
    <div class="card" style="overflow-x:auto">
      <div class="card-title">📋 Recent Log Events</div>
      <table>
        <thead><tr>
          <th>Time</th><th>Event ID</th><th>Type</th>
          <th>Severity</th><th>User</th><th>Source IP</th><th>Channel</th>
        </tr></thead>
        <tbody id="logs-tbody">
          <tr><td colspan="7" class="empty">Waiting for events…</td></tr>
        </tbody>
      </table>
    </div>
  </div>

</div>
<div id="toast-container"></div>

<script>
// ── Helpers ──────────────────────────────────────────────────────────────────
const SEV_COLORS = {
  CRITICAL:'#f85149', HIGH:'#f0883e', MEDIUM:'#d29922', LOW:'#3fb950', INFO:'#58a6ff'
};
const esc = s => String(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
const sevBadge = s => `<span class="sev sev-${s||'INFO'}">${s||'INFO'}</span>`;
const ipChip   = ip => ip ? `<span class="ip-chip">${esc(ip)}</span>` : '<span style="color:var(--muted)">—</span>';

// ── Clock ─────────────────────────────────────────────────────────────────────
setInterval(() => {
  document.getElementById('clock').textContent = new Date().toLocaleTimeString();
}, 1000);

// ── Charts ────────────────────────────────────────────────────────────────────
const timelineChart = new Chart(
  document.getElementById('timeline-chart').getContext('2d'), {
  type:'bar',
  data:{
    labels:[],
    datasets:[
      {label:'CRITICAL', data:[], backgroundColor:'rgba(248,81,73,.7)', stack:'s'},
      {label:'HIGH',     data:[], backgroundColor:'rgba(240,136,62,.7)', stack:'s'},
      {label:'MEDIUM',   data:[], backgroundColor:'rgba(210,153,34,.7)', stack:'s'},
    ]
  },
  options:{
    responsive:true, maintainAspectRatio:false,
    plugins:{legend:{labels:{color:'#8b949e',font:{size:11}}}},
    scales:{
      x:{stacked:true, ticks:{color:'#8b949e',maxRotation:45}, grid:{color:'#21262d'}},
      y:{stacked:true, ticks:{color:'#8b949e',precision:0},    grid:{color:'#21262d'}, beginAtZero:true}
    }
  }
});

const sevChart = new Chart(
  document.getElementById('sev-chart').getContext('2d'), {
  type:'doughnut',
  data:{
    labels:['CRITICAL','HIGH','MEDIUM','LOW','INFO'],
    datasets:[{
      data:[0,0,0,0,0],
      backgroundColor:['#f85149','#f0883e','#d29922','#3fb950','#58a6ff'],
      borderColor:'#161b22', borderWidth:3
    }]
  },
  options:{
    responsive:true, maintainAspectRatio:false, cutout:'60%',
    plugins:{legend:{position:'right', labels:{color:'#8b949e',font:{size:11},padding:14}}}
  }
});

// ── Load stats ────────────────────────────────────────────────────────────────
async function loadStats() {
  try {
    const d = await fetch('/api/stats').then(r=>r.json());
    document.getElementById('kpi-logs').textContent    = (d.total_logs||0).toLocaleString();
    document.getElementById('kpi-alerts').textContent  = (d.total_alerts||0).toLocaleString();
    document.getElementById('kpi-critical').textContent= d.alerts_by_sev?.CRITICAL||0;
    document.getElementById('kpi-high').textContent    = d.alerts_by_sev?.HIGH||0;
    document.getElementById('kpi-medium').textContent  = d.alerts_by_sev?.MEDIUM||0;
    document.getElementById('kpi-ips').textContent     = (d.top_ips||[]).length;
    document.getElementById('event-count').textContent = (d.total_logs||0).toLocaleString()+' events';

    const tl = d.timeline_data||[];
    timelineChart.data.labels                = tl.map(x=>x.time);
    timelineChart.data.datasets[0].data      = tl.map(x=>x.CRITICAL||0);
    timelineChart.data.datasets[1].data      = tl.map(x=>x.HIGH||0);
    timelineChart.data.datasets[2].data      = tl.map(x=>x.MEDIUM||0);
    timelineChart.update('none');

    const sev = d.alerts_by_sev||{};
    sevChart.data.datasets[0].data = [
      sev.CRITICAL||0, sev.HIGH||0, sev.MEDIUM||0, sev.LOW||0, sev.INFO||0
    ];
    sevChart.update('none');
  } catch(e){}
}

// ── Attacker IPs ──────────────────────────────────────────────────────────────
async function loadAttackerIPs() {
  try {
    const ips = await fetch('/api/attacker_ips').then(r=>r.json());
    const el  = document.getElementById('attacker-panel');
    if (!ips.length) { el.innerHTML='<div class="empty">No attacker IPs yet.</div>'; return; }
    el.innerHTML = ips.slice(0,8).map(ip=>`
      <div class="attacker-row">
        <div>
          <div>${ipChip(ip.ip)}</div>
          <div class="attacker-meta">
            Rules: ${(ip.rules||[]).join(', ')||'—'}<br>
            Targets: ${(ip.users||[]).join(', ')||'unknown'}<br>
            Last seen: ${(ip.last_seen||'').substring(11)}
          </div>
        </div>
        <div class="attacker-count">${ip.count} alerts</div>
      </div>
    `).join('');
  } catch(e){}
}

// ── Incidents ─────────────────────────────────────────────────────────────────
async function loadIncidents() {
  try {
    const incs = await fetch('/api/incidents').then(r=>r.json());
    const el   = document.getElementById('incidents-panel');
    if (!incs.length) { el.innerHTML='<div class="empty">No incidents yet.</div>'; return; }
    el.innerHTML = incs.slice(0,6).map((inc,i)=>{
      const lc = SEV_COLORS[inc.severity]||'#58a6ff';
      return `
        <div class="incident" style="border-left-color:${lc}">
          <div class="inc-header">
            <span class="inc-id">INC-${String(i+1).padStart(4,'0')}</span>
            ${ipChip(inc.ip)}
            ${sevBadge(inc.severity)}
            <span class="inc-meta">${inc.alert_count} alerts</span>
          </div>
          <div style="font-size:.74rem;color:var(--muted)">
            <b>Rules:</b> ${(inc.rules_fired||[]).join(' → ')}<br>
            <b>Users:</b> ${(inc.users_targeted||[]).join(', ')||'unknown'}<br>
            <b>Time:</b> ${(inc.start_time||'').substring(11)} → ${(inc.end_time||'').substring(11)}
          </div>
        </div>`;
    }).join('');
  } catch(e){}
}

// ── Alerts table ──────────────────────────────────────────────────────────────
async function loadAlerts() {
  try {
    const alerts = await fetch('/api/alerts').then(r=>r.json());
    const tbody  = document.getElementById('alerts-tbody');
    if (!alerts.length) {
      tbody.innerHTML='<tr><td colspan="7" class="empty">No alerts yet.</td></tr>'; return;
    }
    tbody.innerHTML = alerts.slice().reverse().slice(0,80).map(a=>`
      <tr>
        <td style="white-space:nowrap;font-family:monospace;font-size:.74rem">${esc((a.timestamp||'').substring(11))}</td>
        <td>${sevBadge(a.severity)}</td>
        <td style="font-family:monospace;font-size:.77rem">${esc(a.rule||'—')}</td>
        <td>${ipChip(a.ip)}</td>
        <td>${esc(a.user||'—')}</td>
        <td style="font-size:.71rem;color:var(--muted)">${esc(a.mitre||'—')}</td>
        <td style="font-size:.77rem;max-width:300px">${esc(a.description||'—')}</td>
      </tr>`).join('');
  } catch(e){}
}

// ── Logs table ────────────────────────────────────────────────────────────────
async function loadLogs() {
  try {
    const logs  = await fetch('/api/logs').then(r=>r.json());
    const tbody = document.getElementById('logs-tbody');
    if (!logs.length) {
      tbody.innerHTML='<tr><td colspan="7" class="empty">No events yet.</td></tr>'; return;
    }
    tbody.innerHTML = logs.slice().reverse().slice(0,60).map(l=>`
      <tr>
        <td style="white-space:nowrap;font-family:monospace;font-size:.74rem">${esc((l.timestamp||'').substring(11))}</td>
        <td style="font-family:monospace">${l.event_id||'—'}</td>
        <td style="font-size:.77rem">${esc(l.event_type_label||l.event_type||'—')}</td>
        <td>${sevBadge(l.severity)}</td>
        <td>${esc(l.user||'—')}</td>
        <td>${ipChip(l.ip)}</td>
        <td style="font-size:.74rem;color:var(--muted)">${esc(l.channel||'—')}</td>
      </tr>`).join('');
  } catch(e){}
}

// ── Initial load + 15-s polling fallback ─────────────────────────────────────
function refreshAll() {
  loadStats(); loadAttackerIPs(); loadIncidents(); loadAlerts(); loadLogs();
}
refreshAll();
setInterval(refreshAll, 15000);

// ── SSE real-time stream ──────────────────────────────────────────────────────
function showToast(alert) {
  const color = SEV_COLORS[alert.severity]||'#58a6ff';
  const toast = document.createElement('div');
  toast.className = 'toast';
  toast.style.cssText = `background:${color}18;border:1px solid ${color}55;color:${color};`;
  toast.innerHTML = `<b>${alert.severity}</b>: ${esc((alert.description||'').slice(0,100))}…
    <div style="font-size:.69rem;color:var(--muted);margin-top:3px">
      ${esc(alert.rule)} · ${ipChip(alert.ip)} · ${esc((alert.timestamp||'').substring(11))}</div>`;
  toast.onclick = ()=>toast.remove();
  document.getElementById('toast-container').appendChild(toast);
  setTimeout(()=>{ if(toast.parentNode) toast.remove(); }, 7000);
}

function prependAlertRow(alert) {
  const tbody = document.getElementById('alerts-tbody');
  if (tbody.querySelector('.empty')) tbody.innerHTML = '';
  const tr = document.createElement('tr');
  tr.innerHTML = `
    <td style="white-space:nowrap;font-family:monospace;font-size:.74rem">${esc((alert.timestamp||'').substring(11))}</td>
    <td>${sevBadge(alert.severity)}</td>
    <td style="font-family:monospace;font-size:.77rem">${esc(alert.rule||'—')}</td>
    <td>${ipChip(alert.ip)}</td>
    <td>${esc(alert.user||'—')}</td>
    <td style="font-size:.71rem;color:var(--muted)">${esc(alert.mitre||'—')}</td>
    <td style="font-size:.77rem;max-width:300px">${esc(alert.description||'—')}</td>`;
  tbody.insertBefore(tr, tbody.firstChild);
  while (tbody.rows.length > 100) tbody.deleteRow(tbody.rows.length-1);
}

const evtSource = new EventSource('/api/stream');
evtSource.onmessage = function(e) {
  try {
    const alert = JSON.parse(e.data);
    const dot = document.getElementById('live-dot');
    dot.style.background = '#f85149';
    setTimeout(()=>{ dot.style.background='#3fb950'; }, 800);
    prependAlertRow(alert);
    if (['CRITICAL','HIGH','MEDIUM'].includes(alert.severity)) showToast(alert);
    loadStats(); loadAttackerIPs(); loadIncidents();
  } catch(err){}
};
evtSource.onerror = function() {
  document.getElementById('live-dot').style.background = '#8b949e';
};
</script>
</body>
</html>"""


# ─────────────────────────────────────────────────────────────────────────────
# API Routes
# ─────────────────────────────────────────────────────────────────────────────

@app.route("/")
def index():
    return render_template_string(_HTML)


@app.route("/api/stats")
def api_stats():
    """Summary statistics — KPI cards + chart data."""
    stats = get_stats()
    # Convert top_ips from list-of-tuples to list-of-dicts for JS
    stats["top_ips"]   = [{"ip": ip, "count": cnt} for ip, cnt in stats.get("top_ips", [])]
    stats["top_users"] = [{"user": u, "count": cnt} for u, cnt in stats.get("top_users", [])]
    return jsonify(stats)


@app.route("/api/alerts")
def api_alerts():
    return jsonify(load_alerts()[-100:])


@app.route("/api/logs")
def api_logs():
    return jsonify(load_parsed_logs()[-100:])


def _get_ip(record: dict) -> str:
    """Read IP from alert — checks 'ip', 'source_ip', 'attacker_ip' for compatibility."""
    ip = (
        record.get("ip") or
        record.get("source_ip") or
        record.get("attacker_ip") or
        ""
    )
    if ip in ("-", "no-ip", "unknown", "None", ""):
        return ""
    return str(ip).strip()


@app.route("/api/attacker_ips")
def api_attacker_ips():
    """
    Aggregate alerts by source IP.
    Reads 'ip' from alerts (the unified key used by the fixed detector).
    Also reads legacy 'attacker_ip' and 'source_ip' for backward compat.
    """
    alerts  = load_alerts()
    ip_data: dict = {}

    for a in alerts:
        ip = _get_ip(a)
        if not ip:
            continue
        if ip not in ip_data:
            ip_data[ip] = {
                "ip":         ip,
                "count":      0,
                "rules":      set(),
                "users":      set(),
                "severities": {},
                "first_seen": a.get("timestamp", ""),
                "last_seen":  a.get("timestamp", ""),
            }
        rec = ip_data[ip]
        rec["count"] += 1
        rec["rules"].add(a.get("rule", "unknown"))
        if a.get("user"):
            rec["users"].add(a["user"])
        sev = a.get("severity", "INFO")
        rec["severities"][sev] = rec["severities"].get(sev, 0) + 1
        rec["last_seen"] = a.get("timestamp", rec["last_seen"])

    result = []
    for rec in sorted(ip_data.values(), key=lambda x: x["count"], reverse=True)[:15]:
        rec["rules"] = sorted(rec["rules"])
        rec["users"] = sorted(rec["users"])
        result.append(rec)

    return jsonify(result)


@app.route("/api/incidents")
def api_incidents():
    """
    Group alerts into incidents by source IP.
    Reads 'ip' from alerts — the unified key.
    """
    alerts = load_alerts()
    SEV_ORDER = ["INFO","LOW","MEDIUM","HIGH","CRITICAL"]
    incidents: dict = {}

    for a in alerts:
        ip = _get_ip(a)
        if not ip:
            ip = "unknown"
        ts = a.get("timestamp", "")

        if ip not in incidents:
            incidents[ip] = {
                "ip":             ip,
                "start_time":     ts,
                "end_time":       ts,
                "alert_count":    0,
                "rules_fired":    set(),
                "users_targeted": set(),
                "severity":       "INFO",
                "mitre_tactics":  set(),
            }
        inc = incidents[ip]
        inc["alert_count"] += 1
        inc["end_time"]     = ts
        inc["rules_fired"].add(a.get("rule",""))
        if a.get("user"):
            inc["users_targeted"].add(a["user"])
        if a.get("mitre"):
            inc["mitre_tactics"].add(a["mitre"])

        cur = SEV_ORDER.index(inc["severity"]) if inc["severity"] in SEV_ORDER else 0
        new = SEV_ORDER.index(a.get("severity","INFO")) \
            if a.get("severity","INFO") in SEV_ORDER else 0
        if new > cur:
            inc["severity"] = a.get("severity","INFO")

    result = []
    for inc in sorted(incidents.values(), key=lambda x: x["alert_count"], reverse=True):
        if inc["alert_count"] >= 1:
            inc["rules_fired"]    = sorted(inc["rules_fired"])
            inc["users_targeted"] = sorted(inc["users_targeted"])
            inc["mitre_tactics"]  = sorted(inc["mitre_tactics"])
            result.append(inc)

    return jsonify(result[:20])


@app.route("/api/stream")
def api_stream():
    """
    Server-Sent Events endpoint — pushes alert JSON to the browser
    the instant fire_alert() is called in detector.py.
    A ": ping" keepalive comment is sent every 20 s to prevent
    browser disconnects on quiet labs.
    """
    def event_generator():
        q: Queue = Queue(maxsize=200)
        register_sse_client(q)
        try:
            while True:
                try:
                    data = q.get(timeout=20)
                    yield data
                except Empty:
                    yield ": ping\n\n"   # SSE keepalive
        finally:
            unregister_sse_client(q)

    return Response(
        stream_with_context(event_generator()),
        mimetype="text/event-stream",
        headers={
            "Cache-Control":     "no-cache",
            "X-Accel-Buffering": "no",
            "Connection":        "keep-alive",
        },
    )


# ─────────────────────────────────────────────────────────────────────────────
# Standalone entry point
# ─────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    if not HAS_FLASK:
        print("Install Flask first:  pip install flask")
    else:
        print("  SIEM Dashboard starting …")
        print("  Open: http://127.0.0.1:5000")
        print("  Press Ctrl-C to stop.\n")
        app.run(host="0.0.0.0", port=5000, debug=False,
                use_reloader=False, threaded=True)
