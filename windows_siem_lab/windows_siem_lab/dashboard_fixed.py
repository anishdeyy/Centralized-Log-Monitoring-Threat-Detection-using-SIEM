"""dashboard_fixed.py — Flask SIEM Dashboard (FIXED VERSION)
=====================================
Web UI for the Windows SIEM.

Start standalone:   python dashboard_fixed.py
Or via main.py:     python main_fixed.py --dashboard

Key fixes:
  • Uses corrected API endpoints with proper IP extraction
  • Top Attacking IPs now populated correctly
  • Correlated Incidents working
  • Clean field naming ( attacker_ip, not source_ip)
"""

import json
import threading
from datetime import datetime
from queue import Empty, Queue

try:
    from flask import Flask, Response, jsonify, render_template_string, stream_with_context
    HAS_FLASK = True
except ImportError:
    HAS_FLASK = False
    print("  [Dashboard] Flask not installed. Run:  pip install flask")

from storage_fixed import (
    load_alerts, load_parsed_logs, get_stats, get_recent_logs,
    get_recent_alerts, get_top_attacker_ips, get_correlated_incidents,
    get_timeline_alerts
)
from alert_system_fixed import register_sse_client, unregister_sse_client

app = Flask(__name__) if HAS_FLASK else None

# HTML Template embedded (single-file deployment)
HTML_TEMPLATE = r"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>Windows SIEM Dashboard</title>
  <script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"></script>
  <style>
    *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
    :root {
      --bg: #060911; --surface: #0d1117; --card: #161b22;
      --border: #21262d; --text: #e6edf3; --muted: #8b949e;
      --accent: #58a6ff; --red: #f85149; --orange: #f0883e;
      --yellow: #d29922; --green: #3fb950;
    }
    body { font-family: 'Segoe UI', system-ui, sans-serif; background: var(--bg);
           color: var(--text); min-height: 100vh; }
    header { background: var(--surface); border-bottom: 1px solid var(--border);
             padding: 0 28px; height: 58px; display: flex; align-items: center;
             gap: 12px; position: sticky; top: 0; z-index: 200; }
    .logo { font-size: 1.1rem; font-weight: 800; color: var(--accent);
            font-family: 'Courier New', monospace; }
    .logo span { color: var(--red); }
    .badge { font-family: monospace; font-size: .68rem; background: var(--border);
             color: var(--muted); padding: 2px 8px; border-radius: 4px; }
    .spacer { flex: 1; }
    #live-dot { width: 9px; height: 9px; background: var(--green);
                border-radius: 50%; animation: pulse 2s infinite; }
    @keyframes pulse { 0%,100%{opacity:1} 50%{opacity:.25} }
    #clock { font-family: monospace; font-size: .8rem; color: var(--muted); }
    .container { max-width: 1380px; margin: 0 auto; padding: 24px 28px; }
    .kpi-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(160px, 1fr));
                gap: 16px; margin-bottom: 24px; }
    .kpi { background: var(--card); border: 1px solid var(--border);
           border-radius: 10px; padding: 18px 20px; display: flex;
           flex-direction: column; gap: 6px; }
    .kpi-label { font-size: .75rem; color: var(--muted); text-transform: uppercase;
                 letter-spacing: .05em; }
    .kpi-value { font-size: 2rem; font-weight: 800; font-family: monospace; }
    .kpi.critical .kpi-value { color: var(--red); }
    .kpi.high .kpi-value { color: var(--orange); }
    .kpi.total .kpi-value { color: var(--text); }
    .section { margin-bottom: 28px; }
    .section-title { font-size: .85rem; font-weight: 700; color: var(--muted);
                     text-transform: uppercase; margin-bottom: 12px; }
    .two-col { display: grid; grid-template-columns: 1fr 1fr; gap: 20px; }
    @media (max-width: 900px) { .two-col { grid-template-columns: 1fr; } }
    .card { background: var(--card); border: 1px solid var(--border);
            border-radius: 10px; padding: 18px 20px; }
    .card-title { font-size: .78rem; font-weight: 700; color: var(--muted);
                  text-transform: uppercase; margin-bottom: 14px; }
    table { width: 100%; border-collapse: collapse; font-size: .82rem; }
    th { font-size: .7rem; font-weight: 700; color: var(--muted);
         text-transform: uppercase; padding: 7px 10px;
         border-bottom: 1px solid var(--border); text-align: left; }
    td { padding: 8px 10px; border-bottom: 1px solid var(--border);
         color: var(--text); word-break: break-all; }
    tr:hover td { background: rgba(88,166,255,.05); }
    .sev { display: inline-block; padding: 1px 8px; border-radius: 4px;
           font-size: .72rem; font-weight: 700; }
    .sev-CRITICAL { background: rgba(248,81,73,.2);  color: var(--red); }
    .sev-HIGH { background: rgba(240,136,62,.2); color: var(--orange); }
    .sev-MEDIUM { background: rgba(210,153,34,.2); color: var(--yellow); }
    .ip-chip { font-family: monospace; font-size: .8rem; color: var(--red);
               background: rgba(248,81,73,.1); padding: 1px 7px;
               border-radius: 4px; }
    .attacker-row { display: flex; justify-content: space-between;
                    padding: 10px 14px; border-radius: 8px;
                    border: 1px solid var(--border); margin-bottom: 8px;
                    background: rgba(248,81,73,.04); }
    .attacker-count { font-family: monospace; font-weight: 700;
                      font-size: 1.1rem; color: var(--orange); }
    .incident { border-radius: 8px; padding: 12px 16px; margin-bottom: 10px;
                border: 1px solid var(--border); border-left-width: 3px; }
    .chart-wrap { position: relative; height: 220px; }
    .empty { color: var(--muted); font-size: .85rem; text-align: center;
             padding: 28px 0; }
  </style>
</head>
<body>
<header>
  <div class="logo">SIEM<span>.</span>PY</div>
  <span class="badge">FIXED - Windows SIEM</span>
  <span class="badge" id="event-count">0 events</span>
  <div class="spacer"></div>
  <div id="live-dot"></div>
  <span style="color:var(--muted);font-size:.75rem;margin-left:6px">LIVE</span>
  <span id="clock" style="margin-left:16px"></span>
</header>

<div class="container">
  <!-- KPI Cards -->
  <div class="section">
    <div class="kpi-grid">
      <div class="kpi total"><div class="kpi-label">📋 Total Logs</div>
        <div class="kpi-value" id="kpi-logs">—</div></div>
      <div class="kpi total"><div class="kpi-label">🔔 Total Alerts</div>
        <div class="kpi-value" id="kpi-alerts">—</div></div>
      <div class="kpi critical"><div class="kpi-label">🚨 Critical</div>
        <div class="kpi-value" id="kpi-critical">—</div></div>
      <div class="kpi high"><div class="kpi-label">⚠️  High</div>
        <div class="kpi-value" id="kpi-high">—</div></div>
      <div class="kpi total"><div class="kpi-label">🎯 Attacker IPs</div>
        <div class="kpi-value" id="kpi-ips">—</div></div>
    </div>
  </div>

  <!-- Timeline + Severity Chart -->
  <div class="two-col section">
    <div class="card">
      <div class="card-title">📈 Attack Timeline</div>
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
      <div id="attacker-ips-panel"><div class="empty">Loading...</div></div>
    </div>
    <div class="card">
      <div class="card-title">🔗 Correlated Incidents</div>
      <div id="incidents-panel"><div class="empty">Loading...</div></div>
    </div>
  </div>

  <!-- Recent Alerts -->
  <div class="section">
    <div class="section-title">🔔 Recent Alerts</div>
    <div class="card" style="overflow-x:auto">
      <table id="alerts-table">
        <thead>
          <tr>
            <th>Time</th><th>Severity</th><th>Rule</th><th>Attacker IP</th>
            <th>User</th><th>Description</th>
          </tr>
        </thead>
        <tbody id="alerts-tbody">
          <tr><td colspan="6" class="empty">Waiting for alerts…</td></tr>
        </tbody>
      </table>
    </div>
  </div>

  <!-- Recent Events -->
  <div class="section">
    <div class="section-title">📋 Recent Log Events</div>
    <div class="card" style="overflow-x:auto">
      <table id="logs-table">
        <thead>
          <tr>
            <th>Time</th><th>Event ID</th><th>Type</th><th>Severity</th>
            <th>User</th><th>Source IP</th><th>Channel</th>
          </tr>
        </thead>
        <tbody id="logs-tbody">
          <tr><td colspan="7" class="empty">Waiting for events…</td></tr>
        </tbody>
      </table>
    </div>
  </div>
</div>

<script>
const sev_colors = { CRITICAL: '#f85149', HIGH: '#f0883e', MEDIUM: '#d29922',
                     LOW: '#3fb950', INFO: '#58a6ff' };
function sevBadge(s) { return `<span class="sev sev-${s}">${s}</span>`; }
function ipChip(ip) { return ip && ip !== '-' ? `<span class="ip-chip">${ip}</span>` : '—'; }
function esc(s) { return String(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;'); }

setInterval(() => {
  document.getElementById('clock').textContent = new Date().toLocaleTimeString();
}, 1000);

const chartDefaults = {
  plugins: { legend: { labels: { color: '#8b949e', font: { size: 11 } } } }
};

const timelineCtx = document.getElementById('timeline-chart').getContext('2d');
const timelineChart = new Chart(timelineCtx, {
  type: 'bar',
  data: { labels: [], datasets: [
    { label: 'CRITICAL', data: [], backgroundColor: 'rgba(248,81,73,.7)', stack: 's' },
    { label: 'HIGH', data: [], backgroundColor: 'rgba(240,136,62,.7)', stack: 's' },
    { label: 'MEDIUM', data: [], backgroundColor: 'rgba(210,153,34,.7)', stack: 's' },
  ]},
  options: {
    ...chartDefaults,
    responsive: true, maintainAspectRatio: false,
    scales: {
      x: { stacked: true, ticks: { color:'#8b949e' }, grid: { color:'#21262d' } },
      y: { stacked: true, ticks: { color:'#8b949e', precision:0 },
           grid: { color:'#21262d' }, beginAtZero: true }
    }
  }
});

const sevCtx = document.getElementById('sev-chart').getContext('2d');
const sevChart = new Chart(sevCtx, {
  type: 'doughnut',
  data: {
    labels: ['CRITICAL', 'HIGH', 'MEDIUM'],
    datasets: [{
      data: [0,0,0],
      backgroundColor: ['#f85149','#f0883e','#d29922'],
      borderColor: '#161b22', borderWidth: 3,
    }]
  },
  options: {
    ...chartDefaults, responsive: true, maintainAspectRatio: false,
    cutout: '60%', plugins: { legend: { position: 'right' } }
  }
});

async function loadStats() {
  try {
    const resp = await fetch('/api/stats');
    const data = await resp.json();
    document.getElementById('kpi-logs').textContent = (data.total_logs||0).toLocaleString();
    document.getElementById('kpi-alerts').textContent = (data.total_alerts||0).toLocaleString();
    document.getElementById('kpi-critical').textContent = data.severity_breakdown?.CRITICAL||0;
    document.getElementById('kpi-high').textContent = data.severity_breakdown?.HIGH||0;
    document.getElementById('kpi-ips').textContent = (data.attacker_ip_count||0);
    document.getElementById('event-count').textContent = (data.total_logs||0).toLocaleString() + ' events';
    
    const tl = await fetch('/api/timeline').then(r => r.json());
    timelineChart.data.labels = tl.map(d => d.minute);
    timelineChart.data.datasets[0].data = tl.map(d => d.critical||0);
    timelineChart.data.datasets[1].data = tl.map(d => d.high||0);
    timelineChart.data.datasets[2].data = tl.map(d => d.medium||0);
    timelineChart.update('none');
    
    const sev = data.severity_breakdown || {};
    sevChart.data.datasets[0].data = [sev.CRITICAL||0, sev.HIGH||0, sev.MEDIUM||0];
    sevChart.update('none');
  } catch(e) { console.warn('Stats error:', e); }
}

async function loadAttackerIPs() {
  try {
    const ips = await fetch('/api/attacker_ips').then(r => r.json());
    const panel = document.getElementById('attacker-ips-panel');
    if (!ips || !ips.length) {
      panel.innerHTML = '<div class="empty">No attack IPs detected yet.</div>';
      return;
    }
    panel.innerHTML = ips.slice(0,8).map(ip => `
      <div class="attacker-row">
        <div style="flex:1"><div>${ipChip(ip.ip)}</div>
          <div style="font-size:.75rem;color:#8b949e;margin-top:4px">
            Rules: ${(ip.top_rules||[]).map(r=r.rule).join(', ')||'—'}<br>
            Users: ${(ip.user_targets||[]).join(', ')||'—'}
          </div></div>
        <div class="attacker-count">${ip.alert_count}…</div>
      </div>
    `).join('');
  } catch(e) { console.warn('IPs error:', e); }
}

async function loadIncidents() {
  try {
    const incidents = await fetch('/api/incidents').then(r => r.json());
    const panel = document.getElementById('incidents-panel');
    if (!incidents || !incidents.length) {
      panel.innerHTML = '<div class="empty">No incidents correlated yet.</div>';
      return;
    }
    panel.innerHTML = incidents.slice(0,6).map((inc, i) => {
      const lc = sev_colors[inc.severity_max] || '#58a6ff';
      return `
        <div class="incident" style="border-left-color:${lc}">
          <div style="display:flex;justify-content:space-between;gap:8px;flex-wrap:wrap">
            <span style="color:#58a6ff;font-weight:700">INC-${String(i+1).padStart(4,'0')}</span>
            ${ipChip(inc.ip)}
            ${sevBadge(inc.severity_max)}
            <span style="font-size:.75rem;color:#8b949e">${inc.alert_count} alerts${inc.critical_count?', '+inc.critical_count+' CRITICAL':''}</span>
          </div>
          <div style="font-size:.7rem;color:#8b949e;margin-top:6px">
            Rules: ${(inc.rules||[]).slice(0,3).join(', ')}<br>
            Users: ${(inc.users||[]).join(', ')||'—'}
          </div>
        </div>
      `;
    }).join('');
  } catch(e) { console.warn('Incidents error:', e); }
}

async function refreshAlerts() {
  try {
    const alerts = await fetch('/api/alerts').then(r => r.json());
    const tbody = document.getElementById('alerts-tbody');
    if (!alerts.length) {
      tbody.innerHTML = '<tr><td colspan="6" class="empty">No alerts yet.</td></tr>';
      return;
    }
    tbody.innerHTML = alerts.slice(0, 80).map(a => `
      <tr>
        <td style="font-family:monospace;font-size:.75rem">${esc(a.timestamp||'').substring(11)}</td>
        <td>${sevBadge(a.severity)}</td>
        <td>${esc(a.rule)}</td>
        <td>${ipChip(a.attacker_ip)}</td>
        <td>${esc(a.user)}</td>
        <td>${esc((a.description||'').substring(0,60))}</td>
      </tr>
    `).join('');
  } catch(e) {}
}

async function refreshLogs() {
  try {
    const logs = await fetch('/api/logs').then(r => r.json());
    const tbody = document.getElementById('logs-tbody');
    if (!logs.length) {
      tbody.innerHTML = '<tr><td colspan="7" class="empty">No logs yet.</td></tr>';
      return;
    }
    tbody.innerHTML = logs.slice(0, 60).map(l => `
      <tr>
        <td style="font-family:monospace;font-size:.75rem">${esc(l.timestamp||'').substring(11)}</td>
        <td>${l.event_id}</td>
        <td>${esc(l.event_type_label||l.event_type)}</td>
        <td>${sevBadge(l.severity)}</td>
        <td>${esc(l.user)}</td>
        <td>${ipChip(l.ip||l.source_ip)}</td>
        <td style="font-size:.75rem">${esc(l.channel)}</td>
      </tr>
    `).join('');
  } catch(e) {}
}

setInterval(loadStats, 2000);
setInterval(loadAttackerIPs, 3000);
setInterval(loadIncidents, 5000);
setInterval(refreshAlerts, 1500);
setInterval(refreshLogs, 2000);

loadStats();
loadAttackerIPs();
loadIncidents();
refreshAlerts();
refreshLogs();
</script>
</body>
</html>
"""


# ─── Flask endpoints ──────────────────────────────────────────────────────────

if HAS_FLASK:
    @app.route("/")
    def dashboard():
        return render_template_string(HTML_TEMPLATE)

    @app.route("/api/stats")
    def api_stats():
        """Dashboard KPI summary statistics."""
        stats = get_stats()
        return jsonify({
            "total_logs": stats.get("total_logs", 0),
            "total_alerts": stats.get("total_alerts", 0),
            "severity_breakdown": stats.get("severity_breakdown", {}),
            "attacker_ip_count": stats.get("attacker_ip_count", 0),
            "timestamp": stats.get("timestamp"),
        })

    @app.route("/api/alerts")
    def api_alerts():
        """Recent alerts."""
        return jsonify(get_recent_alerts(limit=100))

    @app.route("/api/logs")
    def api_logs():
        """Recent parsed log events."""
        return jsonify(get_recent_logs(limit=100))

    @app.route("/api/attacker_ips")
    def api_attacker_ips():
        """Top attacking IPs with frequency."""
        return jsonify(get_top_attacker_ips(limit=10))

    @app.route("/api/incidents")
    def api_incidents():
        """Correlated incidents by IP."""
        return jsonify(get_correlated_incidents(limit=50))

    @app.route("/api/timeline")
    def api_timeline():
        """Timeline of alerts per minute."""
        return jsonify(get_timeline_alerts(limit_minutes=60))

    @app.route("/api/stream")
    def api_stream():
        """SSE stream for real-time alerts."""
        def gen():
            q = Queue()
            register_sse_client(q)
            try:
                while True:
                    try:
                        payload = q.get(timeout=30)
                        yield payload
                    except Empty:
                        yield ": heartbeat\n\n"
            finally:
                unregister_sse_client(q)
        
        return Response(stream_with_context(gen()), 
                       mimetype="text/event-stream",
                       headers={"Cache-Control": "no-cache",
                               "X-Accel-Buffering": "no"})


def main():
    if not HAS_FLASK:
        print("Flask not installed. Run:  pip install flask")
        return
    
    print("\n  [Dashboard] Starting at http://127.0.0.1:5000")
    print("  Press Ctrl-C to stop.\n")
    
    app.run(host="0.0.0.0", port=5000, debug=False, use_reloader=False, threaded=True)


if __name__ == "__main__":
    main()
