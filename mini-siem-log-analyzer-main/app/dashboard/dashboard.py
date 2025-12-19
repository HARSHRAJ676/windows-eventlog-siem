from flask import Flask, jsonify, render_template_string
from utils.logging import setup_logger
import sqlite3
import os

logger = setup_logger("dashboard")
app = Flask(__name__)
DB_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), '..', 'data', 'siem.db')
DB_PATH = os.path.normpath(DB_PATH)

# HTML Dashboard Template
DASHBOARD_HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Windows SIEM Dashboard</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { 
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: #fff;
            padding: 20px;
        }
        .container { max-width: 1400px; margin: 0 auto; }
        .header {
            background: rgba(255,255,255,0.1);
            backdrop-filter: blur(10px);
            padding: 30px;
            border-radius: 15px;
            margin-bottom: 30px;
            text-align: center;
        }
        .header h1 { font-size: 2.5em; margin-bottom: 10px; }
        .header .status { 
            display: inline-block;
            background: #4CAF50;
            padding: 8px 20px;
            border-radius: 20px;
            font-weight: bold;
            animation: pulse 2s infinite;
        }
        @keyframes pulse {
            0%, 100% { opacity: 1; }
            50% { opacity: 0.6; }
        }
        .stats {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }
        .stat-card {
            background: rgba(255,255,255,0.1);
            backdrop-filter: blur(10px);
            padding: 25px;
            border-radius: 15px;
            text-align: center;
        }
        .stat-card .number { font-size: 3em; font-weight: bold; margin: 10px 0; }
        .stat-card .label { opacity: 0.8; font-size: 1.1em; }
        .section {
            background: rgba(255,255,255,0.1);
            backdrop-filter: blur(10px);
            padding: 25px;
            border-radius: 15px;
            margin-bottom: 20px;
        }
        .section h2 { margin-bottom: 20px; padding-bottom: 10px; border-bottom: 2px solid rgba(255,255,255,0.3); }
        .alert-item, .event-item {
            background: rgba(255,255,255,0.05);
            padding: 15px;
            border-radius: 10px;
            margin-bottom: 10px;
            border-left: 4px solid;
        }
        .alert-item.HIGH, .alert-item.CRITICAL { border-color: #f44336; }
        .alert-item.MEDIUM { border-color: #ff9800; }
        .alert-item.LOW { border-color: #4CAF50; }
        .alert-item .title { font-weight: bold; margin-bottom: 5px; font-size: 1.1em; }
        .alert-item .time { opacity: 0.7; font-size: 0.9em; margin-bottom: 8px; }
        .alert-item .desc { opacity: 0.9; white-space: pre-wrap; }
        .event-item { border-color: #2196F3; font-family: 'Courier New', monospace; font-size: 0.9em; }
        .event-item .event-header { display: flex; justify-content: space-between; margin-bottom: 5px; }
        .badge { 
            display: inline-block;
            padding: 3px 10px;
            border-radius: 12px;
            font-size: 0.85em;
            font-weight: bold;
            background: rgba(255,255,255,0.2);
        }
        .refresh-btn {
            background: #4CAF50;
            color: white;
            border: none;
            padding: 10px 25px;
            border-radius: 25px;
            cursor: pointer;
            font-size: 1em;
            font-weight: bold;
            margin-bottom: 15px;
        }
        .refresh-btn:hover { background: #45a049; }
        .no-data { text-align: center; opacity: 0.6; padding: 30px; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🛡️ Windows SIEM Dashboard</h1>
            <div class="status">🟢 System Active</div>
        </div>

        <div class="stats">
            <div class="stat-card">
                <div class="label">Total Alerts</div>
                <div class="number" id="totalAlerts">0</div>
            </div>
            <div class="stat-card">
                <div class="label">Recent Events</div>
                <div class="number" id="totalEvents">0</div>
            </div>
            <div class="stat-card">
                <div class="label">Critical Alerts</div>
                <div class="number" id="criticalAlerts">0</div>
            </div>
            <div class="stat-card">
                <div class="label">Auto Refresh</div>
                <div class="number">10s</div>
            </div>
        </div>

        <div class="section">
            <h2>🚨 Recent Alerts</h2>
            <button class="refresh-btn" onclick="loadData()">🔄 Refresh Now</button>
            <div id="alerts"></div>
        </div>

        <div class="section">
            <h2>📋 Recent Events</h2>
            <div id="events"></div>
        </div>
    </div>

    <script>
        function loadData() {
            // Load alerts
            fetch('/api/alerts')
                .then(r => r.json())
                .then(data => {
                    document.getElementById('totalAlerts').textContent = data.length;
                    const critical = data.filter(a => a.severity === 'CRITICAL' || a.severity === 'HIGH').length;
                    document.getElementById('criticalAlerts').textContent = critical;
                    
                    const html = data.length > 0 ? data.map(a => `
                        <div class="alert-item ${a.severity}">
                            <div class="title">${a.title}</div>
                            <div class="time">⏰ ${a.created_at}</div>
                            <div class="desc">${a.description}</div>
                        </div>
                    `).join('') : '<div class="no-data">No alerts yet</div>';
                    document.getElementById('alerts').innerHTML = html;
                });

            // Load events
            fetch('/api/events')
                .then(r => r.json())
                .then(data => {
                    document.getElementById('totalEvents').textContent = data.length;
                    
                    const html = data.length > 0 ? data.slice(0, 50).map(e => `
                        <div class="event-item">
                            <div class="event-header">
                                <span><span class="badge">${e.channel}</span> Event ID: ${e.event_id}</span>
                                <span>${e.timestamp}</span>
                            </div>
                            <div>User: ${e.user || 'N/A'} | IP: ${e.ip || 'N/A'}</div>
                            ${e.command ? '<div>Command: ' + e.command.substring(0, 100) + '</div>' : ''}
                        </div>
                    `).join('') : '<div class="no-data">No events yet</div>';
                    document.getElementById('events').innerHTML = html;
                });
        }

        // Load on startup
        loadData();
        
        // Auto-refresh every 10 seconds
        setInterval(loadData, 10000);
    </script>
</body>
</html>
"""


def _rows(q):
    conn = sqlite3.connect(DB_PATH)
    try:
        cur = conn.cursor()
        cur.execute(q)
        return cur.fetchall()
    finally:
        conn.close()


@app.route('/')
def index():
    """Main dashboard page"""
    return render_template_string(DASHBOARD_HTML)


@app.route('/api/alerts')
def alerts():
    rows = _rows("SELECT created_at, severity, title, description FROM alerts ORDER BY id DESC LIMIT 100")
    return jsonify([{'created_at': r[0], 'severity': r[1], 'title': r[2], 'description': r[3]} for r in rows])


@app.route('/api/events')
def events():
    rows = _rows("SELECT timestamp, channel, event_id, user, ip, command FROM events ORDER BY id DESC LIMIT 250")
    return jsonify([{'timestamp': r[0], 'channel': r[1], 'event_id': r[2], 'user': r[3], 'ip': r[4], 'command': r[5]} for r in rows])


if __name__ == '__main__':
    app.run(host='127.0.0.1', port=5000)
