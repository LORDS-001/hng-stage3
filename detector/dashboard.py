import time
import threading
import psutil
from flask import Flask, jsonify, render_template_string

# HTML template for dashboard
DASHBOARD_HTML = """
<!DOCTYPE html>
<html>
<head>
    <title>HNG Anomaly Detector Dashboard</title>
    <meta http-equiv="refresh" content="3">
    <style>
        body {
            font-family: monospace;
            background: #0d1117;
            color: #c9d1d9;
            padding: 20px;
            margin: 0;
        }
        h1 { color: #58a6ff; border-bottom: 1px solid #30363d; padding-bottom: 10px; }
        h2 { color: #3fb950; margin-top: 20px; }
        .grid { display: grid; grid-template-columns: repeat(3, 1fr); gap: 15px; margin: 20px 0; }
        .card {
            background: #161b22;
            border: 1px solid #30363d;
            border-radius: 8px;
            padding: 15px;
        }
        .card .value { font-size: 2em; color: #58a6ff; font-weight: bold; }
        .card .label { color: #8b949e; font-size: 0.9em; margin-top: 5px; }
        table { width: 100%; border-collapse: collapse; margin-top: 10px; }
        th { background: #21262d; padding: 8px; text-align: left; color: #8b949e; }
        td { padding: 8px; border-bottom: 1px solid #21262d; }
        .banned { color: #f85149; }
        .normal { color: #3fb950; }
        .warning { color: #d29922; }
        .uptime { color: #8b949e; font-size: 0.85em; }
        .refresh { color: #8b949e; font-size: 0.8em; text-align: right; }
    </style>
</head>
<body>
    <h1>🛡️ HNG Anomaly Detection Engine</h1>
    <p class="uptime">Uptime: {{ uptime }} | Last refresh: {{ now }}</p>

    <div class="grid">
        <div class="card">
            <div class="value {{ 'warning' if global_rate > baseline_mean * 2 else 'normal' }}">
                {{ "%.2f"|format(global_rate) }}
            </div>
            <div class="label">Global req/s</div>
        </div>
        <div class="card">
            <div class="value">{{ "%.2f"|format(baseline_mean) }}</div>
            <div class="label">Baseline Mean (req/s)</div>
        </div>
        <div class="card">
            <div class="value">{{ "%.2f"|format(baseline_stddev) }}</div>
            <div class="label">Baseline StdDev</div>
        </div>
        <div class="card">
            <div class="value banned">{{ banned_count }}</div>
            <div class="label">Banned IPs</div>
        </div>
        <div class="card">
            <div class="value">{{ "%.1f"|format(cpu_percent) }}%</div>
            <div class="label">CPU Usage</div>
        </div>
        <div class="card">
            <div class="value">{{ "%.1f"|format(mem_percent) }}%</div>
            <div class="label">Memory Usage</div>
        </div>
    </div>

    <h2>🚫 Banned IPs</h2>
    {% if banned_ips %}
    <table>
        <tr><th>IP Address</th><th>Unban Time</th><th>Status</th></tr>
        {% for ip, unban_time in banned_ips.items() %}
        <tr>
            <td class="banned">{{ ip }}</td>
            <td>{{ "PERMANENT" if unban_time == -1 else unban_time }}</td>
            <td class="banned">BLOCKED</td>
        </tr>
        {% endfor %}
    </table>
    {% else %}
    <p class="normal">No IPs currently banned ✅</p>
    {% endif %}

    <h2>📊 Top 10 Source IPs</h2>
    <table>
        <tr><th>IP Address</th><th>Total Requests</th><th>Current Rate (req/s)</th></tr>
        {% for ip, count in top_ips %}
        <tr>
            <td>{{ ip }}</td>
            <td>{{ count }}</td>
            <td>{{ "%.3f"|format(ip_rates.get(ip, 0)) }}</td>
        </tr>
        {% endfor %}
    </table>

    <p class="refresh">Auto-refreshes every 3 seconds</p>
</body>
</html>
"""


class Dashboard:
    """
    Live web dashboard served via Flask.
    Refreshes every 3 seconds showing:
    - Banned IPs
    - Global req/s
    - Top 10 source IPs
    - CPU/memory usage
    - Baseline mean/stddev
    - Uptime
    """

    def __init__(self, config, detector, blocker, baseline_tracker):
        self.port = config['dashboard']['port']
        self.detector = detector
        self.blocker = blocker
        self.baseline_tracker = baseline_tracker
        self.start_time = time.time()
        self.app = Flask(__name__)
        self._setup_routes()

    def _setup_routes(self):
        """Set up Flask routes."""
        @self.app.route('/')
        def index():
            return self._render_dashboard()

        @self.app.route('/api/metrics')
        def metrics():
            return jsonify(self._get_metrics())

        @self.app.route('/health')
        def health():
            return jsonify({'status': 'ok', 'uptime': self._uptime()})

    def _get_metrics(self):
        """Collect all metrics for dashboard."""
        baseline = self.baseline_tracker.get_baseline()
        top_ips = self.detector.get_top_ips(10)
        banned_ips = self.blocker.get_banned_ips()

        # Get current rate per top IP
        ip_rates = {}
        for ip, _ in top_ips:
            ip_rates[ip] = self.detector.get_ip_rate(ip)

        # Format banned IP unban times
        formatted_banned = {}
        for ip, unban_time in banned_ips.items():
            if unban_time == -1:
                formatted_banned[ip] = -1
            else:
                remaining = int(unban_time - time.time())
                formatted_banned[ip] = f"in {remaining}s" if remaining > 0 else "soon"

        return {
            'global_rate': self.detector.get_global_rate(),
            'baseline_mean': baseline['mean'],
            'baseline_stddev': baseline['stddev'],
            'banned_count': len(banned_ips),
            'banned_ips': formatted_banned,
            'top_ips': top_ips,
            'ip_rates': ip_rates,
            'cpu_percent': psutil.cpu_percent(),
            'mem_percent': psutil.virtual_memory().percent,
            'uptime': self._uptime(),
            'now': time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime()),
        }

    def _render_dashboard(self):
        """Render the HTML dashboard."""
        metrics = self._get_metrics()
        return render_template_string(DASHBOARD_HTML, **metrics)

    def _uptime(self):
        """Return formatted uptime string."""
        elapsed = int(time.time() - self.start_time)
        hours = elapsed // 3600
        minutes = (elapsed % 3600) // 60
        seconds = elapsed % 60
        return f"{hours}h {minutes}m {seconds}s"

    def start(self):
        """Start Flask dashboard in background thread."""
        thread = threading.Thread(
            target=lambda: self.app.run(
                host='0.0.0.0',
                port=self.port,
                debug=False,
                use_reloader=False
            ),
            daemon=True
        )
        thread.start()
        print(f"[dashboard] Started on port {self.port}")
