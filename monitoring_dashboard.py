from flask import Flask, render_template_string, jsonify
from flask_socketio import SocketIO, emit
import threading
import time
import json
from datetime import datetime
from real_time_monitor import RealTimeNetworkMonitor
import logging

app = Flask(__name__)
socketio = SocketIO(app, cors_allowed_origins="*")

# Global monitor instance
monitor = None
monitoring_thread = None
is_monitoring = False

# HTML template for the dashboard
HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Real-Time Network Intrusion Detection</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/socket.io/4.7.2/socket.io.js"></script>
    <style>
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            margin: 0;
            padding: 20px;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
        }
        .container {
            max-width: 1200px;
            margin: 0 auto;
            background: rgba(255, 255, 255, 0.1);
            border-radius: 15px;
            padding: 30px;
            backdrop-filter: blur(10px);
        }
        h1 {
            text-align: center;
            margin-bottom: 30px;
            font-size: 2.5em;
            text-shadow: 2px 2px 4px rgba(0,0,0,0.3);
        }
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }
        .stat-card {
            background: rgba(255, 255, 255, 0.2);
            border-radius: 10px;
            padding: 20px;
            text-align: center;
            border: 1px solid rgba(255, 255, 255, 0.3);
        }
        .stat-value {
            font-size: 2em;
            font-weight: bold;
            margin: 10px 0;
        }
        .stat-label {
            font-size: 0.9em;
            opacity: 0.8;
        }
        .alert-card {
            background: rgba(255, 0, 0, 0.3);
            border: 2px solid #ff4444;
            animation: pulse 2s infinite;
        }
        @keyframes pulse {
            0% { transform: scale(1); }
            50% { transform: scale(1.05); }
            100% { transform: scale(1); }
        }
        .charts-container {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 20px;
            margin-bottom: 30px;
        }
        .chart-card {
            background: rgba(255, 255, 255, 0.2);
            border-radius: 10px;
            padding: 20px;
            border: 1px solid rgba(255, 255, 255, 0.3);
        }
        .alerts-container {
            background: rgba(255, 255, 255, 0.2);
            border-radius: 10px;
            padding: 20px;
            border: 1px solid rgba(255, 255, 255, 0.3);
            max-height: 300px;
            overflow-y: auto;
        }
        .alert-item {
            background: rgba(255, 0, 0, 0.2);
            border-left: 4px solid #ff4444;
            padding: 10px;
            margin: 10px 0;
            border-radius: 5px;
        }
        .controls {
            text-align: center;
            margin-bottom: 30px;
        }
        button {
            background: rgba(255, 255, 255, 0.2);
            color: white;
            border: 2px solid rgba(255, 255, 255, 0.5);
            padding: 12px 24px;
            border-radius: 25px;
            cursor: pointer;
            font-size: 1em;
            margin: 0 10px;
            transition: all 0.3s ease;
        }
        button:hover {
            background: rgba(255, 255, 255, 0.3);
            transform: translateY(-2px);
        }
        button:active {
            transform: translateY(0);
        }
        .status-indicator {
            display: inline-block;
            width: 12px;
            height: 12px;
            border-radius: 50%;
            margin-right: 8px;
        }
        .status-active {
            background: #4CAF50;
            box-shadow: 0 0 10px #4CAF50;
        }
        .status-inactive {
            background: #ff4444;
            box-shadow: 0 0 10px #ff4444;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>🛡️ Real-Time Network Intrusion Detection</h1>

        <div class="controls">
            <span class="status-indicator" id="status-indicator"></span>
            <span id="status-text">Monitoring Inactive</span>
            <br><br>
            <button onclick="startMonitoring()">Start Monitoring</button>
            <button onclick="stopMonitoring()">Stop Monitoring</button>
            <button onclick="clearAlerts()">Clear Alerts</button>
        </div>

        <div class="stats-grid" id="stats-grid">
            <!-- Stats will be populated by JavaScript -->
        </div>

        <div class="charts-container">
            <div class="chart-card">
                <h3>Traffic Classification</h3>
                <canvas id="trafficChart"></canvas>
            </div>
            <div class="chart-card">
                <h3>Attack Types Distribution</h3>
                <canvas id="attackChart"></canvas>
            </div>
        </div>

        <div class="alerts-container">
            <h3>🚨 Recent Alerts</h3>
            <div id="alerts-list">
                <p>No alerts yet...</p>
            </div>
        </div>
    </div>

    <script>
        const socket = io();
        let trafficChart, attackChart;
        let alerts = [];
        let stats = {
            total_packets: 0,
            benign_packets: 0,
            attack_packets: 0,
            alerts: 0
        };

        // Initialize charts
        function initCharts() {
            const trafficCtx = document.getElementById('trafficChart').getContext('2d');
            trafficChart = new Chart(trafficCtx, {
                type: 'doughnut',
                data: {
                    labels: ['Benign', 'Attack'],
                    datasets: [{
                        data: [0, 0],
                        backgroundColor: ['#4CAF50', '#ff4444'],
                        borderWidth: 2
                    }]
                },
                options: {
                    responsive: true,
                    plugins: {
                        legend: {
                            position: 'bottom',
                            labels: { color: 'white' }
                        }
                    }
                }
            });

            const attackCtx = document.getElementById('attackChart').getContext('2d');
            attackChart = new Chart(attackCtx, {
                type: 'bar',
                data: {
                    labels: [],
                    datasets: [{
                        label: 'Attack Count',
                        data: [],
                        backgroundColor: '#ff4444',
                        borderColor: '#ff6666',
                        borderWidth: 1
                    }]
                },
                options: {
                    responsive: true,
                    scales: {
                        y: {
                            beginAtZero: true,
                            ticks: { color: 'white' },
                            grid: { color: 'rgba(255,255,255,0.2)' }
                        },
                        x: {
                            ticks: { color: 'white' },
                            grid: { color: 'rgba(255,255,255,0.2)' }
                        }
                    },
                    plugins: {
                        legend: {
                            labels: { color: 'white' }
                        }
                    }
                }
            });
        }

        // Update statistics display
        function updateStats() {
            const statsGrid = document.getElementById('stats-grid');
            const benignPercent = stats.total_packets > 0 ? ((stats.benign_packets / stats.total_packets) * 100).toFixed(1) : 0;
            const attackPercent = stats.total_packets > 0 ? ((stats.attack_packets / stats.total_packets) * 100).toFixed(1) : 0;

            statsGrid.innerHTML = `
                <div class="stat-card">
                    <div class="stat-label">Total Packets</div>
                    <div class="stat-value">${stats.total_packets}</div>
                </div>
                <div class="stat-card">
                    <div class="stat-label">Benign Traffic</div>
                    <div class="stat-value">${stats.benign_packets}</div>
                    <div class="stat-label">${benignPercent}%</div>
                </div>
                <div class="stat-card ${stats.alerts > 0 ? 'alert-card' : ''}">
                    <div class="stat-label">Attack Traffic</div>
                    <div class="stat-value">${stats.attack_packets}</div>
                    <div class="stat-label">${attackPercent}%</div>
                </div>
                <div class="stat-card ${stats.alerts > 0 ? 'alert-card' : ''}">
                    <div class="stat-label">Alerts Generated</div>
                    <div class="stat-value">${stats.alerts}</div>
                </div>
            `;

            // Update charts
            trafficChart.data.datasets[0].data = [stats.benign_packets, stats.attack_packets];
            trafficChart.update();
        }

        // Add new alert
        function addAlert(alert) {
            alerts.unshift(alert);
            if (alerts.length > 10) {
                alerts = alerts.slice(0, 10);
            }

            const alertsList = document.getElementById('alerts-list');
            alertsList.innerHTML = alerts.map(alert => `
                <div class="alert-item">
                    <strong>${alert.timestamp}</strong><br>
                    <strong>Attack:</strong> ${alert.attack_type}<br>
                    <strong>Confidence:</strong> ${(alert.confidence * 100).toFixed(1)}%<br>
                    <strong>Details:</strong> ${alert.details}
                </div>
            `).join('');
        }

        // Socket.IO event handlers
        socket.on('stats_update', function(data) {
            stats = data;
            updateStats();
        });

        socket.on('new_alert', function(data) {
            addAlert(data);
            stats.alerts++;
            updateStats();
        });

        socket.on('status_update', function(data) {
            const statusIndicator = document.getElementById('status-indicator');
            const statusText = document.getElementById('status-text');

            if (data.status === 'active') {
                statusIndicator.className = 'status-indicator status-active';
                statusText.textContent = 'Monitoring Active';
            } else {
                statusIndicator.className = 'status-indicator status-inactive';
                statusText.textContent = 'Monitoring Inactive';
            }
        });

        // Control functions
        function startMonitoring() {
            fetch('/start_monitoring', { method: 'POST' })
                .then(response => response.json())
                .then(data => console.log(data));
        }

        function stopMonitoring() {
            fetch('/stop_monitoring', { method: 'POST' })
                .then(response => response.json())
                .then(data => console.log(data));
        }

        function clearAlerts() {
            alerts = [];
            document.getElementById('alerts-list').innerHTML = '<p>No alerts yet...</p>';
            stats.alerts = 0;
            updateStats();
        }

        // Initialize
        initCharts();
        updateStats();
    </script>
</body>
</html>
"""

@app.route('/')
def index():
    return render_template_string(HTML_TEMPLATE)

@app.route('/start_monitoring', methods=['POST'])
def start_monitoring():
    global monitor, monitoring_thread, is_monitoring

    if not is_monitoring:
        monitor = RealTimeNetworkMonitor()
        monitoring_thread = threading.Thread(target=start_monitoring_thread, daemon=True)
        monitoring_thread.start()
        is_monitoring = True
        socketio.emit('status_update', {'status': 'active'})

    return jsonify({'status': 'Monitoring started'})

@app.route('/stop_monitoring', methods=['POST'])
def stop_monitoring():
    global is_monitoring
    is_monitoring = False
    socketio.emit('status_update', {'status': 'inactive'})
    return jsonify({'status': 'Monitoring stopped'})

def start_monitoring_thread():
    """Start the monitoring thread"""
    global monitor, is_monitoring

    if monitor:
        # Start monitoring with a short duration for demo
        monitor.start_monitoring(duration=300)  # 5 minutes for demo
        is_monitoring = False
        socketio.emit('status_update', {'status': 'inactive'})

def emit_stats():
    """Emit statistics to clients"""
    global monitor
    while True:
        if monitor and is_monitoring:
            socketio.emit('stats_update', monitor.stats)
        time.sleep(2)  # Update every 2 seconds

if __name__ == '__main__':
    # Start stats emission thread
    stats_thread = threading.Thread(target=emit_stats, daemon=True)
    stats_thread.start()

    print("Starting Network Intrusion Detection Dashboard...")
    print("Open http://localhost:5000 in your browser")
    socketio.run(app, host='0.0.0.0', port=5000, debug=False)
