#!/usr/bin/env python3
"""
V2Ray Detection Dashboard - Real-time Web UI
Flask + WebSocket for live updates
"""

import os
import json
import time
import yaml
import logging
from datetime import datetime
from flask import Flask, render_template, jsonify, request
from flask_socketio import SocketIO, emit
from flask_cors import CORS
import threading

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger('dashboard')

# Initialize Flask app
app = Flask(__name__)
app.config['SECRET_KEY'] = 'v2ray-detection-secret-2026'
CORS(app)

# Initialize SocketIO
socketio = SocketIO(app, cors_allowed_origins="*", async_mode='threading')

# Load config
with open('/app/config.yaml', 'r') as f:
    config = yaml.safe_load(f)

# Global state
dashboard_state = {
    'stats': {
        'total_packets': 0,
        'total_flows': 0,
        'suspicious_flows': 0,
        'high_risk_flows': 0,
        'alerts_count': 0
    },
    'alerts': [],
    'is_attack_running': False,
    'uptime_start': datetime.now()
}


def load_stats_from_file():
    """Load latest stats from detector"""
    try:
        stats_file = '/app/data/stats.json'
        if os.path.exists(stats_file):
            with open(stats_file, 'r') as f:
                return json.load(f)
    except Exception as e:
        logger.error(f"Error loading stats: {e}")
    return {}


def load_alerts_from_file():
    """Load latest alerts from detector"""
    try:
        alerts_file = '/app/data/alerts.json'
        if os.path.exists(alerts_file):
            with open(alerts_file, 'r') as f:
                alerts = json.load(f)
                # Return last 100 alerts
                return alerts[-100:]
    except Exception as e:
        logger.error(f"Error loading alerts: {e}")
    return []


def broadcast_updates():
    """Background thread to broadcast updates to clients"""
    logger.info("Starting broadcast thread...")

    while True:
        try:
            # Load latest data
            stats = load_stats_from_file()
            alerts = load_alerts_from_file()

            if stats:
                dashboard_state['stats'].update(stats)

            if alerts:
                dashboard_state['alerts'] = alerts

            # Calculate uptime
            uptime_seconds = (datetime.now() - dashboard_state['uptime_start']).total_seconds()
            uptime_formatted = format_uptime(uptime_seconds)

            # Prepare update payload
            update = {
                'timestamp': datetime.now().isoformat(),
                'stats': dashboard_state['stats'],
                'recent_alerts': alerts[-10:] if alerts else [],
                'uptime': uptime_formatted,
                'is_attack_running': dashboard_state['is_attack_running']
            }

            # Broadcast to all connected clients
            socketio.emit('dashboard_update', update, namespace='/')

        except Exception as e:
            logger.error(f"Error in broadcast thread: {e}")

        # Update interval from config
        time.sleep(config['dashboard']['update_interval'] / 1000.0)


def format_uptime(seconds):
    """Format uptime in HH:MM:SS"""
    hours = int(seconds // 3600)
    minutes = int((seconds % 3600) // 60)
    secs = int(seconds % 60)
    return f"{hours:02d}:{minutes:02d}:{secs:02d}"


# Routes

@app.route('/')
def index():
    """Main dashboard page"""
    return render_template('index.html', config=config)


@app.route('/health')
def health():
    """Health check endpoint"""
    return jsonify({'status': 'healthy', 'timestamp': datetime.now().isoformat()})


@app.route('/api/stats')
def api_stats():
    """Get current statistics"""
    stats = load_stats_from_file()
    return jsonify(stats)


@app.route('/api/alerts')
def api_alerts():
    """Get recent alerts"""
    limit = request.args.get('limit', 100, type=int)
    alerts = load_alerts_from_file()
    return jsonify(alerts[-limit:])


@app.route('/api/reset', methods=['POST'])
def api_reset():
    """Reset all data"""
    try:
        # Clear stats file
        stats_file = '/app/data/stats.json'
        if os.path.exists(stats_file):
            os.remove(stats_file)

        # Clear alerts file
        alerts_file = '/app/data/alerts.json'
        if os.path.exists(alerts_file):
            os.remove(alerts_file)

        # Clear database (if exists)
        db_file = '/app/data/flows.db'
        if os.path.exists(db_file):
            os.remove(db_file)

        # Reset dashboard state
        dashboard_state['stats'] = {
            'total_packets': 0,
            'total_flows': 0,
            'suspicious_flows': 0,
            'high_risk_flows': 0,
            'alerts_count': 0
        }
        dashboard_state['alerts'] = []
        dashboard_state['uptime_start'] = datetime.now()

        logger.info("All data reset successfully")

        return jsonify({'status': 'success', 'message': 'All data reset'})

    except Exception as e:
        logger.error(f"Error resetting data: {e}")
        return jsonify({'status': 'error', 'message': str(e)}), 500


@app.route('/api/attack/start', methods=['POST'])
def api_attack_start():
    """Start V2Ray traffic generation"""
    try:
        import subprocess

        # Start attacker container using docker-compose
        result = subprocess.run(
            ['docker-compose', '--profile', 'attack', 'up', '-d', 'attacker'],
            cwd='/app',
            capture_output=True,
            text=True
        )

        if result.returncode == 0:
            dashboard_state['is_attack_running'] = True
            logger.info("V2Ray traffic generation started via docker-compose")
            return jsonify({'status': 'success', 'message': 'Traffic generation started'})
        else:
            logger.error(f"Failed to start attacker: {result.stderr}")
            return jsonify({'status': 'error', 'message': 'Failed to start attack container'}), 500

    except Exception as e:
        logger.error(f"Error starting attack: {e}")
        return jsonify({'status': 'error', 'message': str(e)}), 500


@app.route('/api/attack/stop', methods=['POST'])
def api_attack_stop():
    """Stop V2Ray traffic generation"""
    try:
        import subprocess

        # Stop attacker container using docker-compose
        result = subprocess.run(
            ['docker-compose', 'stop', 'attacker'],
            cwd='/app',
            capture_output=True,
            text=True
        )

        if result.returncode == 0:
            # Remove container
            subprocess.run(['docker-compose', 'rm', '-f', 'attacker'], cwd='/app')
            dashboard_state['is_attack_running'] = False
            logger.info("V2Ray traffic generation stopped via docker-compose")
            return jsonify({'status': 'success', 'message': 'Traffic generation stopped'})
        else:
            logger.error(f"Failed to stop attacker: {result.stderr}")
            return jsonify({'status': 'error', 'message': 'Failed to stop attack container'}), 500

    except Exception as e:
        logger.error(f"Error stopping attack: {e}")
        return jsonify({'status': 'error', 'message': str(e)}), 500


@app.route('/api/report/generate', methods=['POST'])
def api_report_generate():
    """Generate detection report"""
    try:
        # Generate HTML report
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        report_file = f'/app/reports/detection_report_{timestamp}.html'

        # Load data
        stats = load_stats_from_file()
        alerts = load_alerts_from_file()

        # Generate HTML report
        html_content = f"""
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>V2Ray Detection Report - {timestamp}</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 40px; background: #f5f5f5; }}
        .header {{ background: #2563eb; color: white; padding: 20px; border-radius: 8px; }}
        .stats {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 20px; margin: 20px 0; }}
        .stat-card {{ background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }}
        .stat-label {{ color: #666; font-size: 14px; }}
        .stat-value {{ font-size: 32px; font-weight: bold; color: #2563eb; }}
        .alerts {{ background: white; padding: 20px; border-radius: 8px; margin-top: 20px; }}
        .alert {{ border-left: 4px solid #ef4444; padding: 15px; margin: 10px 0; background: #fef2f2; }}
        .alert.suspicious {{ border-left-color: #f59e0b; background: #fffbeb; }}
        h2 {{ color: #333; }}
        .timestamp {{ color: #666; font-size: 14px; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>🔍 V2Ray Detection Report</h1>
        <p>Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
    </div>

    <div class="stats">
        <div class="stat-card">
            <div class="stat-label">Total Packets</div>
            <div class="stat-value">{stats.get('total_packets', 0):,}</div>
        </div>
        <div class="stat-card">
            <div class="stat-label">Total Flows</div>
            <div class="stat-value">{stats.get('total_flows', 0):,}</div>
        </div>
        <div class="stat-card">
            <div class="stat-label">Suspicious Flows</div>
            <div class="stat-value">{stats.get('suspicious_flows', 0):,}</div>
        </div>
        <div class="stat-card">
            <div class="stat-label">High Risk Flows</div>
            <div class="stat-value">{stats.get('high_risk_flows', 0):,}</div>
        </div>
    </div>

    <div class="alerts">
        <h2>Detected Alerts ({len(alerts)})</h2>
        {''.join([f'''
        <div class="alert {'suspicious' if alert['level'] != 'HIGH_RISK' else ''}">
            <strong>{alert['level']}</strong> - Score: {alert['score']}/100<br>
            <span class="timestamp">{alert['timestamp']}</span><br>
            Flow: {alert['src']} → {alert['dst']} ({alert['protocol']})<br>
            Indicators: {', '.join(alert['indicators'])}
        </div>
        ''' for alert in alerts])}
    </div>
</body>
</html>
"""

        # Write report
        with open(report_file, 'w') as f:
            f.write(html_content)

        # Also save JSON version
        json_file = f'/app/reports/detection_report_{timestamp}.json'
        with open(json_file, 'w') as f:
            json.dump({
                'timestamp': timestamp,
                'stats': stats,
                'alerts': alerts
            }, f, indent=2)

        logger.info(f"Report generated: {report_file}")

        return jsonify({
            'status': 'success',
            'message': 'Report generated successfully',
            'html_file': f'detection_report_{timestamp}.html',
            'json_file': f'detection_report_{timestamp}.json'
        })

    except Exception as e:
        logger.error(f"Error generating report: {e}")
        return jsonify({'status': 'error', 'message': str(e)}), 500


# WebSocket events

@socketio.on('connect')
def handle_connect():
    """Handle client connection"""
    logger.info(f"Client connected: {request.sid}")
    emit('connection_response', {'status': 'connected'})


@socketio.on('disconnect')
def handle_disconnect():
    """Handle client disconnection"""
    logger.info(f"Client disconnected: {request.sid}")


@socketio.on('request_update')
def handle_request_update():
    """Handle manual update request from client"""
    stats = load_stats_from_file()
    alerts = load_alerts_from_file()

    update = {
        'timestamp': datetime.now().isoformat(),
        'stats': stats,
        'recent_alerts': alerts[-10:] if alerts else []
    }

    emit('dashboard_update', update)


if __name__ == '__main__':
    logger.info("=" * 60)
    logger.info("V2RAY DETECTION DASHBOARD")
    logger.info("=" * 60)
    logger.info(f"Starting server on {config['dashboard']['host']}:{config['dashboard']['port']}")
    logger.info(f"Theme: {config['dashboard']['theme']}")
    logger.info(f"Update interval: {config['dashboard']['update_interval']}ms")
    logger.info("=" * 60)

    # Create data directory if needed
    os.makedirs('/app/data', exist_ok=True)
    os.makedirs('/app/reports', exist_ok=True)

    # Start broadcast thread
    broadcast_thread = threading.Thread(target=broadcast_updates, daemon=True)
    broadcast_thread.start()

    # Run Flask app
    socketio.run(
        app,
        host=config['dashboard']['host'],
        port=config['dashboard']['port'],
        debug=False,
        allow_unsafe_werkzeug=True
    )
