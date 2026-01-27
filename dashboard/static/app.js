// V2Ray Detection Dashboard - Real-time Client
// WebSocket connection and UI updates

// Initialize WebSocket connection
const socket = io();

// State
let isAttackRunning = false;
let trafficChart = null;
let riskChart = null;
let trafficData = {
    labels: [],
    packets: [],
    flows: []
};

// Initialize charts
function initCharts() {
    // Traffic Analysis Chart
    const trafficCtx = document.getElementById('trafficChart').getContext('2d');
    trafficChart = new Chart(trafficCtx, {
        type: 'line',
        data: {
            labels: trafficData.labels,
            datasets: [
                {
                    label: 'Packets',
                    data: trafficData.packets,
                    borderColor: '#2563eb',
                    backgroundColor: 'rgba(37, 99, 235, 0.1)',
                    tension: 0.4,
                    fill: true
                },
                {
                    label: 'Flows',
                    data: trafficData.flows,
                    borderColor: '#10b981',
                    backgroundColor: 'rgba(16, 185, 129, 0.1)',
                    tension: 0.4,
                    fill: true
                }
            ]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    display: true,
                    position: 'top'
                }
            },
            scales: {
                y: {
                    beginAtZero: true
                }
            }
        }
    });

    // Risk Score Distribution Chart
    const riskCtx = document.getElementById('riskChart').getContext('2d');
    riskChart = new Chart(riskCtx, {
        type: 'doughnut',
        data: {
            labels: ['Low Risk', 'Suspicious', 'High Risk'],
            datasets: [{
                data: [0, 0, 0],
                backgroundColor: [
                    '#10b981',
                    '#f59e0b',
                    '#ef4444'
                ]
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    display: true,
                    position: 'bottom'
                }
            }
        }
    });
}

// Update statistics
function updateStats(stats) {
    document.getElementById('stat-packets').textContent = formatNumber(stats.total_packets || 0);
    document.getElementById('stat-flows').textContent = formatNumber(stats.total_flows || 0);
    document.getElementById('stat-suspicious').textContent = formatNumber(stats.suspicious_flows || 0);
    document.getElementById('stat-highrisk').textContent = formatNumber(stats.high_risk_flows || 0);
    document.getElementById('alerts-count').textContent = formatNumber(stats.alerts_count || 0);
}

// Update traffic chart
function updateTrafficChart(stats) {
    const now = new Date().toLocaleTimeString();

    // Add new data point
    trafficData.labels.push(now);
    trafficData.packets.push(stats.total_packets || 0);
    trafficData.flows.push(stats.total_flows || 0);

    // Keep only last 20 data points
    if (trafficData.labels.length > 20) {
        trafficData.labels.shift();
        trafficData.packets.shift();
        trafficData.flows.shift();
    }

    trafficChart.update('none'); // Update without animation for performance
}

// Update risk distribution chart
function updateRiskChart(stats) {
    const total = stats.total_flows || 0;
    const suspicious = stats.suspicious_flows || 0;
    const highRisk = stats.high_risk_flows || 0;
    const lowRisk = Math.max(0, total - suspicious - highRisk);

    riskChart.data.datasets[0].data = [lowRisk, suspicious, highRisk];
    riskChart.update('none');
}

// Update alerts feed
function updateAlerts(alerts) {
    const feed = document.getElementById('alerts-feed');

    if (!alerts || alerts.length === 0) {
        feed.innerHTML = '<div class="no-alerts">No alerts detected yet. System is monitoring...</div>';
        return;
    }

    // Clear feed
    feed.innerHTML = '';

    // Add alerts (newest first)
    alerts.reverse().forEach(alert => {
        const alertDiv = document.createElement('div');
        alertDiv.className = `alert-item ${alert.level === 'HIGH_RISK' ? 'high-risk' : 'suspicious'}`;

        const indicators = alert.indicators.map(ind =>
            `<span class="indicator-tag">${ind}</span>`
        ).join('');

        alertDiv.innerHTML = `
            <div class="alert-header">
                <span class="alert-level ${alert.level === 'HIGH_RISK' ? 'high-risk' : 'suspicious'}">
                    ${alert.level === 'HIGH_RISK' ? '🔴 HIGH RISK' : '🟡 SUSPICIOUS'}
                </span>
                <span class="alert-time">${formatTimestamp(alert.timestamp)}</span>
            </div>
            <div class="alert-flow">${alert.src} → ${alert.dst} (${alert.protocol})</div>
            <div class="alert-score">Score: ${alert.score}/100</div>
            <div class="alert-indicators">${indicators}</div>
        `;

        feed.appendChild(alertDiv);
    });
}

// Update uptime
function updateUptime(uptime) {
    document.getElementById('uptime').textContent = uptime;
}

// Format number with commas
function formatNumber(num) {
    return num.toString().replace(/\B(?=(\d{3})+(?!\d))/g, ',');
}

// Format timestamp
function formatTimestamp(isoString) {
    const date = new Date(isoString);
    return date.toLocaleTimeString();
}

// WebSocket event handlers
socket.on('connect', () => {
    console.log('Connected to dashboard server');
    document.getElementById('status-dot').classList.add('active');
    document.getElementById('status-text').textContent = 'System Active';
});

socket.on('disconnect', () => {
    console.log('Disconnected from dashboard server');
    document.getElementById('status-dot').classList.remove('active');
    document.getElementById('status-text').textContent = 'Disconnected';
});

socket.on('dashboard_update', (data) => {
    console.log('Dashboard update received:', data);

    // Update stats
    if (data.stats) {
        updateStats(data.stats);
        updateTrafficChart(data.stats);
        updateRiskChart(data.stats);
    }

    // Update alerts
    if (data.recent_alerts) {
        updateAlerts(data.recent_alerts);
    }

    // Update uptime
    if (data.uptime) {
        updateUptime(data.uptime);
    }

    // Update attack status
    if (data.is_attack_running !== undefined) {
        updateAttackStatus(data.is_attack_running);
    }

    // Update last update time
    document.getElementById('last-update').textContent = `Last update: ${new Date().toLocaleTimeString()}`;
});

// Control button handlers
document.getElementById('btn-start-attack').addEventListener('click', async () => {
    if (confirm('Start aggressive V2Ray attack simulation?')) {
        try {
            const response = await fetch('/api/attack/start', {method: 'POST'});
            const data = await response.json();

            if (data.status === 'success') {
                showAttackStatus('Attack simulation started. Monitoring traffic...');
                document.getElementById('btn-start-attack').disabled = true;
                document.getElementById('btn-stop-attack').disabled = false;
            }
        } catch (error) {
            console.error('Error starting attack:', error);
            alert('Error starting attack: ' + error.message);
        }
    }
});

document.getElementById('btn-stop-attack').addEventListener('click', async () => {
    try {
        const response = await fetch('/api/attack/stop', {method: 'POST'});
        const data = await response.json();

        if (data.status === 'success') {
            hideAttackStatus();
            document.getElementById('btn-start-attack').disabled = false;
            document.getElementById('btn-stop-attack').disabled = true;
        }
    } catch (error) {
        console.error('Error stopping attack:', error);
        alert('Error stopping attack: ' + error.message);
    }
});

document.getElementById('btn-reset').addEventListener('click', async () => {
    if (confirm('Reset all data? This will clear all flows, alerts, and statistics.')) {
        try {
            const response = await fetch('/api/reset', {method: 'POST'});
            const data = await response.json();

            if (data.status === 'success') {
                alert('All data has been reset');
                location.reload();
            }
        } catch (error) {
            console.error('Error resetting data:', error);
            alert('Error resetting data: ' + error.message);
        }
    }
});

document.getElementById('btn-report').addEventListener('click', async () => {
    if (confirm('Generate detection report? This will create an HTML and JSON report of all detected threats.')) {
        try {
            const response = await fetch('/api/report/generate', {method: 'POST'});
            const data = await response.json();

            if (data.status === 'success') {
                alert(`Report generated successfully!\n\nHTML: ${data.html_file}\nJSON: ${data.json_file}\n\nCheck the /reports directory.`);
            } else {
                alert('Error generating report: ' + data.message);
            }
        } catch (error) {
            console.error('Error generating report:', error);
            alert('Error generating report: ' + error.message);
        }
    }
});

// Attack status helpers
function showAttackStatus(message) {
    const status = document.getElementById('attack-status');
    status.textContent = message;
    status.classList.add('active');
}

function hideAttackStatus() {
    const status = document.getElementById('attack-status');
    status.classList.remove('active');
}

function updateAttackStatus(isRunning) {
    if (isRunning) {
        showAttackStatus('⚠️ Attack simulation is active');
        document.getElementById('btn-start-attack').disabled = true;
        document.getElementById('btn-stop-attack').disabled = false;
    } else {
        hideAttackStatus();
        document.getElementById('btn-start-attack').disabled = false;
        document.getElementById('btn-stop-attack').disabled = true;
    }
}

// Initialize on page load
document.addEventListener('DOMContentLoaded', () => {
    console.log('V2Ray Detection Dashboard initialized');
    initCharts();

    // Load initial data
    fetch('/api/stats')
        .then(response => response.json())
        .then(data => updateStats(data))
        .catch(error => console.error('Error loading initial stats:', error));

    fetch('/api/alerts?limit=10')
        .then(response => response.json())
        .then(data => updateAlerts(data))
        .catch(error => console.error('Error loading initial alerts:', error));
});
