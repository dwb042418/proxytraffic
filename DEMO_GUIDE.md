# V2Ray Detection System - Demo Guide

## Overview

This is a **Deep Packet Inspection (DPI)** system that detects V2Ray proxy traffic including **VMess**, **VLESS**, **Trojan**, and **Shadowsocks** protocols. The system uses behavioral analysis and traffic pattern recognition to identify proxy bypass attempts.

## Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                        Docker Network (172.23.0.0/16)               │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  ┌─────────────────┐   Traffic   ┌─────────────────────────────┐   │
│  │   ATTACKER      │ ─────────▶  │       DETECTOR              │   │
│  │  (172.23.0.20)  │             │     (172.23.0.10)           │   │
│  │                 │             │                             │   │
│  │  Generates real │             │  - Captures all packets     │   │
│  │  V2Ray traffic  │             │  - Analyzes flow patterns   │   │
│  │  using v2ray2   │             │  - Calculates risk scores   │   │
│  │  proxy library  │             │  - Generates alerts         │   │
│  └─────────────────┘             └─────────────────────────────┘   │
│                                              │                      │
│                                              │ Stats/Alerts         │
│                                              ▼                      │
│                                    ┌─────────────────────────┐     │
│                                    │      DASHBOARD          │     │
│                                    │    (172.23.0.30)        │     │
│                                    │    Port 3000            │     │
│                                    │                         │     │
│                                    │  - Real-time graphs     │     │
│                                    │  - Alert display        │     │
│                                    │  - Report generation    │     │
│                                    └─────────────────────────┘     │
│                                              │                      │
└──────────────────────────────────────────────│──────────────────────┘
                                               │
                                               ▼
                                    http://localhost:3000
```

## Detection Methods

The system detects V2Ray traffic using these indicators:

| Indicator | Weight | Description |
|-----------|--------|-------------|
| High Entropy | 25 | Encrypted payload (>7.5 bits/byte) |
| Unidirectional Traffic | 20-40 | Asymmetric packet ratios |
| Missing User-Agent | 15 | WebSocket without browser headers |
| DNS Tunneling | 30 | Large DNS packets (>150 bytes) |
| WebSocket Abuse | 20 | WS protocol misuse patterns |
| Sustained Connection | 5 | Long-lived connections (>1hr) |

## Quick Start

### Prerequisites

- Docker Desktop installed and running
- Port 3000 available
- Internet connection (for V2Ray servers)

### Step 1: Start the System

```bash
# Navigate to project directory
cd v2ray-detection-poc

# Start detector and dashboard
docker compose up -d detector dashboard

# Verify containers are running
docker compose ps
```

Expected output:
```
NAME              STATUS      PORTS
v2ray-detector    Up          8080/tcp
v2ray-dashboard   Up          0.0.0.0:3000->3000/tcp
```

### Step 2: Open Dashboard

Open your browser to: **http://localhost:3000**

You should see the V2Ray Detection Dashboard with:
- Real-time packet counter
- Flow tracker
- Alert panel
- Attack controls

### Step 3: Start Attack Simulation

**Option A: From Dashboard**
- Click the "Start Attack" button in the web UI

**Option B: From Command Line**
```bash
docker compose --profile attack up -d attacker
```

### Step 4: Monitor Detection

Watch the dashboard for:
- **Packets** counter increasing
- **Flows** being tracked
- **Alerts** appearing (HIGH_RISK, SUSPICIOUS)
- **Risk scores** in the 70-100 range

### Step 5: View Logs

```bash
# Detector logs (see what's being detected)
docker compose logs -f detector

# Attacker logs (see V2Ray connections)
docker compose logs -f attacker
```

### Step 6: Generate Report

Click "Generate Report" in the dashboard to create an HTML report of all detections.

---

## Configuration Reference

### config.yaml - Key Settings

```yaml
attacker:
  intensity: "medium"    # light (2/s) | medium (10/s) | aggressive (30/s)
  duration: 300          # seconds (0 = infinite)

  v2ray_servers:         # Real V2Ray server URLs
    - "vless://..."      # Already configured with test servers
    - "vmess://..."

detector:
  alert_threshold: 70    # Score to trigger HIGH_RISK alert
  suspicious_threshold: 40  # Score to trigger SUSPICIOUS alert

scoring:
  weights:
    high_entropy: 25
    unidirectional_high: 40
    dns_tunneling: 30
    # ... (see config.yaml for full list)
```

---

## Command Reference

| Command | Description |
|---------|-------------|
| `docker compose up -d detector dashboard` | Start detector & dashboard |
| `docker compose --profile attack up -d attacker` | Start traffic generator |
| `docker compose logs -f detector` | View detector logs |
| `docker compose logs -f attacker` | View attacker logs |
| `docker compose down` | Stop all containers |
| `docker compose down -v` | Stop and remove volumes |

---

## Expected Detection Output

When running properly, you should see:

### Detector Logs
```
detector | 2026-01-27 12:00:00 - detector - INFO - Packet capture started
detector | 2026-01-27 12:00:05 - detector - WARNING - [HIGH_RISK] V2Ray Detected - Score: 85/100
detector |   Flow: 172.23.0.20:45234 -> 94.131.110.122:443
detector |   Indicators: high_entropy, missing_user_agent, websocket
detector | 2026-01-27 12:00:10 - detector - WARNING - [SUSPICIOUS] V2Ray Detected - Score: 55/100
detector |   Flow: 172.23.0.20:45236 -> 139.59.185.253:443
detector |   Indicators: high_entropy, websocket
```

### Dashboard Metrics
- Packets: 5,000+
- Flows: 50+
- Suspicious: 20+
- High Risk: 10+

### Alert Details
- Score: 70-95 (typical for V2Ray traffic)
- Entropy: 7.8-7.99 (encrypted traffic)
- Flags: `high_entropy`, `websocket`, `missing_user_agent`

---

## Troubleshooting

### Container won't start
```bash
# Check logs
docker compose logs detector

# Rebuild if needed
docker compose build --no-cache detector
```

### No detections appearing
1. Verify attacker is running: `docker compose ps`
2. Check attacker logs for V2Ray connection errors
3. Ensure V2Ray servers are working (try different ones)

### Dashboard not loading
```bash
# Check dashboard container
docker compose logs dashboard

# Restart if needed
docker compose restart dashboard
```

### V2Ray servers not connecting
The configured servers are public and may be unreliable. To test with fresh servers:
1. Visit https://github.com/Kwinshadow/TelegramV2rayCollector
2. Get fresh VLESS/VMess URLs
3. Update `config.yaml` with new URLs
4. Restart: `docker compose restart attacker`

---

## Understanding the Detection

### Why V2Ray is Detectable

Even though V2Ray traffic is encrypted, it has behavioral patterns:

1. **High Entropy**: Encrypted payloads have ~7.8-8.0 bits/byte entropy
2. **WebSocket Pattern**: V2Ray often uses WS transport but lacks browser fingerprints
3. **Traffic Shape**: Proxy traffic tends to be more unidirectional
4. **Missing Headers**: No User-Agent in WebSocket handshakes

### Risk Score Calculation

```
Score = Σ (indicator_weight × indicator_present)

Example:
  high_entropy (7.9) = +25
  websocket = +20
  missing_user_agent = +15
  ─────────────────────
  Total Score = 60 (SUSPICIOUS)
```

---

## Files Modified for Demo

1. **config.yaml** - Updated with real VLESS server URLs
2. **DEMO_GUIDE.md** - This guide (new)

All other files remain unchanged from the original project.

---

## Next Steps

After running the demo:

1. **Analyze the reports** in `./reports/` directory
2. **Tune detection thresholds** in `config.yaml`
3. **Add more V2Ray servers** for broader testing
4. **Review ARCHITECTURE.md** for implementation details
5. **Customize scoring weights** for your use case

---

## Legal Notice

This system is for **educational and authorized security testing only**. Only test against networks and servers you own or have explicit permission to analyze.
