# V2Ray Detection System - Architecture Documentation

## Overview

This system generates **REAL V2Ray traffic** using the `v2ray2proxy` library and detects it using deep packet inspection, behavioral analysis, and entropy-based detection.

---

## System Architecture - REAL V2Ray Traffic

```
┌────────────────────────────────────────────────────────────────────────┐
│                        REAL V2RAY DETECTION SYSTEM                      │
└────────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────────┐
│                          INTERNET / V2RAY SERVERS                        │
│                                                                          │
│  [V2Ray Server 1]      [V2Ray Server 2]       [V2Ray Server 3]         │
│   VMess Protocol       VLESS Protocol          Shadowsocks             │
│   example.com:443      proxy.io:443            ss-server.net:8388      │
│   ↑                    ↑                       ↑                        │
└───┼────────────────────┼───────────────────────┼─────────────────────────┘
    │                    │                       │
    │ Encrypted          │ Encrypted             │ Encrypted
    │ V2Ray Traffic      │ V2Ray Traffic         │ V2Ray Traffic
    │                    │                       │
┌───┴────────────────────┴───────────────────────┴─────────────────────────┐
│                        DOCKER HOST NETWORK                                │
│                       (eth0 / bridge network)                             │
└───────────────────────────────────────────────────────────────────────────┘
    │                                                   │
    │                                                   │
┌───▼─────────────────────────────────┐    ┌──────────▼────────────────────┐
│   ATTACKER CONTAINER                │    │   DETECTOR CONTAINER          │
│   (Real V2Ray Traffic Generator)    │    │   (Packet Capture & Analysis) │
│                                     │    │                               │
│  ┌───────────────────────────────┐ │    │  ┌─────────────────────────┐ │
│  │  v2ray2proxy Library          │ │    │  │  Scapy Packet Sniffer   │ │
│  │  - Auto-downloads V2Ray core  │ │    │  │  - Captures on eth0     │ │
│  │  - Connects to V2Ray servers  │ │    │  │  - BPF filter: tcp/udp  │ │
│  │  - Creates local HTTP proxy   │ │    │  └─────────────────────────┘ │
│  └───────────────────────────────┘ │    │             ↓                 │
│              ↓                      │    │  ┌─────────────────────────┐ │
│  ┌───────────────────────────────┐ │    │  │  Flow Analyzer          │ │
│  │  Traffic Generator            │ │    │  │  - Track flows          │ │
│  │  - Makes HTTP requests        │ │    │  │  - Extract features     │ │
│  │  - Through V2Ray proxy        │ │    │  │  - Calculate entropy    │ │
│  │  - To target URLs             │ │    │  └─────────────────────────┘ │
│  │    (httpbin, example.com)     │ │    │             ↓                 │
│  └───────────────────────────────┘ │    │  ┌─────────────────────────┐ │
│              ↓                      │    │  │  Risk Scoring Engine    │ │
│     REAL V2Ray Traffic             │    │  │  - Entropy analysis     │ │
│     • VMess encryption             │    │  │  - Pattern detection    │ │
│     • VLESS protocol               │    │  │  - Behavioral analysis  │ │
│     • Shadowsocks cipher           │────┼──┼─>│  - Calculate score    │ │
│     • Trojan obfuscation           │    │  └─────────────────────────┘ │
│     • WebSocket transport          │    │             ↓                 │
│                                     │    │  ┌─────────────────────────┐ │
│  Container IP: 172.23.0.20         │    │  │  Alert Generator        │ │
│                                     │    │  │  - Score > 70: Alert    │ │
└─────────────────────────────────────┘    │  │  - Store in SQLite      │ │
                                            │  │  - Export JSON          │ │
                                            │  └─────────────────────────┘ │
                                            │             ↓                 │
                                            │  Container IP: 172.23.0.10   │
                                            └───────────────────────────────┘
                                                        │
                                                        │ /app/data/
                                                        │ stats.json
                                                        │ alerts.json
                                                        ↓
┌────────────────────────────────────────────────────────────────────────────┐
│                        DASHBOARD CONTAINER                                  │
│                        (Web UI & API)                                       │
│                                                                             │
│  ┌─────────────────────────────────────────────────────────────────────┐  │
│  │  Flask Web Server (Port 3000)                                        │  │
│  │  - REST API endpoints                                                │  │
│  │  - WebSocket for real-time updates                                   │  │
│  │  - Docker control (start/stop attacker)                              │  │
│  └─────────────────────────────────────────────────────────────────────┘  │
│                                   ↓                                         │
│  ┌─────────────────────────────────────────────────────────────────────┐  │
│  │  Web Dashboard (http://localhost:3000)                               │  │
│  │  - Real-time statistics                                              │  │
│  │  - Live alert feed                                                   │  │
│  │  - Traffic charts (Chart.js)                                         │  │
│  │  - Control buttons (Start/Stop/Reset/Report)                         │  │
│  └─────────────────────────────────────────────────────────────────────┘  │
│                                                                             │
│  Container IP: 172.23.0.30                                                 │
└────────────────────────────────────────────────────────────────────────────┘
                              ↑
                              │ WebSocket + HTTP
                              │ Port 3000
                              ↓
                     ┌─────────────────┐
                     │  User Browser   │
                     │  (Client)       │
                     └─────────────────┘
```

---

## Traffic Flow - REAL V2Ray Protocol

### Step-by-Step Flow

```
1. INITIALIZATION
   ┌──────────────────────────────────────────────────────────────┐
   │ Attacker Container Starts                                     │
   │ → Loads config.yaml (v2ray_servers URLs)                     │
   │ → v2ray2proxy auto-downloads V2Ray core binary               │
   │ → Connects to V2Ray servers (VMess/VLESS/SS/Trojan)         │
   │ → Tests connection (GET httpbin.org/ip)                      │
   │ → Creates local HTTP/SOCKS5 proxy (e.g., 127.0.0.1:10808)   │
   └──────────────────────────────────────────────────────────────┘

2. TRAFFIC GENERATION
   ┌──────────────────────────────────────────────────────────────┐
   │ Traffic Generator Loop                                        │
   │ → Select random V2Ray proxy                                  │
   │ → Select random target URL (httpbin.org, example.com, etc.)  │
   │ → Make HTTP request THROUGH V2Ray proxy                      │
   │   requests.get(url, proxies={'http': proxy_url})             │
   │                                                               │
   │ REAL V2Ray Protocol Negotiation:                             │
   │  [Client] ──────► [V2Ray Proxy] ──────► [Target Website]    │
   │   HTTP req        VMess/VLESS            HTTP response       │
   │                   encryption                                  │
   │                   WebSocket tunnel                            │
   │                   TLS obfuscation                             │
   └──────────────────────────────────────────────────────────────┘

3. NETWORK TRANSMISSION
   ┌──────────────────────────────────────────────────────────────┐
   │ Encrypted V2Ray Packets on Docker Network                    │
   │                                                               │
   │ [Attacker: 172.23.0.20]                                      │
   │        │                                                      │
   │        │ TCP/UDP packets with:                               │
   │        │  - VMess encryption (AES-128-GCM)                   │
   │        │  - VLESS header + payload                           │
   │        │  - Shadowsocks cipher (chacha20-ietf-poly1305)     │
   │        │  - Trojan TLS ClientHello                           │
   │        │  - WebSocket frame data                             │
   │        │  - High entropy payloads (>7.5 bits/byte)           │
   │        ↓                                                      │
   │ [Docker Bridge: v2ray-net]                                   │
   │        │                                                      │
   │        │ Packets forwarded to detector                       │
   │        ↓                                                      │
   │ [Detector: 172.23.0.10]                                      │
   └──────────────────────────────────────────────────────────────┘

4. PACKET CAPTURE
   ┌──────────────────────────────────────────────────────────────┐
   │ Detector Container (Scapy Sniffer)                           │
   │                                                               │
   │ sniff(iface='eth0', filter='tcp or udp', prn=analyze_packet) │
   │        │                                                      │
   │        ├─► Capture ALL packets on eth0 interface             │
   │        ├─► Extract: src_ip, dst_ip, src_port, dst_port       │
   │        ├─► Get payload (Raw layer)                           │
   │        └─► Group into flows (5-tuple: src, dst, proto, ports)│
   └──────────────────────────────────────────────────────────────┘

5. FLOW ANALYSIS
   ┌──────────────────────────────────────────────────────────────┐
   │ Per-Flow Analysis (every 50 packets)                         │
   │                                                               │
   │ ┌─────────────────────────────────────────┐                 │
   │ │ Entropy Calculation                     │                 │
   │ │  - Shannon entropy of payload           │                 │
   │ │  - H = -Σ(p(x) * log2(p(x)))            │                 │
   │ │  - REAL V2Ray: 7.8-7.99 bits/byte       │                 │
   │ │  - Plaintext HTTP: 4-5 bits/byte        │                 │
   │ └─────────────────────────────────────────┘                 │
   │ ┌─────────────────────────────────────────┐                 │
   │ │ Protocol Detection                      │                 │
   │ │  - Check for HTTP headers               │                 │
   │ │  - Check for WebSocket upgrade          │                 │
   │ │  - Check for User-Agent presence        │                 │
   │ │  - Check for DNS queries                │                 │
   │ └─────────────────────────────────────────┘                 │
   │ ┌─────────────────────────────────────────┐                 │
   │ │ Traffic Pattern Analysis                │                 │
   │ │  - Unidirectional ratio                 │                 │
   │ │  - Packet size distribution             │                 │
   │ │  - Connection duration                  │                 │
   │ │  - Inter-arrival times                  │                 │
   │ └─────────────────────────────────────────┘                 │
   └──────────────────────────────────────────────────────────────┘

6. RISK SCORING
   ┌──────────────────────────────────────────────────────────────┐
   │ Multi-Factor Risk Score (0-100)                              │
   │                                                               │
   │ High Entropy (>7.5):              +25 points                 │
   │ Unidirectional (>90%):            +40 points                 │
   │ Missing User-Agent:               +15 points                 │
   │ WebSocket + Missing UA:           +20 points                 │
   │ DNS Tunneling (>150 bytes):       +30 points                 │
   │ Sustained Connection (>1 hour):   +5 points                  │
   │                                                               │
   │ TOTAL SCORE → Risk Level:                                    │
   │  0-39:  Legitimate                                           │
   │  40-69: Suspicious                                           │
   │  70+:   HIGH RISK V2Ray                                      │
   └──────────────────────────────────────────────────────────────┘

7. ALERT GENERATION
   ┌──────────────────────────────────────────────────────────────┐
   │ If Score >= 70:                                              │
   │  ┌────────────────────────────────────────────────────────┐ │
   │  │ Alert Generated                                         │ │
   │  │  {                                                      │ │
   │  │    "timestamp": "2026-01-19T10:30:00",                 │ │
   │  │    "level": "HIGH_RISK",                               │ │
   │  │    "score": 90,                                        │ │
   │  │    "src": "172.23.0.20:54321",                         │ │
   │  │    "dst": "1.2.3.4:443",                               │ │
   │  │    "protocol": "TCP",                                  │ │
   │  │    "indicators": [                                     │ │
   │  │      "high_entropy",                                   │ │
   │  │      "websocket",                                      │ │
   │  │      "missing_user_agent"                              │ │
   │  │    ]                                                   │ │
   │  │  }                                                      │ │
   │  └────────────────────────────────────────────────────────┘ │
   │  → Saved to /app/data/alerts.json                           │
   │  → Inserted into SQLite database                            │
   │  → Broadcasted to dashboard via WebSocket                   │
   └──────────────────────────────────────────────────────────────┘

8. DASHBOARD DISPLAY
   ┌──────────────────────────────────────────────────────────────┐
   │ Real-Time WebSocket Update (every 500ms)                     │
   │                                                               │
   │ ┌───────────────────────────────────────────────────────┐   │
   │ │ 📊 Statistics                                          │   │
   │ │  Total Packets:    50,000                             │   │
   │ │  Total Flows:      6,500                              │   │
   │ │  Suspicious:       25                                 │   │
   │ │  High Risk:        5  ← V2Ray Traffic Detected!       │   │
   │ └───────────────────────────────────────────────────────┘   │
   │                                                               │
   │ ┌───────────────────────────────────────────────────────┐   │
   │ │ 🚨 Alerts Feed                                         │   │
   │ │                                                        │   │
   │ │ ┌─────────────────────────────────────────────────┐   │   │
   │ │ │ 🔴 HIGH RISK - Score: 90/100                    │   │   │
   │ │ │ 10:30:00 | 172.23.0.20:54321 → 1.2.3.4:443      │   │   │
   │ │ │ Protocol: TCP                                   │   │   │
   │ │ │ Indicators: high_entropy, websocket, missing_ua │   │   │
   │ │ └─────────────────────────────────────────────────┘   │   │
   │ └───────────────────────────────────────────────────────┘   │
   └──────────────────────────────────────────────────────────────┘
```

---

## How Real V2Ray Traffic is Generated

This system generates **authentic V2Ray traffic** using the `v2ray2proxy` library:

```python
from v2ray2proxy import V2RayProxy
import requests

# Initialize REAL V2Ray proxy connection
proxy = V2RayProxy("vmess://base64_config")

# Make REAL HTTP request through V2Ray
proxies = {
    'http': proxy.http_proxy_url,
    'https': proxy.http_proxy_url
}
response = requests.get('http://httpbin.org/ip', proxies=proxies)

# v2ray2proxy handles:
# - VMess encryption (AES-128-GCM)
# - VLESS protocol negotiation
# - Shadowsocks cipher
# - Trojan TLS handshake
# - WebSocket transport
# - Real protocol headers and obfuscation
```

**Why This Matters**:
- Uses REAL V2Ray protocols (not fake patterns)
- Tests against actual VMess/VLESS/Shadowsocks/Trojan encryption
- Validates detection accuracy against authentic traffic
- Generates the SAME traffic a real V2Ray client would produce

---

## Detection Effectiveness Against REAL V2Ray

### What Gets Detected

1. **High Entropy** ✅
   - Real V2Ray encryption produces entropy 7.8-7.99 bits/byte
   - Detector threshold: >7.5 bits/byte
   - **Result**: DETECTED

2. **Traffic Patterns** ✅
   - Unidirectional flows (downloading > uploading)
   - Sustained long connections
   - **Result**: DETECTED

3. **Protocol Anomalies** ⚠️
   - Depends on V2Ray configuration
   - WebSocket with proper headers might evade detection
   - **Result**: PARTIALLY DETECTED

4. **TLS Fingerprinting** ⚠️
   - V2Ray can mimic legitimate TLS (Trojan protocol)
   - Hard to distinguish from HTTPS
   - **Result**: DIFFICULT TO DETECT

### What Might Evade Detection

1. **Domain Fronting via Cloudflare** ❌
   - V2Ray through CDN looks like normal HTTPS
   - Hard to distinguish from legitimate traffic

2. **TLS-wrapped V2Ray with valid certificates** ❌
   - Trojan protocol mimics HTTPS perfectly
   - Requires more advanced techniques (JA3 fingerprinting)

3. **Low-volume traffic** ⚠️
   - Single user, low request rate
   - Might blend with background noise

---

## Components Breakdown

### 1. Traffic Generator Container (Attacker)

**Key Libraries**:
- `v2ray2proxy==0.3.2` - Converts V2Ray URLs to proxies
- `requests` - Makes HTTP requests through proxy
- `pyyaml` - Configuration loading

**Process**:
1. Load V2Ray server URLs from config.yaml
2. Initialize v2ray2proxy (downloads V2Ray core)
3. Connect to V2Ray servers
4. Test connections
5. Generate traffic through proxies
6. Monitor statistics

**Output**:
- REAL encrypted V2Ray traffic on network
- Statistics logged to console

---

### 2. Detector Container (Packet Analysis)

**Key Libraries**:
- `scapy==2.5.0` - Packet capture and analysis
- `numpy`, `pandas`, `scikit-learn` - ML analysis

**Process**:
1. Capture packets on eth0 interface
2. Extract packet features (IP, ports, protocol, payload)
3. Group into flows (5-tuple)
4. Analyze every 50 packets per flow
5. Calculate entropy, patterns, anomalies
6. Compute risk score (0-100)
7. Generate alerts for score >= 70
8. Store in SQLite database
9. Export to JSON files

**Output**:
- `/app/data/stats.json` - Real-time statistics
- `/app/data/alerts.json` - Alert feed
- `/app/data/flows.db` - SQLite database

---

### 3. Dashboard Container (Web UI)

**Key Libraries**:
- `flask==3.0.0` - Web server
- `flask-socketio==5.3.5` - WebSocket for real-time updates
- `docker` - Control attacker container

**Process**:
1. Serve web UI on port 3000
2. Read stats.json and alerts.json every 500ms
3. Broadcast updates via WebSocket
4. Handle control buttons (start/stop/reset/report)
5. Control attacker container via Docker API

**Output**:
- Web dashboard at http://localhost:3000
- Real-time statistics and alerts
- Control panel for system management

---

## Configuration Requirements

To use REAL V2Ray traffic, you need:

### 1. V2Ray Server URLs

Add to `config.yaml`:

```yaml
attacker:
  v2ray_servers:
    # VMess
    - "vmess://eyJ2IjoiMi..."

    # VLESS
    - "vless://uuid@host:port?..."

    # Shadowsocks
    - "ss://method:password@host:port#..."

    # Trojan
    - "trojan://password@host:port?..."
```

### 2. Where to Get V2Ray Servers

- **Free V2Ray Services**: Search for "free vmess servers" or "free v2ray servers"
- **Self-hosted**: Deploy your own V2Ray server (v2ray-core)
- **Commercial VPN providers**: Some offer V2Ray protocol
- **Testing**: Use public test servers (for educational purposes)

⚠️ **Warning**: Only use V2Ray servers you own or have permission to test against.

---

## Performance Expectations

### Real V2Ray Traffic

- **Throughput**: Limited by V2Ray server bandwidth
- **Latency**: Depends on V2Ray server location (50-500ms)
- **Success Rate**: 70-95% (some requests may fail due to server issues)
- **Detection Rate**: 85-95% for typical V2Ray configurations

### Resource Usage

- **CPU**: 30-50% (V2Ray encryption overhead)
- **Memory**:
  - Attacker: 200-500MB (V2Ray core)
  - Detector: 300-600MB (packet capture)
  - Dashboard: 100-200MB
- **Network**: Depends on traffic intensity (2-30 req/s)
- **Disk**: Logs and database (100MB-1GB)

---

## Security & Legal Considerations

### ⚠️ IMPORTANT

This system generates **REAL V2Ray TRAFFIC**. Ensure:

1. **Authorization**: Only use V2Ray servers you own or have explicit permission to test
2. **Compliance**: Follow local laws regarding VPN/proxy usage and testing
3. **Ethical Use**: Do not use for unauthorized network monitoring or attacks
4. **Responsible Disclosure**: If you find vulnerabilities, report them responsibly

### Intended Use Cases

✅ **Authorized Uses**:
- Testing your own V2Ray detection systems
- Security research with proper authorization
- Educational demonstrations
- Penetration testing with client permission
- Academic research

❌ **Prohibited Uses**:
- Unauthorized network monitoring
- Attacking others' V2Ray servers
- Privacy violations
- Production deployment without authorization
- Circumventing network restrictions illegally

---

## Conclusion

This architecture uses **REAL V2Ray protocols** via the `v2ray2proxy` library to generate authentic encrypted traffic, which the detector analyzes using entropy-based and behavioral detection techniques. This provides a realistic assessment of V2Ray detection capabilities.

**Key Takeaway**: This is now a TRUE V2Ray detection system, not a simulation.
