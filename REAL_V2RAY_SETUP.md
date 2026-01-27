# Setting Up REAL V2Ray Traffic Generation

## What Changed

The system has been upgraded from **SIMULATED** to **REAL** V2Ray traffic generation.

### Before (Simulated)
- ❌ Generated fake packets with random bytes
- ❌ Crafted WebSocket handshakes manually
- ❌ No real V2Ray protocols
- ❌ Patterns were simplified/fake

### After (Real)
- ✅ Uses `v2ray2proxy` library
- ✅ Connects to real V2Ray servers
- ✅ Generates authentic VMess/VLESS/Shadowsocks/Trojan traffic
- ✅ Real encryption and protocols

---

## Quick Start Guide

### Step 1: Get V2Ray Server URLs

You need at least ONE working V2Ray server URL. Format examples:

#### VMess
```
vmess://eyJ2IjoiMiIsInBzIjoiVGVzdCBTZXJ2ZXIiLCJhZGQiOiJleGFtcGxlLmNvbSIsInBvcnQiOiI0NDMiLCJpZCI6IjEyMzQ1Njc4LTEyMzQtMTIzNC0xMjM0LTEyMzQ1Njc4OTBhYiIsImFpZCI6IjAiLCJuZXQiOiJ3cyIsInR5cGUiOiJub25lIiwiaG9zdCI6ImV4YW1wbGUuY29tIiwicGF0aCI6Ii92bWVzcyIsInRscyI6InRscyJ9
```

#### VLESS
```
vless://12345678-1234-1234-1234-1234567890ab@example.com:443?encryption=none&security=tls&type=ws&host=example.com&path=/vless#TestServer
```

#### Shadowsocks
```
ss://YWVzLTI1Ni1nY206cGFzc3dvcmQ=@example.com:8388#TestServer
```

#### Trojan
```
trojan://password@example.com:443?security=tls&type=tcp#TestServer
```

### Step 2: Configure config.yaml

Open `config.yaml` and add your V2Ray server URLs:

```yaml
attacker:
  intensity: "medium"  # light (2 req/s), medium (10 req/s), aggressive (30 req/s)
  duration: 300        # 5 minutes (0 = infinite)

  # ADD YOUR REAL V2RAY SERVER URLS HERE
  v2ray_servers:
    - "vmess://YOUR_VMESS_URL_HERE"
    - "vless://YOUR_VLESS_URL_HERE"
    - "ss://YOUR_SHADOWSOCKS_URL_HERE"
    # Add as many as you want - system will use all of them

  # Target URLs to access through V2Ray
  target_urls:
    - "http://httpbin.org/ip"
    - "http://httpbin.org/user-agent"
    - "http://example.com"
    - "http://ifconfig.me"
```

**Important**: Remove the placeholder URLs and add real ones!

### Step 3: Rebuild Containers

Since we added v2ray2proxy to requirements.txt, rebuild:

```bash
# Stop current containers
./demo.sh down

# Rebuild with new dependencies
docker-compose build --no-cache

# Start system
./demo.sh start
```

### Step 4: Start Attack with Real V2Ray

```bash
# From dashboard: Click "Start Attack" button
# OR from command line:
./demo.sh attack

# Watch logs to see V2Ray connection
docker-compose logs -f attacker
```

Expected output:
```
attacker | ============================================================
attacker | REAL V2RAY TRAFFIC GENERATOR
attacker | ============================================================
attacker | Loaded 2 V2Ray server(s)
attacker | Intensity: medium (10 requests/sec)
attacker | Duration: 300s
attacker | Initializing V2Ray proxies...
attacker | [1/2] Connecting to VMESS server...
attacker |   ✓ VMESS proxy connected successfully
attacker |   ✓ External IP: 1.2.3.4
attacker | [2/2] Connecting to VLESS server...
attacker |   ✓ VLESS proxy connected successfully
attacker |   ✓ External IP: 5.6.7.8
attacker | Successfully connected to 2 V2Ray server(s)
attacker | Starting real V2Ray traffic generation...
attacker | Progress: 10 requests | 10.2 req/s | 45.3 KB | Protocol: VMESS
attacker | Progress: 20 requests | 10.1 req/s | 89.7 KB | Protocol: VLESS
```

### Step 5: Watch Detection

Open dashboard: http://localhost:3000

You should see:
- Packets increasing (real V2Ray traffic)
- Flows being tracked
- **High Risk alerts** when V2Ray is detected
- Entropy values ~7.8-7.99 (real encryption)

---

## Where to Get V2Ray Servers

### Option 1: Free Public Servers (Testing Only)

⚠️ **Warning**: Free servers are unreliable and may log your traffic. Use only for testing.

Search for:
- "free vmess servers"
- "free v2ray subscription"
- Telegram channels with V2Ray shares

### Option 2: Self-Hosted (Recommended)

Deploy your own V2Ray server:

```bash
# Install V2Ray on a VPS
bash <(curl -L https://raw.githubusercontent.com/v2fly/fhs-install-v2ray/master/install-release.sh)

# Configure /usr/local/etc/v2ray/config.json
# Generate UUID: uuidgen

# Start V2Ray
systemctl start v2ray
systemctl enable v2ray

# Get your VMess/VLESS URL from config
```

**Providers for VPS**:
- DigitalOcean, Vultr, Linode, AWS EC2
- $5-10/month for testing

### Option 3: Commercial V2Ray VPN

Some VPN providers offer V2Ray protocol:
- Check if your VPN supports VMess/VLESS
- Export connection URL from app settings

---

## Troubleshooting

### Error: "No V2Ray servers configured!"

**Cause**: config.yaml has placeholder URLs

**Fix**:
1. Open `config.yaml`
2. Replace `REPLACE_WITH_YOUR_VMESS_URL` with actual V2Ray server URLs
3. Remove any lines with `REPLACE_WITH_...`

### Error: "v2ray2proxy not installed"

**Cause**: Library not in container

**Fix**:
```bash
# Rebuild containers
docker-compose build --no-cache attacker
docker-compose up -d attacker
```

### Error: "Failed to connect to server"

**Cause**: V2Ray server is down or URL is invalid

**Fix**:
1. Test URL in V2Ray client (v2rayN, Shadowrocket, etc.)
2. Verify server is accessible
3. Check for typos in URL
4. Try different server

### Error: "No working V2Ray proxies available!"

**Cause**: All configured servers failed to connect

**Fix**:
1. Check V2Ray server status
2. Test servers manually with v2ray2proxy CLI:
   ```bash
   docker exec -it v2ray-attacker python
   >>> from v2ray2proxy import V2RayProxy
   >>> proxy = V2RayProxy("vmess://...")
   >>> # If this fails, server is not working
   ```
3. Use different V2Ray servers

### Attacker Container Exits Immediately

**Check logs**:
```bash
docker-compose logs attacker
```

**Common causes**:
- No v2ray_servers in config.yaml
- All servers failed to connect
- Invalid server URL format

---

## Testing Without Real V2Ray Servers

If you don't have V2Ray servers but want to test the detector:

### Option 1: Use Fallback Mode (TODO)

We can add a fallback to simulated traffic if no servers configured.

### Option 2: Deploy Local V2Ray Server

Run V2Ray server in another Docker container:

```bash
# Pull V2Ray image
docker pull v2fly/v2fly-core

# Run with example config
docker run -d --name v2ray-server \
  -p 10086:10086 \
  v2fly/v2fly-core run -c /etc/v2ray/config.json
```

Then use `vmess://localhost:10086` in config.

---

## Validation Checklist

After setup, verify:

- [ ] v2ray2proxy library installed in attacker container
- [ ] Real V2Ray server URLs in config.yaml (not placeholders)
- [ ] Attacker container starts successfully
- [ ] Logs show "✓ proxy connected successfully"
- [ ] Dashboard shows increasing packet count
- [ ] Alerts appear with high entropy (~7.8-7.9)
- [ ] Traffic is visible in detector logs

---

## Performance Tips

### For Best Detection Results

1. **Use multiple V2Ray servers** - Tests detection across protocols
2. **Vary intensity** - Try light, medium, aggressive
3. **Run for 5-10 minutes** - Gives detector time to analyze patterns
4. **Check entropy values** - Should be 7.8-7.99 for real V2Ray

### Monitoring

```bash
# Watch attacker logs
docker-compose logs -f attacker

# Watch detector logs
docker-compose logs -f detector

# Check statistics in real-time
watch -n 1 'curl -s http://localhost:3000/api/stats | jq'
```

---

## Next Steps

1. ✅ Configure V2Ray servers in config.yaml
2. ✅ Rebuild containers
3. ✅ Start attack and verify connection
4. ✅ Monitor dashboard for detections
5. ✅ Generate report to see results

**Need Help?**
- Check ARCHITECTURE.md for detailed flow diagrams
- Review attacker container logs for connection issues
- Test V2Ray URLs in standalone v2ray2proxy before using in system

---

## Legal & Security Notice

⚠️ **IMPORTANT**

- Only use V2Ray servers you **OWN** or have **explicit permission** to test
- Do not use for unauthorized network monitoring
- Comply with local laws regarding VPN/proxy usage
- This is for **educational and authorized security testing only**

Misuse of this system may violate laws and terms of service. Use responsibly.

---

**System Status**: ✅ Now uses REAL V2Ray protocols
**Documentation**: See ARCHITECTURE.md for detailed diagrams
**Support**: Check logs and troubleshooting section above
