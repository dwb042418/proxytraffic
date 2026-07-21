#!/usr/bin/env bash
set -euo pipefail
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
[[ "${1:-}" != "--dry-run" ]] || {
  echo "openssl s_client -connect 192.168.100.20:20001 -servername etip-server.lab -CAfile /etc/proxytraffic/pki/ca.crt </dev/null"
  echo "ss -ltnp | grep '127.0.0.1:11080'"
  echo "curl --fail --show-error --socks5-hostname 127.0.0.1:11080 https://etip-server.lab:18443/files/file_10m.bin -o /dev/null"
  exit 0
}
openssl s_client -connect 192.168.100.20:20001 -servername etip-server.lab -CAfile /etc/proxytraffic/pki/ca.crt </dev/null 2>&1 | tee /tmp/etip-xray-tls-verify.txt
grep -F 'Verify return code: 0 (ok)' /tmp/etip-xray-tls-verify.txt >/dev/null
ss -ltnp | grep '127.0.0.1:11080'
curl --fail --show-error --socks5-hostname 127.0.0.1:11080 https://etip-server.lab:18443/files/file_10m.bin -o /dev/null
echo "Collector TLS and SOCKS5 verification passed"

