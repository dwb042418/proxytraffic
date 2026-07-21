#!/usr/bin/env bash
set -euo pipefail
umask 077

XRAY_VERSION="v26.6.1"
XRAY_ARCHIVE="Xray-linux-64.zip"
OFFICIAL_BASE="https://github.com/XTLS/Xray-core/releases/download/${XRAY_VERSION}"
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
UUID_FILE="${SCRIPT_DIR}/.vless_uuid"
DRY_RUN=0
[[ "${1:-}" == "--dry-run" ]] && DRY_RUN=1

require() { command -v "$1" >/dev/null || { echo "missing command: $1" >&2; exit 1; }; }
for cmd in curl unzip sha256sum openssl sed install; do require "$cmd"; done

if [[ ! -f "$UUID_FILE" ]]; then
  [[ "$DRY_RUN" -eq 1 ]] || { cat /proc/sys/kernel/random/uuid >"$UUID_FILE"; chmod 600 "$UUID_FILE"; }
fi

tmp_dir="$(mktemp -d)"
trap 'rm -rf -- "$tmp_dir"' EXIT
archive="${tmp_dir}/${XRAY_ARCHIVE}"
digest="${archive}.dgst"

echo "Pinned Xray version: ${XRAY_VERSION}"
echo "Official source: ${OFFICIAL_BASE}/${XRAY_ARCHIVE}"
# ETIP_SHA256_OVERRIDE_BEGIN
digest="$(
  curl -fsSL \
    --retry 3 \
    --connect-timeout 15 \
    "${OFFICIAL_BASE}/Xray-linux-64.zip.dgst" \
  | grep -Eio '[0-9a-fA-F]{64}' \
  | head -n 1 \
  | tr '[:upper:]' '[:lower:]'
)"
# ETIP_SHA256_OVERRIDE_END

if [[ "$DRY_RUN" -eq 1 ]]; then
  echo "DRY-RUN: would download archive and .dgst, verify SHA256, install binary/config/service, and restrict UFW"
  echo "DRY-RUN: would generate ${UUID_FILE} once if absent (mode 0600); UUID is not printed"
  exit 0
fi

curl --fail --location --proto '=https' --tlsv1.2 -o "$archive" "${OFFICIAL_BASE}/${XRAY_ARCHIVE}"
curl --fail --location --proto '=https' --tlsv1.2 -o "$digest" "${OFFICIAL_BASE}/${XRAY_ARCHIVE}.dgst"
expected_sha256="$(grep -Ei 'SHA2-256|SHA-256|SHA256' "$digest" | grep -Eio '[0-9A-Fa-f]{64}' | head -n 1 | tr '[:upper:]' '[:lower:]')"
[[ "$expected_sha256" =~ ^[0-9A-Fa-f]{64}$ ]] || { echo "official digest has no valid SHA256" >&2; exit 1; }
printf '%s  %s\n' "$expected_sha256" "$archive" | sha256sum --check --strict

unzip -q "$archive" xray -d "$tmp_dir"
sudo install -o root -g root -m 0755 "${tmp_dir}/xray" /usr/local/bin/xray
sudo install -d -o root -g root -m 0755 /etc/xray

uuid="$(<"$UUID_FILE")"
[[ "$uuid" =~ ^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$ ]] || { echo "invalid local UUID" >&2; exit 1; }
sed "s/__VLESS_UUID__/${uuid}/g" "${SCRIPT_DIR}/xray-server.json" >"${tmp_dir}/config.json"
sudo install -o root -g root -m 0600 "${tmp_dir}/config.json" /etc/xray/config-vless-20001.json

sudo test -r /etc/proxytraffic/pki/server.crt
sudo test -r /etc/proxytraffic/pki/server.key
sudo openssl x509 -in /etc/proxytraffic/pki/server.crt -noout -ext subjectAltName | grep -F 'DNS:etip-server.lab' >/dev/null
sudo openssl x509 -in /etc/proxytraffic/pki/server.crt -noout -ext subjectAltName | grep -F 'DNS:etip-server' >/dev/null
sudo openssl x509 -in /etc/proxytraffic/pki/server.crt -noout -ext subjectAltName | grep -F 'IP Address:192.168.100.20' >/dev/null
sudo /usr/local/bin/xray run -test -config /etc/xray/config-vless-20001.json

service_file="${tmp_dir}/xray-vless-20001.service"
printf '%s\n' \
  '[Unit]' 'Description=ETIP VLESS TCP TLS Pilot' 'After=network-online.target' 'Wants=network-online.target' '' \
  '[Service]' 'Type=simple' 'ExecStart=/usr/local/bin/xray run -config /etc/xray/config-vless-20001.json' \
  'Restart=on-failure' 'RestartSec=3' 'NoNewPrivileges=true' '' \
  '[Install]' 'WantedBy=multi-user.target' >"$service_file"
sudo install -o root -g root -m 0644 "$service_file" /etc/systemd/system/xray-vless-20001.service
sudo systemctl daemon-reload
sudo systemctl enable --now xray-vless-20001.service

if command -v ufw >/dev/null && sudo ufw status | grep -q '^Status: active'; then
  existing_rules="$(sudo ufw status | awk '$0 ~ /20001\/tcp/ {print}')"
  if [[ -n "$existing_rules" ]] && grep -Fv '192.168.100.10' <<<"$existing_rules" >/dev/null; then
    echo "ERROR: a TCP 20001 UFW rule exists for a source other than 192.168.100.10; remove it explicitly" >&2
    printf '%s\n' "$existing_rules" >&2
    exit 1
  fi
  sudo ufw allow from 192.168.100.10 to 192.168.100.20 port 20001 proto tcp comment 'ETIP Xray Collector only'
else
  echo "ERROR: active UFW not found; apply an equivalent source-restricted firewall rule before acceptance" >&2
  exit 1
fi

echo "Provisioned Xray ${XRAY_VERSION}; UUID remains in ${UUID_FILE} and was not printed."
