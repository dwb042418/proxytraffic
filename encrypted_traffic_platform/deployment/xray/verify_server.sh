#!/usr/bin/env bash
set -euo pipefail
DRY_RUN=0
[[ "${1:-}" == "--dry-run" ]] && DRY_RUN=1
commands=(
  "/usr/local/bin/xray version"
  "/usr/local/bin/xray run -test -config /etc/xray/config-vless-20001.json"
  "openssl x509 -in /etc/proxytraffic/pki/server.crt -noout -subject -issuer -dates -ext subjectAltName"
  "ss -ltnp | grep '192.168.100.20:20001'"
  "systemctl status xray-vless-20001.service --no-pager"
  "ufw status | grep -F '192.168.100.10'"
)
if [[ "$DRY_RUN" -eq 1 ]]; then printf 'sudo %s\n' "${commands[@]}"; exit 0; fi
for command_text in "${commands[@]}"; do sudo bash -c "$command_text"; done

