#!/usr/bin/env bash
set -euo pipefail
umask 077
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
UUID_FILE="${SCRIPT_DIR}/.vless_uuid"
RUNTIME_DIR="${SCRIPT_DIR}/.runtime"
XRAY_BIN="${XRAY_BIN:-xray}"
[[ -r "$UUID_FILE" ]] || { echo "copy the Server .vless_uuid securely to ${UUID_FILE} (mode 0600)" >&2; exit 1; }
mkdir -p "$RUNTIME_DIR"
chmod 700 "$RUNTIME_DIR"
[[ ! -s "${RUNTIME_DIR}/xray.pid" ]] || { echo "client already has a PID file" >&2; exit 1; }
uuid="$(<"$UUID_FILE")"
sed "s/__VLESS_UUID__/${uuid}/g" "${SCRIPT_DIR}/xray-client.json" >"${RUNTIME_DIR}/client.json"
chmod 600 "${RUNTIME_DIR}/client.json"
"$XRAY_BIN" run -test -config "${RUNTIME_DIR}/client.json"
nohup "$XRAY_BIN" run -config "${RUNTIME_DIR}/client.json" >"${RUNTIME_DIR}/client.log" 2>&1 &
echo "$!" >"${RUNTIME_DIR}/xray.pid"
echo "Xray SOCKS5 client started on 127.0.0.1:11080"

