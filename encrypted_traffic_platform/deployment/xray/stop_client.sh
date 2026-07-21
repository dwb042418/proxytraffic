#!/usr/bin/env bash
set -euo pipefail
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
PID_FILE="${SCRIPT_DIR}/.runtime/xray.pid"
[[ -s "$PID_FILE" ]] || { echo "client is not running"; exit 0; }
pid="$(<"$PID_FILE")"
[[ "$pid" =~ ^[0-9]+$ ]] || { echo "invalid PID file" >&2; exit 1; }
kill "$pid"
for _ in {1..50}; do kill -0 "$pid" 2>/dev/null || break; sleep 0.1; done
kill -0 "$pid" 2>/dev/null && { echo "client did not stop cleanly" >&2; exit 1; }
rm -f -- "$PID_FILE"
echo "Xray client stopped"

