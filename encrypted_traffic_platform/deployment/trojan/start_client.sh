#!/usr/bin/env bash
set -Eeuo pipefail

XRAY_BIN=$(command -v xray)

CONFIG=${HOME}/.config/proxytraffic/trojan/client.json

CACHE_DIR=${HOME}/.cache/proxytraffic
LOG_DIR=${HOME}/logs/trojan

PIDFILE=${CACHE_DIR}/trojan-client.pid
LOGFILE=${LOG_DIR}/client.log

mkdir -p \
  "${CACHE_DIR}" \
  "${LOG_DIR}"

if [ -f "${PIDFILE}" ]; then

    PID=$(
        cat "${PIDFILE}" \
        2>/dev/null \
        || true
    )

    if [ -n "${PID}" ] \
       && kill -0 "${PID}" \
          2>/dev/null
    then
        kill "${PID}" \
          2>/dev/null \
          || true

        sleep 1
    fi

    rm -f "${PIDFILE}"
fi

nohup \
  "${XRAY_BIN}" \
  run \
  -config "${CONFIG}" \
  > "${LOGFILE}" \
  2>&1 &

PID=$!

printf '%s\n' \
  "${PID}" \
  > "${PIDFILE}"

for _ in $(seq 1 40)
do
    if ss -lntH \
      | grep -q \
        '127.0.0.1:11082'
    then
        echo TROJAN_CLIENT_READY
        exit 0
    fi

    if ! kill -0 "${PID}" \
      2>/dev/null
    then

        echo TROJAN_CLIENT_DIED

        tail -n 80 \
          "${LOGFILE}" \
          || true

        exit 1
    fi

    sleep 0.25
done

echo TROJAN_CLIENT_LISTENER_TIMEOUT

tail -n 80 \
  "${LOGFILE}" \
  || true

exit 1
