#!/usr/bin/env bash
set -Eeuo pipefail

PIDFILE=/home/etip/logs/shadowsocks/sslocal.pid

if [ ! -f ${PIDFILE} ]; then
    echo SHADOWSOCKS_CLIENT_ALREADY_STOPPED
    exit 0
fi

PID=$(cat ${PIDFILE})

if kill -0 ${PID} 2>/dev/null; then
    kill ${PID} || true

    for _ in $(seq 1 30)
    do
        if ! kill -0 ${PID} 2>/dev/null; then
            break
        fi
        sleep 0.2
    done
fi

rm -f ${PIDFILE}

if ss -lnt | grep -q '127.0.0.1:11081'; then
    echo SHADOWSOCKS_CLIENT_PORT_STILL_LISTENING >&2
    exit 1
fi

echo SHADOWSOCKS_CLIENT_STOPPED
