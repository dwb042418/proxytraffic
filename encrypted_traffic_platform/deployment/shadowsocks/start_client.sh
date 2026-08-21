#!/usr/bin/env bash
set -Eeuo pipefail

VERSION=v1.24.0
ROOT=/home/etip/.local/opt/shadowsocks-rust-${VERSION}
CONF=/home/etip/.config/proxytraffic/shadowsocks/client.json
LOG_DIR=/home/etip/logs/shadowsocks
PIDFILE=${LOG_DIR}/sslocal.pid
LOG=${LOG_DIR}/sslocal.log

mkdir -p ${LOG_DIR}

SSLOCAL=$(
  find ${ROOT} \
    -type f \
    -name sslocal \
    -print \
    -quit
)

test -x ${SSLOCAL}
test -f ${CONF}

if [ -f ${PIDFILE} ]; then
    OLD_PID=$(cat ${PIDFILE})

    if kill -0 ${OLD_PID} 2>/dev/null; then
        kill ${OLD_PID} || true

        for _ in $(seq 1 20)
        do
            if ! kill -0 ${OLD_PID} 2>/dev/null; then
                break
            fi
            sleep 0.2
        done
    fi
fi

nohup \
  ${SSLOCAL} \
  -c ${CONF} \
  > ${LOG} \
  2>&1 &

PID=$!

echo ${PID} > ${PIDFILE}

for _ in $(seq 1 30)
do
    if ss -lnt | grep -q '127.0.0.1:11081'; then
        echo SHADOWSOCKS_CLIENT_READY
        exit 0
    fi

    if ! kill -0 ${PID} 2>/dev/null; then
        break
    fi

    sleep 0.2
done

cat ${LOG}
echo SHADOWSOCKS_CLIENT_START_FAILED >&2
exit 1
