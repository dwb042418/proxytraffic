#!/usr/bin/env bash
set -Eeuo pipefail

PIDFILE=${HOME}/.cache/proxytraffic/trojan-client.pid

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

        for _ in $(seq 1 20)
        do
            if ! kill -0 "${PID}" \
              2>/dev/null
            then
                break
            fi

            sleep 0.25
        done

        if kill -0 "${PID}" \
          2>/dev/null
        then
            kill -9 "${PID}" \
              2>/dev/null \
              || true
        fi
    fi

    rm -f "${PIDFILE}"
fi

echo TROJAN_CLIENT_STOPPED
