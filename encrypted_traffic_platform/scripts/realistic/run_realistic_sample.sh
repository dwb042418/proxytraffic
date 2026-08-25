#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 6 ]]; then
  echo "usage: $0 MODE SEED INTENSITY PLAN LOCAL_ROOT REMOTE_ROOT" >&2
  exit 2
fi

MODE=$1
SEED=$2
INTENSITY=$3
PLAN=$(readlink -f "$4")
LOCAL_ROOT=$5
REMOTE_ROOT=$6
case "$MODE" in direct|vless|shadowsocks|trojan) ;; *) echo "invalid mode" >&2; exit 2;; esac
case "$INTENSITY" in light|medium|heavy) ;; *) echo "invalid intensity" >&2; exit 2;; esac

REPO=/home/etip/Tunnel/proxytraffic
MODE_TOOL=/home/etip/bin/realistic-mode
AUDITOR=$REPO/encrypted_traffic_platform/realistic/audit_realistic_sample.py
USER_HOST=realistic-user
SERVER_HOST=etip@192.168.100.20
UPLOAD_HOST=proxydata-server
STAMP=$(date -u +%Y%m%dT%H%M%SZ)
PAIR_GROUP_ID="seed${SEED}_${INTENSITY}"
SAMPLE_ID="sample_${MODE}_seed${SEED}_${INTENSITY}_${STAMP}"
SAMPLE_DIR=$LOCAL_ROOT/$SAMPLE_ID
REMOTE_SAMPLE=$REMOTE_ROOT/$SAMPLE_ID
USER_RUN_ROOT="/home/etip/.cache/proxytraffic-realistic-runs/$SAMPLE_ID"
SERVER_TMP_ROOT="/tmp/proxytraffic-realistic-capture-$SAMPLE_ID"
mkdir -p "$SAMPLE_DIR/workload"

ORIGINAL_PID=
OBSERVED_PID=
SERVER_CAPTURE_STARTED=0

stop_captures() {
  for pid in "$ORIGINAL_PID" "$OBSERVED_PID"; do
    if [[ -n "$pid" ]] && sudo -n kill -0 "$pid" 2>/dev/null; then sudo -n kill -INT "$pid" 2>/dev/null || true; fi
  done
  if [[ $SERVER_CAPTURE_STARTED -eq 1 ]]; then
    ssh -o BatchMode=yes "$SERVER_HOST" "sudo -n bash -c 'if test -s $SERVER_TMP_ROOT/tcpdump.pid; then p=\$(cat $SERVER_TMP_ROOT/tcpdump.pid); kill -INT \$p 2>/dev/null || true; for i in \$(seq 1 50); do kill -0 \$p 2>/dev/null || break; sleep 0.1; done; fi'" || true
  fi
}

cleanup_runtime() {
  stop_captures
  "$MODE_TOOL" clear >/dev/null 2>&1 || true
}
trap cleanup_runtime EXIT INT TERM

"$MODE_TOOL" clear
"$MODE_TOOL" "$MODE"
sleep 1

sudo -n tcpdump -i ens38 -s 0 -U -w "$SAMPLE_DIR/original_raw.pcap" 'host 192.168.210.10 and tcp' >"$SAMPLE_DIR/original_tcpdump.log" 2>&1 &
ORIGINAL_PID=$!
sudo -n tcpdump -i ens39 -s 0 -U -w "$SAMPLE_DIR/observed_raw.pcap" 'tcp and not port 22' >"$SAMPLE_DIR/observed_tcpdump.log" 2>&1 &
OBSERVED_PID=$!
ssh -o BatchMode=yes "$SERVER_HOST" "sudo -n bash -c 'install -d -o root -g root -m 700 $SERVER_TMP_ROOT; tcpdump -i ens33 -s 0 -U -w $SERVER_TMP_ROOT/egress_raw.pcap \"tcp and not port 22\" >$SERVER_TMP_ROOT/tcpdump.log 2>&1 & echo \$! >$SERVER_TMP_ROOT/tcpdump.pid'"
SERVER_CAPTURE_STARTED=1
sleep 1

PLAN_SHA=$(sha256sum "$PLAN" | awk '{print $1}')
ssh -o BatchMode=yes "$USER_HOST" "install -d -m 700 '$USER_RUN_ROOT'"
scp -q "$PLAN" "$USER_HOST:$USER_RUN_ROOT/workload_plan.json"
ssh -o BatchMode=yes "$USER_HOST" "/home/etip/.venvs/realistic/bin/python /home/etip/proxytraffic-realistic/realistic_browser.py --plan '$USER_RUN_ROOT/workload_plan.json' --output-dir '$USER_RUN_ROOT/workload' --mode '$MODE'"
sleep 3
stop_captures
sleep 1
sudo -n chown etip:etip "$SAMPLE_DIR/original_raw.pcap" "$SAMPLE_DIR/observed_raw.pcap"
ssh -o BatchMode=yes "$SERVER_HOST" "sudo -n chown -R etip:etip '$SERVER_TMP_ROOT'; chmod 700 '$SERVER_TMP_ROOT'"
scp -q "$SERVER_HOST:$SERVER_TMP_ROOT/egress_raw.pcap" "$SAMPLE_DIR/egress_raw.pcap"
rsync -a "$USER_HOST:$USER_RUN_ROOT/workload/" "$SAMPLE_DIR/workload/"

reordercap "$SAMPLE_DIR/original_raw.pcap" "$SAMPLE_DIR/original.pcap" >/dev/null
reordercap "$SAMPLE_DIR/observed_raw.pcap" "$SAMPLE_DIR/observed.pcap" >/dev/null
reordercap "$SAMPLE_DIR/egress_raw.pcap" "$SAMPLE_DIR/egress.pcap" >/dev/null

IS_PROXY=true
PROTOCOL=$MODE
IMPLEMENTATION=xray
if [[ $MODE == direct ]]; then IS_PROXY=false; PROTOCOL=none; IMPLEMENTATION=direct; fi
if [[ $MODE == shadowsocks ]]; then IMPLEMENTATION=shadowsocks-rust; fi
jq -n --argjson is_proxy "$IS_PROXY" --arg protocol "$PROTOCOL" --arg implementation "$IMPLEMENTATION" '{is_proxy:$is_proxy,proxy_protocol:$protocol,implementation:$implementation,transport:"tcp"}' > "$SAMPLE_DIR/label.json"
BROWSER_VERSION=$(jq -r '.browser_version' "$SAMPLE_DIR/workload/workload_report.json")
GIT_HEAD=$(git -C "$REPO" rev-parse HEAD)
XRAY_VERSION=$(xray version | head -1)
SS_VERSION=$(/home/etip/.local/opt/shadowsocks-rust-v1.24.0/sslocal --version | head -1)
jq -n --arg git_head "$GIT_HEAD" --arg browser_version "$BROWSER_VERSION" --arg xray_version "$XRAY_VERSION" --arg shadowsocks_version "$SS_VERSION" --arg collection_time "$STAMP" --arg network_condition "vmnet5-vmnet6-vmnet8-baseline" --arg mode "$MODE" --arg seed "$SEED" --arg intensity "$INTENSITY" '{git_head:$git_head,browser_version:$browser_version,xray_version:$xray_version,shadowsocks_version:$shadowsocks_version,collection_time_utc:$collection_time,network_condition:$network_condition,mode:$mode,seed:($seed|tonumber),intensity:$intensity,capture_interfaces:{original:"collector:ens38",observed:"collector:ens39",egress:"server:ens33"}}' > "$SAMPLE_DIR/environment.json"
jq -n --arg pair_group_id "$PAIR_GROUP_ID" --arg plan_sha "$PLAN_SHA" '{pair_group_id:$pair_group_id,workload_plan_sha256:$plan_sha,egress_applicable:true,model_input:"observed.pcap"}' > "$SAMPLE_DIR/pairing.json"

python3 "$AUDITOR" --sample-dir "$SAMPLE_DIR" --mode "$MODE"
(
  cd "$SAMPLE_DIR"
  find . -type f ! -name SHA256SUMS.txt ! -name SAMPLE_COMPLETE -print0 | sort -z | xargs -0 sha256sum > SHA256SUMS.txt
  sha256sum -c SHA256SUMS.txt >/dev/null
)

ssh -o BatchMode=yes "$UPLOAD_HOST" "mkdir -p '$REMOTE_SAMPLE'"
rsync -a "$SAMPLE_DIR/" "$UPLOAD_HOST:$REMOTE_SAMPLE/"
ssh -o BatchMode=yes "$UPLOAD_HOST" "cd '$REMOTE_SAMPLE' && sha256sum -c SHA256SUMS.txt >/dev/null"
printf 'REMOTE_SHA256_PASS host=%s path=%s\n' "$UPLOAD_HOST" "$REMOTE_SAMPLE" > "$SAMPLE_DIR/remote_sha_verification.txt"
printf 'SAMPLE_COMPLETE %s\n' "$STAMP" > "$SAMPLE_DIR/SAMPLE_COMPLETE"
rsync -a "$SAMPLE_DIR/remote_sha_verification.txt" "$SAMPLE_DIR/SAMPLE_COMPLETE" "$UPLOAD_HOST:$REMOTE_SAMPLE/"

ssh -o BatchMode=yes "$SERVER_HOST" "sudo -n unlink '$SERVER_TMP_ROOT/egress_raw.pcap'; sudo -n unlink '$SERVER_TMP_ROOT/tcpdump.log'; sudo -n unlink '$SERVER_TMP_ROOT/tcpdump.pid'; sudo -n rmdir '$SERVER_TMP_ROOT'" || true
"$MODE_TOOL" clear
trap - EXIT INT TERM
echo "SAMPLE_COMPLETE=$SAMPLE_DIR"
echo "REMOTE_SAMPLE=$REMOTE_SAMPLE"
