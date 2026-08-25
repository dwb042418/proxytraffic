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

ORIGINAL_PID_FILE=$SAMPLE_DIR/original_tcpdump.pid
OBSERVED_PID_FILE=$SAMPLE_DIR/observed_tcpdump.pid
SERVER_PID_FILE=$SERVER_TMP_ROOT/tcpdump.pid
SERVER_CAPTURE_STARTED=0
CAPTURES_FINALIZED=0
RUN_COMPLETE=0

mark_sample_fail() {
  local reason=$1
  if [[ -d $SAMPLE_DIR && ! -e $SAMPLE_DIR/SAMPLE_COMPLETE ]]; then
    printf 'SAMPLE_FAIL %s reason=%s\n' "$(date -u +%Y%m%dT%H%M%SZ)" "$reason" > "$SAMPLE_DIR/SAMPLE_FAIL"
  fi
}

wait_local_pid_exit() {
  local pid=$1 signal timeout_ticks tick
  for signal in INT TERM; do
    sudo -n kill -"$signal" "$pid" 2>/dev/null || true
    timeout_ticks=75
    [[ $signal == TERM ]] && timeout_ticks=25
    for ((tick=0; tick<timeout_ticks; tick++)); do
      if ! sudo -n kill -0 "$pid" 2>/dev/null; then
        wait "$pid" 2>/dev/null || true
        return 0
      fi
      sleep 0.2
    done
  done
  echo "capture process did not exit after INT and TERM: pid=$pid" >&2
  return 1
}

wait_remote_pid_exit() {
  local pid=$1
  ssh -o BatchMode=yes "$SERVER_HOST" "sudo -n bash -s -- '$pid'" <<'REMOTE_STOP'
set -u
pid=$1
for signal in INT TERM; do
  kill -"$signal" "$pid" 2>/dev/null || true
  ticks=75
  test "$signal" = TERM && ticks=25
  tick=0
  while test "$tick" -lt "$ticks"; do
    if ! kill -0 "$pid" 2>/dev/null; then exit 0; fi
    sleep 0.2
    tick=$((tick + 1))
  done
done
echo "remote capture process did not exit after INT and TERM: pid=$pid" >&2
exit 1
REMOTE_STOP
}

verify_file_stable() {
  local path=$1 first second
  [[ -s $path ]] || { echo "capture file is empty: $path" >&2; return 1; }
  first=$(stat -c %s "$path")
  sleep 0.4
  second=$(stat -c %s "$path")
  [[ $first == "$second" ]] || {
    echo "capture file size is not stable: $path ($first -> $second)" >&2
    return 1
  }
}

stop_stale_local_captures() {
  local -a pids=()
  mapfile -t pids < <(sudo -n pgrep -f '^tcpdump .*realistic.*\.pcap' 2>/dev/null || true)
  ((${#pids[@]} == 0)) && return 0
  printf 'WARNING stale local Realistic captures found: %s\n' "${pids[*]}" | tee -a "$SAMPLE_DIR/capture_warnings.log" >&2
  local pid
  for pid in "${pids[@]}"; do wait_local_pid_exit "$pid" || return 1; done
  mapfile -t pids < <(sudo -n pgrep -f '^tcpdump .*realistic.*\.pcap' 2>/dev/null || true)
  ((${#pids[@]} == 0)) || { echo "stale local capture count=${#pids[@]}" >&2; return 1; }
}

stop_stale_remote_captures() {
  local output
  output=$(ssh -o BatchMode=yes "$SERVER_HOST" "sudo -n pgrep -f '^tcpdump .*proxytraffic-realistic-capture-.*\.pcap' 2>/dev/null || true")
  [[ -z $output ]] && return 0
  printf 'WARNING stale remote Realistic captures found: %s\n' "${output//$'\n'/ }" | tee -a "$SAMPLE_DIR/capture_warnings.log" >&2
  local pid
  while read -r pid; do [[ -n $pid ]] && wait_remote_pid_exit "$pid" || return 1; done <<< "$output"
  output=$(ssh -o BatchMode=yes "$SERVER_HOST" "sudo -n pgrep -f '^tcpdump .*proxytraffic-realistic-capture-.*\.pcap' 2>/dev/null || true")
  [[ -z $output ]] || { echo "stale remote captures remain: ${output//$'\n'/ }" >&2; return 1; }
}

start_local_capture() {
  local interface=$1 pcap=$2 log=$3 pid_file=$4
  shift 4
  sudo -n bash -c '
    interface=$1; pcap=$2; log=$3; pid_file=$4; shift 4
    tcpdump -i "$interface" -s 0 -U -w "$pcap" "$@" >"$log" 2>&1 &
    printf "%s\n" "$!" > "$pid_file"
  ' capture-launcher "$interface" "$pcap" "$log" "$pid_file" "$@"
  sudo -n chown etip:etip "$pid_file"
}

stop_captures() {
  local pid
  for pid_file in "$ORIGINAL_PID_FILE" "$OBSERVED_PID_FILE"; do
    if [[ -s $pid_file ]]; then
      pid=$(<"$pid_file")
      if sudo -n kill -0 "$pid" 2>/dev/null; then wait_local_pid_exit "$pid" || return 1; fi
      sudo -n kill -0 "$pid" 2>/dev/null && { echo "local capture still exists: pid=$pid" >&2; return 1; }
    fi
  done
  if [[ $SERVER_CAPTURE_STARTED -eq 1 ]]; then
    pid=$(ssh -o BatchMode=yes "$SERVER_HOST" "sudo -n cat '$SERVER_PID_FILE'")
    if ssh -o BatchMode=yes "$SERVER_HOST" "sudo -n kill -0 '$pid'" 2>/dev/null; then wait_remote_pid_exit "$pid" || return 1; fi
    ssh -o BatchMode=yes "$SERVER_HOST" "! sudo -n kill -0 '$pid' 2>/dev/null" || { echo "remote capture still exists: pid=$pid" >&2; return 1; }
  fi
  verify_file_stable "$SAMPLE_DIR/original_raw.pcap" || return 1
  verify_file_stable "$SAMPLE_DIR/observed_raw.pcap" || return 1
  ssh -o BatchMode=yes "$SERVER_HOST" "sudo -n bash -c 'test -s \"$SERVER_TMP_ROOT/egress_raw.pcap\"; a=\$(stat -c %s \"$SERVER_TMP_ROOT/egress_raw.pcap\"); sleep 0.4; b=\$(stat -c %s \"$SERVER_TMP_ROOT/egress_raw.pcap\"); test \"\$a\" = \"\$b\"'" || { echo "remote capture file is empty or unstable" >&2; return 1; }
  CAPTURES_FINALIZED=1
}

cleanup_runtime() {
  local exit_status=$?
  set +e
  if [[ $CAPTURES_FINALIZED -ne 1 ]]; then stop_captures; fi
  "$MODE_TOOL" clear >/dev/null 2>&1 || true
  if [[ $RUN_COMPLETE -ne 1 ]]; then mark_sample_fail "runner_exit_$exit_status"; fi
  return "$exit_status"
}
handle_signal() {
  local status=$1
  trap - INT TERM
  exit "$status"
}
trap cleanup_runtime EXIT
trap 'handle_signal 130' INT
trap 'handle_signal 143' TERM

stop_stale_local_captures
stop_stale_remote_captures
"$MODE_TOOL" clear
"$MODE_TOOL" "$MODE"
sleep 1

start_local_capture ens38 "$SAMPLE_DIR/original_raw.pcap" "$SAMPLE_DIR/original_tcpdump.log" "$ORIGINAL_PID_FILE" host 192.168.210.10 and tcp
start_local_capture ens39 "$SAMPLE_DIR/observed_raw.pcap" "$SAMPLE_DIR/observed_tcpdump.log" "$OBSERVED_PID_FILE" tcp and not port 22
ssh -o BatchMode=yes "$SERVER_HOST" "sudo -n bash -c 'install -d -o root -g root -m 700 $SERVER_TMP_ROOT; tcpdump -i ens33 -s 0 -U -w $SERVER_TMP_ROOT/egress_raw.pcap \"tcp and not port 22\" >$SERVER_TMP_ROOT/tcpdump.log 2>&1 & echo \$! >$SERVER_TMP_ROOT/tcpdump.pid'"
SERVER_CAPTURE_STARTED=1
sleep 1
for pid_file in "$ORIGINAL_PID_FILE" "$OBSERVED_PID_FILE"; do
  pid=$(<"$pid_file")
  sudo -n kill -0 "$pid" 2>/dev/null || { echo "local capture failed to start: pid=$pid" >&2; exit 1; }
done
pid=$(ssh -o BatchMode=yes "$SERVER_HOST" "sudo -n cat '$SERVER_PID_FILE'")
ssh -o BatchMode=yes "$SERVER_HOST" "sudo -n kill -0 '$pid'" 2>/dev/null || { echo "remote capture failed to start: pid=$pid" >&2; exit 1; }

PLAN_SHA=$(sha256sum "$PLAN" | awk '{print $1}')
ssh -o BatchMode=yes "$USER_HOST" "install -d -m 700 '$USER_RUN_ROOT'"
scp -q "$PLAN" "$USER_HOST:$USER_RUN_ROOT/workload_plan.json"
ssh -o BatchMode=yes "$USER_HOST" "/home/etip/.venvs/realistic/bin/python /home/etip/proxytraffic-realistic/realistic_browser.py --plan '$USER_RUN_ROOT/workload_plan.json' --output-dir '$USER_RUN_ROOT/workload' --mode '$MODE'"
sleep 3
stop_captures
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
LOCAL_RESIDUAL_COUNT=$(sudo -n pgrep -fc '^tcpdump .*realistic.*\.pcap' 2>/dev/null || true)
REMOTE_RESIDUAL_COUNT=$(ssh -o BatchMode=yes "$SERVER_HOST" "sudo -n pgrep -fc '^tcpdump .*proxytraffic-realistic-capture-.*\.pcap' 2>/dev/null || true")
[[ $LOCAL_RESIDUAL_COUNT -eq 0 && $REMOTE_RESIDUAL_COUNT -eq 0 ]] || {
  echo "residual captures detected: local=$LOCAL_RESIDUAL_COUNT remote=$REMOTE_RESIDUAL_COUNT" >&2
  exit 1
}
printf 'RESIDUAL_CAPTURE_COUNT=0 local=0 remote=0\n' > "$SAMPLE_DIR/capture_finalization.txt"
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
RUN_COMPLETE=1
trap - EXIT INT TERM
echo "SAMPLE_COMPLETE=$SAMPLE_DIR"
echo "REMOTE_SAMPLE=$REMOTE_SAMPLE"
