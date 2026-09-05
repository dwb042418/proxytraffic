#!/usr/bin/env python3
"""Run one non-Formal Formal-T0-v3 quartet with isolated health and capture windows."""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import os
import shutil
import signal
import stat
import subprocess
import threading
import time
from collections import Counter, defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path


REPO = Path("/home/etip/Tunnel/proxytraffic")
DOC = REPO / "docs/realistic_v1/formal_t0_v3"
POOL = DOC / "formal_domain_pool_v3.tsv"
SPLIT = DOC / "formal_domain_split_v3.tsv"
REGISTRY = DOC / "FORMAL_T0_V3_PLAN_SHA256SUMS.txt"
SCHEDULE = DOC / "formal_t0_v3_schedule.tsv"
EXECUTOR = REPO / "encrypted_traffic_platform/realistic/realistic_browser_v3.py"
SUPERVISOR = REPO / "encrypted_traffic_platform/scripts/realistic/realistic-executor-supervisor"
AUDITOR = REPO / "encrypted_traffic_platform/realistic/audit_realistic_sample.py"
MODE_TOOL = Path("/home/etip/bin/realistic-mode")
HEALTH_HELPER = "/home/etip/bin/realistic-health-curl-probe"

FROZEN_SHA256 = {
    POOL: "ded7fd1277a32295fb1e5fef3b6df0967f10a578cb2d204b04409b55b6878071",
    SPLIT: "0bb7fe4d5d8052e89047cc043ffe3ee24c9eecdfbebd9fcbce6b2314aca5d7a0",
    REGISTRY: "5c6024cd99f8d8280186d7d32c97b0d6f6bfdd230008ba174aa03cc9e350443a",
    SCHEDULE: "59af23a493cdf78cf1b6fea697b69d23c7746a69ac96ee05b6e694908ea309fa",
}
EXPECTED_EXECUTOR_SHA256 = "8e034da6979c463391f78ff95c4f98f76d675d44f72377980ab00e4636cc74a1"
EXPECTED_SUPERVISOR_SHA256 = "9a97f5912310d877f5ec24f09873f005ff6d9c4d0c0e4d4c583e1e423d7ee63c"

USER_HOST = "realistic-user"
SERVER_HOST = "etip@192.168.100.20"
UPLOAD_HOST = "proxydata-server"
MODES = ("direct", "vless", "shadowsocks", "trojan")
PORTS = (21001, 21002, 21003)
EXPECTED_PORT = {"direct": None, "vless": 21001, "shadowsocks": 21002, "trojan": 21003}
MODE_UNITS = {
    "direct": (),
    "vless": ("xray-realistic-vless-client-12080.service", "redsocks-realistic@vless.service"),
    "shadowsocks": ("shadowsocks-realistic-client-12081.service", "redsocks-realistic@shadowsocks.service"),
    "trojan": ("xray-realistic-trojan-client-12082.service", "redsocks-realistic@trojan.service"),
}
ALL_UNITS = tuple(dict.fromkeys(unit for units in MODE_UNITS.values() for unit in units))
REDSOCKS_UNIT = {
    "vless": "redsocks-realistic@vless.service",
    "shadowsocks": "redsocks-realistic@shadowsocks.service",
    "trojan": "redsocks-realistic@trojan.service",
}
PUBLIC_CONTROLS = (
    ("cloudflare", "https://cp.cloudflare.com/generate_204", ""),
    ("microsoft", "https://www.msftconnecttest.com/connecttest.txt", "Microsoft Connect Test"),
    ("mozilla", "https://detectportal.firefox.com/success.txt", "success"),
    ("apple", "https://captive.apple.com/hotspot-detect.html", "<HTML><HEAD><TITLE>Success</TITLE></HEAD><BODY>Success</BODY></HTML>"),
    ("ubuntu", "https://connectivity-check.ubuntu.com/", ""),
)
CANARY = {
    "url": "https://192.168.220.20:24443/healthz-v3",
    "expected_body": "REALISTIC_TROJAN_CANARY_V3_OK",
    "connect_timeout_seconds": 10,
    "timeout_seconds": 15,
}


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def stamp_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def write_json(path: Path, value: object) -> None:
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def run(
    argv: list[str],
    timeout: float = 60,
    check: bool = False,
    input_text: str | None = None,
) -> subprocess.CompletedProcess[str]:
    completed = subprocess.run(
        argv,
        input=input_text,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=timeout,
    )
    if check and completed.returncode:
        raise RuntimeError(
            f"command failed rc={completed.returncode}: {' '.join(argv)}\n"
            f"stdout={completed.stdout[-2000:]}\nstderr={completed.stderr[-2000:]}"
        )
    return completed


def require(condition: bool, message: str) -> None:
    if not condition:
        raise RuntimeError(message)


def read_tsv(path: Path) -> list[dict[str, str]]:
    with path.open(newline="", encoding="utf-8") as handle:
        return list(csv.DictReader(handle, delimiter="\t"))


def verify_frozen_inputs() -> None:
    for path, expected in FROZEN_SHA256.items():
        require(path.is_file(), f"missing frozen input: {path}")
        require(sha256(path) == expected, f"frozen input SHA mismatch: {path}")
    require(sha256(EXECUTOR) == EXPECTED_EXECUTOR_SHA256, "v3 bounded executor SHA mismatch")
    require(sha256(SUPERVISOR) == EXPECTED_SUPERVISOR_SHA256, "executor supervisor SHA mismatch")
    registry_rows = []
    for line in REGISTRY.read_text(encoding="utf-8").splitlines():
        if line.strip():
            digest, path = line.split("  ", 1)
            registry_rows.append((digest, Path(path)))
    require(len(registry_rows) == 300, "plan registry count mismatch")
    for expected, path in registry_rows:
        require(path.is_file() and sha256(path) == expected, f"plan registry mismatch: {path}")
        require(stat.S_IMODE(path.stat().st_mode) == 0o444, f"plan not 0444: {path}")


def select_quartet() -> dict[str, object]:
    rows = read_tsv(SCHEDULE)
    require(len(rows) == 1200, "schedule row count mismatch")
    grouped: dict[str, list[dict[str, str]]] = defaultdict(list)
    for row in rows:
        if row["intensity"] == "heavy":
            grouped[row["pair_group_id"]].append(row)
    require(grouped, "no heavy pair group in schedule")
    pair_group_id, group = min(
        grouped.items(), key=lambda item: (int(item[1][0]["quartet_index"]), item[0])
    )
    require(len(group) == 4 and {row["mode_order"] for row in group} == set(MODES), "selected schedule group incomplete")
    first = group[0]
    fields = ("seed", "seed_assignment_id", "split", "intensity", "pair_group_id", "plan_path", "plan_sha256", "plan_id")
    for field in fields:
        require(len({row[field] for row in group}) == 1, f"selected group {field} mismatch")
    plan = Path(first["plan_path"])
    require(plan.is_file() and sha256(plan) == first["plan_sha256"], "selected plan SHA mismatch")
    return {
        "selection_rule": "filter intensity=heavy; sort pair groups by numeric quartet_index ascending then pair_group_id ascending; select first",
        "quartet_index": int(first["quartet_index"]),
        "seed": first["seed"],
        "seed_assignment_id": first["seed_assignment_id"],
        "split": first["split"],
        "intensity": first["intensity"],
        "pair_group_id": pair_group_id,
        "plan_id": first["plan_id"],
        "plan_path": str(plan),
        "plan_sha256": first["plan_sha256"],
    }


def service_pids(mode: str) -> dict[str, int]:
    values: dict[str, int] = {}
    for unit in MODE_UNITS[mode]:
        completed = run(["systemctl", "show", unit, "-p", "MainPID", "--value"], 10, True)
        values[unit] = int(completed.stdout.strip() or "0")
    return values


def verify_mode_services(mode: str) -> dict[str, int]:
    expected = set(MODE_UNITS[mode])
    states = {}
    for unit in ALL_UNITS:
        state = run(["systemctl", "is-active", unit], 10).stdout.strip()
        states[unit] = state
        require((unit in expected and state == "active") or (unit not in expected and state == "inactive"), f"service state mismatch mode={mode} unit={unit} state={state}")
    pids = service_pids(mode)
    require(all(pid > 1 and Path(f"/proc/{pid}").exists() for pid in pids.values()), f"service PID failure mode={mode}")
    return pids


def canary_rule(add: bool) -> None:
    rule = [
        "PREROUTING", "-i", "ens38", "-s", "192.168.210.10/32", "-d", "192.168.220.20/32",
        "-p", "tcp", "--dport", "24443", "-j", "REALISTIC_PROXY",
    ]
    check = run(["sudo", "-n", "iptables", "-t", "nat", "-C", *rule], 15).returncode == 0
    if add and not check:
        run(["sudo", "-n", "iptables", "-t", "nat", "-I", *rule[:1], "1", *rule[1:]], 15, True)
    if not add:
        while run(["sudo", "-n", "iptables", "-t", "nat", "-C", *rule], 15).returncode == 0:
            run(["sudo", "-n", "iptables", "-t", "nat", "-D", *rule], 15, True)


def active_probe(host: str, request: dict[str, object]) -> dict[str, object]:
    started = utc_now()
    try:
        completed = run(
            ["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=10", host, HEALTH_HELPER],
            25,
            input_text=json.dumps(request),
        )
        try:
            result = json.loads(completed.stdout)
        except json.JSONDecodeError:
            result = {"failure_stage": "HELPER_OUTPUT_ERROR", "raw_stdout": completed.stdout[-1000:]}
        result.update(
            {
                "pass": completed.returncode == 0 and result.get("failure_stage") == "PASS",
                "helper_exit_code": completed.returncode,
                "helper_stderr": completed.stderr[-1000:],
                "host": host,
                "started_utc": started,
                "ended_utc": utc_now(),
            }
        )
        return result
    except subprocess.TimeoutExpired:
        return {
            "pass": False,
            "failure_stage": "HELPER_SUPERVISOR_TIMEOUT",
            "host": host,
            "started_utc": started,
            "ended_utc": utc_now(),
        }


def health_check(mode: str, phase: str, sample_dir: Path) -> dict[str, object]:
    started = utc_now()
    jobs = []
    with ThreadPoolExecutor(max_workers=12) as pool:
        for side, host in (("server_direct", SERVER_HOST), ("mode_path", USER_HOST)):
            for control_id, url, expected_body in PUBLIC_CONTROLS:
                request = {
                    "url": url,
                    "expected_body": expected_body,
                    "connect_timeout_seconds": 10,
                    "timeout_seconds": 15,
                }
                jobs.append((side, control_id, pool.submit(active_probe, host, request)))
        if mode == "trojan":
            jobs.append(("controlled_canary", "trojan_canary_v3", pool.submit(active_probe, USER_HOST, CANARY)))
        results: dict[str, list[dict[str, object]]] = defaultdict(list)
        for side, control_id, future in jobs:
            result = future.result()
            result["control_id"] = control_id
            results[side].append(result)
    server_pass = sum(bool(item["pass"]) for item in results["server_direct"])
    mode_pass = sum(bool(item["pass"]) for item in results["mode_path"])
    canary_status: bool | str = "NOT_APPLICABLE"
    if mode == "trojan":
        canary_status = bool(results["controlled_canary"][0]["pass"])
    services = verify_mode_services(mode)
    passed = server_pass >= 3 and mode_pass >= 3 and canary_status in (True, "NOT_APPLICABLE")
    record = {
        "classification": "NON_FORMAL_VALIDATION",
        "phase": phase,
        "mode": mode,
        "started_utc": started,
        "ended_utc": utc_now(),
        "server_public_pass_count": server_pass,
        "server_public_total": 5,
        "mode_public_pass_count": mode_pass,
        "mode_public_total": 5,
        "controlled_canary_pass": canary_status,
        "service_pids": services,
        "results": dict(results),
        "status": "PASS" if passed else "FAIL",
    }
    write_json(sample_dir / f"{phase.lower()}.json", record)
    require(passed, f"{phase} failed mode={mode}")
    return record


def health_probe_processes() -> dict[str, list[str]]:
    command = "ps -eo pid=,args= | awk '/[r]ealistic-health-curl-probe|[h]ealth-guard-v3/ {print}'"
    values = {}
    for name, argv in (
        ("collector", ["bash", "-lc", command]),
        ("user", ["ssh", "-o", "BatchMode=yes", USER_HOST, command]),
        ("server", ["ssh", "-o", "BatchMode=yes", SERVER_HOST, command]),
    ):
        completed = run(argv, 15)
        values[name] = [line for line in completed.stdout.splitlines() if line.strip()]
    return values


def start_local_capture(interface: str, pcap: Path, log: Path, pid_file: Path, capture_filter: list[str]) -> int:
    script = 'tcpdump -i "$1" -s 0 -U -w "$2" "${@:5}" >"$3" 2>&1 & printf "%s\\n" "$!" >"$4"'
    run(
        ["sudo", "-n", "bash", "-c", script, "capture-launcher", interface, str(pcap), str(log), str(pid_file), *capture_filter],
        20,
        True,
    )
    run(["sudo", "-n", "chown", "etip:etip", str(pid_file)], 10, True)
    pid = int(pid_file.read_text().strip())
    require(pid > 1 and run(["sudo", "-n", "kill", "-0", str(pid)], 10).returncode == 0, f"local tcpdump failed pid={pid}")
    return pid


def start_remote_capture(remote_root: str) -> int:
    command = (
        "sudo -n bash -c 'install -d -o root -g root -m 700 \"$1\"; "
        "tcpdump -i ens33 -s 0 -U -w \"$1/egress_raw.pcap\" tcp and not port 22 "
        ">\"$1/tcpdump.log\" 2>&1 & printf \"%s\\n\" \"$!\" >\"$1/tcpdump.pid\"' capture \"$1\""
    )
    completed = run(["ssh", "-o", "BatchMode=yes", SERVER_HOST, "bash", "-s", "--", remote_root], 20, input_text=command + "\n")
    if completed.returncode:
        raise RuntimeError(f"remote capture start failed: {completed.stderr[-2000:]}")
    pid = int(run(["ssh", "-o", "BatchMode=yes", SERVER_HOST, "sudo", "-n", "cat", f"{remote_root}/tcpdump.pid"], 15, True).stdout.strip())
    require(run(["ssh", "-o", "BatchMode=yes", SERVER_HOST, "sudo", "-n", "kill", "-0", str(pid)], 15).returncode == 0, f"remote tcpdump failed pid={pid}")
    return pid


def stop_pid_local(pid: int) -> None:
    for sig, seconds in (("INT", 15), ("TERM", 5), ("KILL", 2)):
        run(["sudo", "-n", "kill", f"-{sig}", str(pid)], 10)
        deadline = time.monotonic() + seconds
        while time.monotonic() < deadline:
            if run(["sudo", "-n", "kill", "-0", str(pid)], 5).returncode != 0:
                return
            time.sleep(0.2)
    raise RuntimeError(f"local tcpdump residual pid={pid}")


def stop_pid_remote(pid: int) -> None:
    for sig, seconds in (("INT", 15), ("TERM", 5), ("KILL", 2)):
        run(["ssh", "-o", "BatchMode=yes", SERVER_HOST, "sudo", "-n", "kill", f"-{sig}", str(pid)], 15)
        deadline = time.monotonic() + seconds
        while time.monotonic() < deadline:
            if run(["ssh", "-o", "BatchMode=yes", SERVER_HOST, "sudo", "-n", "kill", "-0", str(pid)], 15).returncode != 0:
                return
            time.sleep(0.2)
    raise RuntimeError(f"remote tcpdump residual pid={pid}")


def stable_nonempty(path: Path) -> dict[str, object]:
    require(path.is_file() and path.stat().st_size > 0, f"empty capture: {path}")
    first = path.stat().st_size
    time.sleep(0.5)
    second = path.stat().st_size
    require(first == second, f"unstable capture size: {path} {first}->{second}")
    return {"path": str(path), "size_bytes": second, "stable": True}


def process_metrics(unit_pids: dict[str, int], local_capture_pids: list[int], remote_capture_pid: int) -> dict[str, object]:
    services = {}
    for unit, expected_pid in unit_pids.items():
        actual = int(run(["systemctl", "show", unit, "-p", "MainPID", "--value"], 5).stdout.strip() or "0")
        item: dict[str, object] = {"expected_pid": expected_pid, "pid": actual, "alive": actual == expected_pid and Path(f"/proc/{actual}").exists()}
        if actual > 1 and Path(f"/proc/{actual}").exists():
            try:
                item["fd_count"] = len(list(Path(f"/proc/{actual}/fd").iterdir()))
            except PermissionError:
                item["fd_count"] = len(run(["sudo", "-n", "find", f"/proc/{actual}/fd", "-mindepth", "1", "-maxdepth", "1"], 5).stdout.splitlines())
        services[unit] = item
    sockets = run(["sudo", "-n", "ss", "-Htanp"], 10)
    redsocks_rows = [line for line in sockets.stdout.splitlines() if '(("redsocks"' in line]
    conntrack = int(Path("/proc/sys/net/netfilter/nf_conntrack_count").read_text().strip())
    conntrack_max = int(Path("/proc/sys/net/netfilter/nf_conntrack_max").read_text().strip())
    browser_count = int(run(["ssh", "-o", "BatchMode=yes", USER_HOST, "bash", "-lc", "pgrep -c chrome-headless 2>/dev/null || true"], 15).stdout.strip() or "0")
    probe_processes = health_probe_processes()
    local_capture_alive = [pid for pid in local_capture_pids if run(["sudo", "-n", "kill", "-0", str(pid)], 5).returncode == 0]
    remote_capture_alive = run(["ssh", "-o", "BatchMode=yes", SERVER_HOST, "sudo", "-n", "kill", "-0", str(remote_capture_pid)], 15).returncode == 0
    return {
        "timestamp": utc_now(),
        "services": services,
        "redsocks_socket_rows": len(redsocks_rows),
        "conntrack_current": conntrack,
        "conntrack_max": conntrack_max,
        "browser_process_count": browser_count,
        "active_health_probe_processes": probe_processes,
        "local_capture_alive_pids": local_capture_alive,
        "remote_capture_alive": remote_capture_alive,
    }


class PassiveMonitor:
    def __init__(self, output: Path, unit_pids: dict[str, int], local_capture_pids: list[int], remote_capture_pid: int):
        self.output = output
        self.unit_pids = unit_pids
        self.local_capture_pids = local_capture_pids
        self.remote_capture_pid = remote_capture_pid
        self.stop_event = threading.Event()
        self.error: str | None = None
        self.thread = threading.Thread(target=self._run, daemon=True)

    def _run(self) -> None:
        try:
            with self.output.open("a", encoding="utf-8", buffering=1) as handle:
                while not self.stop_event.is_set():
                    record = process_metrics(self.unit_pids, self.local_capture_pids, self.remote_capture_pid)
                    handle.write(json.dumps(record, sort_keys=True) + "\n")
                    handle.flush()
                    os.fsync(handle.fileno())
                    self.stop_event.wait(2)
        except BaseException as exc:
            self.error = f"{type(exc).__name__}: {exc}"

    def start(self) -> None:
        self.thread.start()

    def stop(self) -> None:
        self.stop_event.set()
        self.thread.join(timeout=30)
        require(not self.thread.is_alive(), "passive monitor did not stop")
        require(self.error is None, f"passive monitor failure: {self.error}")


def tshark_count(pcap: Path, display_filter: str | None = None) -> int:
    argv = ["tshark", "-r", str(pcap)]
    if display_filter:
        argv += ["-Y", display_filter]
    argv += ["-T", "fields", "-e", "frame.number"]
    completed = run(argv, 120, True)
    return sum(bool(line.strip()) for line in completed.stdout.splitlines())


def journal_count(unit: str, since: str, pattern: str) -> int:
    normalized = since.replace("T", " ").split(".", 1)[0]
    completed = run(["sudo", "-n", "journalctl", "-u", unit, "--since", normalized, "--no-pager", "-o", "cat"], 30, True)
    return sum(pattern in line for line in completed.stdout.splitlines())


def oom_evidence(since: str) -> list[str]:
    normalized = since.replace("T", " ").split(".", 1)[0]
    completed = run(["sudo", "-n", "journalctl", "-k", "--since", normalized, "--no-pager", "-o", "cat"], 30)
    needles = ("out of memory", "oom-kill", "killed process")
    return [line for line in completed.stdout.splitlines() if any(token in line.lower() for token in needles)]


def cleanup_mode() -> None:
    canary_rule(False)
    run([str(MODE_TOOL), "clear"], 30)


def run_one_mode(
    mode: str,
    selection: dict[str, object],
    run_root: Path,
    remote_exec_root: str,
) -> dict[str, object]:
    sample_dir = run_root / f"validation_{mode}_{selection['pair_group_id']}"
    sample_dir.mkdir()
    (sample_dir / "NON_FORMAL_VALIDATION").write_text("NON_FORMAL_VALIDATION\n", encoding="utf-8")
    mode_started = utc_now()
    local_pids: list[int] = []
    remote_capture_pid = 0
    remote_capture_root = f"/tmp/proxytraffic-realistic-v3-validation-{run_root.name}-{mode}"
    monitor: PassiveMonitor | None = None
    capture_start = ""
    capture_end = ""
    pre: dict[str, object] = {}
    post: dict[str, object] = {}
    executor_rc = -1
    executor_timed_out = False
    try:
        cleanup_mode()
        run([str(MODE_TOOL), mode], 30, True)
        if mode == "trojan":
            canary_rule(True)
        time.sleep(1)
        pre = health_check(mode, "PRE_SAMPLE_HEALTH_CHECK", sample_dir)
        time.sleep(2)
        require(not any(health_probe_processes().values()), f"active health probe residual before capture mode={mode}")
        expected_service_pids = verify_mode_services(mode)

        local_pids.append(start_local_capture("ens38", sample_dir / "original_raw.pcap", sample_dir / "original_tcpdump.log", sample_dir / "original_tcpdump.pid", ["host", "192.168.210.10", "and", "tcp"]))
        local_pids.append(start_local_capture("ens39", sample_dir / "observed_raw.pcap", sample_dir / "observed_tcpdump.log", sample_dir / "observed_tcpdump.pid", ["tcp", "and", "not", "port", "22"]))
        remote_capture_pid = start_remote_capture(remote_capture_root)
        time.sleep(1)
        capture_start = utc_now()

        monitor = PassiveMonitor(sample_dir / "capture_passive_monitor.jsonl", expected_service_pids, local_pids, remote_capture_pid)
        monitor.start()
        remote_sample = f"{remote_exec_root}/{mode}"
        run(["ssh", "-o", "BatchMode=yes", USER_HOST, "mkdir", "-p", remote_sample], 20, True)
        stdout = (sample_dir / "executor_ssh_stdout.log").open("wb")
        stderr = (sample_dir / "executor_ssh_stderr.log").open("wb")
        command = [
            "ssh", "-o", "BatchMode=yes", USER_HOST,
            "/home/etip/bin/realistic-executor-supervisor",
            "--label", f"single_quartet_v3_validation_{mode}",
            "--evidence", f"{remote_sample}/supervisor",
            "--timeout", "420", "--int-grace", "10", "--term-grace", "10", "--kill-grace", "5", "run", "--",
            "/home/etip/.venvs/realistic/bin/python", f"{remote_exec_root}/input/realistic_browser_v3.py",
            "--plan", f"{remote_exec_root}/input/workload_plan.json",
            "--output-dir", f"{remote_sample}/workload",
            "--mode", mode,
            "--phase-log", f"{remote_sample}/executor_phase.jsonl",
        ]
        process = subprocess.Popen(command, stdout=stdout, stderr=stderr)
        try:
            executor_rc = process.wait(timeout=450)
        except subprocess.TimeoutExpired:
            executor_timed_out = True
            process.send_signal(signal.SIGTERM)
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)
        stdout.close()
        stderr.close()

        if monitor is not None:
            monitor.stop()
            monitor = None
        for pid in local_pids:
            stop_pid_local(pid)
        if remote_capture_pid:
            stop_pid_remote(remote_capture_pid)
        capture_end = utc_now()

        run(["sudo", "-n", "chown", "etip:etip", str(sample_dir / "original_raw.pcap"), str(sample_dir / "observed_raw.pcap")], 20, True)
        run(["ssh", "-o", "BatchMode=yes", SERVER_HOST, "sudo", "-n", "chown", "-R", "etip:etip", remote_capture_root], 20, True)
        run(["scp", "-q", f"{SERVER_HOST}:{remote_capture_root}/egress_raw.pcap", str(sample_dir / "egress_raw.pcap")], 120, True)
        for name in ("original", "observed", "egress"):
            stable_nonempty(sample_dir / f"{name}_raw.pcap")
            run(["reordercap", str(sample_dir / f"{name}_raw.pcap"), str(sample_dir / f"{name}.pcap")], 120, True)
            stable_nonempty(sample_dir / f"{name}.pcap")

        remote_sample = f"{remote_exec_root}/{mode}"
        supervisor_exists = run(["ssh", "-o", "BatchMode=yes", USER_HOST, "test", "-f", f"{remote_sample}/supervisor/result.json"], 20).returncode == 0
        if supervisor_exists:
            run(["rsync", "-a", f"{USER_HOST}:{remote_sample}/supervisor/", str(sample_dir / "executor_supervisor/")], 180, True)
        phase_exists = run(["ssh", "-o", "BatchMode=yes", USER_HOST, "test", "-f", f"{remote_sample}/executor_phase.jsonl"], 20).returncode == 0
        if phase_exists:
            run(["scp", "-q", f"{USER_HOST}:{remote_sample}/executor_phase.jsonl", str(sample_dir / "executor_phase.jsonl")], 60, True)

        require(not executor_timed_out and executor_rc == 0, f"executor failed mode={mode} rc={executor_rc} local_timeout={executor_timed_out}")
        require(supervisor_exists, f"executor supervisor result missing mode={mode}")
        (sample_dir / "workload").mkdir()
        run(["rsync", "-a", f"{USER_HOST}:{remote_sample}/workload/", str(sample_dir / "workload/")], 180, True)

        supervisor_result = json.loads((sample_dir / "executor_supervisor/result.json").read_text(encoding="utf-8"))
        workload_report = json.loads((sample_dir / "workload/workload_report.json").read_text(encoding="utf-8"))
        require(supervisor_result["status"] == "PASS", f"executor supervisor status={supervisor_result['status']} mode={mode}")
        require(not supervisor_result["timed_out"], f"executor watchdog timeout mode={mode}")
        require(supervisor_result["residual_count"] == 0, f"executor residual mode={mode}")
        require(workload_report["hard_failure_count"] == 0, f"workload hard failure mode={mode}")
        require(workload_report["success_count"] == workload_report["event_count"] == 6, f"unclassified/incomplete workload mode={mode}")
        require(workload_report["workload_plan_sha256"] == selection["plan_sha256"], f"workload plan SHA mismatch mode={mode}")

        pairing = {
            "classification": "NON_FORMAL_VALIDATION",
            "pair_group_id": selection["pair_group_id"],
            "plan_id": selection["plan_id"],
            "workload_plan_sha256": selection["plan_sha256"],
            "seed": selection["seed"],
            "split": selection["split"],
            "intensity": selection["intensity"],
            "mode": mode,
            "future_formal_manifest_eligible": False,
        }
        write_json(sample_dir / "pairing.json", pairing)
        write_json(sample_dir / "label.json", {"classification": "NON_FORMAL_VALIDATION", "mode": mode, "is_proxy": mode != "direct"})
        audit = run(["python3", str(AUDITOR), "--sample-dir", str(sample_dir), "--mode", mode], 300)
        (sample_dir / "quality_auditor_stdout.log").write_text(audit.stdout, encoding="utf-8")
        (sample_dir / "quality_auditor_stderr.log").write_text(audit.stderr, encoding="utf-8")
        require(audit.returncode == 0, f"mode purity/quality audit failed mode={mode}")
        quality = json.loads((sample_dir / "quality_report.json").read_text(encoding="utf-8"))
        health_port_packets = tshark_count(sample_dir / "observed.pcap", "tcp.port==24443")

        passive_rows = [json.loads(line) for line in (sample_dir / "capture_passive_monitor.jsonl").read_text(encoding="utf-8").splitlines() if line.strip()]
        require(passive_rows, f"missing passive monitor rows mode={mode}")
        active_probe_process_count = sum(
            len(lines)
            for row in passive_rows
            for lines in row["active_health_probe_processes"].values()
        )
        unexpected_exit = sum(
            not service["alive"]
            for row in passive_rows
            for service in row["services"].values()
        )
        require(active_probe_process_count == 0 and health_port_packets == 0, f"active health traffic during capture mode={mode}")
        require(unexpected_exit == 0, f"unexpected service exit mode={mode}")
        require(all(row["conntrack_current"] < row["conntrack_max"] for row in passive_rows), f"conntrack exhausted mode={mode}")

        post = health_check(mode, "POST_SAMPLE_HEALTH_CHECK", sample_dir)
        post_pids = verify_mode_services(mode)
        require(post_pids == expected_service_pids, f"service PID changed mode={mode}")
        conn_max_hits = journal_count(REDSOCKS_UNIT[mode], mode_started, "reached redsocks_conn_max limit") if mode != "direct" else 0
        oom_lines = oom_evidence(mode_started)
        require(conn_max_hits == 0, f"REDSOCKS_CONN_MAX_HITS mode={mode} count={conn_max_hits}")
        require(not oom_lines, f"OOM evidence mode={mode}")

        cleanup_mode()
        browser_residual = int(run(["ssh", "-o", "BatchMode=yes", USER_HOST, "bash", "-lc", "pgrep -c chrome-headless 2>/dev/null || true"], 20).stdout.strip() or "0")
        local_tcpdump_residual = sum(run(["sudo", "-n", "kill", "-0", str(pid)], 5).returncode == 0 for pid in local_pids)
        remote_tcpdump_residual = int(remote_capture_pid > 0 and run(["ssh", "-o", "BatchMode=yes", SERVER_HOST, "sudo", "-n", "kill", "-0", str(remote_capture_pid)], 15).returncode == 0)
        client_residual = sum(run(["systemctl", "is-active", unit], 10).stdout.strip() == "active" for unit in ALL_UNITS)
        require(browser_residual == local_tcpdump_residual == remote_tcpdump_residual == client_residual == 0, f"residual process mode={mode}")

        capture_finalization = {
            "status": "PASS",
            "executor_bounded": True,
            "executor_watchdog_timeout": False,
            "pcap_stable_size": True,
            "browser_residual": browser_residual,
            "executor_residual": supervisor_result["residual_count"],
            "tcpdump_residual": local_tcpdump_residual + remote_tcpdump_residual,
            "client_residual": client_residual,
            "redsocks_conn_max_hits": conn_max_hits,
            "oom": len(oom_lines),
        }
        write_json(sample_dir / "capture_finalization.json", capture_finalization)
        active_assertion = {
            "status": "PASS",
            "pre_health_ended_utc": pre["ended_utc"],
            "capture_started_utc": capture_start,
            "capture_ended_utc": capture_end,
            "post_health_started_utc": post["started_utc"],
            "active_health_probe_process_observations_during_capture": active_probe_process_count,
            "controlled_canary_port_packets_during_capture": health_port_packets,
            "ACTIVE_HEALTH_PROBE_DURING_CAPTURE": 0,
        }
        write_json(sample_dir / "active_health_capture_isolation.json", active_assertion)
        result = {
            "classification": "NON_FORMAL_VALIDATION",
            "mode": mode,
            "status": "PASS",
            "packet_counts": quality["packet_counts"],
            "mode_purity": {
                "tunnel_syn_counts": quality["observed_tunnel_syn_counts"],
                "direct_public_443_syn_count": quality["observed_direct_public_443_syn_count"],
                "issues": quality["issues"],
            },
            "browser": {
                "event_count": workload_report["event_count"],
                "success_count": workload_report["success_count"],
                "hard_failure_count": workload_report["hard_failure_count"],
                "warning_count": workload_report["warning_count"],
                "outcome": "PASS",
            },
            "pre_health": pre["status"],
            "post_health": post["status"],
            "active_health_probe_during_capture": 0,
            "capture_finalization": capture_finalization,
        }
        write_json(sample_dir / "validation_sample_result.json", result)
        (sample_dir / "VALIDATION_SAMPLE_PASS").write_text("NON_FORMAL_VALIDATION_SAMPLE_PASS\n", encoding="utf-8")
        run(["ssh", "-o", "BatchMode=yes", SERVER_HOST, "sudo", "-n", "rm", "-f", f"{remote_capture_root}/egress_raw.pcap", f"{remote_capture_root}/tcpdump.log", f"{remote_capture_root}/tcpdump.pid"], 30)
        run(["ssh", "-o", "BatchMode=yes", SERVER_HOST, "sudo", "-n", "rmdir", remote_capture_root], 30)
        return result
    finally:
        if monitor is not None:
            try:
                monitor.stop()
            except Exception:
                pass
        for pid in local_pids:
            if run(["sudo", "-n", "kill", "-0", str(pid)], 5).returncode == 0:
                try:
                    stop_pid_local(pid)
                except Exception:
                    pass
        if remote_capture_pid and run(["ssh", "-o", "BatchMode=yes", SERVER_HOST, "sudo", "-n", "kill", "-0", str(remote_capture_pid)], 15).returncode == 0:
            try:
                stop_pid_remote(remote_capture_pid)
            except Exception:
                pass
        cleanup_mode()


def canonical_hash(value: object) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def pairing_audit(selection: dict[str, object], run_root: Path) -> dict[str, object]:
    plan_hashes = set()
    pair_groups = set()
    seeds = set()
    splits = set()
    intensities = set()
    domain_event_sequences = set()
    timing_plans = set()
    modes = set()
    for mode in MODES:
        sample = run_root / f"validation_{mode}_{selection['pair_group_id']}"
        pairing = json.loads((sample / "pairing.json").read_text(encoding="utf-8"))
        plan = json.loads((sample / "workload/workload_plan.json").read_text(encoding="utf-8"))
        plan_hashes.add(sha256(sample / "workload/workload_plan.json"))
        pair_groups.add(pairing["pair_group_id"])
        seeds.add(pairing["seed"])
        splits.add(pairing["split"])
        intensities.add(pairing["intensity"])
        modes.add(pairing["mode"])
        domain_event_sequences.add(canonical_hash([(event["domain_id"], event["event_index"], event["url"], event["tab_index"]) for event in plan["events"]]))
        timing_plans.add(canonical_hash([(event["pre_navigation_idle_ms"], event["post_navigation_idle_ms"], event["navigation_timeout_ms"], event["scrolls"]) for event in plan["events"]]))
    issues = []
    for label, actual, expected in (
        ("PAIR_GROUP_MODES", len(modes), 4),
        ("PLAN_SHA_UNIQUE_COUNT", len(plan_hashes), 1),
        ("PAIR_GROUP_UNIQUE_COUNT", len(pair_groups), 1),
        ("SEED_UNIQUE_COUNT", len(seeds), 1),
        ("SPLIT_UNIQUE_COUNT", len(splits), 1),
        ("INTENSITY_UNIQUE_COUNT", len(intensities), 1),
        ("DOMAIN_EVENT_SEQUENCE_UNIQUE_COUNT", len(domain_event_sequences), 1),
        ("TIMING_PLAN_UNIQUE_COUNT", len(timing_plans), 1),
    ):
        if actual != expected:
            issues.append(f"{label}={actual} expected={expected}")
    if plan_hashes != {selection["plan_sha256"]}:
        issues.append("selected plan SHA mismatch")
    report = {
        "classification": "NON_FORMAL_VALIDATION",
        "status": "PASS" if not issues else "FAIL",
        "PAIR_GROUP_MODES": len(modes),
        "PLAN_SHA_UNIQUE_COUNT": len(plan_hashes),
        "SEED_UNIQUE_COUNT": len(seeds),
        "SPLIT_UNIQUE_COUNT": len(splits),
        "INTENSITY_UNIQUE_COUNT": len(intensities),
        "DOMAIN_EVENT_SEQUENCE_UNIQUE_COUNT": len(domain_event_sequences),
        "TIMING_PLAN_UNIQUE_COUNT": len(timing_plans),
        "modes": sorted(modes),
        "plan_sha256": next(iter(plan_hashes)) if len(plan_hashes) == 1 else sorted(plan_hashes),
        "issues": issues,
    }
    write_json(run_root / "pairing_audit.json", report)
    require(not issues, "pairing audit failed")
    return report


def create_checksums(root: Path, output_name: str, excluded: set[str]) -> None:
    rows = []
    for path in sorted(item for item in root.rglob("*") if item.is_file()):
        relative = path.relative_to(root).as_posix()
        if relative in excluded or path.name == "SAMPLE_COMPLETE":
            continue
        rows.append(f"{sha256(path)}  {relative}")
    (root / output_name).write_text("\n".join(rows) + "\n", encoding="utf-8")


def verify_checksums(root: Path, name: str) -> None:
    completed = subprocess.run(["sha256sum", "-c", name], cwd=root, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=1800)
    require(completed.returncode == 0, f"local SHA verification failed: {completed.stderr[-2000:]}")


def upload_and_verify(root: Path, remote_root: str, registry_name: str) -> str:
    remote_precheck = run(["ssh", "-o", "BatchMode=yes", UPLOAD_HOST, "test", "!", "-e", remote_root], 30)
    require(remote_precheck.returncode != 255, f"remote validation host unavailable: {remote_precheck.stderr[-1000:]}")
    require(remote_precheck.returncode == 0, f"remote validation root exists: {remote_root}")
    run(["ssh", "-o", "BatchMode=yes", UPLOAD_HOST, "mkdir", "-p", remote_root], 30, True)
    run(["rsync", "-a", f"{root}/", f"{UPLOAD_HOST}:{remote_root}/"], 3600, True)
    completed = run(["ssh", "-o", "BatchMode=yes", UPLOAD_HOST, f"cd {remote_root} && sha256sum -c {registry_name}"], 1800)
    require(completed.returncode == 0, f"remote independent SHA failed: {completed.stderr[-2000:]}")
    return completed.stdout


def final_remote_verify(root: Path, remote_root: str, registry_name: str) -> str:
    run(["rsync", "-a", f"{root}/", f"{UPLOAD_HOST}:{remote_root}/"], 1800, True)
    completed = run(["ssh", "-o", "BatchMode=yes", UPLOAD_HOST, f"cd {remote_root} && sha256sum -c {registry_name}"], 1800)
    require(completed.returncode == 0, f"remote final metadata SHA failed: {completed.stderr[-2000:]}")
    return completed.stdout


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--local-parent", type=Path, default=Path("/home/etip/datasets/staging/realistic_v1/single_quartet_v3_validation"))
    parser.add_argument("--remote-parent", default="/home/dataset-assist-0/duwenbiao/Tunnel/proxydata/realistic_v1/single_quartet_v3_validation")
    args = parser.parse_args()
    verify_frozen_inputs()
    selection = select_quartet()
    run_id = "single_quartet_v3_validation_" + stamp_now()
    args.local_parent.mkdir(parents=True, exist_ok=True)
    run_root = args.local_parent / run_id
    run_root.mkdir()
    remote_root = f"{args.remote_parent}/{run_id}"
    remote_exec_root = f"/home/etip/.cache/proxytraffic-realistic-v3-single-quartet-validation/{run_id}"
    (run_root / "NON_FORMAL_VALIDATION").write_text("NON_FORMAL_VALIDATION\nFUTURE_FORMAL_MANIFEST_ELIGIBLE=NO\n", encoding="utf-8")
    write_json(run_root / "selection.json", selection)
    write_json(run_root / "frozen_inputs.json", {str(path): digest for path, digest in FROZEN_SHA256.items()})
    write_json(run_root / "runner_provenance.json", {
        "classification": "NON_FORMAL_VALIDATION",
        "runner_sha256": sha256(Path(__file__)),
        "executor_sha256": sha256(EXECUTOR),
        "supervisor_sha256": sha256(SUPERVISOR),
        "auditor_sha256": sha256(AUDITOR),
        "started_utc": utc_now(),
        "local_root": str(run_root),
        "remote_root": remote_root,
    })
    success = False
    try:
        require(not any(health_probe_processes().values()), "preexisting active health probe process")
        require(not run(["sudo", "-n", "pgrep", "-f", "^tcpdump .*realistic.*\\.pcap"], 10).stdout.strip(), "preexisting local Realistic tcpdump")
        require(not run(["ssh", "-o", "BatchMode=yes", SERVER_HOST, "sudo", "-n", "pgrep", "-f", "^tcpdump .*proxytraffic-realistic.*\\.pcap"], 15).stdout.strip(), "preexisting remote Realistic tcpdump")
        browser_pre = int(run(["ssh", "-o", "BatchMode=yes", USER_HOST, "bash", "-lc", "pgrep -c chrome-headless 2>/dev/null || true"], 15).stdout.strip() or "0")
        require(browser_pre == 0, f"preexisting browser process count={browser_pre}")

        run(["ssh", "-o", "BatchMode=yes", USER_HOST, "mkdir", "-p", f"{remote_exec_root}/input"], 30, True)
        run(["scp", "-q", str(EXECUTOR), str(selection["plan_path"]), f"{USER_HOST}:{remote_exec_root}/input/"], 120, True)
        remote_hashes = run(["ssh", "-o", "BatchMode=yes", USER_HOST, "sha256sum", f"{remote_exec_root}/input/realistic_browser_v3.py", f"{remote_exec_root}/input/{Path(str(selection['plan_path'])).name}"], 30, True).stdout
        expected_lines = {
            EXPECTED_EXECUTOR_SHA256,
            str(selection["plan_sha256"]),
        }
        require({line.split()[0] for line in remote_hashes.splitlines()} == expected_lines, "remote input SHA mismatch")
        run(["ssh", "-o", "BatchMode=yes", USER_HOST, "cp", f"{remote_exec_root}/input/{Path(str(selection['plan_path'])).name}", f"{remote_exec_root}/input/workload_plan.json"], 30, True)

        mode_results = []
        for mode in MODES:
            mode_results.append(run_one_mode(mode, selection, run_root, remote_exec_root))
        pairing = pairing_audit(selection, run_root)

        summary = {
            "marker": "REALISTIC_V3_SINGLE_QUARTET_VALIDATION_PASS",
            "classification": "NON_FORMAL_VALIDATION",
            "future_formal_manifest_eligible": False,
            "modes_passed": "4/4",
            "selection": selection,
            "packet_counts": {result["mode"]: result["packet_counts"] for result in mode_results},
            "mode_purity": {result["mode"]: result["mode_purity"] for result in mode_results},
            "capture_finalization": {result["mode"]: result["capture_finalization"]["status"] for result in mode_results},
            "browser_outcome": {result["mode"]: result["browser"]["outcome"] for result in mode_results},
            "pre_health": {result["mode"]: result["pre_health"] for result in mode_results},
            "post_health": {result["mode"]: result["post_health"] for result in mode_results},
            "active_health_probe_during_capture": 0,
            "pairing_audit": pairing,
            "residual": 0,
            "local_sha": "PENDING",
            "remote_upload": "PENDING",
            "remote_independent_sha": "PENDING",
        }
        write_json(run_root / "quartet_validation_result.json", summary)
        create_checksums(run_root, "ARTIFACT_SHA256SUMS.txt", {"ARTIFACT_SHA256SUMS.txt", "FINAL_METADATA_SHA256SUMS.txt", "remote_sha_verification.json", "quartet_validation_result.json", "REALISTIC_V3_SINGLE_QUARTET_VALIDATION_PASS"})
        verify_checksums(run_root, "ARTIFACT_SHA256SUMS.txt")
        remote_stdout = upload_and_verify(run_root, remote_root, "ARTIFACT_SHA256SUMS.txt")
        remote_verification = {
            "classification": "NON_FORMAL_VALIDATION",
            "local_sha": "PASS",
            "remote_upload": "PASS",
            "remote_independent_sha": "PASS",
            "remote_host": UPLOAD_HOST,
            "remote_root": remote_root,
            "verified_file_count": len(remote_stdout.splitlines()),
            "verified_utc": utc_now(),
        }
        write_json(run_root / "remote_sha_verification.json", remote_verification)
        summary.update({"local_sha": "PASS", "remote_upload": "PASS", "remote_independent_sha": "PASS"})
        write_json(run_root / "quartet_validation_result.json", summary)
        (run_root / "REALISTIC_V3_SINGLE_QUARTET_VALIDATION_PASS").write_text("REALISTIC_V3_SINGLE_QUARTET_VALIDATION_PASS\nNON_FORMAL_VALIDATION\n", encoding="utf-8")
        create_checksums(run_root, "FINAL_METADATA_SHA256SUMS.txt", {"FINAL_METADATA_SHA256SUMS.txt"})
        verify_checksums(run_root, "FINAL_METADATA_SHA256SUMS.txt")
        final_remote_verify(run_root, remote_root, "FINAL_METADATA_SHA256SUMS.txt")
        success = True
        print(json.dumps(summary, indent=2, sort_keys=True))
        print(f"LOCAL_ROOT={run_root}")
        print(f"REMOTE_ROOT={remote_root}")
        print("REALISTIC_V3_SINGLE_QUARTET_VALIDATION_PASS")
        return 0
    except BaseException as exc:
        write_json(run_root / "VALIDATION_FAIL.json", {
            "classification": "NON_FORMAL_VALIDATION",
            "status": "FAIL",
            "error": f"{type(exc).__name__}: {exc}",
            "failed_utc": utc_now(),
            "retry_performed": False,
        })
        print(f"SINGLE_QUARTET_V3_VALIDATION_FAIL root={run_root} error={type(exc).__name__}: {exc}", flush=True)
        return 1
    finally:
        cleanup_mode()
        if not success:
            print("NON_FORMAL_VALIDATION evidence preserved; manual review required", flush=True)


if __name__ == "__main__":
    from run_single_quartet_v3_validation_retry import main as retry_policy_main

    raise SystemExit(retry_policy_main())
