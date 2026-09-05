#!/usr/bin/env python3
"""Run the seed001_heavy non-Formal quartet under frozen transient retry policy v1."""

from __future__ import annotations

import argparse
import csv
import importlib.util
import json
import os
import re
import shutil
import signal
import subprocess
import time
from collections import Counter
from pathlib import Path


REPO = Path("/home/etip/Tunnel/proxytraffic")
BASE_RUNNER = REPO / "encrypted_traffic_platform/realistic/run_single_quartet_v3_validation.py"
DOC = REPO / "docs/realistic_v1/formal_t0_v3"
POLICY = DOC / "formal_transient_retry_policy_v1.txt"
POLICY_FREEZE = DOC / "formal_transient_retry_policy_v1.sha256"
LEDGER = DOC / "formal_t0_v3_retry_ledger.tsv"
POLICY_SHA256 = "f84522b948804b218893b5638937f0632f9339495b75502ba5a4cc79808e4227"
MAX_ATTEMPTS_PER_SAMPLE = 2
SUCCESS_MARKER = "REALISTIC_V3_SINGLE_QUARTET_VALIDATION_PASS"
EXPECTED_REDSOCKS_CONN_MAX = 256
RETRYABLE = {
    "MAIN_NAVIGATION_TIMEOUT",
    "CONNECTION_CLOSED",
    "DNS_NAVIGATION_FAILURE",
    "TCP_NAVIGATION_FAILURE",
    "TLS_NAVIGATION_FAILURE",
}
LEDGER_FIELDS = (
    "run_id", "sample_id", "pair_group_id", "split", "seed", "intensity", "mode", "attempt",
    "attempt_artifact", "failure_class", "failure_event_index", "failure_url", "pre_health", "post_health",
    "mode_purity", "redsocks_conn_max_hits", "infrastructure_health_lost", "server_egress_degraded",
    "trojan_public_path_degraded", "plan_sha256", "git_head", "retry_authorized", "retry_reason",
    "final_attempt_status", "attempt_finished_utc",
)


def load_base():
    spec = importlib.util.spec_from_file_location("single_quartet_v3_base", BASE_RUNNER)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


base = load_base()


def read_json(path: Path) -> dict[str, object]:
    return json.loads(path.read_text(encoding="utf-8"))


def safe_health(mode: str, phase: str, sample_dir: Path) -> dict[str, object]:
    try:
        return base.health_check(mode, phase, sample_dir)
    except RuntimeError:
        path = sample_dir / f"{phase.lower()}.json"
        if path.is_file():
            return read_json(path)
        raise


def classify_workload_failure(
    workload: dict[str, object] | None,
    phase_log: Path,
) -> tuple[str, object, str, str]:
    event_index: object = ""
    failure_url = ""
    error = ""
    if workload:
        failures = workload.get("hard_failures") or workload.get("failures") or []
        if failures:
            failure = failures[0]
            event_index = failure.get("event_index", "")
            failure_url = str(failure.get("url", ""))
            error = str(failure.get("error", ""))
    if not error and phase_log.is_file():
        rows = [json.loads(line) for line in phase_log.read_text(encoding="utf-8").splitlines() if line.strip()]
        exits = [row for row in rows if row.get("phase") == "EXECUTOR_EXIT"]
        if exits:
            error = str(exits[-1].get("error", ""))
    lowered = error.lower()
    if "unacceptable main http status: 403" in lowered:
        return "HTTP_STATUS_403", event_index, failure_url, error
    if "unacceptable main http status: 429" in lowered:
        return "HTTP_STATUS_429", event_index, failure_url, error
    if "programmatic_scroll_timeout" in lowered or "action_timeout" in lowered:
        return "ACTION_TIMEOUT", event_index, failure_url, error
    if "evaluate" in lowered and "timeout" in lowered:
        return "EVALUATE_TIMEOUT", event_index, failure_url, error
    if "renderer" in lowered and ("hang" in lowered or "unresponsive" in lowered):
        return "RENDERER_HANG", event_index, failure_url, error
    if "err_connection_closed" in lowered or "connection closed" in lowered:
        return "CONNECTION_CLOSED", event_index, failure_url, error
    if "err_name_not_resolved" in lowered or "dns" in lowered and "navigation" in lowered:
        return "DNS_NAVIGATION_FAILURE", event_index, failure_url, error
    if any(token in lowered for token in ("err_cert_", "err_ssl_", "tls handshake", "tls navigation")):
        return "TLS_NAVIGATION_FAILURE", event_index, failure_url, error
    if any(token in lowered for token in (
        "err_connection_refused", "err_connection_reset", "err_connection_timed_out",
        "err_address_unreachable", "tcp navigation",
    )):
        return "TCP_NAVIGATION_FAILURE", event_index, failure_url, error
    if "page.goto" in lowered and "timeout 30000ms exceeded" in lowered:
        return "MAIN_NAVIGATION_TIMEOUT", event_index, failure_url, error
    if "unacceptable main http status:" in lowered:
        suffix = lowered.split("unacceptable main http status:", 1)[1].strip().split()[0]
        return f"HTTP_STATUS_{suffix}", event_index, failure_url, error
    if "lifecycle_timeout" in lowered:
        return "UNBOUNDED_LIFECYCLE", event_index, failure_url, error
    return "WORKLOAD_HARD_FAILURE", event_index, failure_url, error


def health_flags(mode: str, pre: dict[str, object], post: dict[str, object]) -> tuple[int, int, int]:
    infrastructure = int(pre.get("status") != "PASS" or post.get("status") != "PASS")
    server_egress = int(
        int(pre.get("server_public_pass_count", 0)) < 3
        or int(post.get("server_public_pass_count", 0)) < 3
    )
    trojan_path = 0
    if mode == "trojan":
        trojan_path = int(
            int(pre.get("mode_public_pass_count", 0)) < 3
            or int(post.get("mode_public_pass_count", 0)) < 3
            or pre.get("controlled_canary_pass") is not True
            or post.get("controlled_canary_pass") is not True
        )
    return infrastructure, server_egress, trojan_path


def redsocks_capacity_precheck(mode: str, mode_started: str, sample_dir: Path) -> dict[str, object]:
    if mode == "direct":
        result = {
            "classification": "REDSOCKS_CAPACITY_PRECHECK",
            "status": "PASS",
            "mode": mode,
            "actual_conn_max": "NOT_APPLICABLE",
        }
        base.write_json(sample_dir / "redsocks_capacity_precheck.json", result)
        return result

    unit = base.REDSOCKS_UNIT[mode]
    services = base.verify_mode_services(mode)
    pid = services[unit]
    limits_line = next(
        line for line in Path(f"/proc/{pid}/limits").read_text(encoding="utf-8").splitlines()
        if line.startswith("Max open files")
    )
    match = re.fullmatch(r"Max open files\s+(\d+)\s+(\d+)\s+files\s*", limits_line)
    base.require(match is not None, f"could not parse redsocks Max open files mode={mode}: {limits_line}")
    soft_nofile, hard_nofile = int(match.group(1)), int(match.group(2))

    normalized = mode_started.replace("T", " ").split(".", 1)[0]
    journal = base.run(
        ["sudo", "-n", "journalctl", "-u", unit, "--since", normalized, "--no-pager", "-o", "json"],
        30,
        True,
    )
    startup_rows = []
    for line in journal.stdout.splitlines():
        if not line.strip():
            continue
        row = json.loads(line)
        message = str(row.get("MESSAGE", ""))
        if int(row.get("_PID", 0)) == pid and "redsocks started, conn_max=" in message:
            startup_rows.append(row)
    base.require(len(startup_rows) == 1, f"redsocks startup record count mode={mode} pid={pid}: {len(startup_rows)}")
    startup = startup_rows[0]
    conn_match = re.search(r"conn_max=(\d+)", str(startup["MESSAGE"]))
    base.require(conn_match is not None, f"could not parse redsocks conn_max mode={mode}")
    actual_conn_max = int(conn_match.group(1))
    timestamp_us = int(startup.get("_SOURCE_REALTIME_TIMESTAMP", startup["__REALTIME_TIMESTAMP"]))
    startup_utc = base.datetime.fromtimestamp(timestamp_us / 1_000_000, base.timezone.utc).isoformat().replace("+00:00", "Z")
    status = "PASS" if (
        soft_nofile == 2048
        and hard_nofile == 524288
        and actual_conn_max == EXPECTED_REDSOCKS_CONN_MAX
    ) else "FAIL"
    result = {
        "classification": "REDSOCKS_CAPACITY_PRECHECK",
        "status": status,
        "mode": mode,
        "systemd_unit": unit,
        "pid": pid,
        "startup_utc": startup_utc,
        "startup_message": startup["MESSAGE"],
        "soft_nofile": soft_nofile,
        "hard_nofile": hard_nofile,
        "expected_conn_max": EXPECTED_REDSOCKS_CONN_MAX,
        "actual_conn_max": actual_conn_max,
        "checked_before_pre_health_and_workload": True,
    }
    base.write_json(sample_dir / "redsocks_capacity_precheck.json", result)
    return result


def run_attempt(
    mode: str,
    attempt: int,
    selection: dict[str, object],
    mode_root: Path,
    remote_exec_root: str,
    classification: str = "NON_FORMAL_VALIDATION",
) -> dict[str, object]:
    expected_event_count = len(read_json(Path(str(selection["plan_path"]))) ["events"])
    sample_dir = mode_root / f"attempt_{attempt}"
    sample_dir.mkdir(parents=True, exist_ok=False)
    (sample_dir / classification).write_text(
        f"{classification}\nTRANSIENT_RETRY_POLICY_V1\n", encoding="utf-8"
    )
    mode_started = base.utc_now()
    local_pids: list[int] = []
    remote_capture_pid = 0
    monitor = None
    remote_capture_root = f"/tmp/proxytraffic-realistic-v3-validation-{mode_root.parent.name}-{mode}-attempt-{attempt}"
    remote_sample = f"{remote_exec_root}/{mode}/attempt_{attempt}"
    capture_start = ""
    capture_end = ""
    pre: dict[str, object] = {}
    post: dict[str, object] = {}
    expected_service_pids: dict[str, int] = {}
    post_service_pids: dict[str, int] = {}
    executor_rc = -1
    executor_local_timeout = False
    supervisor: dict[str, object] = {}
    workload: dict[str, object] | None = None
    quality: dict[str, object] = {}
    audit_rc = -1
    active_probe_process_count = 0
    health_port_packets = 0
    unexpected_exit = 0
    conntrack_exhausted = 0
    conn_max_hits = 0
    oom_lines: list[str] = []
    browser_residual = -1
    local_tcpdump_residual = -1
    remote_tcpdump_residual = -1
    client_residual = -1
    capacity_precheck: dict[str, object] = {}
    try:
        base.cleanup_mode()
        base.run([str(base.MODE_TOOL), mode], 30, True)
        if mode == "trojan":
            base.canary_rule(True)
        time.sleep(1)
        capacity_precheck = redsocks_capacity_precheck(mode, mode_started, sample_dir)
        if capacity_precheck["status"] != "PASS":
            result = {
                "classification": classification,
                "status": "FAIL",
                "mode": mode,
                "attempt": attempt,
                "artifact_dir": str(sample_dir),
                "failure_class": "REDSOCKS_CAPACITY_PRECHECK_FAIL",
                "failure_event_index": "",
                "failure_url": "",
                "failure_error": f"REDSOCKS_ACTUAL_CONN_MAX={capacity_precheck['actual_conn_max']} expected={EXPECTED_REDSOCKS_CONN_MAX}",
                "pre_health": "NOT_RUN_CAPACITY_PRECHECK_FAIL",
                "post_health": "NOT_RUN_CAPACITY_PRECHECK_FAIL",
                "mode_purity": "NOT_RUN_CAPACITY_PRECHECK_FAIL",
                "redsocks_actual_conn_max": capacity_precheck["actual_conn_max"],
                "redsocks_conn_max_hits": 0,
                "infrastructure_health_lost": 0,
                "server_egress_degraded": 0,
                "trojan_public_path_degraded": 0,
                "plan_sha256": selection["plan_sha256"],
                "capture": {"status": "NOT_STARTED"},
                "residual": 0,
                "attempt_finished_utc": base.utc_now(),
            }
            base.write_json(sample_dir / "validation_attempt_result.json", result)
            (sample_dir / "REDSOCKS_CAPACITY_PRECHECK_FAIL").write_text(
                "REDSOCKS_CAPACITY_PRECHECK_FAIL\n", encoding="utf-8"
            )
            return result
        pre = safe_health(mode, "PRE_SAMPLE_HEALTH_CHECK", sample_dir)
        if pre["status"] != "PASS":
            result = {
                "classification": classification,
                "status": "FAIL",
                "mode": mode,
                "attempt": attempt,
                "artifact_dir": str(sample_dir),
                "failure_class": "INFRASTRUCTURE_HEALTH_LOST",
                "failure_event_index": "",
                "failure_url": "",
                "failure_error": "PRE_SAMPLE_HEALTH_CHECK failed",
                "pre_health": pre["status"],
                "post_health": "NOT_RUN_PRE_HEALTH_FAIL",
                "mode_purity": "NOT_RUN_PRE_HEALTH_FAIL",
                "redsocks_actual_conn_max": capacity_precheck["actual_conn_max"],
                "redsocks_conn_max_hits": 0,
                "infrastructure_health_lost": 1,
                "server_egress_degraded": int(int(pre.get("server_public_pass_count", 0)) < 3),
                "trojan_public_path_degraded": int(mode == "trojan"),
                "plan_sha256": selection["plan_sha256"],
                "capture": {"status": "NOT_STARTED"},
                "residual": 0,
                "attempt_finished_utc": base.utc_now(),
            }
            base.write_json(sample_dir / "validation_attempt_result.json", result)
            return result
        time.sleep(2)
        base.require(not any(base.health_probe_processes().values()), f"active health probe residual mode={mode} attempt={attempt}")
        expected_service_pids = base.verify_mode_services(mode)

        local_pids.append(base.start_local_capture(
            "ens38", sample_dir / "original_raw.pcap", sample_dir / "original_tcpdump.log",
            sample_dir / "original_tcpdump.pid", ["host", "192.168.210.10", "and", "tcp"],
        ))
        local_pids.append(base.start_local_capture(
            "ens39", sample_dir / "observed_raw.pcap", sample_dir / "observed_tcpdump.log",
            sample_dir / "observed_tcpdump.pid", ["tcp", "and", "not", "port", "22"],
        ))
        remote_capture_pid = base.start_remote_capture(remote_capture_root)
        time.sleep(1)
        capture_start = base.utc_now()
        monitor = base.PassiveMonitor(
            sample_dir / "capture_passive_monitor.jsonl", expected_service_pids, local_pids, remote_capture_pid
        )
        monitor.start()
        base.run(["ssh", "-o", "BatchMode=yes", base.USER_HOST, "mkdir", "-p", remote_sample], 20, True)
        stdout = (sample_dir / "executor_ssh_stdout.log").open("wb")
        stderr = (sample_dir / "executor_ssh_stderr.log").open("wb")
        command = [
            "ssh", "-o", "BatchMode=yes", base.USER_HOST,
            "/home/etip/bin/realistic-executor-supervisor",
            "--label", f"single_quartet_v3_validation_{mode}_attempt_{attempt}",
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
            executor_local_timeout = True
            process.send_signal(signal.SIGTERM)
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)
        stdout.close()
        stderr.close()

        monitor.stop()
        monitor = None
        for pid in local_pids:
            base.stop_pid_local(pid)
        if remote_capture_pid:
            base.stop_pid_remote(remote_capture_pid)
        capture_end = base.utc_now()

        base.run([
            "sudo", "-n", "chown", "etip:etip",
            str(sample_dir / "original_raw.pcap"), str(sample_dir / "observed_raw.pcap"),
        ], 20, True)
        base.run(["ssh", "-o", "BatchMode=yes", base.SERVER_HOST, "sudo", "-n", "chown", "-R", "etip:etip", remote_capture_root], 20, True)
        base.run(["scp", "-q", f"{base.SERVER_HOST}:{remote_capture_root}/egress_raw.pcap", str(sample_dir / "egress_raw.pcap")], 120, True)
        for name in ("original", "observed", "egress"):
            base.stable_nonempty(sample_dir / f"{name}_raw.pcap")
            base.run(["reordercap", str(sample_dir / f"{name}_raw.pcap"), str(sample_dir / f"{name}.pcap")], 120, True)
            base.stable_nonempty(sample_dir / f"{name}.pcap")

        base.require(base.run(["ssh", "-o", "BatchMode=yes", base.USER_HOST, "test", "-f", f"{remote_sample}/supervisor/result.json"], 20).returncode == 0, "supervisor result missing")
        base.run(["rsync", "-a", f"{base.USER_HOST}:{remote_sample}/supervisor/", str(sample_dir / "executor_supervisor/")], 180, True)
        supervisor = read_json(sample_dir / "executor_supervisor/result.json")
        if base.run(["ssh", "-o", "BatchMode=yes", base.USER_HOST, "test", "-f", f"{remote_sample}/executor_phase.jsonl"], 20).returncode == 0:
            base.run(["scp", "-q", f"{base.USER_HOST}:{remote_sample}/executor_phase.jsonl", str(sample_dir / "executor_phase.jsonl")], 60, True)
        if base.run(["ssh", "-o", "BatchMode=yes", base.USER_HOST, "test", "-d", f"{remote_sample}/workload"], 20).returncode == 0:
            (sample_dir / "workload").mkdir()
            base.run(["rsync", "-a", f"{base.USER_HOST}:{remote_sample}/workload/", str(sample_dir / "workload/")], 180, True)
        report_path = sample_dir / "workload/workload_report.json"
        if report_path.is_file():
            workload = read_json(report_path)

        pairing = {
            "classification": classification,
            "retry_policy": "FORMAL_T0_V3_TRANSIENT_RETRY_POLICY_V1",
            "attempt": attempt,
            "pair_group_id": selection["pair_group_id"],
            "plan_id": selection["plan_id"],
            "workload_plan_sha256": selection["plan_sha256"],
            "seed": selection["seed"],
            "split": selection["split"],
            "intensity": selection["intensity"],
            "mode": mode,
            "future_formal_manifest_eligible": False,
        }
        base.write_json(sample_dir / "pairing.json", pairing)
        base.write_json(sample_dir / "label.json", {
            "classification": classification, "mode": mode, "attempt": attempt, "is_proxy": mode != "direct",
        })
        if workload:
            audit = base.run(["python3", str(base.AUDITOR), "--sample-dir", str(sample_dir), "--mode", mode], 300)
            audit_rc = audit.returncode
            (sample_dir / "quality_auditor_stdout.log").write_text(audit.stdout, encoding="utf-8")
            (sample_dir / "quality_auditor_stderr.log").write_text(audit.stderr, encoding="utf-8")
            if (sample_dir / "quality_report.json").is_file():
                quality = read_json(sample_dir / "quality_report.json")

        passive_rows = [
            json.loads(line)
            for line in (sample_dir / "capture_passive_monitor.jsonl").read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]
        base.require(passive_rows, f"missing passive rows mode={mode} attempt={attempt}")
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
        conntrack_exhausted = sum(row["conntrack_current"] >= row["conntrack_max"] for row in passive_rows)
        health_port_packets = base.tshark_count(sample_dir / "observed.pcap", "tcp.port==24443")
        post = safe_health(mode, "POST_SAMPLE_HEALTH_CHECK", sample_dir)
        try:
            post_service_pids = base.verify_mode_services(mode)
        except RuntimeError:
            post_service_pids = {}
            unexpected_exit += 1
        conn_max_hits = base.journal_count(base.REDSOCKS_UNIT[mode], mode_started, "reached redsocks_conn_max limit") if mode != "direct" else 0
        oom_lines = base.oom_evidence(mode_started)

        base.cleanup_mode()
        browser_residual = int(base.run(["ssh", "-o", "BatchMode=yes", base.USER_HOST, "bash", "-lc", "pgrep -c chrome-headless 2>/dev/null || true"], 20).stdout.strip() or "0")
        local_tcpdump_residual = sum(base.run(["sudo", "-n", "kill", "-0", str(pid)], 5).returncode == 0 for pid in local_pids)
        remote_tcpdump_residual = int(remote_capture_pid > 0 and base.run(["ssh", "-o", "BatchMode=yes", base.SERVER_HOST, "sudo", "-n", "kill", "-0", str(remote_capture_pid)], 15).returncode == 0)
        client_residual = sum(base.run(["systemctl", "is-active", unit], 10).stdout.strip() == "active" for unit in base.ALL_UNITS)

        purity_issues = [issue for issue in quality.get("issues", []) if issue != "workload_hard_failure"]
        mode_purity = "PASS" if quality and not purity_issues else "FAIL"
        capture_status = "PASS" if (
            active_probe_process_count == 0
            and health_port_packets == 0
            and conntrack_exhausted == 0
            and local_tcpdump_residual == 0
            and remote_tcpdump_residual == 0
        ) else "FAIL"
        infrastructure, server_egress, trojan_path = health_flags(mode, pre, post)
        failure_class = ""
        failure_event_index: object = ""
        failure_url = ""
        failure_error = ""
        if executor_local_timeout or supervisor.get("timed_out"):
            failure_class = "SUPERVISOR_TIMEOUT"
        elif int(supervisor.get("residual_count", 0)) or browser_residual:
            failure_class = "UNBOUNDED_LIFECYCLE"
        elif conn_max_hits:
            failure_class = "REDSOCKS_CONN_MAX_HIT"
        elif oom_lines:
            failure_class = "OOM"
        elif unexpected_exit or (expected_service_pids and post_service_pids != expected_service_pids):
            failure_class = "UNEXPECTED_PROCESS_EXIT"
        elif infrastructure:
            failure_class = "INFRASTRUCTURE_HEALTH_LOST"
        elif "proxy_public_443_bypass" in purity_issues:
            failure_class = "PROXY_BYPASS"
        elif mode_purity != "PASS":
            failure_class = "MODE_PURITY_FAIL"
        elif capture_status != "PASS":
            failure_class = "CAPTURE_FINALIZATION_FAIL"
        elif workload and workload.get("workload_plan_sha256") != selection["plan_sha256"]:
            failure_class = "SHA_FAIL"
        elif not workload or int(workload.get("hard_failure_count", 1)) != 0 or executor_rc != 0:
            failure_class, failure_event_index, failure_url, failure_error = classify_workload_failure(
                workload, sample_dir / "executor_phase.jsonl"
            )
        elif not (
            int(workload.get("success_count", 0))
            == int(workload.get("event_count", -1))
            == expected_event_count
        ):
            failure_class = "WORKLOAD_HARD_FAILURE"

        status = "PASS" if not failure_class else "FAIL"
        capture_finalization = {
            "status": capture_status,
            "capture_started_utc": capture_start,
            "capture_ended_utc": capture_end,
            "executor_bounded": not executor_local_timeout and not bool(supervisor.get("timed_out")),
            "executor_watchdog_timeout": bool(executor_local_timeout or supervisor.get("timed_out")),
            "pcap_stable_size": True,
            "browser_residual": browser_residual,
            "executor_residual": supervisor.get("residual_count", -1),
            "tcpdump_residual": local_tcpdump_residual + remote_tcpdump_residual,
            "client_residual": client_residual,
            "redsocks_conn_max_hits": conn_max_hits,
            "oom": len(oom_lines),
            "unexpected_process_exit": unexpected_exit,
            "active_health_probe_during_capture": active_probe_process_count,
            "controlled_canary_port_packets_during_capture": health_port_packets,
            "conntrack_exhausted_observations": conntrack_exhausted,
        }
        base.write_json(sample_dir / "capture_finalization.json", capture_finalization)
        result = {
            "classification": classification,
            "retry_policy": "FORMAL_T0_V3_TRANSIENT_RETRY_POLICY_V1",
            "mode": mode,
            "attempt": attempt,
            "status": status,
            "artifact_dir": str(sample_dir),
            "failure_class": failure_class,
            "failure_event_index": failure_event_index,
            "failure_url": failure_url,
            "failure_error": failure_error,
            "pre_health": pre["status"],
            "post_health": post["status"],
            "mode_purity": mode_purity,
            "mode_purity_issues": purity_issues,
            "redsocks_actual_conn_max": capacity_precheck["actual_conn_max"],
            "redsocks_conn_max_hits": conn_max_hits,
            "infrastructure_health_lost": infrastructure,
            "server_egress_degraded": server_egress,
            "trojan_public_path_degraded": trojan_path,
            "plan_sha256": selection["plan_sha256"],
            "packet_counts": quality.get("packet_counts", {}),
            "observed_tunnel_syn_counts": quality.get("observed_tunnel_syn_counts", {}),
            "observed_direct_public_443_syn_count": quality.get("observed_direct_public_443_syn_count", 0),
            "browser": {
                "event_count": workload.get("event_count") if workload else None,
                "success_count": workload.get("success_count") if workload else None,
                "hard_failure_count": workload.get("hard_failure_count") if workload else None,
                "warning_count": workload.get("warning_count") if workload else None,
                "outcome": status,
            },
            "capture": capture_finalization,
            "residual": browser_residual + int(supervisor.get("residual_count", 0)) + local_tcpdump_residual + remote_tcpdump_residual + client_residual,
            "attempt_finished_utc": base.utc_now(),
        }
        base.write_json(sample_dir / "validation_attempt_result.json", result)
        marker = "VALIDATION_ATTEMPT_PASS" if status == "PASS" else "VALIDATION_ATTEMPT_FAIL"
        (sample_dir / marker).write_text(f"{marker}\n{classification}\n", encoding="utf-8")
        return result
    finally:
        if monitor is not None:
            try:
                monitor.stop()
            except Exception:
                pass
        for pid in local_pids:
            if base.run(["sudo", "-n", "kill", "-0", str(pid)], 5).returncode == 0:
                try:
                    base.stop_pid_local(pid)
                except Exception:
                    pass
        if remote_capture_pid and base.run(["ssh", "-o", "BatchMode=yes", base.SERVER_HOST, "sudo", "-n", "kill", "-0", str(remote_capture_pid)], 15).returncode == 0:
            try:
                base.stop_pid_remote(remote_capture_pid)
            except Exception:
                pass
        if remote_capture_pid:
            base.run(["ssh", "-o", "BatchMode=yes", base.SERVER_HOST, "sudo", "-n", "rm", "-f", f"{remote_capture_root}/egress_raw.pcap", f"{remote_capture_root}/tcpdump.log", f"{remote_capture_root}/tcpdump.pid"], 30)
            base.run(["ssh", "-o", "BatchMode=yes", base.SERVER_HOST, "sudo", "-n", "rmdir", remote_capture_root], 30)
        base.cleanup_mode()


def retry_authorized(attempt_result: dict[str, object]) -> tuple[bool, str]:
    if attempt_result["status"] == "PASS":
        return False, "ATTEMPT_PASS"
    failure_class = str(attempt_result["failure_class"])
    if failure_class not in RETRYABLE:
        return False, f"NON_RETRYABLE_FAILURE_CLASS:{failure_class}"
    gates = {
        "PRE_HEALTH": attempt_result["pre_health"] == "PASS",
        "POST_HEALTH": attempt_result["post_health"] == "PASS",
        "mode_purity": attempt_result["mode_purity"] == "PASS",
        "REDSOCKS_CONN_MAX_HITS": int(attempt_result["redsocks_conn_max_hits"]) == 0,
        "INFRASTRUCTURE_HEALTH_LOST": int(attempt_result["infrastructure_health_lost"]) == 0,
        "SERVER_EGRESS_DEGRADED": int(attempt_result["server_egress_degraded"]) == 0,
        "TROJAN_PUBLIC_PATH_DEGRADED": int(attempt_result["trojan_public_path_degraded"]) == 0,
        "CAPTURE": attempt_result["capture"]["status"] == "PASS",
        "RESIDUAL": int(attempt_result["residual"]) == 0,
    }
    failed = [name for name, passed in gates.items() if not passed]
    if failed:
        return False, "RETRY_GATES_FAILED:" + ",".join(failed)
    return True, f"AUTHORIZED_TRANSIENT:{failure_class}"


def ledger_row(
    run_id: str,
    git_head: str,
    selection: dict[str, object],
    result: dict[str, object],
    retry_allowed: bool,
    retry_reason: str,
    final_status: str,
) -> dict[str, object]:
    mode = str(result["mode"])
    return {
        "run_id": run_id,
        "sample_id": f"{run_id}_{selection['pair_group_id']}_{mode}",
        "pair_group_id": selection["pair_group_id"],
        "split": selection["split"],
        "seed": selection["seed"],
        "intensity": selection["intensity"],
        "mode": mode,
        "attempt": result["attempt"],
        "attempt_artifact": result["artifact_dir"],
        "failure_class": result["failure_class"],
        "failure_event_index": result["failure_event_index"],
        "failure_url": result["failure_url"],
        "pre_health": result["pre_health"],
        "post_health": result["post_health"],
        "mode_purity": result["mode_purity"],
        "redsocks_conn_max_hits": result["redsocks_conn_max_hits"],
        "infrastructure_health_lost": result["infrastructure_health_lost"],
        "server_egress_degraded": result["server_egress_degraded"],
        "trojan_public_path_degraded": result["trojan_public_path_degraded"],
        "plan_sha256": selection["plan_sha256"],
        "git_head": git_head,
        "retry_authorized": str(retry_allowed).lower(),
        "retry_reason": retry_reason,
        "final_attempt_status": final_status,
        "attempt_finished_utc": result.get("attempt_finished_utc", base.utc_now()),
    }


def append_ledger(rows: list[dict[str, object]]) -> None:
    with LEDGER.open("a", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=LEDGER_FIELDS, delimiter="\t", lineterminator="\n")
        writer.writerows(rows)
        handle.flush()
        os.fsync(handle.fileno())


def pairing_audit(selection: dict[str, object], final_results: list[dict[str, object]], run_root: Path) -> dict[str, object]:
    plan_hashes, pair_groups, seeds, splits, intensities, modes = set(), set(), set(), set(), set(), set()
    domain_sequences, timing_plans = set(), set()
    for result in final_results:
        sample = Path(str(result["artifact_dir"]))
        pairing = read_json(sample / "pairing.json")
        plan_path = sample / "workload/workload_plan.json"
        plan = read_json(plan_path)
        plan_hashes.add(base.sha256(plan_path))
        pair_groups.add(pairing["pair_group_id"])
        seeds.add(pairing["seed"])
        splits.add(pairing["split"])
        intensities.add(pairing["intensity"])
        modes.add(pairing["mode"])
        domain_sequences.add(base.canonical_hash([
            (event["domain_id"], event["event_index"], event["url"], event["tab_index"])
            for event in plan["events"]
        ]))
        timing_plans.add(base.canonical_hash([
            (event["pre_navigation_idle_ms"], event["post_navigation_idle_ms"], event["navigation_timeout_ms"], event["scrolls"])
            for event in plan["events"]
        ]))
    checks = {
        "PAIR_GROUP_MODES": (len(modes), 4),
        "PLAN_SHA_UNIQUE_COUNT": (len(plan_hashes), 1),
        "PAIR_GROUP_UNIQUE_COUNT": (len(pair_groups), 1),
        "SEED_UNIQUE_COUNT": (len(seeds), 1),
        "SPLIT_UNIQUE_COUNT": (len(splits), 1),
        "INTENSITY_UNIQUE_COUNT": (len(intensities), 1),
        "DOMAIN_EVENT_SEQUENCE_UNIQUE_COUNT": (len(domain_sequences), 1),
        "TIMING_PLAN_UNIQUE_COUNT": (len(timing_plans), 1),
    }
    issues = [f"{name}={actual} expected={expected}" for name, (actual, expected) in checks.items() if actual != expected]
    if plan_hashes != {selection["plan_sha256"]}:
        issues.append("selected plan SHA mismatch")
    report = {
        "classification": "NON_FORMAL_VALIDATION",
        "status": "PASS" if not issues else "FAIL",
        **{name: value[0] for name, value in checks.items()},
        "modes": sorted(modes),
        "plan_sha256": next(iter(plan_hashes)) if len(plan_hashes) == 1 else sorted(plan_hashes),
        "issues": issues,
    }
    base.write_json(run_root / "pairing_audit.json", report)
    base.require(not issues, "pairing audit failed")
    return report


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--local-parent", type=Path, default=Path("/home/etip/datasets/staging/realistic_v1/single_quartet_v3_validation"))
    parser.add_argument("--remote-parent", default="/home/dataset-assist-0/duwenbiao/Tunnel/proxydata/realistic_v1/single_quartet_v3_validation")
    args = parser.parse_args()
    base.verify_frozen_inputs()
    base.require(base.sha256(POLICY) == POLICY_SHA256, "transient retry policy SHA mismatch")
    freeze_tokens = POLICY_FREEZE.read_text(encoding="utf-8").split()
    base.require(freeze_tokens == [POLICY_SHA256, POLICY.name], "transient retry policy freeze file mismatch")
    with LEDGER.open(newline="", encoding="utf-8") as handle:
        base.require(tuple(next(csv.reader(handle, delimiter="\t"))) == LEDGER_FIELDS, "retry ledger header mismatch")
    selection = base.select_quartet()
    base.require(selection["pair_group_id"] == "seed001_heavy", "selected quartet is not seed001_heavy")
    run_id = "single_quartet_v3_validation_retry_v1_" + base.stamp_now()
    args.local_parent.mkdir(parents=True, exist_ok=True)
    run_root = args.local_parent / run_id
    run_root.mkdir()
    remote_root = f"{args.remote_parent}/{run_id}"
    remote_exec_root = f"/home/etip/.cache/proxytraffic-realistic-v3-single-quartet-validation/{run_id}"
    git_head = base.run(["git", "rev-parse", "HEAD"], 30, True).stdout.strip()
    (run_root / "NON_FORMAL_VALIDATION").write_text(
        "NON_FORMAL_VALIDATION\nFUTURE_FORMAL_MANIFEST_ELIGIBLE=NO\nTRANSIENT_RETRY_POLICY_V1\n",
        encoding="utf-8",
    )
    base.write_json(run_root / "selection.json", selection)
    base.write_json(run_root / "frozen_inputs.json", {str(path): digest for path, digest in base.FROZEN_SHA256.items()})
    shutil.copy2(POLICY, run_root / POLICY.name)
    shutil.copy2(POLICY_FREEZE, run_root / POLICY_FREEZE.name)
    base.write_json(run_root / "runner_provenance.json", {
        "classification": "NON_FORMAL_VALIDATION",
        "runner_sha256": base.sha256(Path(__file__)),
        "base_runner_sha256": base.sha256(BASE_RUNNER),
        "executor_sha256": base.sha256(base.EXECUTOR),
        "supervisor_sha256": base.sha256(base.SUPERVISOR),
        "auditor_sha256": base.sha256(base.AUDITOR),
        "retry_policy_sha256": POLICY_SHA256,
        "git_head": git_head,
        "started_utc": base.utc_now(),
        "local_root": str(run_root),
        "remote_root": remote_root,
    })
    mode_summaries: list[dict[str, object]] = []
    all_attempts: list[dict[str, object]] = []
    retry_classes: Counter[str] = Counter()
    success = False
    fatal_mode = ""
    try:
        base.require(not any(base.health_probe_processes().values()), "preexisting active health probe process")
        base.require(not base.run(["sudo", "-n", "pgrep", "-f", "^tcpdump .*realistic.*\\.pcap"], 10).stdout.strip(), "preexisting local Realistic tcpdump")
        base.require(not base.run(["ssh", "-o", "BatchMode=yes", base.SERVER_HOST, "sudo", "-n", "pgrep", "-f", "^tcpdump .*proxytraffic-realistic.*\\.pcap"], 15).stdout.strip(), "preexisting remote Realistic tcpdump")
        browser_pre = int(base.run(["ssh", "-o", "BatchMode=yes", base.USER_HOST, "bash", "-lc", "pgrep -c chrome-headless 2>/dev/null || true"], 15).stdout.strip() or "0")
        base.require(browser_pre == 0, f"preexisting browser process count={browser_pre}")
        base.run(["ssh", "-o", "BatchMode=yes", base.USER_HOST, "mkdir", "-p", f"{remote_exec_root}/input"], 30, True)
        base.run(["scp", "-q", str(base.EXECUTOR), str(selection["plan_path"]), f"{base.USER_HOST}:{remote_exec_root}/input/"], 120, True)
        remote_hashes = base.run([
            "ssh", "-o", "BatchMode=yes", base.USER_HOST, "sha256sum",
            f"{remote_exec_root}/input/realistic_browser_v3.py",
            f"{remote_exec_root}/input/{Path(str(selection['plan_path'])).name}",
        ], 30, True).stdout
        base.require(
            {line.split()[0] for line in remote_hashes.splitlines()} == {base.EXPECTED_EXECUTOR_SHA256, str(selection["plan_sha256"])},
            "remote immutable inputs SHA mismatch",
        )
        base.run([
            "ssh", "-o", "BatchMode=yes", base.USER_HOST, "cp",
            f"{remote_exec_root}/input/{Path(str(selection['plan_path'])).name}",
            f"{remote_exec_root}/input/workload_plan.json",
        ], 30, True)

        for mode in base.MODES:
            mode_root = run_root / f"validation_{mode}_{selection['pair_group_id']}"
            mode_root.mkdir()
            attempts: list[dict[str, object]] = []
            first = run_attempt(mode, 1, selection, mode_root, remote_exec_root)
            attempts.append(first)
            all_attempts.append(first)
            allowed, reason = retry_authorized(first)
            if first["status"] == "PASS":
                final_status = "SAMPLE_PASS_ATTEMPT1"
            elif allowed:
                retry_classes[str(first["failure_class"])] += 1
                second = run_attempt(mode, 2, selection, mode_root, remote_exec_root)
                attempts.append(second)
                all_attempts.append(second)
                final_status = "SAMPLE_PASS_ATTEMPT2" if second["status"] == "PASS" else "SAMPLE_FAIL_ATTEMPT2"
            else:
                final_status = "SAMPLE_FAIL_NON_RETRYABLE_ATTEMPT1"
            final_result = attempts[-1]
            ledger_rows = []
            for item in attempts:
                item_allowed, item_reason = retry_authorized(item)
                if int(item["attempt"]) == 2:
                    item_allowed = False
                    item_reason = "MAX_ATTEMPTS_REACHED"
                ledger_rows.append(ledger_row(
                    run_id, git_head, selection, item, item_allowed, item_reason, final_status
                ))
            append_ledger(ledger_rows)
            base.write_json(mode_root / "mode_attempts_result.json", {
                "classification": "NON_FORMAL_VALIDATION",
                "mode": mode,
                "max_attempts": MAX_ATTEMPTS_PER_SAMPLE,
                "attempt_count": len(attempts),
                "retry_count": len(attempts) - 1,
                "final_status": "PASS" if final_result["status"] == "PASS" else "FAIL",
                "final_attempt": final_result["attempt"],
                "attempts": attempts,
            })
            mode_summaries.append({
                "mode": mode,
                "status": final_result["status"],
                "attempt_count": len(attempts),
                "retry_count": len(attempts) - 1,
                "final_attempt": final_result["attempt"],
                "final_result": final_result,
            })
            print(
                f"MODE_FINAL mode={mode} status={final_result['status']} attempts={len(attempts)} "
                f"retry_count={len(attempts)-1} failure_class={final_result['failure_class'] or 'NONE'}",
                flush=True,
            )
            if final_result["status"] != "PASS":
                fatal_mode = mode
                break

        shutil.copy2(LEDGER, run_root / LEDGER.name)
        total_attempts = len(all_attempts)
        retry_count = total_attempts - len(mode_summaries)
        if fatal_mode:
            summary = {
                "marker": "REALISTIC_V3_SINGLE_QUARTET_VALIDATION_FAIL",
                "classification": "NON_FORMAL_VALIDATION",
                "retry_policy": "FORMAL_T0_V3_TRANSIENT_RETRY_POLICY_V1",
                "policy_sha256": POLICY_SHA256,
                "selection": selection,
                "total_attempts": total_attempts,
                "retry_count": retry_count,
                "retry_failure_classes": dict(retry_classes),
                "mode_final_status": {item["mode"]: item["status"] for item in mode_summaries},
                "failed_mode": fatal_mode,
                "residual": sum(int(item["residual"]) for item in all_attempts),
                "local_sha": "PENDING",
                "remote_upload": "PENDING",
                "remote_independent_sha": "PENDING",
            }
            base.write_json(run_root / "quartet_validation_result.json", summary)
            (run_root / "REALISTIC_V3_SINGLE_QUARTET_VALIDATION_FAIL").write_text(
                "REALISTIC_V3_SINGLE_QUARTET_VALIDATION_FAIL\nNON_FORMAL_VALIDATION\n", encoding="utf-8"
            )
            base.create_checksums(run_root, "ARTIFACT_SHA256SUMS.txt", {
                "ARTIFACT_SHA256SUMS.txt", "quartet_validation_result.json",
            })
            base.verify_checksums(run_root, "ARTIFACT_SHA256SUMS.txt")
            remote_stdout = base.upload_and_verify(run_root, remote_root, "ARTIFACT_SHA256SUMS.txt")
            summary.update({
                "local_sha": "PASS", "remote_upload": "PASS", "remote_independent_sha": "PASS",
                "remote_verified_file_count": len(remote_stdout.splitlines()),
            })
            base.write_json(run_root / "quartet_validation_result.json", summary)
            print(json.dumps(summary, indent=2, sort_keys=True))
            print(f"LOCAL_ROOT={run_root}")
            print(f"REMOTE_ROOT={remote_root}")
            print("REALISTIC_V3_SINGLE_QUARTET_VALIDATION_FAIL")
            return 1

        final_results = [item["final_result"] for item in mode_summaries]
        pairing = pairing_audit(selection, final_results, run_root)
        summary = {
            "marker": SUCCESS_MARKER,
            "classification": "NON_FORMAL_VALIDATION",
            "future_formal_manifest_eligible": False,
            "retry_policy": "FORMAL_T0_V3_TRANSIENT_RETRY_POLICY_V1",
            "policy_sha256": POLICY_SHA256,
            "selection": selection,
            "total_attempts": total_attempts,
            "retry_count": retry_count,
            "retry_failure_classes": dict(retry_classes),
            "mode_final_status": {item["mode"]: item["status"] for item in mode_summaries},
            "mode_final_attempt": {item["mode"]: item["final_attempt"] for item in mode_summaries},
            "pairing_audit": pairing,
            "mode_purity": {item["mode"]: item["final_result"]["mode_purity"] for item in mode_summaries},
            "redsocks_actual_conn_max": {
                item["mode"]: item["final_result"]["redsocks_actual_conn_max"]
                for item in mode_summaries if item["mode"] != "direct"
            },
            "capture": {item["mode"]: item["final_result"]["capture"]["status"] for item in mode_summaries},
            "packet_counts": {item["mode"]: item["final_result"]["packet_counts"] for item in mode_summaries},
            "pre_health": {item["mode"]: item["final_result"]["pre_health"] for item in mode_summaries},
            "post_health": {item["mode"]: item["final_result"]["post_health"] for item in mode_summaries},
            "residual": sum(int(item["residual"]) for item in all_attempts),
            "local_sha": "PENDING",
            "remote_upload": "PENDING",
            "remote_independent_sha": "PENDING",
        }
        base.write_json(run_root / "quartet_validation_result.json", summary)
        base.create_checksums(run_root, "ARTIFACT_SHA256SUMS.txt", {
            "ARTIFACT_SHA256SUMS.txt", "FINAL_METADATA_SHA256SUMS.txt", "remote_sha_verification.json",
            "quartet_validation_result.json", "REALISTIC_V3_SINGLE_QUARTET_VALIDATION_PASS",
        })
        base.verify_checksums(run_root, "ARTIFACT_SHA256SUMS.txt")
        remote_stdout = base.upload_and_verify(run_root, remote_root, "ARTIFACT_SHA256SUMS.txt")
        remote_verification = {
            "classification": "NON_FORMAL_VALIDATION",
            "local_sha": "PASS",
            "remote_upload": "PASS",
            "remote_independent_sha": "PASS",
            "remote_host": base.UPLOAD_HOST,
            "remote_root": remote_root,
            "verified_file_count": len(remote_stdout.splitlines()),
            "verified_utc": base.utc_now(),
        }
        base.write_json(run_root / "remote_sha_verification.json", remote_verification)
        summary.update({"local_sha": "PASS", "remote_upload": "PASS", "remote_independent_sha": "PASS"})
        base.write_json(run_root / "quartet_validation_result.json", summary)
        (run_root / SUCCESS_MARKER).write_text(
            f"{SUCCESS_MARKER}\nNON_FORMAL_VALIDATION\n", encoding="utf-8"
        )
        base.create_checksums(run_root, "FINAL_METADATA_SHA256SUMS.txt", {"FINAL_METADATA_SHA256SUMS.txt"})
        base.verify_checksums(run_root, "FINAL_METADATA_SHA256SUMS.txt")
        base.final_remote_verify(run_root, remote_root, "FINAL_METADATA_SHA256SUMS.txt")
        success = True
        print(json.dumps(summary, indent=2, sort_keys=True))
        print(f"LOCAL_ROOT={run_root}")
        print(f"REMOTE_ROOT={remote_root}")
        print(SUCCESS_MARKER)
        return 0
    except BaseException as exc:
        base.write_json(run_root / "VALIDATION_FAIL.json", {
            "classification": "NON_FORMAL_VALIDATION",
            "status": "FAIL",
            "error": f"{type(exc).__name__}: {exc}",
            "failed_utc": base.utc_now(),
            "total_attempts": len(all_attempts),
            "retry_count": max(0, len(all_attempts) - len(mode_summaries)),
        })
        print(f"SINGLE_QUARTET_V3_VALIDATION_FAIL root={run_root} error={type(exc).__name__}: {exc}", flush=True)
        return 1
    finally:
        base.cleanup_mode()
        if not success:
            print("NON_FORMAL_VALIDATION evidence preserved; smoke not started", flush=True)


if __name__ == "__main__":
    raise SystemExit(main())
