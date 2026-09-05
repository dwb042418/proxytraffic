#!/usr/bin/env python3
"""Run the authorized Formal T0 v3 domain-replacement qualification."""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import os
import signal
import subprocess
import time
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path


REPO = Path("/home/etip/Tunnel/proxytraffic")
DOC = REPO / "docs/realistic_v1/formal_t0_v3"
SOURCE = Path("/home/etip/datasets/plans/realistic_v1/t0_source/tranco_46W9X_top1m.csv")
SYNTAX = REPO / "docs/realistic_v1/tranco_46W9X_eligibility_audit.tsv"
POOL = Path(
    "/home/etip/.cache/realistic-v3-current500-capacity256-20260903T084052Z/"
    "remote-evidence/input/formal_domain_pool.tsv"
)
CURRENT_AUDIT = DOC / "actionability_audit_current500_capacity256_20260903.tsv"
CURRENT_RESULT = DOC / "current500_actionability_audit_capacity256_result.txt"
GATE = DOC / "formal_t0_v3_actionability_gate_definition.txt"
HEALTH_DEFINITION = DOC / "trojan_transport_qualification_v3_definition.txt"
AMENDMENT = DOC / "current500_redsocks_capacity_amendment_v3.txt"
TRIAL_SCRIPT = REPO / "encrypted_traffic_platform/realistic/audit_actionability_trial_v3.py"
CONTROLLER = REPO / "encrypted_traffic_platform/realistic/run_domain_replacement_v3.py"
SUPERVISOR = REPO / "encrypted_traffic_platform/scripts/realistic/realistic-executor-supervisor"
HEALTH_GUARD = Path("/home/etip/.cache/realistic-v3-trojan-qualification-v3/realistic-trojan-health-guard-v3")
MONITOR = Path("/home/etip/.cache/realistic-v3-current500-capacity256/capacity-resource-monitor.py")

SOURCE_SHA = "264830dfe5bbf84daeb23d482123d0a7eab1f6ee6830f08984c563be18d998aa"
POOL_SHA = "762cb40b906936b137ad80dae0ac37bc38fee971a8f6bfbe24182d37de89473e"
CURRENT_AUDIT_SHA = "5f2102f4c195078114719e872945eaa126cbb41f9df9fa4945b7b99fe4daf307"
CURRENT_RESULT_SHA = "ece0be3b5eb6289b41491823c6b9d58f23b2351ade68565cf9252964bac3606e"
GATE_SHA = "baac5e249f81a743098d8e12c43f6c8ba4aca1745e12e03d9a2d69452258fd1e"
HEALTH_SHA = "b26988debe3b4fd147a986f31902a8e628209b3825d0f2798a847e0203a09ffb"
AMENDMENT_SHA = "063620cd26d85a374cdb3618841114d337297d662bc347883f6fd25784db4051"
TRIAL_SHA = "3dd7f6d9d5de55f61b1a94e6c3367961620a3ead47eaf787ddbaf77dd06feab8"
SUPERVISOR_SHA = "9a97f5912310d877f5ec24f09873f005ff6d9c4d0c0e4d4c583e1e423d7ee63c"
HEALTH_GUARD_SHA = "ff65c5caf5020fb41507ba3bef7e3e128d377a857281b8caaef754cc266553af"
MONITOR_SHA = "5daaabe103487eaf61fc13cc050689ee4458853b2ad6faa97c2bbcd3a0a17a54"
REDSOCKS_CONFIG_SHA = "5c46694892aee4039559f43d0b7c5e3a3b3e25ed61c114176aff32c09e871017"

UNSTABLE_DOMAINS = (
    "amazonaws.com", "github.com", "wa.me", "baidu.com", "intuit.com",
    "userapi.com", "nature.com", "ip-api.com", "espn.com", "mega.co.nz",
    "bugsnag.com", "amazon.com.au", "myspace.com", "biblegateway.com",
    "bankofamerica.com", "fwmrm.net", "thenai.org", "state.gov", "verify.hn",
    "as.com", "fortune.com", "lanacion.com.ar", "imagepond.net", "manifold.markets",
)
BUCKETS = {
    "top_1_1000": (1, 1000),
    "rank_1001_100000": (1001, 100000),
    "rank_100001_1000000": (100001, 1000000),
}
EXPECTED_UNSTABLE_BUCKETS = {
    "top_1_1000": 18,
    "rank_1001_100000": 4,
    "rank_100001_1000000": 2,
}


def now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def sha(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def run(argv: list[str], timeout: float = 60, check: bool = False) -> subprocess.CompletedProcess:
    return subprocess.run(
        argv, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        timeout=timeout, check=check,
    )


def iptables(argv: list[str], check: bool = True) -> subprocess.CompletedProcess:
    return run(["sudo", "-n", "iptables", *argv], 20, check)


def delete_rule(table: list[str], rule: list[str]) -> None:
    while iptables([*table, "-C", *rule], False).returncode == 0:
        iptables([*table, "-D", *rule])


def setup_transport() -> None:
    run([
        "sudo", "-n", "systemctl", "stop", "redsocks-realistic@trojan.service",
        "xray-realistic-trojan-client-12082.service",
    ], 30)
    proxy_rule = [
        "PREROUTING", "-i", "ens38", "-s", "192.168.210.10", "-p", "tcp",
        "-m", "multiport", "--dports", "80,443,24443", "-j", "REALISTIC_PROXY",
    ]
    guard_rule = [
        "FORWARD", "-i", "ens38", "-s", "192.168.210.10", "-j", "REALISTIC_GUARD",
    ]
    delete_rule(["-t", "nat"], proxy_rule)
    delete_rule([], guard_rule)
    iptables(["-t", "nat", "-F", "REALISTIC_PROXY"])
    iptables([
        "-t", "nat", "-A", "REALISTIC_PROXY", "-p", "tcp", "-j", "DNAT",
        "--to-destination", "127.0.0.1:12345",
    ])
    iptables(["-t", "nat", "-A", *proxy_rule])
    iptables(["-F", "REALISTIC_GUARD"])
    for rule in (
        ["-p", "udp", "--dport", "53", "-j", "ACCEPT"],
        ["-p", "udp", "--dport", "123", "-j", "ACCEPT"],
        ["-p", "udp", "-j", "DROP"],
        ["-p", "tcp", "-m", "multiport", "--dports", "80,443,24443", "-j",
         "REJECT", "--reject-with", "tcp-reset"],
        ["-j", "RETURN"],
    ):
        iptables(["-A", "REALISTIC_GUARD", *rule])
    iptables(["-I", *guard_rule[:1], "1", *guard_rule[1:]])
    run([
        "sudo", "-n", "systemctl", "start", "xray-realistic-trojan-client-12082.service",
        "redsocks-realistic@trojan.service",
    ], 30, True)
    time.sleep(1)


def cleanup_transport() -> None:
    proxy_rule = [
        "PREROUTING", "-i", "ens38", "-s", "192.168.210.10", "-p", "tcp",
        "-m", "multiport", "--dports", "80,443,24443", "-j", "REALISTIC_PROXY",
    ]
    guard_rule = [
        "FORWARD", "-i", "ens38", "-s", "192.168.210.10", "-j", "REALISTIC_GUARD",
    ]
    try:
        delete_rule(["-t", "nat"], proxy_rule)
        delete_rule([], guard_rule)
        iptables(["-t", "nat", "-F", "REALISTIC_PROXY"], False)
        iptables(["-F", "REALISTIC_GUARD"], False)
        run([
            "sudo", "-n", "systemctl", "stop", "redsocks-realistic@trojan.service",
            "xray-realistic-trojan-client-12082.service",
        ], 30)
    except Exception:
        pass


def verify_redsocks_capacity(since: str) -> dict:
    config_sha = run([
        "sudo", "-n", "sha256sum", "/etc/proxytraffic/redsocks-realistic/trojan.conf",
    ], 15, True).stdout.split()[0]
    pid = int(run([
        "systemctl", "show", "redsocks-realistic@trojan.service", "-p", "MainPID", "--value",
    ], 10, True).stdout.strip())
    if pid <= 1:
        raise RuntimeError("REDSOCKS_CAPACITY_PREFLIGHT_NO_PID")
    limits = run(["sudo", "-n", "cat", f"/proc/{pid}/limits"], 10, True).stdout
    line = next((item for item in limits.splitlines() if item.startswith("Max open files")), "")
    fields = line.split()
    if len(fields) < 6:
        raise RuntimeError("REDSOCKS_CAPACITY_PREFLIGHT_NOFILE_PARSE_FAILURE")
    soft_nofile, hard_nofile = int(fields[3]), int(fields[4])
    journal_since = since.replace("T", " ").split(".", 1)[0]
    journal = run([
        "journalctl", "-u", "redsocks-realistic@trojan.service", "--since", journal_since,
        "--no-pager", "-o", "cat",
    ], 15, True).stdout
    starts = [item for item in journal.splitlines() if "redsocks started, conn_max=" in item]
    if not starts:
        raise RuntimeError("REDSOCKS_CAPACITY_PREFLIGHT_START_LOG_MISSING")
    conn_max = int(starts[-1].rsplit("conn_max=", 1)[1].split()[0])
    record = {
        "redsocks_pid": pid,
        "redsocks_config_sha256": config_sha,
        "soft_nofile": soft_nofile,
        "hard_nofile": hard_nofile,
        "conn_max": conn_max,
        "startup_log": starts[-1],
    }
    if config_sha != REDSOCKS_CONFIG_SHA:
        raise RuntimeError("REDSOCKS_CONFIG_SHA_MISMATCH")
    if (soft_nofile, hard_nofile) != (2048, 524288):
        raise RuntimeError("REDSOCKS_NOFILE_MISMATCH")
    if conn_max != 256:
        raise RuntimeError("REDSOCKS_CONN_MAX_MISMATCH")
    return record


def remote_exists(path: str) -> bool:
    return run([
        "ssh", "-o", "BatchMode=yes", "realistic-user", "test", "-f", path,
    ], 15).returncode == 0


def remote_json(path: str) -> dict:
    completed = run([
        "ssh", "-o", "BatchMode=yes", "realistic-user", "cat", path,
    ], 15, True)
    return json.loads(completed.stdout)


def jsonl_last(path: Path) -> dict:
    if not path.exists() or not path.stat().st_size:
        return {}
    return json.loads(path.read_text().splitlines()[-1])


def capacity_failure(record: dict) -> str:
    if not record:
        return ""
    if int(record.get("redsocks_conn_max_hits", -1)) < 0:
        return "REDSOCKS_CONN_MAX_OBSERVATION_FAILURE"
    if int(record.get("redsocks_conn_max_hits", 0)) > 0:
        return "REDSOCKS_CONN_MAX_HIT"
    if not record.get("redsocks", {}).get("alive", False):
        return "UNEXPECTED_REDSOCKS_EXIT"
    if not record.get("trojan", {}).get("alive", False):
        return "UNEXPECTED_TROJAN_EXIT"
    current = int(record.get("conntrack_current", -1))
    maximum = int(record.get("conntrack_max", -1))
    if current < 0 or maximum <= 0:
        return "CONNTRACK_OBSERVATION_FAILURE"
    if current >= maximum:
        return "RESOURCE_EXHAUSTION_CONNTRACK"
    return ""


def stop_remote_outer(remote_outer: str) -> None:
    try:
        state = remote_json(remote_outer + "/state.json")
        pgid = int(state["executor_pgid"])
    except Exception:
        return
    for name in ("INT", "TERM", "KILL"):
        run([
            "ssh", "-o", "BatchMode=yes", "realistic-user",
            "kill", f"-{name}", "--", f"-{pgid}",
        ], 15)
        time.sleep(2)
        if not remote_exists(remote_outer + "/state.json"):
            break


def frozen_hashes() -> dict[str, str]:
    paths = [CURRENT_AUDIT, CURRENT_RESULT, *sorted((DOC / "evidence").iterdir())]
    return {str(path): sha(path) for path in paths if path.is_file()}


def verify_static_inputs() -> None:
    expected = {
        SOURCE: SOURCE_SHA,
        POOL: POOL_SHA,
        CURRENT_AUDIT: CURRENT_AUDIT_SHA,
        CURRENT_RESULT: CURRENT_RESULT_SHA,
        GATE: GATE_SHA,
        HEALTH_DEFINITION: HEALTH_SHA,
        AMENDMENT: AMENDMENT_SHA,
        TRIAL_SCRIPT: TRIAL_SHA,
        SUPERVISOR: SUPERVISOR_SHA,
        HEALTH_GUARD: HEALTH_GUARD_SHA,
        MONITOR: MONITOR_SHA,
    }
    mismatches = [f"{path}: {sha(path)} != {wanted}" for path, wanted in expected.items()
                  if sha(path) != wanted]
    if mismatches:
        raise RuntimeError("FROZEN_INPUT_SHA_MISMATCH\n" + "\n".join(mismatches))


def prepare_inputs(root: Path) -> dict:
    input_dir = root / "input"
    input_dir.mkdir()
    pool_rows = list(csv.DictReader(POOL.open(newline=""), delimiter="\t"))
    audit_rows = list(csv.DictReader(CURRENT_AUDIT.open(newline=""), delimiter="\t"))
    audit_by_domain = {row["domain"]: row for row in audit_rows}
    unstable = [row for row in audit_rows if row["final_actionability_status"] == "ACTIONABILITY_UNSTABLE"]
    stable = [row for row in audit_rows if row["final_actionability_status"] == "ACTIONABILITY_STABLE"]
    if len(pool_rows) != 500 or len(audit_rows) != 500 or len(stable) != 476 or len(unstable) != 24:
        raise RuntimeError("CURRENT500_COUNT_MISMATCH")
    if tuple(row["domain"] for row in unstable) != UNSTABLE_DOMAINS:
        raise RuntimeError("AUTHORIZED_UNSTABLE_DOMAIN_SET_OR_ORDER_MISMATCH")
    if Counter(row["bucket"] for row in unstable) != EXPECTED_UNSTABLE_BUCKETS:
        raise RuntimeError("AUTHORIZED_UNSTABLE_BUCKET_MISMATCH")
    if {row["domain"] for row in pool_rows} != set(audit_by_domain):
        raise RuntimeError("CURRENT_POOL_AUDIT_DOMAIN_MISMATCH")
    pool_by_domain = {row["domain"]: row for row in pool_rows}
    slots = []
    for domain in UNSTABLE_DOMAINS:
        audit = audit_by_domain[domain]
        pool = pool_by_domain[domain]
        if int(audit["rank"]) != int(pool["rank"]) or audit["bucket"] != pool["rank_bucket"]:
            raise RuntimeError(f"UNSTABLE_PROVENANCE_MISMATCH domain={domain}")
        slots.append({
            "old_rank": pool["rank"],
            "old_domain": domain,
            "old_bucket": pool["rank_bucket"],
            "old_failure_reason": audit["failure_reason"],
        })
    slot_path = input_dir / "replacement_slots.tsv"
    with slot_path.open("w", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(slots[0]), delimiter="\t", lineterminator="\n")
        writer.writeheader()
        writer.writerows(slots)

    historical_unstable = set()
    historical_files = (
        DOC / "formal_domain_replay_stability_base500.tsv",
        DOC / "formal_domain_replacement_audit_rejected_pre_reserve.tsv",
        DOC / "formal_domain_replacement_audit_batch2.tsv",
    )
    for path in historical_files:
        for row in csv.DictReader(path.open(newline=""), delimiter="\t"):
            if row.get("replay_stable", "").strip().lower() != "true":
                historical_unstable.add(row["domain"])
    current_domains = set(pool_by_domain)
    candidate_path = input_dir / "replacement_candidates.tsv"
    candidate_counts = Counter()
    first_candidates = {}
    excluded = Counter()
    with SOURCE.open(newline="") as source_handle, SYNTAX.open(newline="") as syntax_handle, candidate_path.open("w", newline="") as output:
        source_reader = csv.reader(source_handle)
        syntax_reader = csv.DictReader(syntax_handle, delimiter="\t")
        writer = csv.DictWriter(
            output,
            fieldnames=["candidate_rank", "candidate_domain", "candidate_bucket"],
            delimiter="\t", lineterminator="\n",
        )
        writer.writeheader()
        source_count = 0
        for source_row, syntax_row in zip(source_reader, syntax_reader):
            source_count += 1
            rank, domain = int(source_row[0]), source_row[1]
            if rank != int(syntax_row["rank"]) or domain != syntax_row["domain"]:
                raise RuntimeError(f"SOURCE_SYNTAX_ALIGNMENT_FAILURE rank={rank}")
            bucket = next(name for name, (low, high) in BUCKETS.items() if low <= rank <= high)
            if syntax_row["eligible"].strip().lower() != "true":
                excluded["syntax_ineligible"] += 1
                continue
            if domain in current_domains:
                excluded["current_pool"] += 1
                continue
            if domain in historical_unstable:
                excluded["historical_replay_unstable"] += 1
                continue
            writer.writerow({
                "candidate_rank": rank,
                "candidate_domain": domain,
                "candidate_bucket": bucket,
            })
            candidate_counts[bucket] += 1
            first_candidates.setdefault(bucket, {"rank": rank, "domain": domain})
        if source_count != 1_000_000:
            raise RuntimeError(f"SOURCE_ROW_COUNT_MISMATCH count={source_count}")
        if next(syntax_reader, None) is not None or next(source_reader, None) is not None:
            raise RuntimeError("SOURCE_SYNTAX_LENGTH_MISMATCH")

    for path in (TRIAL_SCRIPT, CONTROLLER, GATE, HEALTH_DEFINITION, AMENDMENT):
        target = input_dir / path.name
        target.write_bytes(path.read_bytes())
    manifest = {
        "created_utc": now(),
        "run": "FORMAL_T0_V3_DOMAIN_REPLACEMENT_ONLY",
        "workers": 2,
        "redsocks_conn_max": 256,
        "original_stable": 476,
        "replacement_slots": 24,
        "unstable_domains": list(UNSTABLE_DOMAINS),
        "unstable_bucket_counts": EXPECTED_UNSTABLE_BUCKETS,
        "candidate_order": "same bucket, Tranco rank strictly ascending",
        "candidate_scan_start": "first rank in each bucket",
        "candidate_exclusions": dict(excluded),
        "historical_replay_unstable_domains": len(historical_unstable),
        "candidate_counts": dict(candidate_counts),
        "first_candidates": first_candidates,
        "source_sha256": SOURCE_SHA,
        "current_pool_sha256": POOL_SHA,
        "current_audit_sha256": CURRENT_AUDIT_SHA,
        "current_result_sha256": CURRENT_RESULT_SHA,
        "gate_sha256": GATE_SHA,
        "health_definition_sha256": HEALTH_SHA,
        "health_guard_sha256": HEALTH_GUARD_SHA,
        "trial_script_sha256": TRIAL_SHA,
        "supervisor_sha256": SUPERVISOR_SHA,
        "replacement_controller_sha256": sha(CONTROLLER),
        "slots_sha256": sha(slot_path),
        "candidates_sha256": sha(candidate_path),
        "frozen_current500_hashes_before": frozen_hashes(),
    }
    (root / "prerun_manifest.json").write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")
    return manifest


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--remote-root", required=True)
    args = parser.parse_args()
    if args.root.exists():
        raise SystemExit(f"evidence root already exists: {args.root}")
    verify_static_inputs()
    args.root.mkdir(parents=True)
    manifest = prepare_inputs(args.root)
    (args.root / "run_started_utc.txt").write_text(now() + "\n")
    remote_input = args.remote_root + "/input"
    remote_outer = args.remote_root + "/outer-supervisor"
    remote_audit = args.remote_root + "/replacement-evidence"
    barrier = remote_audit + "/START_AFTER_HEALTH_PREFLIGHT"
    guard = None
    monitor = None
    guard_stdout = (args.root / "health_guard_stdout.log").open("w", buffering=1)
    guard_stderr = (args.root / "health_guard_stderr.log").open("w", buffering=1)
    monitor_stdout = (args.root / "monitor_stdout.log").open("w", buffering=1)
    monitor_stderr = (args.root / "monitor_stderr.log").open("w", buffering=1)
    health_path = args.root / "health.jsonl"
    resource_path = args.root / "resources.jsonl"
    transport_started = now()
    try:
        run(["ssh", "-o", "BatchMode=yes", "realistic-user", "mkdir", "-p", remote_input], 30, True)
        copy = run(["scp", "-q", *[str(path) for path in (args.root / "input").iterdir()],
                    "realistic-user:" + remote_input + "/"], 1800)
        if copy.returncode:
            raise RuntimeError(f"REMOTE_INPUT_COPY_FAILURE: {copy.stderr}")
        setup_transport()
        capacity_preflight = verify_redsocks_capacity(transport_started)
        (args.root / "redsocks_capacity_preflight.json").write_text(
            json.dumps(capacity_preflight, indent=2, sort_keys=True) + "\n"
        )
        outer_command = [
            "ssh", "-o", "BatchMode=yes", "realistic-user",
            "/home/etip/bin/realistic-executor-supervisor",
            "--label", "formal_t0_v3_domain_replacement", "--evidence", remote_outer,
            "--timeout", "30000", "--int-grace", "10", "--term-grace", "10",
            "--kill-grace", "5", "start", "--",
            "/home/etip/.venvs/realistic/bin/python",
            remote_input + "/run_domain_replacement_v3.py",
            "--slots", remote_input + "/replacement_slots.tsv",
            "--candidates", remote_input + "/replacement_candidates.tsv",
            "--evidence-root", remote_audit,
            "--trial-script", remote_input + "/audit_actionability_trial_v3.py",
            "--supervisor", "/home/etip/bin/realistic-executor-supervisor",
            "--python", "/home/etip/.venvs/realistic/bin/python",
            "--workers", "2", "--start-barrier", barrier,
        ]
        start = run(outer_command, 30, True)
        (args.root / "outer_start.json").write_text(start.stdout)
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline and not remote_exists(remote_audit + "/CONTROLLER_READY"):
            time.sleep(0.5)
        if not remote_exists(remote_audit + "/CONTROLLER_READY"):
            raise RuntimeError("REMOTE_CONTROLLER_READINESS_TIMEOUT")
        guard = subprocess.Popen([
            str(HEALTH_GUARD), "--output", str(health_path), "--interval", "30",
            "--remote-worker-state", remote_outer + "/state.json",
        ], stdout=guard_stdout, stderr=guard_stderr)
        stage_start = now()
        (args.root / "stage_start_utc.txt").write_text(stage_start + "\n")
        monitor = subprocess.Popen([
            "python3", str(MONITOR), "--output", str(resource_path), "--interval", "5",
            "--since", stage_start, "--remote-progress", remote_audit + "/progress.json",
        ], stdout=monitor_stdout, stderr=monitor_stderr)

        deadline = time.monotonic() + 180
        preflight = None
        while time.monotonic() < deadline:
            if guard.poll() is not None:
                raise RuntimeError(f"HEALTH_GUARD_EXIT_DURING_PREFLIGHT rc={guard.returncode}")
            if monitor.poll() is not None:
                raise RuntimeError(f"CAPACITY_MONITOR_EXIT_DURING_PREFLIGHT rc={monitor.returncode}")
            if health_path.exists() and health_path.stat().st_size:
                preflight = jsonl_last(health_path)
                break
            time.sleep(1)
        if preflight is None:
            raise RuntimeError("HEALTH_PREFLIGHT_CYCLE_TIMEOUT")
        if (preflight.get("infrastructure_health_lost")
                or not preflight.get("canary", {}).get("pass")
                or int(preflight.get("server_pass_count", 0)) < 3
                or int(preflight.get("trojan_pass_count", 0)) < 3
                or preflight.get("unexpected_exit")):
            raise RuntimeError("HEALTH_PREFLIGHT_DID_NOT_PASS")
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline and (
            not resource_path.exists() or not resource_path.stat().st_size
        ):
            if monitor.poll() is not None:
                raise RuntimeError(f"CAPACITY_MONITOR_EXIT_DURING_PREFLIGHT rc={monitor.returncode}")
            time.sleep(0.5)
        failure = capacity_failure(jsonl_last(resource_path))
        if failure:
            raise RuntimeError(failure)
        run(["ssh", "-o", "BatchMode=yes", "realistic-user", "touch", barrier], 15, True)
        qualification_started = now()
        (args.root / "qualification_started_utc.txt").write_text(qualification_started + "\n")
        last_selected = -1
        while True:
            if guard.poll() is not None:
                if (args.root / "INFRASTRUCTURE_HEALTH_LOST").exists():
                    raise RuntimeError("INFRASTRUCTURE_HEALTH_LOST")
                raise RuntimeError(f"HEALTH_GUARD_UNEXPECTED_EXIT rc={guard.returncode}")
            if monitor.poll() is not None:
                raise RuntimeError(f"CAPACITY_MONITOR_UNEXPECTED_EXIT rc={monitor.returncode}")
            failure = capacity_failure(jsonl_last(resource_path))
            if failure:
                raise RuntimeError(failure)
            if remote_exists(remote_outer + "/result.json"):
                break
            if remote_exists(remote_audit + "/progress.json"):
                progress = remote_json(remote_audit + "/progress.json")
                selected = int(progress.get("selected", 0))
                if selected != last_selected:
                    print(
                        f"REPLACEMENT_RUN_PROGRESS selected={selected}/24 "
                        f"tested={progress.get('tested', 0)} rejected={progress.get('rejected', 0)}",
                        flush=True,
                    )
                    last_selected = selected
            time.sleep(5)
        outer_result = remote_json(remote_outer + "/result.json")
        controller_result = remote_json(remote_audit + "/controller_result.json")
        if outer_result.get("status") != "PASS" or controller_result.get("status") != "COMPLETE":
            raise RuntimeError(
                f"REPLACEMENT_PROCESS_FAILED outer={outer_result} controller={controller_result}"
            )
        failure = capacity_failure(jsonl_last(resource_path))
        if failure:
            raise RuntimeError(failure)
        prior_cycles = len(health_path.read_text().splitlines())
        deadline = time.monotonic() + 90
        while time.monotonic() < deadline:
            if guard.poll() is not None:
                raise RuntimeError(f"HEALTH_GUARD_EXIT_BEFORE_POST_CYCLE rc={guard.returncode}")
            if monitor.poll() is not None:
                raise RuntimeError(f"CAPACITY_MONITOR_EXIT_BEFORE_POST_CYCLE rc={monitor.returncode}")
            if len(health_path.read_text().splitlines()) > prior_cycles:
                break
            time.sleep(1)
        else:
            raise RuntimeError("POST_QUALIFICATION_HEALTH_CYCLE_TIMEOUT")
        guard.send_signal(signal.SIGTERM)
        guard.wait(timeout=15)
        monitor.send_signal(signal.SIGTERM)
        monitor.wait(timeout=15)
        health_records = [json.loads(line) for line in health_path.read_text().splitlines() if line]
        resource_records = [json.loads(line) for line in resource_path.read_text().splitlines() if line]
        if any(record.get("infrastructure_health_lost") for record in health_records):
            raise RuntimeError("HEALTH_RECORD_CONTAINS_INFRASTRUCTURE_LOSS")
        failures = [capacity_failure(record) for record in resource_records]
        if any(failures):
            raise RuntimeError(next(item for item in failures if item))
        if frozen_hashes() != manifest["frozen_current500_hashes_before"]:
            raise RuntimeError("FROZEN_CURRENT500_ARTIFACT_CHANGED_DURING_RUN")
        copy = run([
            "scp", "-qr", "realistic-user:" + args.remote_root,
            str(args.root / "remote-evidence"),
        ], 1800)
        if copy.returncode:
            raise RuntimeError(f"REMOTE_EVIDENCE_COPY_FAILURE: {copy.stderr}")
        result = {
            "status": "REPLACEMENT_QUALIFICATION_COMPLETE",
            "qualification_started_utc": qualification_started,
            "qualification_finished_utc": now(),
            "workers": 2,
            "redsocks_conn_max": 256,
            "controller_result": controller_result,
            "outer_result": outer_result,
            "health_cycles": len(health_records),
            "infrastructure_health_loss": 0,
            "redsocks_conn_max_hits": max(int(row["redsocks_conn_max_hits"]) for row in resource_records),
            "peak_redsocks_connections": max(
                row.get("sockets", {}).get("redsocks_client_connection_count", 0)
                for row in resource_records
            ),
            "peak_redsocks_fd": max(row.get("redsocks", {}).get("fd_count", -1) for row in resource_records),
            "peak_conntrack": max(row.get("conntrack_current", -1) for row in resource_records),
            "frozen_current500_hashes_after": frozen_hashes(),
        }
        (args.root / "orchestration_result.json").write_text(
            json.dumps(result, indent=2, sort_keys=True) + "\n"
        )
        print("REPLACEMENT_QUALIFICATION_COMPLETE", flush=True)
        return 0
    except BaseException as exc:
        for process in (guard, monitor):
            if process is not None and process.poll() is None:
                process.send_signal(signal.SIGTERM)
                try:
                    process.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    process.kill()
        stop_remote_outer(remote_outer)
        copy = run([
            "scp", "-qr", "realistic-user:" + args.remote_root,
            str(args.root / "remote-evidence"),
        ], 1800)
        failure = {
            "status": "INVALID_INFRASTRUCTURE_FAILURE",
            "timestamp": now(),
            "reason": f"{type(exc).__name__}: {exc}",
            "evidence_copy_rc": copy.returncode,
            "frozen_current500_hashes_after": frozen_hashes(),
        }
        (args.root / "INVALID_INFRASTRUCTURE_FAILURE.json").write_text(
            json.dumps(failure, indent=2, sort_keys=True) + "\n"
        )
        print(f"INVALID_INFRASTRUCTURE_FAILURE {type(exc).__name__}: {exc}", flush=True)
        return 3
    finally:
        guard_stdout.close()
        guard_stderr.close()
        monitor_stdout.close()
        monitor_stderr.close()
        cleanup_transport()


if __name__ == "__main__":
    raise SystemExit(main())
