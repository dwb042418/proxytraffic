#!/usr/bin/env python3
"""Run the deterministic 24-sample Realistic v3 non-Formal smoke."""

from __future__ import annotations

import argparse
import csv
import importlib.util
import json
import shutil
from collections import Counter, defaultdict
from pathlib import Path


REPO = Path("/home/etip/Tunnel/proxytraffic")
RETRY_RUNNER = REPO / "encrypted_traffic_platform/realistic/run_single_quartet_v3_validation_retry.py"
CLASSIFICATION = "NON_FORMAL_SMOKE"
PASS_MARKER = "REALISTIC_V3_24_SAMPLE_SMOKE_PASS"
FAIL_MARKER = "REALISTIC_V3_24_SAMPLE_SMOKE_FAIL"


def load_retry_runner():
    spec = importlib.util.spec_from_file_location("realistic_v3_retry", RETRY_RUNNER)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


retry = load_retry_runner()
base = retry.base


def read_json(path: Path) -> dict[str, object]:
    return json.loads(path.read_text(encoding="utf-8"))


def select_pair_groups() -> list[dict[str, object]]:
    rows = base.read_tsv(base.SCHEDULE)
    base.require(len(rows) == 1200, "schedule row count mismatch")
    grouped: dict[str, list[dict[str, str]]] = defaultdict(list)
    for row in rows:
        grouped[row["pair_group_id"]].append(row)
    candidates: list[dict[str, object]] = []
    for pair_group_id, group in grouped.items():
        base.require(len(group) == 4, f"schedule pair group incomplete: {pair_group_id}")
        base.require({row["mode_order"] for row in group} == set(base.MODES), f"schedule modes invalid: {pair_group_id}")
        fields = (
            "quartet_index", "seed", "seed_assignment_id", "split", "intensity",
            "pair_group_id", "plan_id", "plan_path", "plan_sha256",
        )
        for field in fields:
            base.require(len({row[field] for row in group}) == 1, f"schedule {field} mismatch: {pair_group_id}")
        first = group[0]
        plan_path = Path(first["plan_path"])
        base.require(plan_path.is_file(), f"plan missing: {plan_path}")
        base.require(base.sha256(plan_path) == first["plan_sha256"], f"plan SHA mismatch: {plan_path}")
        candidates.append({
            "selection_rule": (
                "group frozen schedule by intensity; sort pair groups by numeric quartet_index ascending "
                "then pair_group_id ascending; select first two per light/medium/heavy"
            ),
            "quartet_index": int(first["quartet_index"]),
            "seed": first["seed"],
            "seed_assignment_id": first["seed_assignment_id"],
            "split": first["split"],
            "intensity": first["intensity"],
            "pair_group_id": pair_group_id,
            "plan_id": first["plan_id"],
            "plan_path": str(plan_path),
            "plan_sha256": first["plan_sha256"],
            "mode_order": [row["mode_order"] for row in sorted(group, key=lambda row: int(row["mode_position"]))],
        })
    selected = []
    for intensity in ("light", "medium", "heavy"):
        choices = sorted(
            (item for item in candidates if item["intensity"] == intensity),
            key=lambda item: (int(item["quartet_index"]), str(item["pair_group_id"])),
        )[:2]
        base.require(len(choices) == 2, f"insufficient deterministic {intensity} pair groups")
        selected.extend(choices)
    selected.sort(key=lambda item: (int(item["quartet_index"]), str(item["pair_group_id"])))
    base.require(len(selected) == 6, "deterministic selection did not yield six pair groups")
    return selected


def verify_retry_policy() -> None:
    base.require(base.sha256(retry.POLICY) == retry.POLICY_SHA256, "transient retry policy SHA mismatch")
    base.require(
        retry.POLICY_FREEZE.read_text(encoding="utf-8").split()
        == [retry.POLICY_SHA256, retry.POLICY.name],
        "transient retry policy freeze mismatch",
    )
    with retry.LEDGER.open(newline="", encoding="utf-8") as handle:
        base.require(tuple(next(csv.reader(handle, delimiter="\t"))) == retry.LEDGER_FIELDS, "retry ledger header mismatch")
    base.require(retry.MAX_ATTEMPTS_PER_SAMPLE == 2, "MAX_ATTEMPTS_PER_SAMPLE changed")


def prepare_remote_inputs(selection: dict[str, object], remote_exec_root: str) -> None:
    input_root = f"{remote_exec_root}/input"
    plan_path = Path(str(selection["plan_path"]))
    base.run(["ssh", "-o", "BatchMode=yes", base.USER_HOST, "mkdir", "-p", input_root], 30, True)
    base.run(["scp", "-q", str(base.EXECUTOR), str(plan_path), f"{base.USER_HOST}:{input_root}/"], 120, True)
    hashes = base.run([
        "ssh", "-o", "BatchMode=yes", base.USER_HOST, "sha256sum",
        f"{input_root}/realistic_browser_v3.py", f"{input_root}/{plan_path.name}",
    ], 30, True).stdout
    base.require(
        {line.split()[0] for line in hashes.splitlines()}
        == {base.EXPECTED_EXECUTOR_SHA256, str(selection["plan_sha256"])},
        f"remote immutable input SHA mismatch: {selection['pair_group_id']}",
    )
    base.run([
        "ssh", "-o", "BatchMode=yes", base.USER_HOST, "cp",
        f"{input_root}/{plan_path.name}", f"{input_root}/workload_plan.json",
    ], 30, True)
    copied = base.run([
        "ssh", "-o", "BatchMode=yes", base.USER_HOST, "sha256sum", f"{input_root}/workload_plan.json",
    ], 30, True).stdout.split()[0]
    base.require(copied == selection["plan_sha256"], "remote workload_plan SHA mismatch")


def synthetic_attempt_failure(
    exc: BaseException,
    mode: str,
    attempt: int,
    selection: dict[str, object],
    mode_root: Path,
) -> dict[str, object]:
    attempt_dir = mode_root / f"attempt_{attempt}"
    attempt_dir.mkdir(parents=True, exist_ok=True)
    result = {
        "classification": CLASSIFICATION,
        "retry_policy": "FORMAL_T0_V3_TRANSIENT_RETRY_POLICY_V1",
        "mode": mode,
        "attempt": attempt,
        "status": "FAIL",
        "artifact_dir": str(attempt_dir),
        "failure_class": "CAPTURE_FINALIZATION_FAIL",
        "failure_event_index": "",
        "failure_url": "",
        "failure_error": f"{type(exc).__name__}: {exc}",
        "pre_health": "UNKNOWN",
        "post_health": "UNKNOWN",
        "mode_purity": "NOT_ESTABLISHED",
        "redsocks_conn_max_hits": -1,
        "infrastructure_health_lost": 1,
        "server_egress_degraded": 1,
        "trojan_public_path_degraded": int(mode == "trojan"),
        "plan_sha256": selection["plan_sha256"],
        "packet_counts": {},
        "observed_tunnel_syn_counts": {},
        "observed_direct_public_443_syn_count": 0,
        "browser": {"outcome": "FAIL"},
        "capture": {"status": "FAIL"},
        "residual": -1,
        "attempt_finished_utc": base.utc_now(),
    }
    base.write_json(attempt_dir / "validation_attempt_result.json", result)
    (attempt_dir / CLASSIFICATION).write_text(f"{CLASSIFICATION}\n", encoding="utf-8")
    (attempt_dir / "VALIDATION_ATTEMPT_FAIL").write_text(
        f"VALIDATION_ATTEMPT_FAIL\n{CLASSIFICATION}\n", encoding="utf-8"
    )
    return result


def create_sample_manifest(mode_root: Path) -> None:
    name = "SAMPLE_ARTIFACT_SHA256SUMS.txt"
    base.create_checksums(mode_root, name, {name})
    base.verify_checksums(mode_root, name)


def audit_pairing(
    selection: dict[str, object],
    summaries: list[dict[str, object]],
    pair_root: Path,
) -> dict[str, object]:
    plan_hashes, pair_groups, intensities, modes = set(), set(), set(), set()
    domain_sequences, timing_and_dwell = set(), set()
    for summary in summaries:
        result = summary["final_result"]
        attempt_dir = Path(str(result["artifact_dir"]))
        pairing = read_json(attempt_dir / "pairing.json")
        plan_path = attempt_dir / "workload/workload_plan.json"
        plan = read_json(plan_path)
        plan_hashes.add(base.sha256(plan_path))
        pair_groups.add(pairing["pair_group_id"])
        intensities.add(pairing["intensity"])
        modes.add(pairing["mode"])
        domain_sequences.add(base.canonical_hash([
            (event["domain_id"], event["event_index"], event["url"], event["tab_index"])
            for event in plan["events"]
        ]))
        timing_and_dwell.add(base.canonical_hash([
            (
                event["pre_navigation_idle_ms"], event["post_navigation_idle_ms"],
                event["navigation_timeout_ms"], event["scrolls"],
            )
            for event in plan["events"]
        ]))
    checks = {
        "PAIR_GROUP_MODES": len(modes) == 4 and modes == set(base.MODES),
        "PLAN_SHA_UNIQUE_COUNT": len(plan_hashes) == 1,
        "PAIR_GROUP_UNIQUE_COUNT": len(pair_groups) == 1,
        "INTENSITY_UNIQUE_COUNT": len(intensities) == 1,
        "DOMAIN_EVENT_SEQUENCE_UNIQUE_COUNT": len(domain_sequences) == 1,
        "TIMING_DWELL_UNIQUE_COUNT": len(timing_and_dwell) == 1,
        "SELECTED_PLAN_SHA": plan_hashes == {selection["plan_sha256"]},
    }
    issues = [name for name, passed in checks.items() if not passed]
    report = {
        "classification": CLASSIFICATION,
        "status": "PASS" if not issues else "FAIL",
        "pair_group_id": selection["pair_group_id"],
        "intensity": selection["intensity"],
        "PAIR_GROUP_MODES": len(modes),
        "PLAN_SHA_UNIQUE_COUNT": len(plan_hashes),
        "DOMAIN_EVENT_SEQUENCE_UNIQUE_COUNT": len(domain_sequences),
        "TIMING_DWELL_UNIQUE_COUNT": len(timing_and_dwell),
        "plan_sha256": next(iter(plan_hashes)) if len(plan_hashes) == 1 else sorted(plan_hashes),
        "modes": sorted(modes),
        "issues": issues,
    }
    base.write_json(pair_root / "pairing_audit.json", report)
    base.require(not issues, f"pairing audit failed: {selection['pair_group_id']}")
    return report


def aggregate_failures(attempts: list[dict[str, object]]) -> dict[str, int]:
    browser_classes = retry.RETRYABLE | {
        "HTTP_STATUS_403", "HTTP_STATUS_429", "EVALUATE_TIMEOUT", "ACTION_TIMEOUT",
        "RENDERER_HANG", "SUPERVISOR_TIMEOUT", "UNBOUNDED_LIFECYCLE", "WORKLOAD_HARD_FAILURE",
    }
    return {
        "mode_purity_failures": sum(item["mode_purity"] == "FAIL" for item in attempts),
        "browser_failures": sum(str(item["failure_class"]) in browser_classes for item in attempts),
        "capture_failures": sum(item["capture"]["status"] != "PASS" for item in attempts),
        "health_failures": sum(item["pre_health"] != "PASS" or item["post_health"] != "PASS" for item in attempts),
        "conn_max_hits": sum(max(0, int(item["redsocks_conn_max_hits"])) for item in attempts),
        "bypass_failures": sum(item["failure_class"] == "PROXY_BYPASS" for item in attempts),
        "oom_failures": sum(item["failure_class"] == "OOM" for item in attempts),
        "unexpected_service_exit_failures": sum(item["failure_class"] == "UNEXPECTED_PROCESS_EXIT" for item in attempts),
    }


def remote_sample_audit(run_root: Path, remote_root: str, sample_roots: list[Path]) -> dict[str, object]:
    passed = 0
    for sample_root in sample_roots:
        relative = sample_root.relative_to(run_root).as_posix()
        command = f"cd {remote_root}/{relative} && sha256sum -c SAMPLE_ARTIFACT_SHA256SUMS.txt"
        completed = base.run(["ssh", "-o", "BatchMode=yes", base.UPLOAD_HOST, command], 1800)
        base.require(completed.returncode == 0, f"remote sample SHA failed: {relative}: {completed.stderr[-1000:]}")
        passed += 1
    markers = base.run([
        "ssh", "-o", "BatchMode=yes", base.UPLOAD_HOST,
        f"find {remote_root}/samples -type f -name NON_FORMAL_SMOKE_SAMPLE_PASS | wc -l",
    ], 60, True).stdout.strip()
    base.require(int(markers) == 24, f"remote complete sample marker count={markers}")
    return {"remote_sample_sha_pass": passed, "remote_complete_mode_artifacts": int(markers)}


def write_fail(run_root: Path, error: str, attempts: list[dict[str, object]], completed: list[dict[str, object]]) -> None:
    stats = aggregate_failures(attempts)
    result = {
        "marker": FAIL_MARKER,
        "classification": CLASSIFICATION,
        "future_formal_manifest_eligible": False,
        "error": error,
        "samples_started": len(completed),
        "total_attempts": len(attempts),
        "total_retries": max(0, len(attempts) - len(completed)),
        **stats,
        "failed_utc": base.utc_now(),
    }
    base.write_json(run_root / "smoke_result.json", result)
    (run_root / FAIL_MARKER).write_text(f"{FAIL_MARKER}\n{CLASSIFICATION}\n", encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--local-parent", type=Path,
        default=Path("/home/etip/datasets/staging/realistic_v1/non_formal_smoke_v3"),
    )
    parser.add_argument(
        "--remote-parent",
        default="/home/dataset-assist-0/duwenbiao/Tunnel/proxydata/realistic_v1/non_formal_smoke_v3",
    )
    args = parser.parse_args()
    base.verify_frozen_inputs()
    verify_retry_policy()
    selections = select_pair_groups()
    run_id = "realistic_v3_24_sample_smoke_" + base.stamp_now()
    args.local_parent.mkdir(parents=True, exist_ok=True)
    run_root = args.local_parent / run_id
    run_root.mkdir()
    remote_root = f"{args.remote_parent}/{run_id}"
    remote_exec_base = f"/home/etip/.cache/proxytraffic-realistic-v3-24-sample-smoke/{run_id}"
    git_head = base.run(["git", "rev-parse", "HEAD"], 30, True).stdout.strip()
    (run_root / CLASSIFICATION).write_text(
        f"{CLASSIFICATION}\nFUTURE_FORMAL_MANIFEST_ELIGIBLE=NO\n", encoding="utf-8"
    )
    base.write_json(run_root / "selection.json", {
        "classification": CLASSIFICATION,
        "selection_rule": selections[0]["selection_rule"],
        "pair_group_count": 6,
        "sample_count": 24,
        "pair_groups": selections,
    })
    base.write_json(run_root / "frozen_inputs.json", {str(path): digest for path, digest in base.FROZEN_SHA256.items()})
    shutil.copy2(retry.POLICY, run_root / retry.POLICY.name)
    shutil.copy2(retry.POLICY_FREEZE, run_root / retry.POLICY_FREEZE.name)
    base.write_json(run_root / "runner_provenance.json", {
        "classification": CLASSIFICATION,
        "future_formal_manifest_eligible": False,
        "runner_sha256": base.sha256(Path(__file__)),
        "retry_runner_sha256": base.sha256(RETRY_RUNNER),
        "executor_sha256": base.sha256(base.EXECUTOR),
        "supervisor_sha256": base.sha256(base.SUPERVISOR),
        "auditor_sha256": base.sha256(base.AUDITOR),
        "retry_policy_sha256": retry.POLICY_SHA256,
        "git_head": git_head,
        "started_utc": base.utc_now(),
        "local_root": str(run_root),
        "remote_root": remote_root,
    })
    all_attempts: list[dict[str, object]] = []
    completed_samples: list[dict[str, object]] = []
    sample_roots: list[Path] = []
    pairing_audits: list[dict[str, object]] = []
    retry_classes: Counter[str] = Counter()
    success = False
    try:
        remote_preflight = base.run([
            "ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=10",
            base.UPLOAD_HOST, "echo", "PROXYDATA_SERVER_PASS",
        ], 20)
        base.require(
            remote_preflight.returncode == 0 and remote_preflight.stdout.strip() == "PROXYDATA_SERVER_PASS",
            f"remote archive preflight failed: {remote_preflight.stderr[-1000:]}",
        )
        base.require(not any(base.health_probe_processes().values()), "preexisting active health probe process")
        base.require(
            not base.run(["sudo", "-n", "pgrep", "-f", "^tcpdump .*realistic.*\\.pcap"], 10).stdout.strip(),
            "preexisting local Realistic tcpdump",
        )
        base.require(
            not base.run([
                "ssh", "-o", "BatchMode=yes", base.SERVER_HOST, "sudo", "-n", "pgrep", "-f",
                "^tcpdump .*proxytraffic-realistic.*\\.pcap",
            ], 15).stdout.strip(),
            "preexisting remote Realistic tcpdump",
        )
        browser_pre = int(base.run([
            "ssh", "-o", "BatchMode=yes", base.USER_HOST, "bash", "-lc",
            "pgrep -c chrome-headless 2>/dev/null || true",
        ], 15).stdout.strip() or "0")
        base.require(browser_pre == 0, f"preexisting browser process count={browser_pre}")

        for selection in selections:
            pair_group = str(selection["pair_group_id"])
            pair_root = run_root / "samples" / pair_group
            pair_root.mkdir(parents=True)
            (pair_root / CLASSIFICATION).write_text(f"{CLASSIFICATION}\n", encoding="utf-8")
            base.write_json(pair_root / "selection.json", selection)
            remote_exec_root = f"{remote_exec_base}/{pair_group}"
            prepare_remote_inputs(selection, remote_exec_root)
            pair_summaries: list[dict[str, object]] = []
            for mode in selection["mode_order"]:
                mode_root = pair_root / str(mode)
                mode_root.mkdir()
                (mode_root / CLASSIFICATION).write_text(
                    f"{CLASSIFICATION}\nFUTURE_FORMAL_MANIFEST_ELIGIBLE=NO\n", encoding="utf-8"
                )
                attempts: list[dict[str, object]] = []
                try:
                    first = retry.run_attempt(
                        str(mode), 1, selection, mode_root, remote_exec_root, classification=CLASSIFICATION
                    )
                except BaseException as exc:
                    first = synthetic_attempt_failure(exc, str(mode), 1, selection, mode_root)
                attempts.append(first)
                all_attempts.append(first)
                allowed, reason = retry.retry_authorized(first)
                if first["status"] == "PASS":
                    final_status = "SAMPLE_PASS_ATTEMPT1"
                elif allowed:
                    retry_classes[str(first["failure_class"])] += 1
                    try:
                        second = retry.run_attempt(
                            str(mode), 2, selection, mode_root, remote_exec_root, classification=CLASSIFICATION
                        )
                    except BaseException as exc:
                        second = synthetic_attempt_failure(exc, str(mode), 2, selection, mode_root)
                    attempts.append(second)
                    all_attempts.append(second)
                    final_status = "SAMPLE_PASS_ATTEMPT2" if second["status"] == "PASS" else "SAMPLE_FAIL_ATTEMPT2"
                else:
                    final_status = "SAMPLE_FAIL_NON_RETRYABLE_ATTEMPT1"
                final_result = attempts[-1]
                ledger_rows = []
                for item in attempts:
                    item_allowed, item_reason = retry.retry_authorized(item)
                    if int(item["attempt"]) == 2:
                        item_allowed, item_reason = False, "MAX_ATTEMPTS_REACHED"
                    ledger_rows.append(retry.ledger_row(
                        run_id, git_head, selection, item, item_allowed, item_reason, final_status
                    ))
                retry.append_ledger(ledger_rows)
                mode_result = {
                    "classification": CLASSIFICATION,
                    "future_formal_manifest_eligible": False,
                    "pair_group_id": pair_group,
                    "intensity": selection["intensity"],
                    "mode": mode,
                    "max_attempts": retry.MAX_ATTEMPTS_PER_SAMPLE,
                    "attempt_count": len(attempts),
                    "retry_count": len(attempts) - 1,
                    "final_status": final_result["status"],
                    "final_attempt": final_result["attempt"],
                    "attempts": attempts,
                }
                base.write_json(mode_root / "mode_attempts_result.json", mode_result)
                if final_result["status"] == "PASS":
                    (mode_root / "NON_FORMAL_SMOKE_SAMPLE_PASS").write_text(
                        "NON_FORMAL_SMOKE_SAMPLE_PASS\nFUTURE_FORMAL_MANIFEST_ELIGIBLE=NO\n", encoding="utf-8"
                    )
                else:
                    (mode_root / "NON_FORMAL_SMOKE_SAMPLE_FAIL").write_text(
                        "NON_FORMAL_SMOKE_SAMPLE_FAIL\n", encoding="utf-8"
                    )
                create_sample_manifest(mode_root)
                summary = {
                    "pair_group_id": pair_group,
                    "intensity": selection["intensity"],
                    "mode": mode,
                    "status": final_result["status"],
                    "attempt_count": len(attempts),
                    "retry_count": len(attempts) - 1,
                    "final_attempt": final_result["attempt"],
                    "final_result": final_result,
                    "local_sha": "PASS",
                }
                completed_samples.append(summary)
                pair_summaries.append(summary)
                sample_roots.append(mode_root)
                print(
                    f"SAMPLE_FINAL pair_group={pair_group} intensity={selection['intensity']} mode={mode} "
                    f"status={final_result['status']} attempts={len(attempts)} "
                    f"failure_class={final_result['failure_class'] or 'NONE'}",
                    flush=True,
                )
                if final_result["status"] != "PASS":
                    shutil.copy2(retry.LEDGER, run_root / retry.LEDGER.name)
                    write_fail(
                        run_root,
                        f"sample failed: {pair_group}/{mode}; final_status={final_status}",
                        all_attempts,
                        completed_samples,
                    )
                    print(FAIL_MARKER, flush=True)
                    return 1
            pairing_audits.append(audit_pairing(selection, pair_summaries, pair_root))
            print(f"PAIR_GROUP_FINAL pair_group={pair_group} status=PASS modes=4", flush=True)

        base.require(len(completed_samples) == 24, "sample count mismatch")
        base.require(len(pairing_audits) == 6, "pair group count mismatch")
        mode_counts = Counter(str(item["mode"]) for item in completed_samples)
        intensity_pair_counts = Counter(str(item["intensity"]) for item in selections)
        intensity_sample_counts = Counter(str(item["intensity"]) for item in completed_samples)
        base.require(mode_counts == Counter({mode: 6 for mode in base.MODES}), "mode counts mismatch")
        base.require(intensity_pair_counts == Counter({"light": 2, "medium": 2, "heavy": 2}), "intensity pair counts mismatch")
        base.require(all(item["status"] == "PASS" for item in completed_samples), "not all samples passed")
        base.require(all(item["status"] == "PASS" for item in pairing_audits), "not all pairing audits passed")
        base.require(all(int(item["final_result"]["residual"]) == 0 for item in completed_samples), "nonzero residual")
        base.require(all(
            item["mode"] == "direct" or item["final_result"].get("redsocks_actual_conn_max") == 256
            for item in completed_samples
        ), "proxy sample actual conn_max mismatch")
        shutil.copy2(retry.LEDGER, run_root / retry.LEDGER.name)
        total_attempts = len(all_attempts)
        total_retries = total_attempts - 24
        completed_attempt1 = sum(int(item["final_attempt"]) == 1 for item in completed_samples)
        completed_attempt2 = sum(int(item["final_attempt"]) == 2 for item in completed_samples)
        failures = aggregate_failures(all_attempts)
        integrity = {
            "classification": CLASSIFICATION,
            "status": "PASS",
            "PAIR_GROUPS": 6,
            "SAMPLES": 24,
            "mode_counts": dict(mode_counts),
            "proxy_actual_conn_max": {
                f"{item['pair_group_id']}/{item['mode']}": item["final_result"].get("redsocks_actual_conn_max")
                for item in completed_samples if item["mode"] != "direct"
            },
            "intensity_pair_group_counts": dict(intensity_pair_counts),
            "intensity_sample_counts": dict(intensity_sample_counts),
            "pairing_audits": pairing_audits,
        }
        base.write_json(run_root / "smoke_integrity.json", integrity)
        summary = {
            "marker": PASS_MARKER,
            "classification": CLASSIFICATION,
            "future_formal_manifest_eligible": False,
            "pair_groups": 6,
            "samples": 24,
            "intensity_pair_group_counts": dict(intensity_pair_counts),
            "intensity_sample_counts": dict(intensity_sample_counts),
            "mode_counts": dict(mode_counts),
            "total_attempts": total_attempts,
            "total_retries": total_retries,
            "retry_rate": total_retries / 24,
            "retry_failure_classes": dict(retry_classes),
            "samples_completed_on_attempt1": completed_attempt1,
            "samples_completed_on_attempt2": completed_attempt2,
            **failures,
            "local_sample_sha": "24/24 PASS",
            "local_sha": "PENDING",
            "remote_upload": "PENDING",
            "remote_sample_sha": "PENDING",
            "remote_independent_sha": "PENDING",
            "residual": sum(int(item["residual"]) for item in all_attempts),
        }
        base.write_json(run_root / "smoke_result.json", summary)
        base.create_checksums(run_root, "ARTIFACT_SHA256SUMS.txt", {
            "ARTIFACT_SHA256SUMS.txt", "FINAL_METADATA_SHA256SUMS.txt", "remote_sha_verification.json",
            "smoke_result.json", PASS_MARKER,
        })
        base.verify_checksums(run_root, "ARTIFACT_SHA256SUMS.txt")
        remote_stdout = base.upload_and_verify(run_root, remote_root, "ARTIFACT_SHA256SUMS.txt")
        remote_samples = remote_sample_audit(run_root, remote_root, sample_roots)
        summary.update({
            "local_sha": "PASS",
            "remote_upload": "24/24 PASS",
            "remote_sample_sha": "24/24 PASS",
            "remote_independent_sha": "PASS",
        })
        expected_final_file_count = sum(path.is_file() for path in run_root.rglob("*")) + 3
        summary["local_expected_file_count"] = expected_final_file_count
        base.write_json(run_root / "smoke_result.json", summary)
        base.write_json(run_root / "remote_sha_verification.json", {
            "classification": CLASSIFICATION,
            "remote_host": base.UPLOAD_HOST,
            "remote_root": remote_root,
            "remote_upload": "24/24 PASS",
            "remote_root_artifact_sha": "PASS",
            **remote_samples,
            "root_manifest_verified_file_count": len(remote_stdout.splitlines()),
            "verified_utc": base.utc_now(),
        })
        (run_root / PASS_MARKER).write_text(f"{PASS_MARKER}\n{CLASSIFICATION}\n", encoding="utf-8")
        base.create_checksums(run_root, "FINAL_METADATA_SHA256SUMS.txt", {"FINAL_METADATA_SHA256SUMS.txt"})
        base.verify_checksums(run_root, "FINAL_METADATA_SHA256SUMS.txt")
        base.final_remote_verify(run_root, remote_root, "FINAL_METADATA_SHA256SUMS.txt")
        local_count = sum(path.is_file() for path in run_root.rglob("*"))
        remote_count = int(base.run([
            "ssh", "-o", "BatchMode=yes", base.UPLOAD_HOST,
            f"find {remote_root} -type f | wc -l",
        ], 60, True).stdout.strip())
        base.require(local_count == expected_final_file_count, "local final file count changed")
        base.require(remote_count == local_count, f"remote/local file count mismatch: {remote_count}!={local_count}")
        success = True
        print(json.dumps(summary, indent=2, sort_keys=True), flush=True)
        print(f"LOCAL_ROOT={run_root}", flush=True)
        print(f"REMOTE_ROOT={remote_root}", flush=True)
        print(f"LOCAL_FILE_COUNT={local_count}", flush=True)
        print(f"REMOTE_FILE_COUNT={remote_count}", flush=True)
        print(PASS_MARKER, flush=True)
        return 0
    except BaseException as exc:
        if not (run_root / FAIL_MARKER).exists():
            try:
                shutil.copy2(retry.LEDGER, run_root / retry.LEDGER.name)
                write_fail(run_root, f"{type(exc).__name__}: {exc}", all_attempts, completed_samples)
            except Exception:
                pass
        print(f"{FAIL_MARKER} root={run_root} error={type(exc).__name__}: {exc}", flush=True)
        return 1
    finally:
        base.cleanup_mode()
        if not success:
            print(f"{CLASSIFICATION} evidence preserved; no further pair group started", flush=True)


if __name__ == "__main__":
    raise SystemExit(main())
