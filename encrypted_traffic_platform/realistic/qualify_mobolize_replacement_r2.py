#!/usr/bin/env python3
"""Qualify the deterministic R2 replacement for persistently failing mobolize.com."""
from __future__ import annotations

import argparse
import csv
import importlib.util
import json
import re
import time
from pathlib import Path


REPO = Path("/home/etip/Tunnel/proxytraffic")
DOC = REPO / "docs/realistic_v1/formal_t0_v3"
BASE_QUALIFIER = REPO / "encrypted_traffic_platform/realistic/qualify_ivi_replacement_r1.py"
RETRY_RUNNER = REPO / "encrypted_traffic_platform/realistic/run_single_quartet_v3_validation_retry.py"
SOURCE = Path("/home/etip/datasets/plans/realistic_v1/t0_source/tranco_46W9X_top1m.csv")
SYNTAX = REPO / "docs/realistic_v1/tranco_46W9X_eligibility_audit.tsv"
POOL = DOC / "formal_domain_pool_v3_r1.tsv"
OLD_LEDGER = DOC / "domain_replacement_ledger_v3_r1.tsv"
CURRENT_AUDIT = DOC / "actionability_audit_current500_capacity256_20260903.tsv"
AMENDMENT = DOC / "mobolize_cross_mode_replacement_amendment_v1.txt"
DIAGNOSTIC = Path(
    "/home/etip/datasets/staging/realistic_v1/non_formal_diagnostics/"
    "mobolize_cross_mode_diagnostic_20260904T175157Z/mobolize_cross_mode_diagnostic_result.json"
)
OUTPUT_PARENT = Path("/home/etip/datasets/staging/realistic_v1/non_formal_replacement_r2")
SOURCE_SHA = "264830dfe5bbf84daeb23d482123d0a7eab1f6ee6830f08984c563be18d998aa"
SYNTAX_SHA = "be130d80c6e351ba64f6de54c6e3f4feb92e628c9903957c29cfa0e93c0944d6"
POOL_SHA = "c3439f6db36f9ee94470c35a1b82e288da65c2f0cb7b2d347de334d73bb3b171"
OLD_LEDGER_SHA = "e068f038b39e95bab64e9f698996f6d1b83ba4e463df8a25660dfd781a422a0b"
CURRENT_AUDIT_SHA = "5f2102f4c195078114719e872945eaa126cbb41f9df9fa4945b7b99fe4daf307"
ACTION_SCRIPT_SHA = "3dd7f6d9d5de55f61b1a94e6c3367961620a3ead47eaf787ddbaf77dd06feab8"
NAV_SCRIPT_SHA = "fc1c79bcad8a666f0296e7b3e423e53e342d49dc9dd09a43e43305e23a237b16"
OLD_RANK = 689
OLD_DOMAIN = "mobolize.com"
OLD_BUCKET = "top_1_1000"
OLD_REASON = "PERSISTENT_DOMAIN_HTTP_5XX_FAILURE"


def load(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


base = load(BASE_QUALIFIER, "mobolize_r2_base_qualifier")
retry = load(RETRY_RUNNER, "mobolize_r2_retry")
diag = base.diag
qv3 = base.qv3
ACTIVE_MODE_START: dict[str, str] = {}
ORIGINAL_COMMON_TRIAL_EVIDENCE = base.common_trial_evidence
ORIGINAL_INFRASTRUCTURE_PASS = base.infrastructure_pass


def corrected_process_snapshot() -> dict[str, object]:
    command = (
        "ps -eo pid=,ppid=,pgid=,sid=,etimes=,args= | "
        "awk '/[c]hrome-headless|[a]udit_actionability_trial_v3.py|[n]avigation_only_trial_v3.py|[r]ealistic-executor-supervisor/ {print}'"
    )
    result = diag.run(["ssh", "-o", "BatchMode=yes", diag.USER_HOST, command], 20)
    rows = [line.strip() for line in result.stdout.splitlines() if line.strip()]
    return {"count": len(rows), "rows": rows, "ssh_exit_code": result.returncode}


diag.process_snapshot = corrected_process_snapshot


def read_tsv(path: Path) -> list[dict[str, str]]:
    with path.open(newline="", encoding="utf-8") as handle:
        return list(csv.DictReader(handle, delimiter="\t"))


def verify_inputs() -> None:
    expected = {
        SOURCE: SOURCE_SHA,
        SYNTAX: SYNTAX_SHA,
        POOL: POOL_SHA,
        OLD_LEDGER: OLD_LEDGER_SHA,
        CURRENT_AUDIT: CURRENT_AUDIT_SHA,
        base.ACTION_SCRIPT: ACTION_SCRIPT_SHA,
        base.NAV_SCRIPT: NAV_SCRIPT_SHA,
    }
    for path, digest in expected.items():
        if not path.is_file() or base.sha(path) != digest:
            raise RuntimeError(f"frozen input mismatch: {path}")
    if not AMENDMENT.is_file():
        raise RuntimeError("R2 replacement amendment missing")
    diagnostic = json.loads(DIAGNOSTIC.read_text(encoding="utf-8"))
    if not (
        diagnostic["result"] == "MOBOLIZE_ACTIONABILITY_INSTABILITY_CONFIRMED"
        and diagnostic["http_5xx_count"] == 12
        and diagnostic["infrastructure_failure_count"] == 0
    ):
        raise RuntimeError("Mobolize diagnostic provenance mismatch")
    old = [row for row in read_tsv(POOL) if row["domain"] == OLD_DOMAIN]
    if len(old) != 1 or int(old[0]["rank"]) != OLD_RANK or old[0]["rank_bucket"] != OLD_BUCKET:
        raise RuntimeError("Mobolize R1 pool provenance mismatch")


def eligible_candidates() -> list[dict[str, object]]:
    current_domains = {row["domain"] for row in read_tsv(POOL)}
    previously_tested = {
        row["candidate_domain"] for row in read_tsv(OLD_LEDGER) if row.get("candidate_domain")
    }
    known_unstable = {
        row["domain"] for row in read_tsv(CURRENT_AUDIT)
        if row["final_actionability_status"] != "ACTIONABILITY_STABLE"
    }
    for path in (
        DOC / "formal_domain_replay_stability_base500.tsv",
        DOC / "formal_domain_replacement_audit_rejected_pre_reserve.tsv",
        DOC / "formal_domain_replacement_audit_batch2.tsv",
    ):
        for row in read_tsv(path):
            if row.get("replay_stable", "").strip().lower() != "true":
                known_unstable.add(row["domain"])
    result = []
    count = 0
    with SOURCE.open(newline="", encoding="utf-8") as source_handle, SYNTAX.open(newline="", encoding="utf-8") as syntax_handle:
        source_reader = csv.reader(source_handle)
        syntax_reader = csv.DictReader(syntax_handle, delimiter="\t")
        for source_row, syntax_row in zip(source_reader, syntax_reader):
            count += 1
            rank, domain = int(source_row[0]), source_row[1]
            if rank != int(syntax_row["rank"]) or domain != syntax_row["domain"]:
                raise RuntimeError(f"source/syntax alignment failure rank={rank}")
            if not OLD_RANK < rank <= 1000:
                continue
            if syntax_row["eligible"].strip().lower() != "true":
                continue
            if domain in current_domains or domain in previously_tested or domain in known_unstable:
                continue
            result.append({"rank": rank, "domain": domain, "bucket": OLD_BUCKET})
        if count != 1_000_000 or next(source_reader, None) is not None or next(syntax_reader, None) is not None:
            raise RuntimeError("source/syntax length mismatch")
    result.sort(key=lambda item: (int(item["rank"]), str(item["domain"])))
    if not result or result[0] != {"rank": 913, "domain": "miwifi.com", "bucket": OLD_BUCKET}:
        raise RuntimeError(f"rank-ascending candidate head changed: {result[:1]}")
    return result


def capacity_snapshot(mode: str) -> dict[str, object]:
    if mode == "direct":
        return {"status": "PASS", "actual_conn_max": "NOT_APPLICABLE"}
    unit = diag.REDSOCKS_UNIT[mode]
    pid = int(diag.run(["systemctl", "show", unit, "-p", "MainPID", "--value"], 10, True).stdout.strip())
    limits = Path(f"/proc/{pid}/limits").read_text(encoding="utf-8")
    line = next(item for item in limits.splitlines() if item.startswith("Max open files"))
    match = re.fullmatch(r"Max open files\s+(\d+)\s+(\d+)\s+files\s*", line)
    if match is None:
        raise RuntimeError(f"cannot parse NOFILE mode={mode}: {line}")
    soft, hard = int(match.group(1)), int(match.group(2))
    started = ACTIVE_MODE_START[mode].replace("T", " ").split(".", 1)[0]
    journal = diag.run(
        ["sudo", "-n", "journalctl", "-u", unit, "--since", started, "--no-pager", "-o", "json"],
        30,
        True,
    )
    records = []
    for raw in journal.stdout.splitlines():
        row = json.loads(raw)
        if int(row.get("_PID", 0)) == pid and "redsocks started, conn_max=" in str(row.get("MESSAGE", "")):
            records.append(row)
    if len(records) != 1:
        raise RuntimeError(f"startup journal count mode={mode} pid={pid}: {len(records)}")
    conn_max = int(re.search(r"conn_max=(\d+)", str(records[0]["MESSAGE"])).group(1))
    status = "PASS" if soft == 2048 and hard == 524288 and conn_max == 256 else "FAIL"
    return {
        "status": status,
        "systemd_unit": unit,
        "pid": pid,
        "soft_nofile": soft,
        "hard_nofile": hard,
        "startup_message": records[0]["MESSAGE"],
        "actual_conn_max": conn_max,
    }


def activate_mode(mode: str) -> None:
    qv3.cleanup_mode()
    ACTIVE_MODE_START[mode] = diag.utc_now()
    diag.run([str(diag.MODE_TOOL), mode], 30, True)
    if mode == "trojan":
        qv3.canary_rule(True)
    time.sleep(1)
    if diag.mode_purity(mode)["status"] != "PASS":
        raise RuntimeError(f"mode activation purity failed: {mode}")
    capacity = capacity_snapshot(mode)
    if capacity["status"] != "PASS":
        raise RuntimeError(f"REDSOCKS_CAPACITY_PRECHECK_FAIL mode={mode}: {capacity}")


def common_trial_evidence(mode, started, pre_health, post_health, purity_pre, purity_post, process_after, supervisor):
    record = ORIGINAL_COMMON_TRIAL_EVIDENCE(
        mode, started, pre_health, post_health, purity_pre, purity_post, process_after, supervisor
    )
    capacity = capacity_snapshot(mode)
    oom = qv3.oom_evidence(started)
    record.update({
        "capacity_precheck": capacity,
        "redsocks_actual_conn_max": capacity["actual_conn_max"],
        "soft_nofile": capacity.get("soft_nofile", "NOT_APPLICABLE"),
        "hard_nofile": capacity.get("hard_nofile", "NOT_APPLICABLE"),
        "oom": len(oom),
        "residual": max(0, int(record["browser_residual"])) + max(0, int(record["executor_residual"])),
    })
    return record


def infrastructure_pass(evidence: dict[str, object]) -> bool:
    return (
        ORIGINAL_INFRASTRUCTURE_PASS(evidence)
        and evidence["capacity_precheck"]["status"] == "PASS"
        and (evidence["redsocks_actual_conn_max"] == "NOT_APPLICABLE" or int(evidence["redsocks_actual_conn_max"]) == 256)
        and int(evidence["oom"]) == 0
        and int(evidence["residual"]) == 0
    )


base.activate_mode = activate_mode
base.common_trial_evidence = common_trial_evidence
base.infrastructure_pass = infrastructure_pass


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.parse_args()
    verify_inputs()
    candidates = eligible_candidates()
    stamp = qv3.stamp_now()
    OUTPUT_PARENT.mkdir(parents=True, exist_ok=True)
    root = OUTPUT_PARENT / f"mobolize_replacement_r2_{stamp}"
    root.mkdir()
    (root / "NON_FORMAL_REPLACEMENT_QUALIFICATION").write_text(
        "NON_FORMAL_REPLACEMENT_QUALIFICATION\nFORMAL_SAMPLE=NO\n", encoding="utf-8"
    )
    remote_root = f"/tmp/mobolize-replacement-r2-{stamp}"
    input_root = f"{remote_root}/input"
    diag.run(["ssh", "-o", "BatchMode=yes", diag.USER_HOST, "mkdir", "-p", input_root], 30, True)
    diag.run(["scp", "-q", str(base.ACTION_SCRIPT), str(base.NAV_SCRIPT), f"{diag.USER_HOST}:{input_root}/"], 120, True)
    with (root / "candidate_order.tsv").open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=["rank", "domain", "bucket"], delimiter="\t", lineterminator="\n")
        writer.writeheader()
        writer.writerows(candidates)
    base.write_json(root / "provenance.json", {
        "classification": "NON_FORMAL_REPLACEMENT_QUALIFICATION",
        "old_domain": OLD_DOMAIN,
        "old_rank": OLD_RANK,
        "old_bucket": OLD_BUCKET,
        "old_reason": OLD_REASON,
        "selection_rule": "same bucket; rank strictly greater than 689; exclude R1 Final500, prior-tested and known replay/actionability-unstable domains; rank ascending",
        "source_sha256": SOURCE_SHA,
        "syntax_sha256": SYNTAX_SHA,
        "historical_pool_sha256": POOL_SHA,
        "historical_ledger_sha256": OLD_LEDGER_SHA,
        "amendment_sha256": base.sha(AMENDMENT),
        "actionability_script_sha256": ACTION_SCRIPT_SHA,
        "navigation_only_script_sha256": NAV_SCRIPT_SHA,
        "remote_root": remote_root,
        "started_utc": diag.utc_now(),
    })
    records = []
    selected = None
    success = False
    try:
        if diag.process_snapshot()["count"]:
            raise RuntimeError("preexisting browser/executor process")
        for order, candidate in enumerate(candidates, 1):
            actionability = base.actionability_candidate(candidate, root, remote_root)
            sanity = {"status": "NOT_RUN", "pass_count": 0, "trial_count": 0, "mode_counts": {}, "trials": []}
            if actionability["status"] == "PASS":
                sanity = base.cross_mode_sanity(candidate, root, remote_root)
            qualified = actionability["status"] == "PASS" and sanity["status"] == "8/8 PASS"
            record = {
                "candidate_attempt_order": order,
                **candidate,
                "syntax_gate": "PASS",
                "replay_stability_gate": actionability["replay_stability"],
                "actionability_gate": actionability["actionability"],
                "cross_mode_sanity": sanity["status"],
                "qualification_status": "QUALIFIED" if qualified else "REPLACEMENT_CANDIDATE_REJECTED",
                "final_selected": qualified,
                "actionability": actionability,
                "cross_mode": sanity,
                "completed_utc": diag.utc_now(),
            }
            records.append(record)
            with (root / "candidate_qualification_ledger.jsonl").open("a", encoding="utf-8") as handle:
                handle.write(json.dumps(record, sort_keys=True) + "\n")
            candidate_root = root / "candidates" / f"{int(candidate['rank']):07d}_{candidate['domain']}"
            base.write_json(candidate_root / "candidate_result.json", record)
            print(
                f"CANDIDATE_FINAL order={order} rank={candidate['rank']} domain={candidate['domain']} "
                f"actionability={actionability['status']} cross_mode={sanity['status']} "
                f"status={record['qualification_status']}",
                flush=True,
            )
            if qualified:
                selected = record
                break
        if selected is None:
            raise RuntimeError("eligible same-bucket candidate queue exhausted")
        result = {
            "status": "PASS",
            "classification": "NON_FORMAL_REPLACEMENT_QUALIFICATION",
            "old_domain": OLD_DOMAIN,
            "old_rank": OLD_RANK,
            "old_bucket": OLD_BUCKET,
            "old_reason": OLD_REASON,
            "candidate_count_tested": len(records),
            "candidate_count_rejected": len(records) - 1,
            "selected": selected,
            "candidate_order_prefix": candidates[:len(records)],
            "ended_utc": diag.utc_now(),
        }
        base.write_json(root / "qualification_result.json", result)
        (root / "REPLACEMENT_QUALIFICATION_PASS").write_text(
            "REPLACEMENT_QUALIFICATION_PASS\nNON_FORMAL_REPLACEMENT_QUALIFICATION\n", encoding="utf-8"
        )
        success = True
        print(json.dumps({
            "selected_rank": selected["rank"],
            "selected_domain": selected["domain"],
            "candidates_tested": len(records),
            "actionability": selected["actionability_gate"],
            "cross_mode_sanity": selected["cross_mode_sanity"],
        }, sort_keys=True), flush=True)
        print(f"OUTPUT_ROOT={root}", flush=True)
        return 0
    except BaseException as exc:
        base.write_json(root / "QUALIFICATION_FAIL.json", {
            "status": "FAIL",
            "error": f"{type(exc).__name__}: {exc}",
            "candidate_count_tested": len(records),
            "failed_utc": diag.utc_now(),
        })
        print(f"REPLACEMENT_QUALIFICATION_FAIL root={root} error={type(exc).__name__}: {exc}", flush=True)
        return 1
    finally:
        qv3.cleanup_mode()
        if not success:
            print("replacement qualification evidence preserved", flush=True)


if __name__ == "__main__":
    raise SystemExit(main())
