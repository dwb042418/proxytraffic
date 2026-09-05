#!/usr/bin/env python3
"""Qualify the rank-ascending R1 replacement for unstable ivi.ru."""

from __future__ import annotations

import argparse
import csv
import hashlib
import importlib.util
import json
import shutil
import time
from pathlib import Path


REPO = Path("/home/etip/Tunnel/proxytraffic")
DOC = REPO / "docs/realistic_v1/formal_t0_v3"
SOURCE = Path("/home/etip/datasets/plans/realistic_v1/t0_source/tranco_46W9X_top1m.csv")
SYNTAX = REPO / "docs/realistic_v1/tranco_46W9X_eligibility_audit.tsv"
POOL = DOC / "formal_domain_pool_v3.tsv"
OLD_LEDGER = DOC / "domain_replacement_ledger_v3.tsv"
CURRENT_AUDIT = DOC / "actionability_audit_current500_capacity256_20260903.tsv"
AMENDMENT = DOC / "ivi_ru_cross_mode_replacement_amendment_v1.txt"
ACTION_SCRIPT = REPO / "encrypted_traffic_platform/realistic/audit_actionability_trial_v3.py"
NAV_SCRIPT = REPO / "encrypted_traffic_platform/realistic/navigation_only_trial_v3.py"
SUPERVISOR = "/home/etip/bin/realistic-executor-supervisor"
DIAGNOSTIC_HELPER = Path("/home/etip/.cache/cross_mode_domain_diagnostic_runner.py")
OUTPUT_PARENT = Path("/home/etip/datasets/staging/realistic_v1/non_formal_replacement_r1")
SOURCE_SHA = "264830dfe5bbf84daeb23d482123d0a7eab1f6ee6830f08984c563be18d998aa"
SYNTAX_SHA = "be130d80c6e351ba64f6de54c6e3f4feb92e628c9903957c29cfa0e93c0944d6"
POOL_SHA = "ded7fd1277a32295fb1e5fef3b6df0967f10a578cb2d204b04409b55b6878071"
OLD_LEDGER_SHA = "59dd595f8c409756a2cfb6445c004291e75f11c2e3d8d6bef6c84cce6dadbf85"
CURRENT_AUDIT_SHA = "5f2102f4c195078114719e872945eaa126cbb41f9df9fa4945b7b99fe4daf307"
ACTION_SCRIPT_SHA = "3dd7f6d9d5de55f61b1a94e6c3367961620a3ead47eaf787ddbaf77dd06feab8"
NAV_SCRIPT_SHA = "fc1c79bcad8a666f0296e7b3e423e53e342d49dc9dd09a43e43305e23a237b16"
MODES = ("direct", "vless", "shadowsocks", "trojan")
DELAYS = (10.251, 11.255, 13.266)


def load_helper():
    spec = importlib.util.spec_from_file_location("ivi_diag_helper", DIAGNOSTIC_HELPER)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


diag = load_helper()
qv3 = diag.qv3


def sha(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def write_json(path: Path, value: object) -> None:
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


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
        ACTION_SCRIPT: ACTION_SCRIPT_SHA,
        NAV_SCRIPT: NAV_SCRIPT_SHA,
    }
    for path, wanted in expected.items():
        if not path.is_file() or sha(path) != wanted:
            raise RuntimeError(f"frozen input mismatch: {path}")
    if not AMENDMENT.is_file():
        raise RuntimeError("replacement amendment missing")
    pool_rows = read_tsv(POOL)
    old = [row for row in pool_rows if row["domain"] == "ivi.ru"]
    if len(old) != 1 or old[0]["rank"] != "479" or old[0]["rank_bucket"] != "top_1_1000":
        raise RuntimeError("ivi.ru pool provenance mismatch")


def eligible_candidates() -> list[dict[str, object]]:
    current_domains = {row["domain"] for row in read_tsv(POOL)}
    previously_tested = {row["candidate_domain"] for row in read_tsv(OLD_LEDGER)}
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
    with SOURCE.open(newline="", encoding="utf-8") as source_handle, SYNTAX.open(newline="", encoding="utf-8") as syntax_handle:
        source_reader = csv.reader(source_handle)
        syntax_reader = csv.DictReader(syntax_handle, delimiter="\t")
        count = 0
        for source_row, syntax_row in zip(source_reader, syntax_reader):
            count += 1
            rank, domain = int(source_row[0]), source_row[1]
            if rank != int(syntax_row["rank"]) or domain != syntax_row["domain"]:
                raise RuntimeError(f"source/syntax alignment failure rank={rank}")
            if rank > 1000:
                continue
            if syntax_row["eligible"].strip().lower() != "true":
                continue
            if domain in current_domains or domain in previously_tested or domain in known_unstable:
                continue
            result.append({"rank": rank, "domain": domain, "bucket": "top_1_1000"})
        if count != 1_000_000 or next(source_reader, None) is not None or next(syntax_reader, None) is not None:
            raise RuntimeError("source/syntax length mismatch")
    result.sort(key=lambda item: (int(item["rank"]), str(item["domain"])))
    if not result or result[0] != {"rank": 899, "domain": "eu-1-id5-sync.com", "bucket": "top_1_1000"}:
        raise RuntimeError(f"rank-ascending candidate head changed: {result[:1]}")
    return result


def service_exit(pre: dict[str, object], post: dict[str, object], mode: str) -> int:
    return sum(
        post["services"][unit]["state"] != "active"
        or post["services"][unit]["pid"] != pre["services"][unit]["pid"]
        for unit in diag.MODE_UNITS[mode]
    )


def run_supervised(
    remote_script: str,
    script_args: list[str],
    remote_trial: str,
    local_trial: Path,
    label: str,
) -> tuple[int, dict[str, object], dict[str, object]]:
    command = [
        "ssh", "-o", "BatchMode=yes", diag.USER_HOST,
        SUPERVISOR,
        "--label", label,
        "--evidence", remote_trial,
        "--timeout", "75", "--int-grace", "2", "--term-grace", "2", "--kill-grace", "2", "run", "--",
        "/home/etip/.venvs/realistic/bin/python", remote_script,
        *script_args,
        "--result", f"{remote_trial}/trial.json",
    ]
    completed = diag.run(command, 100)
    local_trial.mkdir(parents=True, exist_ok=False)
    diag.run(["rsync", "-a", f"{diag.USER_HOST}:{remote_trial}/", f"{local_trial}/"], 120, True)
    supervisor = json.loads((local_trial / "result.json").read_text(encoding="utf-8"))
    trial = json.loads((local_trial / "trial.json").read_text(encoding="utf-8"))
    return completed.returncode, supervisor, trial


def common_trial_evidence(
    mode: str,
    started: str,
    pre_health: dict[str, object],
    post_health: dict[str, object],
    purity_pre: dict[str, object],
    purity_post: dict[str, object],
    process_after: dict[str, object],
    supervisor: dict[str, object],
) -> dict[str, object]:
    delta = int(purity_post["redsocks_dnat_packet_counter"]) - int(purity_pre["redsocks_dnat_packet_counter"])
    purity_pass = purity_pre["status"] == "PASS" and purity_post["status"] == "PASS"
    return {
        "pre_health": pre_health["status"],
        "post_health": post_health["status"],
        "mode_purity": "PASS" if purity_pass else "FAIL",
        "redsocks_dnat_packet_delta": delta,
        "expected_proxy_traffic_observed": mode == "direct" or delta > 0,
        "redsocks_conn_max_hits": diag.conn_max_hits(mode, started),
        "unexpected_service_exit": service_exit(purity_pre, purity_post, mode),
        "browser_residual": process_after["count"],
        "executor_residual": supervisor.get("residual_count", -1),
        "supervisor_timed_out": int(bool(supervisor.get("timed_out", True))),
        "supervisor_status": supervisor.get("status", "MISSING"),
    }


def infrastructure_pass(evidence: dict[str, object]) -> bool:
    return (
        evidence["pre_health"] == "PASS"
        and evidence["post_health"] == "PASS"
        and evidence["mode_purity"] == "PASS"
        and int(evidence["redsocks_conn_max_hits"]) == 0
        and int(evidence["unexpected_service_exit"]) == 0
        and int(evidence["browser_residual"]) == 0
        and int(evidence["executor_residual"]) == 0
        and int(evidence["supervisor_timed_out"]) == 0
    )


def activate_mode(mode: str) -> None:
    qv3.cleanup_mode()
    diag.run([str(diag.MODE_TOOL), mode], 30, True)
    if mode == "trojan":
        qv3.canary_rule(True)
    time.sleep(1)
    if diag.mode_purity(mode)["status"] != "PASS":
        raise RuntimeError(f"mode activation purity failed: {mode}")


def actionability_candidate(candidate: dict[str, object], root: Path, remote_root: str) -> dict[str, object]:
    mode = "trojan"
    trials = []
    candidate_root = root / "candidates" / f"{int(candidate['rank']):07d}_{candidate['domain']}" / "actionability"
    for replay in (1, 2, 3):
        local_trial = candidate_root / f"trial_{replay}"
        if not (local_trial / "trial.json").is_file():
            break
        if (local_trial / "qualification_record.json").is_file():
            trials.append(json.loads((local_trial / "qualification_record.json").read_text(encoding="utf-8")))
            continue
        failure_record = root / "QUALIFICATION_FAIL.json"
        if not failure_record.is_file():
            raise RuntimeError(f"partial actionability trial lacks qualification evidence: {local_trial}")
        failure_text = json.loads(failure_record.read_text(encoding="utf-8")).get("error", "")
        required = (
            "'pre_health': 'PASS'", "'post_health': 'PASS'", "'redsocks_conn_max_hits': 0",
            "'unexpected_service_exit': 0", "'browser_residual': 0", "'executor_residual': 0",
        )
        if not all(token in failure_text for token in required):
            raise RuntimeError(f"cannot recover partial trial infrastructure evidence: {local_trial}")
        trial = json.loads((local_trial / "trial.json").read_text(encoding="utf-8"))
        supervisor = json.loads((local_trial / "result.json").read_text(encoding="utf-8"))
        recovered = {
            **trial,
            "pre_health": "PASS", "post_health": "PASS", "mode_purity": "PASS",
            "redsocks_dnat_packet_delta": 0, "expected_proxy_traffic_observed": False,
            "redsocks_conn_max_hits": 0, "unexpected_service_exit": 0,
            "browser_residual": 0, "executor_residual": supervisor.get("residual_count", -1),
            "supervisor_timed_out": int(bool(supervisor.get("timed_out", True))),
            "supervisor_status": supervisor.get("status", "MISSING"),
            "trial_pass": False, "local_evidence": str(local_trial),
            "evidence_recovered_from": str(failure_record),
        }
        write_json(local_trial / "qualification_record.json", recovered)
        trials.append(recovered)
    if len(trials) < 3:
        activate_mode(mode)
    try:
        for replay in range(len(trials) + 1, 4):
            delay = DELAYS[replay - 1]
            pre_health = diag.health_check(mode, "PRE_HEALTH")
            purity_pre = diag.mode_purity(mode)
            if diag.process_snapshot()["count"]:
                raise RuntimeError("preexisting browser before actionability trial")
            started = diag.utc_now()
            label = f"ivi_r1_cand{int(candidate['rank']):07d}_{str(candidate['domain']).replace('.', '_')}_action_r{replay}"
            remote_trial = f"{remote_root}/candidates/{candidate['rank']}/actionability/r{replay}"
            local_trial = root / "candidates" / f"{int(candidate['rank']):07d}_{candidate['domain']}" / "actionability" / f"trial_{replay}"
            rc, supervisor, trial = run_supervised(
                f"{remote_root}/input/{ACTION_SCRIPT.name}",
                [
                    "--rank", str(candidate["rank"]), "--domain", str(candidate["domain"]),
                    "--bucket", str(candidate["bucket"]), "--replay", str(replay), "--delay", str(delay),
                ],
                remote_trial, local_trial, label,
            )
            purity_post = diag.mode_purity(mode)
            post_health = diag.health_check(mode, "POST_HEALTH")
            evidence = common_trial_evidence(
                mode, started, pre_health, post_health, purity_pre, purity_post,
                diag.process_snapshot(), supervisor,
            )
            if not infrastructure_pass(evidence):
                raise RuntimeError(f"actionability infrastructure evidence failed: {candidate} r{replay}: {evidence}")
            passed = (
                rc == 0
                and trial.get("navigation_status") == "PASS"
                and trial.get("evaluate_status") == "PASS"
                and trial.get("action_status") == "PASS"
                and evidence["expected_proxy_traffic_observed"] is True
                and trial.get("playwright_version") == "1.62.0"
                and trial.get("chromium_version") == "151.0.7922.34"
            )
            record = {**trial, **evidence, "trial_pass": passed, "local_evidence": str(local_trial)}
            trials.append(record)
            write_json(local_trial / "qualification_record.json", record)
            print(
                f"ACTIONABILITY candidate_rank={candidate['rank']} domain={candidate['domain']} "
                f"trial={replay} status={'PASS' if passed else 'FAIL'} nav={trial.get('navigation_status')} "
                f"evaluate={trial.get('evaluate_status')} action={trial.get('action_status')}",
                flush=True,
            )
    finally:
        qv3.cleanup_mode()
    passed = len(trials) == 3 and all(item["trial_pass"] for item in trials)
    return {
        "status": "PASS" if passed else "FAIL",
        "replay_stability": "PASS" if passed else "FAIL",
        "actionability": "PASS" if passed else "FAIL",
        "navigation_pass_count": sum(item.get("navigation_status") == "PASS" for item in trials),
        "evaluate_pass_count": sum(item.get("evaluate_status") == "PASS" for item in trials),
        "action_pass_count": sum(item.get("action_status") == "PASS" for item in trials),
        "trials": trials,
    }


def cross_mode_sanity(candidate: dict[str, object], root: Path, remote_root: str) -> dict[str, object]:
    trials = []
    for mode in MODES:
        activate_mode(mode)
        try:
            for trial_number in (1, 2):
                pre_health = diag.health_check(mode, "PRE_HEALTH")
                purity_pre = diag.mode_purity(mode)
                if diag.process_snapshot()["count"]:
                    raise RuntimeError("preexisting browser before cross-mode trial")
                started = diag.utc_now()
                label = f"ivi_r1_cand{int(candidate['rank']):07d}_{str(candidate['domain']).replace('.', '_')}_{mode}_r{trial_number}"
                remote_trial = f"{remote_root}/candidates/{candidate['rank']}/cross_mode/{mode}/r{trial_number}"
                local_trial = root / "candidates" / f"{int(candidate['rank']):07d}_{candidate['domain']}" / "cross_mode" / mode / f"trial_{trial_number}"
                rc, supervisor, trial = run_supervised(
                    f"{remote_root}/input/{NAV_SCRIPT.name}",
                    ["--domain", str(candidate["domain"]), "--mode", mode, "--trial", str(trial_number)],
                    remote_trial, local_trial, label,
                )
                purity_post = diag.mode_purity(mode)
                post_health = diag.health_check(mode, "POST_HEALTH")
                evidence = common_trial_evidence(
                    mode, started, pre_health, post_health, purity_pre, purity_post,
                    diag.process_snapshot(), supervisor,
                )
                if not infrastructure_pass(evidence):
                    raise RuntimeError(f"cross-mode infrastructure evidence failed: {candidate} {mode} r{trial_number}: {evidence}")
                passed = (
                    rc == 0
                    and trial.get("main_navigation") == "PASS"
                    and evidence["expected_proxy_traffic_observed"] is True
                    and trial.get("playwright_version") == "1.62.0"
                    and trial.get("chromium_version") == "151.0.7922.34"
                )
                record = {**trial, **evidence, "trial_pass": passed, "local_evidence": str(local_trial)}
                trials.append(record)
                write_json(local_trial / "qualification_record.json", record)
                print(
                    f"CROSS_MODE candidate_rank={candidate['rank']} domain={candidate['domain']} mode={mode} "
                    f"trial={trial_number} status={'PASS' if passed else 'FAIL'} "
                    f"http={trial.get('http_status')} failure={trial.get('failure_class')}",
                    flush=True,
                )
        finally:
            qv3.cleanup_mode()
    passed = len(trials) == 8 and all(item["trial_pass"] for item in trials)
    return {
        "status": "8/8 PASS" if passed else "FAIL",
        "pass_count": sum(item["trial_pass"] for item in trials),
        "trial_count": len(trials),
        "mode_counts": {
            mode: sum(item["trial_pass"] for item in trials if item["mode"] == mode)
            for mode in MODES
        },
        "trials": trials,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--resume-root", type=Path)
    args = parser.parse_args()
    verify_inputs()
    candidates = eligible_candidates()
    if args.resume_root:
        root = args.resume_root.resolve()
        if not root.is_dir():
            raise RuntimeError(f"resume root missing: {root}")
        provenance = json.loads((root / "provenance.json").read_text(encoding="utf-8"))
        remote_root = str(provenance["remote_root"])
    else:
        stamp = qv3.stamp_now()
        OUTPUT_PARENT.mkdir(parents=True, exist_ok=True)
        root = OUTPUT_PARENT / f"ivi_ru_replacement_r1_{stamp}"
        root.mkdir()
        (root / "NON_FORMAL_REPLACEMENT_QUALIFICATION").write_text(
            "NON_FORMAL_REPLACEMENT_QUALIFICATION\n", encoding="utf-8"
        )
        remote_root = f"/tmp/ivi-ru-replacement-r1-{stamp}"
    input_root = f"{remote_root}/input"
    diag.run(["ssh", "-o", "BatchMode=yes", diag.USER_HOST, "mkdir", "-p", input_root], 30, True)
    diag.run(["scp", "-q", str(ACTION_SCRIPT), str(NAV_SCRIPT), f"{diag.USER_HOST}:{input_root}/"], 120, True)
    if not args.resume_root:
        with (root / "candidate_order.tsv").open("w", newline="", encoding="utf-8") as handle:
            writer = csv.DictWriter(handle, fieldnames=["rank", "domain", "bucket"], delimiter="\t", lineterminator="\n")
            writer.writeheader()
            writer.writerows(candidates)
        write_json(root / "provenance.json", {
            "classification": "NON_FORMAL_REPLACEMENT_QUALIFICATION",
            "old_domain": "ivi.ru", "old_rank": 479, "old_bucket": "top_1_1000",
            "old_reason": "CROSS_MODE_DOMAIN_ACTIONABILITY_INSTABILITY",
            "selection_rule": "same bucket; exclude current Final500, prior-tested and known replay/actionability-unstable domains; rank ascending",
            "source_sha256": SOURCE_SHA, "syntax_sha256": SYNTAX_SHA,
            "historical_pool_sha256": POOL_SHA, "historical_ledger_sha256": OLD_LEDGER_SHA,
            "amendment_sha256": sha(AMENDMENT), "actionability_script_sha256": ACTION_SCRIPT_SHA,
            "navigation_only_script_sha256": NAV_SCRIPT_SHA, "remote_root": remote_root,
            "started_utc": diag.utc_now(),
        })
    ledger_path = root / "candidate_qualification_ledger.jsonl"
    records = [json.loads(line) for line in ledger_path.read_text(encoding="utf-8").splitlines()] if ledger_path.is_file() else []
    selected = None
    success = False
    try:
        if diag.process_snapshot()["count"]:
            raise RuntimeError("preexisting browser/executor process")
        for order, candidate in enumerate(candidates[len(records):], len(records) + 1):
            actionability = actionability_candidate(candidate, root, remote_root)
            sanity = {"status": "NOT_RUN", "pass_count": 0, "trial_count": 0, "mode_counts": {}, "trials": []}
            if actionability["status"] == "PASS":
                sanity = cross_mode_sanity(candidate, root, remote_root)
            qualified = actionability["status"] == "PASS" and sanity["status"] == "8/8 PASS"
            record = {
                "candidate_attempt_order": order,
                **candidate,
                "syntax_gate": "PASS",
                "replay_stability_gate": actionability["replay_stability"],
                "actionability_gate": actionability["actionability"],
                "cross_mode_sanity": sanity["status"],
                "qualification_status": "QUALIFIED" if qualified else "REJECT",
                "final_selected": qualified,
                "actionability": actionability,
                "cross_mode": sanity,
                "completed_utc": diag.utc_now(),
            }
            records.append(record)
            with (root / "candidate_qualification_ledger.jsonl").open("a", encoding="utf-8") as handle:
                handle.write(json.dumps(record, sort_keys=True) + "\n")
            write_json(root / "candidates" / f"{int(candidate['rank']):07d}_{candidate['domain']}" / "candidate_result.json", record)
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
            raise RuntimeError("eligible top_1_1000 candidate queue exhausted")
        result = {
            "status": "PASS",
            "classification": "NON_FORMAL_REPLACEMENT_QUALIFICATION",
            "old_domain": "ivi.ru", "old_rank": 479, "old_bucket": "top_1_1000",
            "old_reason": "CROSS_MODE_DOMAIN_ACTIONABILITY_INSTABILITY",
            "candidate_count_tested": len(records),
            "candidate_count_rejected": len(records) - 1,
            "selected": selected,
            "candidate_order_prefix": candidates[:len(records)],
            "ended_utc": diag.utc_now(),
        }
        write_json(root / "qualification_result.json", result)
        (root / "REPLACEMENT_QUALIFICATION_PASS").write_text(
            "REPLACEMENT_QUALIFICATION_PASS\nNON_FORMAL_REPLACEMENT_QUALIFICATION\n", encoding="utf-8"
        )
        success = True
        print(json.dumps({
            "selected_rank": selected["rank"], "selected_domain": selected["domain"],
            "candidates_tested": len(records), "actionability": selected["actionability_gate"],
            "cross_mode_sanity": selected["cross_mode_sanity"],
        }, sort_keys=True), flush=True)
        print(f"OUTPUT_ROOT={root}", flush=True)
        return 0
    except BaseException as exc:
        write_json(root / "QUALIFICATION_FAIL.json", {
            "status": "FAIL", "error": f"{type(exc).__name__}: {exc}",
            "candidate_count_tested": len(records), "failed_utc": diag.utc_now(),
        })
        print(f"REPLACEMENT_QUALIFICATION_FAIL root={root} error={type(exc).__name__}: {exc}", flush=True)
        return 1
    finally:
        qv3.cleanup_mode()
        if not success:
            print("replacement qualification evidence preserved", flush=True)


if __name__ == "__main__":
    raise SystemExit(main())
