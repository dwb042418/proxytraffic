#!/usr/bin/env python3
"""Build and integrity-audit the authorized Formal T0 v3 final 500 pool."""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
from collections import Counter, defaultdict
from pathlib import Path


REPO = Path("/home/etip/Tunnel/proxytraffic")
DOC = REPO / "docs/realistic_v1/formal_t0_v3"
SOURCE = Path("/home/etip/datasets/plans/realistic_v1/t0_source/tranco_46W9X_top1m.csv")
POOL = Path(
    "/home/etip/.cache/realistic-v3-current500-capacity256-20260903T084052Z/"
    "remote-evidence/input/formal_domain_pool.tsv"
)
CURRENT_AUDIT = DOC / "actionability_audit_current500_capacity256_20260903.tsv"
CURRENT_RESULT = DOC / "current500_actionability_audit_capacity256_result.txt"
CURRENT_EVIDENCE = DOC / "evidence/current500_capacity256_valid_20260903T084052Z.tar.gz"
LEDGER_OUTPUT = DOC / "domain_replacement_ledger_v3.tsv"
POOL_OUTPUT = DOC / "formal_domain_pool_v3.tsv"
RESULT_OUTPUT = DOC / "formal_domain_pool_v3_result.txt"

SOURCE_SHA = "264830dfe5bbf84daeb23d482123d0a7eab1f6ee6830f08984c563be18d998aa"
CURRENT_POOL_SHA = "762cb40b906936b137ad80dae0ac37bc38fee971a8f6bfbe24182d37de89473e"
CURRENT_AUDIT_SHA = "5f2102f4c195078114719e872945eaa126cbb41f9df9fa4945b7b99fe4daf307"
CURRENT_RESULT_SHA = "ece0be3b5eb6289b41491823c6b9d58f23b2351ade68565cf9252964bac3606e"
CURRENT_EVIDENCE_SHA = "2e93193fa31e4fd8d3b5f47755c526b224066e1b17d69d6a622675efe10991e3"
BUCKET_COUNTS = {
    "top_1_1000": 350,
    "rank_1001_100000": 100,
    "rank_100001_1000000": 50,
}


def sha(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def read_tsv(path: Path) -> list[dict[str, str]]:
    return list(csv.DictReader(path.open(newline=""), delimiter="\t"))


def write_tsv(path: Path, fields: list[str], rows: list[dict]) -> None:
    temporary = path.with_suffix(path.suffix + ".tmp")
    with temporary.open("w", newline="") as handle:
        writer = csv.DictWriter(
            handle, fieldnames=fields, delimiter="\t", lineterminator="\n",
            extrasaction="ignore",
        )
        writer.writeheader()
        writer.writerows(rows)
    temporary.replace(path)


def load_source() -> dict[int, str]:
    source = {}
    with SOURCE.open(newline="") as handle:
        for row in csv.reader(handle):
            source[int(row[0])] = row[1]
    if len(source) != 1_000_000 or sha(SOURCE) != SOURCE_SHA:
        raise RuntimeError("TRANCO_SOURCE_INTEGRITY_FAILURE")
    return source


def bool_text(value: bool) -> str:
    return "true" if value else "false"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--run-root", type=Path, required=True)
    parser.add_argument("--evidence-archive", type=Path, required=True)
    args = parser.parse_args()
    evidence_archive = args.evidence_archive.resolve()
    orchestration = json.loads((args.run_root / "orchestration_result.json").read_text())
    if orchestration.get("status") != "REPLACEMENT_QUALIFICATION_COMPLETE":
        raise RuntimeError("REPLACEMENT_RUN_NOT_COMPLETE")
    controller = orchestration["controller_result"]
    if controller.get("status") != "COMPLETE" or int(controller.get("selected", 0)) != 24:
        raise RuntimeError("REPLACEMENT_CONTROLLER_NOT_COMPLETE")
    if int(orchestration.get("infrastructure_health_loss", -1)) != 0:
        raise RuntimeError("INFRASTRUCTURE_HEALTH_LOSS_NONZERO")
    if int(orchestration.get("redsocks_conn_max_hits", -1)) != 0:
        raise RuntimeError("REDSOCKS_CONN_MAX_HITS_NONZERO")
    if sha(CURRENT_AUDIT) != CURRENT_AUDIT_SHA or sha(CURRENT_RESULT) != CURRENT_RESULT_SHA:
        raise RuntimeError("FROZEN_CURRENT500_RESULT_CHANGED")
    if sha(POOL) != CURRENT_POOL_SHA:
        raise RuntimeError("FROZEN_CURRENT500_POOL_CHANGED")
    if sha(CURRENT_EVIDENCE) != CURRENT_EVIDENCE_SHA:
        raise RuntimeError("FROZEN_CURRENT500_EVIDENCE_CHANGED")

    remote = args.run_root / "remote-evidence"
    replacement_root = remote / "replacement-evidence"
    raw_ledger_path = replacement_root / "replacement_ledger.jsonl"
    records = [json.loads(line) for line in raw_ledger_path.read_text().splitlines() if line]
    if len(records) != int(controller["tested"]):
        raise RuntimeError("RAW_LEDGER_CANDIDATE_COUNT_MISMATCH")
    selected = [record for record in records if record["final_selected"]]
    rejected = [record for record in records if not record["final_selected"]]
    if len(selected) != 24 or len(rejected) != int(controller["rejected"]):
        raise RuntimeError("RAW_LEDGER_DISPOSITION_COUNT_MISMATCH")
    if len({record["candidate_domain"] for record in records}) != len(records):
        raise RuntimeError("REPLACEMENT_CANDIDATE_REUSE_DETECTED")
    if len({record["old_domain"] for record in selected}) != 24:
        raise RuntimeError("REPLACEMENT_SLOT_SELECTION_MISMATCH")

    candidates = read_tsv(args.run_root / "input/replacement_candidates.tsv")
    expected_by_bucket = defaultdict(list)
    used_by_bucket = defaultdict(list)
    for row in candidates:
        expected_by_bucket[row["candidate_bucket"]].append(
            (int(row["candidate_rank"]), row["candidate_domain"])
        )
    for record in records:
        used_by_bucket[record["candidate_bucket"]].append(
            (int(record["candidate_rank"]), record["candidate_domain"])
        )
    for bucket, used in used_by_bucket.items():
        if sorted(used) != expected_by_bucket[bucket][:len(used)]:
            raise RuntimeError(f"CANDIDATE_RANK_ORDER_OR_EXCLUSION_FAILURE bucket={bucket}")

    by_old = defaultdict(list)
    for record in records:
        by_old[record["old_domain"]].append(record)
    for old_domain, attempts in by_old.items():
        orders = sorted(int(record["candidate_attempt_order"]) for record in attempts)
        if orders != list(range(1, len(orders) + 1)):
            raise RuntimeError(f"CANDIDATE_ATTEMPT_ORDER_FAILURE old_domain={old_domain}")
        if sum(bool(record["final_selected"]) for record in attempts) != 1:
            raise RuntimeError(f"CANDIDATE_FINAL_SELECTION_FAILURE old_domain={old_domain}")

    ledger_rows = []
    for record in sorted(
        records,
        key=lambda item: (int(item["old_rank"]), int(item["candidate_attempt_order"])),
    ):
        trials = record["trials"]
        if len(trials) != 3 or sorted(int(trial["replay"]) for trial in trials) != [1, 2, 3]:
            raise RuntimeError("REPLACEMENT_REPLAY_COMPLETENESS_FAILURE")
        evidence_labels = []
        for trial in trials:
            label = Path(trial["trial_evidence"]).name
            evidence = replacement_root / "trials" / label
            if not (evidence / "trial.json").is_file() or not (evidence / "result.json").is_file():
                raise RuntimeError(f"REPLACEMENT_TRIAL_EVIDENCE_MISSING label={label}")
            trial_evidence = json.loads((evidence / "trial.json").read_text())
            supervisor_evidence = json.loads((evidence / "result.json").read_text())
            for field in ("domain", "rank", "replay", "navigation_status",
                          "evaluate_status", "action_status", "renderer_unresponsive"):
                if str(trial_evidence.get(field, "")) != str(trial.get(field, "")):
                    raise RuntimeError(
                        f"REPLACEMENT_TRIAL_EVIDENCE_MISMATCH label={label} field={field}"
                    )
            if (supervisor_evidence.get("timed_out")
                    or int(supervisor_evidence.get("residual_count", -1)) != 0
                    or supervisor_evidence.get("status") not in {"PASS", "FAIL"}):
                raise RuntimeError(f"REPLACEMENT_SUPERVISOR_EVIDENCE_FAILURE label={label}")
            evidence_labels.append(label)
        selected_record = bool(record["final_selected"])
        stable = (
            int(record["navigation_pass_count"]) == 3
            and int(record["evaluate_pass_count"]) == 3
            and int(record["action_pass_count"]) == 3
            and int(record["evaluate_timeout_count"]) == 0
            and int(record["action_timeout_count"]) == 0
            and int(record["renderer_unresponsive_count"]) == 0
            and int(record["http429_count"]) == 0
            and int(record["supervisor_pass_count"]) == 3
            and all(int(trial.get("executor_residual", -1)) == 0 for trial in trials)
            and all(int(trial.get("browser_residual", -1)) == 0 for trial in trials)
            and all(int(trial.get("supervisor_timed_out", 1)) == 0 for trial in trials)
        )
        if selected_record != stable:
            raise RuntimeError("REPLACEMENT_STATUS_EVIDENCE_MISMATCH")
        expected_status = (
            "REPLACEMENT_CANDIDATE_QUALIFIED"
            if selected_record else "REPLACEMENT_CANDIDATE_REJECTED"
        )
        if record["qualification_status"] != expected_status:
            raise RuntimeError("REPLACEMENT_QUALIFICATION_LABEL_MISMATCH")
        errors = [
            " ".join(str(trial.get("error", "")).splitlines()).replace("\t", "\\t")
            for trial in trials if trial.get("error")
        ]
        ledger_rows.append({
            "old_rank": record["old_rank"],
            "old_domain": record["old_domain"],
            "old_bucket": record["old_bucket"],
            "old_failure_reason": record["old_failure_reason"],
            "candidate_rank": record["candidate_rank"],
            "candidate_domain": record["candidate_domain"],
            "candidate_attempt_order": record["candidate_attempt_order"],
            "navigation_pass_count": record["navigation_pass_count"],
            "evaluate_pass_count": record["evaluate_pass_count"],
            "action_pass_count": record["action_pass_count"],
            "evaluate_timeout_count": record["evaluate_timeout_count"],
            "action_timeout_count": record["action_timeout_count"],
            "renderer_unresponsive_count": record["renderer_unresponsive_count"],
            "http429_count": record["http429_count"],
            "qualification_status": record["qualification_status"],
            "qualification_failure_reason": record["qualification_failure_reason"],
            "trial_errors": " | ".join(errors),
            "qualification_completed_utc": record["qualification_completed_utc"],
            "evidence_archive": str(evidence_archive.relative_to(REPO)),
            "trial_evidence_labels": ",".join(evidence_labels),
            "final_selected": bool_text(selected_record),
        })
    ledger_fields = list(ledger_rows[0])
    write_tsv(LEDGER_OUTPUT, ledger_fields, ledger_rows)

    source = load_source()
    pool_rows = read_tsv(POOL)
    audit_rows = read_tsv(CURRENT_AUDIT)
    audit_by_domain = {row["domain"]: row for row in audit_rows}
    original_stable = [
        row for row in pool_rows
        if audit_by_domain[row["domain"]]["final_actionability_status"] == "ACTIONABILITY_STABLE"
    ]
    if len(original_stable) != 476:
        raise RuntimeError("ORIGINAL_STABLE_COUNT_FAILURE")
    final_rows = []
    for row in original_stable:
        evidence = audit_by_domain[row["domain"]]
        final_rows.append({
            **row,
            "actionability_evidence_type": "current500_capacity256_20260903",
            "actionability_evidence_reference": str(CURRENT_AUDIT.relative_to(REPO)),
            "navigation_pass_count": evidence["navigation_pass_count"],
            "evaluate_pass_count": evidence["evaluate_pass_count"],
            "action_pass_count": evidence["action_pass_count"],
            "actionability_status": evidence["final_actionability_status"],
            "pool_membership": "original_stable",
        })
    selected_by_candidate = {record["candidate_domain"]: record for record in selected}
    for domain, record in selected_by_candidate.items():
        rank = int(record["candidate_rank"])
        if source.get(rank) != domain:
            raise RuntimeError(f"REPLACEMENT_SOURCE_PROVENANCE_FAILURE domain={domain}")
        trial1 = sorted(record["trials"], key=lambda item: int(item["replay"]))[0]
        final_rows.append({
            "domain_id": "",
            "rank": rank,
            "domain": domain,
            "rank_bucket": record["candidate_bucket"],
            "source_list_id": "46W9X",
            "source_sha256": SOURCE_SHA,
            "syntax_eligible": "true",
            "reachability_eligible": "true",
            "main_http_status": trial1["main_http_status"],
            "main_commit_success": "true",
            "main_commit_latency_ms": int(float(trial1.get("navigation_duration_seconds", 0)) * 1000),
            "warning_count": "",
            "audit_timestamp": record["qualification_completed_utc"],
            "replay_stable": "true",
            "rate_limit_429_count": "0",
            "actionability_evidence_type": "replacement_v3_3of3",
            "actionability_evidence_reference": (
                f"{LEDGER_OUTPUT.relative_to(REPO)}#candidate_domain={domain}"
            ),
            "navigation_pass_count": "3",
            "evaluate_pass_count": "3",
            "action_pass_count": "3",
            "actionability_status": "ACTIONABILITY_STABLE",
            "pool_membership": "replacement_stable",
        })
    final_rows.sort(key=lambda row: int(row["rank"]))
    for index, row in enumerate(final_rows, 1):
        row["domain_id"] = f"domain{index:04d}"
    if len(final_rows) != 500:
        raise RuntimeError("FINAL_POOL_TOTAL_FAILURE")
    if len({row["domain"] for row in final_rows}) != 500:
        raise RuntimeError("FINAL_POOL_DUPLICATE_FAILURE")
    if Counter(row["rank_bucket"] for row in final_rows) != BUCKET_COUNTS:
        raise RuntimeError("FINAL_POOL_BUCKET_FAILURE")
    for row in final_rows:
        rank = int(row["rank"])
        if source.get(rank) != row["domain"]:
            raise RuntimeError(f"FINAL_POOL_SOURCE_PROVENANCE_FAILURE rank={rank}")
        if row["source_list_id"] != "46W9X" or row["source_sha256"] != SOURCE_SHA:
            raise RuntimeError("FINAL_POOL_SOURCE_ID_OR_SHA_FAILURE")
        if row["actionability_status"] != "ACTIONABILITY_STABLE":
            raise RuntimeError("FINAL_POOL_ACTIONABILITY_FAILURE")
        if not all(int(row[field]) == 3 for field in (
            "navigation_pass_count", "evaluate_pass_count", "action_pass_count",
        )):
            raise RuntimeError("FINAL_POOL_ACTIONABILITY_COUNT_FAILURE")
    pool_fields = list(final_rows[0])
    write_tsv(POOL_OUTPUT, pool_fields, final_rows)

    pool_sha = sha(POOL_OUTPUT)
    ledger_sha = sha(LEDGER_OUTPUT)
    archive_sha = sha(evidence_archive)
    result = "\n".join((
        "REALISTIC_V3_FINAL500_DOMAIN_POOL_READY",
        "original_stable=476",
        "unstable_replaced=24",
        f"replacement_candidates_tested={len(records)}",
        f"replacement_candidates_rejected={len(rejected)}",
        "replacement_selected=24",
        "final_total=500",
        "A=350",
        "B=100",
        "C=50",
        "duplicate=0",
        "missing=0",
        "evidence_missing=0",
        "source_provenance_failure=0",
        "infrastructure_loss=0",
        "conn_max_hits=0",
        "workers=2",
        "redsocks_conn_max=256",
        f"final_pool_sha256={pool_sha}",
        f"replacement_ledger_sha256={ledger_sha}",
        f"replacement_evidence_archive={evidence_archive.relative_to(REPO)}",
        f"replacement_evidence_archive_sha256={archive_sha}",
        f"current500_audit_sha256={CURRENT_AUDIT_SHA}",
        f"current500_result_sha256={CURRENT_RESULT_SHA}",
        f"current500_evidence_sha256={CURRENT_EVIDENCE_SHA}",
        f"source_sha256={SOURCE_SHA}",
        "final500_browser_reaudit=NOT_RUN",
        "next_action=WAIT_FOR_HUMAN_REVIEW",
        "",
    ))
    RESULT_OUTPUT.write_text(result)
    print(result, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
