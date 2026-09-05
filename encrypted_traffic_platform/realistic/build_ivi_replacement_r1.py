#!/usr/bin/env python3
"""Build the approved immutable-history-preserving Formal T0 v3 R1 pool and ledger."""

from __future__ import annotations

import csv
import hashlib
import json
import os
from collections import Counter
from pathlib import Path


REPO = Path("/home/etip/Tunnel/proxytraffic")
DOC = REPO / "docs/realistic_v1/formal_t0_v3"
SOURCE = Path("/home/etip/datasets/plans/realistic_v1/t0_source/tranco_46W9X_top1m.csv")
OLD_POOL = DOC / "formal_domain_pool_v3.tsv"
OLD_LEDGER = DOC / "domain_replacement_ledger_v3.tsv"
AMENDMENT = DOC / "ivi_ru_cross_mode_replacement_amendment_v1.txt"
QUALIFICATION_ROOT = Path(
    "/home/etip/datasets/staging/realistic_v1/non_formal_replacement_r1/"
    "ivi_ru_replacement_r1_20260904T161802Z"
)
NEW_POOL = DOC / "formal_domain_pool_v3_r1.tsv"
NEW_LEDGER = DOC / "domain_replacement_ledger_v3_r1.tsv"
RESULT = DOC / "formal_domain_pool_v3_r1_result.txt"
SOURCE_SHA = "264830dfe5bbf84daeb23d482123d0a7eab1f6ee6830f08984c563be18d998aa"
OLD_POOL_SHA = "ded7fd1277a32295fb1e5fef3b6df0967f10a578cb2d204b04409b55b6878071"
OLD_LEDGER_SHA = "59dd595f8c409756a2cfb6445c004291e75f11c2e3d8d6bef6c84cce6dadbf85"
BUCKET_COUNTS = {"top_1_1000": 350, "rank_1001_100000": 100, "rank_100001_1000000": 50}


def sha(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def read_tsv(path: Path) -> list[dict[str, str]]:
    with path.open(newline="", encoding="utf-8") as handle:
        return list(csv.DictReader(handle, delimiter="\t"))


def write_tsv(path: Path, fields: list[str], rows: list[dict[str, object]]) -> None:
    temporary = path.with_suffix(path.suffix + ".tmp")
    with temporary.open("x", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields, delimiter="\t", lineterminator="\n", extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(temporary, path)


def bool_text(value: bool) -> str:
    return "true" if value else "false"


def main() -> int:
    for path in (NEW_POOL, NEW_LEDGER, RESULT):
        if path.exists():
            raise RuntimeError(f"refusing to overwrite R1 output: {path}")
    if sha(SOURCE) != SOURCE_SHA or sha(OLD_POOL) != OLD_POOL_SHA or sha(OLD_LEDGER) != OLD_LEDGER_SHA:
        raise RuntimeError("historical/source SHA mismatch")
    qualification = json.loads((QUALIFICATION_ROOT / "qualification_result.json").read_text(encoding="utf-8"))
    if qualification["status"] != "PASS":
        raise RuntimeError("replacement qualification did not pass")
    selected = qualification["selected"]
    if not (
        selected["rank"] == 912
        and selected["domain"] == "deloitte.com"
        and selected["bucket"] == "top_1_1000"
        and selected["actionability_gate"] == "PASS"
        and selected["cross_mode_sanity"] == "8/8 PASS"
    ):
        raise RuntimeError("selected replacement provenance mismatch")
    records = [
        json.loads(line)
        for line in (QUALIFICATION_ROOT / "candidate_qualification_ledger.jsonl").read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    expected_order = [(899, "eu-1-id5-sync.com"), (900, "sentinelone.net"), (901, "tiktokw.us"),
                      (902, "go-mpulse.net"), (903, "dv.tech"), (906, "coupang.com"),
                      (907, "life360.com"), (909, "samsungosp.com"), (911, "ln-msedge.net"),
                      (912, "deloitte.com")]
    if [(row["rank"], row["domain"]) for row in records] != expected_order:
        raise RuntimeError("candidate rank order mismatch")
    if sum(bool(row["final_selected"]) for row in records) != 1 or not records[-1]["final_selected"]:
        raise RuntimeError("candidate disposition mismatch")
    for row in records:
        trials = row["actionability"]["trials"]
        if len(trials) != 3 or sorted(int(trial["replay"]) for trial in trials) != [1, 2, 3]:
            raise RuntimeError(f"actionability trial completeness failure: {row['domain']}")
        if not all(
            trial["pre_health"] == trial["post_health"] == trial["mode_purity"] == "PASS"
            and int(trial["redsocks_conn_max_hits"]) == 0
            and int(trial["unexpected_service_exit"]) == 0
            and int(trial["browser_residual"]) == 0
            and int(trial["executor_residual"]) == 0
            for trial in trials
        ):
            raise RuntimeError(f"actionability infrastructure evidence failure: {row['domain']}")
        if row["actionability_gate"] == "PASS":
            sanity = row["cross_mode"]["trials"]
            if len(sanity) != 8:
                raise RuntimeError(f"cross-mode trial completeness failure: {row['domain']}")
            if not all(
                trial["trial_pass"]
                and trial["pre_health"] == trial["post_health"] == trial["mode_purity"] == "PASS"
                and int(trial["redsocks_conn_max_hits"]) == 0
                and int(trial["unexpected_service_exit"]) == 0
                and int(trial["browser_residual"]) == 0
                and int(trial["executor_residual"]) == 0
                for trial in sanity
            ):
                raise RuntimeError(f"cross-mode sanity evidence failure: {row['domain']}")

    old_ledger_rows = read_tsv(OLD_LEDGER)
    old_fields = list(old_ledger_rows[0])
    extension = ["old_reason", "new_domain", "new_rank", "same_bucket", "actionability", "cross_mode_sanity"]
    ledger_fields = old_fields + extension
    ledger_rows: list[dict[str, object]] = [{**row, **{field: "" for field in extension}} for row in old_ledger_rows]
    for record in records:
        action_trials = record["actionability"]["trials"]
        errors = [" ".join(str(trial.get("error", "")).splitlines()) for trial in action_trials if trial.get("error")]
        nav_count = int(record["actionability"]["navigation_pass_count"])
        eval_count = int(record["actionability"]["evaluate_pass_count"])
        action_count = int(record["actionability"]["action_pass_count"])
        selected_record = bool(record["final_selected"])
        reasons = []
        if nav_count != 3:
            reasons.append(f"navigation_pass={nav_count}/3")
        if eval_count != 3:
            reasons.append(f"evaluate_pass={eval_count}/3")
        if action_count != 3:
            reasons.append(f"action_pass={action_count}/3")
        if record["actionability_gate"] == "PASS" and record["cross_mode_sanity"] != "8/8 PASS":
            reasons.append(f"cross_mode_sanity={record['cross_mode_sanity']}")
        labels = [str(Path(trial["local_evidence"]).relative_to(QUALIFICATION_ROOT)) for trial in action_trials]
        labels += [
            str(Path(trial["local_evidence"]).relative_to(QUALIFICATION_ROOT))
            for trial in record["cross_mode"]["trials"]
        ]
        ledger_rows.append({
            "old_rank": 479,
            "old_domain": "ivi.ru",
            "old_bucket": "top_1_1000",
            "old_failure_reason": "CROSS_MODE_DOMAIN_ACTIONABILITY_INSTABILITY",
            "candidate_rank": record["rank"],
            "candidate_domain": record["domain"],
            "candidate_attempt_order": record["candidate_attempt_order"],
            "navigation_pass_count": nav_count,
            "evaluate_pass_count": eval_count,
            "action_pass_count": action_count,
            "evaluate_timeout_count": sum(trial.get("evaluate_status") == "TIMEOUT" for trial in action_trials),
            "action_timeout_count": sum(trial.get("action_status") == "TIMEOUT" for trial in action_trials),
            "renderer_unresponsive_count": sum(int(trial.get("renderer_unresponsive", 0)) for trial in action_trials),
            "http429_count": sum(int(trial.get("http429", 0)) for trial in action_trials),
            "qualification_status": "REPLACEMENT_CANDIDATE_QUALIFIED" if selected_record else "REPLACEMENT_CANDIDATE_REJECTED",
            "qualification_failure_reason": ";".join(reasons),
            "trial_errors": " | ".join(errors),
            "qualification_completed_utc": record["completed_utc"],
            "evidence_archive": str(QUALIFICATION_ROOT),
            "trial_evidence_labels": ",".join(labels),
            "final_selected": bool_text(selected_record),
            "old_reason": "CROSS_MODE_DOMAIN_ACTIONABILITY_INSTABILITY",
            "new_domain": record["domain"],
            "new_rank": record["rank"],
            "same_bucket": "true",
            "actionability": record["actionability_gate"],
            "cross_mode_sanity": record["cross_mode_sanity"],
        })
    write_tsv(NEW_LEDGER, ledger_fields, ledger_rows)

    source = {}
    with SOURCE.open(newline="", encoding="utf-8") as handle:
        for row in csv.reader(handle):
            source[int(row[0])] = row[1]
    pool_rows = read_tsv(OLD_POOL)
    old_domains = {row["domain"] for row in pool_rows}
    old_ivi = [row for row in pool_rows if row["domain"] == "ivi.ru"]
    if len(old_ivi) != 1 or source[479] != "ivi.ru" or source[912] != "deloitte.com":
        raise RuntimeError("Tranco old/new rank provenance mismatch")
    first_trial = selected["actionability"]["trials"][0]
    replacement = {
        **old_ivi[0],
        "rank": "912",
        "domain": "deloitte.com",
        "rank_bucket": "top_1_1000",
        "source_list_id": "46W9X",
        "source_sha256": SOURCE_SHA,
        "syntax_eligible": "true",
        "reachability_eligible": "true",
        "main_http_status": str(first_trial["main_http_status"]),
        "main_commit_success": "true",
        "main_commit_latency_ms": str(round(float(first_trial["navigation_duration_seconds"]) * 1000)),
        "warning_count": "",
        "audit_timestamp": selected["completed_utc"],
        "actionability_evidence_type": "replacement_v3_r1_3of3_cross_mode_8of8",
        "actionability_evidence_reference": (
            "docs/realistic_v1/formal_t0_v3/domain_replacement_ledger_v3_r1.tsv#candidate_domain=deloitte.com"
        ),
        "navigation_pass_count": "3",
        "evaluate_pass_count": "3",
        "action_pass_count": "3",
        "actionability_status": "ACTIONABILITY_STABLE",
        "pool_membership": "replacement_stable",
    }
    new_rows = [row for row in pool_rows if row["domain"] != "ivi.ru"] + [replacement]
    new_rows.sort(key=lambda row: int(row["rank"]))
    for index, row in enumerate(new_rows, 1):
        row["domain_id"] = f"domain{index:04d}"
    new_domains = {row["domain"] for row in new_rows}
    if len(new_rows) != 500 or len(new_domains) != 500:
        raise RuntimeError("R1 pool total/duplicate failure")
    if new_domains != old_domains - {"ivi.ru"} | {"deloitte.com"}:
        raise RuntimeError("R1 pool membership delta is not exactly one replacement")
    if Counter(row["rank_bucket"] for row in new_rows) != Counter(BUCKET_COUNTS):
        raise RuntimeError("R1 pool bucket count failure")
    if any(source[int(row["rank"])] != row["domain"] for row in new_rows):
        raise RuntimeError("R1 source provenance failure")
    write_tsv(NEW_POOL, list(new_rows[0]), new_rows)
    if sha(OLD_POOL) != OLD_POOL_SHA or sha(OLD_LEDGER) != OLD_LEDGER_SHA:
        raise RuntimeError("historical pool/ledger changed during R1 build")
    result = "\n".join((
        "REALISTIC_V3_R1_FINAL500_DOMAIN_POOL_READY",
        "old_domain=ivi.ru",
        "old_rank=479",
        "old_bucket=top_1_1000",
        "old_reason=CROSS_MODE_DOMAIN_ACTIONABILITY_INSTABILITY",
        "new_domain=deloitte.com",
        "new_rank=912",
        "same_bucket=true",
        "actionability=PASS",
        "cross_mode_sanity=8/8 PASS",
        f"replacement_candidates_tested={len(records)}",
        f"replacement_candidates_rejected={len(records)-1}",
        "TOTAL=500",
        "A=350",
        "B=100",
        "C=50",
        "duplicate=0",
        "missing=0",
        f"formal_domain_pool_v3_r1_sha256={sha(NEW_POOL)}",
        f"domain_replacement_ledger_v3_r1_sha256={sha(NEW_LEDGER)}",
        f"historical_pool_sha256={OLD_POOL_SHA}",
        f"historical_ledger_sha256={OLD_LEDGER_SHA}",
        "",
    ))
    RESULT.write_text(result, encoding="utf-8")
    print(result, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
