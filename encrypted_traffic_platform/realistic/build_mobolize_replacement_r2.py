#!/usr/bin/env python3
"""Build the approved, history-preserving Formal T0 v3 R2 pool and ledger."""

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
OLD_POOL = DOC / "formal_domain_pool_v3_r1.tsv"
OLD_LEDGER = DOC / "domain_replacement_ledger_v3_r1.tsv"
AMENDMENT = DOC / "mobolize_cross_mode_replacement_amendment_v1.txt"
QUALIFICATION_ROOT = Path(
    "/home/etip/datasets/staging/realistic_v1/non_formal_replacement_r2/"
    "mobolize_replacement_r2_20260905T011919Z"
)
NEW_POOL = DOC / "formal_domain_pool_v3_r2.tsv"
NEW_LEDGER = DOC / "domain_replacement_ledger_v3_r2.tsv"
RESULT = DOC / "formal_domain_pool_v3_r2_result.txt"
SOURCE_SHA = "264830dfe5bbf84daeb23d482123d0a7eab1f6ee6830f08984c563be18d998aa"
OLD_POOL_SHA = "c3439f6db36f9ee94470c35a1b82e288da65c2f0cb7b2d347de334d73bb3b171"
OLD_LEDGER_SHA = "e068f038b39e95bab64e9f698996f6d1b83ba4e463df8a25660dfd781a422a0b"
OLD_DOMAIN = "mobolize.com"
OLD_RANK = 689
OLD_BUCKET = "top_1_1000"
OLD_FAILURE = "PERSISTENT_DOMAIN_HTTP_5XX_FAILURE"
NEW_DOMAIN = "internetwarriors.net"
NEW_RANK = 925
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


def clean_error(value: object) -> str:
    return " ".join(str(value or "").splitlines())


def validate_trial(trial: dict[str, object], *, require_pass: bool) -> None:
    if not (
        trial["pre_health"] == trial["post_health"] == trial["mode_purity"] == "PASS"
        and int(trial["redsocks_conn_max_hits"]) == 0
        and int(trial["unexpected_service_exit"]) == 0
        and int(trial.get("oom", 0)) == 0
        and int(trial["browser_residual"]) == 0
        and int(trial["executor_residual"]) == 0
        and int(trial.get("residual", 0)) == 0
    ):
        raise RuntimeError(f"trial infrastructure evidence failure: {trial['domain']}")
    if trial.get("mode") != "direct" and int(trial["redsocks_actual_conn_max"]) != 256:
        raise RuntimeError(f"trial capacity mismatch: {trial['domain']}")
    if require_pass and not bool(trial["trial_pass"]):
        raise RuntimeError(f"selected trial failed: {trial['domain']}")


def main() -> int:
    for path in (NEW_POOL, NEW_LEDGER, RESULT):
        if path.exists():
            raise RuntimeError(f"refusing to overwrite R2 output: {path}")
    if not AMENDMENT.is_file():
        raise RuntimeError("missing approved R2 amendment")
    if sha(SOURCE) != SOURCE_SHA or sha(OLD_POOL) != OLD_POOL_SHA or sha(OLD_LEDGER) != OLD_LEDGER_SHA:
        raise RuntimeError("historical/source SHA mismatch")

    qualification = json.loads((QUALIFICATION_ROOT / "qualification_result.json").read_text(encoding="utf-8"))
    selected = qualification.get("selected", {})
    if not (
        qualification.get("status") == "PASS"
        and selected.get("rank") == NEW_RANK
        and selected.get("domain") == NEW_DOMAIN
        and selected.get("bucket") == OLD_BUCKET
        and selected.get("actionability_gate") == "PASS"
        and selected.get("cross_mode_sanity") == "8/8 PASS"
    ):
        raise RuntimeError("selected replacement provenance mismatch")
    records = [
        json.loads(line)
        for line in (QUALIFICATION_ROOT / "candidate_qualification_ledger.jsonl").read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    expected_order = [(913, "miwifi.com"), (914, "nic.direct"), (915, "cdn-vk.ru"),
                      (916, "paramountplus.com"), (921, "samsungiotcloud.com"),
                      (922, "spiegel.de"), (924, "investopedia.com"),
                      (925, "internetwarriors.net")]
    if [(row["rank"], row["domain"]) for row in records] != expected_order:
        raise RuntimeError("candidate rank order mismatch")
    if sum(bool(row["final_selected"]) for row in records) != 1 or not records[-1]["final_selected"]:
        raise RuntimeError("candidate disposition mismatch")
    for record in records:
        trials = record["actionability"]["trials"]
        if len(trials) != 3 or sorted(int(t["replay"]) for t in trials) != [1, 2, 3]:
            raise RuntimeError(f"actionability trial completeness failure: {record['domain']}")
        for trial in trials:
            validate_trial(trial, require_pass=bool(record["final_selected"]))
        if record["final_selected"]:
            sanity = record["cross_mode"]["trials"]
            if len(sanity) != 8 or Counter(t["mode"] for t in sanity) != Counter({m: 2 for m in ("direct", "vless", "shadowsocks", "trojan")}):
                raise RuntimeError("cross-mode trial completeness failure")
            for trial in sanity:
                validate_trial(trial, require_pass=True)

    old_ledger_rows = read_tsv(OLD_LEDGER)
    old_fields = list(old_ledger_rows[0])
    extension = [field for field in ("old_failure", "bucket") if field not in old_fields]
    ledger_fields = old_fields + extension
    ledger_rows: list[dict[str, object]] = [{**row, **{field: "" for field in extension}} for row in old_ledger_rows]
    for record in records:
        trials = record["actionability"]["trials"]
        nav = int(record["actionability"]["navigation_pass_count"])
        evaluate = int(record["actionability"]["evaluate_pass_count"])
        action = int(record["actionability"]["action_pass_count"])
        selected_record = bool(record["final_selected"])
        reasons = []
        if nav != 3: reasons.append(f"navigation_pass={nav}/3")
        if evaluate != 3: reasons.append(f"evaluate_pass={evaluate}/3")
        if action != 3: reasons.append(f"action_pass={action}/3")
        labels = [str(Path(t["local_evidence"]).relative_to(QUALIFICATION_ROOT)) for t in trials]
        labels += [str(Path(t["local_evidence"]).relative_to(QUALIFICATION_ROOT)) for t in record["cross_mode"]["trials"]]
        ledger_rows.append({
            "old_rank": OLD_RANK,
            "old_domain": OLD_DOMAIN,
            "old_bucket": OLD_BUCKET,
            "old_failure_reason": OLD_FAILURE,
            "candidate_rank": record["rank"],
            "candidate_domain": record["domain"],
            "candidate_attempt_order": record["candidate_attempt_order"],
            "navigation_pass_count": nav,
            "evaluate_pass_count": evaluate,
            "action_pass_count": action,
            "evaluate_timeout_count": sum(t.get("evaluate_status") == "TIMEOUT" for t in trials),
            "action_timeout_count": sum(t.get("action_status") == "TIMEOUT" for t in trials),
            "renderer_unresponsive_count": sum(int(t.get("renderer_unresponsive", 0)) for t in trials),
            "http429_count": sum(int(t.get("http429", 0)) for t in trials),
            "qualification_status": "REPLACEMENT_CANDIDATE_QUALIFIED" if selected_record else "REPLACEMENT_CANDIDATE_REJECTED",
            "qualification_failure_reason": ";".join(reasons),
            "trial_errors": " | ".join(clean_error(t.get("error")) for t in trials if t.get("error")),
            "qualification_completed_utc": record["completed_utc"],
            "evidence_archive": str(QUALIFICATION_ROOT),
            "trial_evidence_labels": ",".join(labels),
            "final_selected": "true" if selected_record else "false",
            "old_reason": OLD_FAILURE,
            "new_domain": record["domain"],
            "new_rank": record["rank"],
            "same_bucket": "true",
            "actionability": record["actionability_gate"],
            "cross_mode_sanity": record["cross_mode_sanity"],
            "old_failure": OLD_FAILURE,
            "bucket": OLD_BUCKET,
        })
    write_tsv(NEW_LEDGER, ledger_fields, ledger_rows)

    source: dict[int, str] = {}
    with SOURCE.open(newline="", encoding="utf-8") as handle:
        for rank, domain, *_ in csv.reader(handle):
            source[int(rank)] = domain
    pool_rows = read_tsv(OLD_POOL)
    old_domains = {row["domain"] for row in pool_rows}
    target = [row for row in pool_rows if row["domain"] == OLD_DOMAIN]
    if len(target) != 1 or int(target[0]["rank"]) != OLD_RANK or target[0]["rank_bucket"] != OLD_BUCKET:
        raise RuntimeError("R1 old-domain rank/bucket mismatch")
    if source[OLD_RANK] != OLD_DOMAIN or source[NEW_RANK] != NEW_DOMAIN:
        raise RuntimeError("Tranco old/new rank provenance mismatch")
    first_trial = selected["actionability"]["trials"][0]
    replacement = {
        **target[0],
        "rank": str(NEW_RANK),
        "domain": NEW_DOMAIN,
        "rank_bucket": OLD_BUCKET,
        "source_list_id": "46W9X",
        "source_sha256": SOURCE_SHA,
        "syntax_eligible": "true",
        "reachability_eligible": "true",
        "main_http_status": str(first_trial["main_http_status"]),
        "main_commit_success": "true",
        "main_commit_latency_ms": str(round(float(first_trial["navigation_duration_seconds"]) * 1000)),
        "warning_count": "",
        "audit_timestamp": selected["completed_utc"],
        "actionability_evidence_type": "replacement_v3_r2_3of3_cross_mode_8of8",
        "actionability_evidence_reference": "docs/realistic_v1/formal_t0_v3/domain_replacement_ledger_v3_r2.tsv#candidate_domain=internetwarriors.net",
        "navigation_pass_count": "3",
        "evaluate_pass_count": "3",
        "action_pass_count": "3",
        "actionability_status": "ACTIONABILITY_STABLE",
        "pool_membership": "replacement_stable",
    }
    new_rows = [row for row in pool_rows if row["domain"] != OLD_DOMAIN] + [replacement]
    new_rows.sort(key=lambda row: int(row["rank"]))
    for index, row in enumerate(new_rows, 1):
        row["domain_id"] = f"domain{index:04d}"
    new_domains = {row["domain"] for row in new_rows}
    if len(new_rows) != 500 or len(new_domains) != 500:
        raise RuntimeError("R2 total/duplicate failure")
    if new_domains != (old_domains - {OLD_DOMAIN}) | {NEW_DOMAIN}:
        raise RuntimeError("R2 pool delta is not exactly one replacement")
    if Counter(row["rank_bucket"] for row in new_rows) != Counter(BUCKET_COUNTS):
        raise RuntimeError("R2 bucket count failure")
    if any(source[int(row["rank"])] != row["domain"] for row in new_rows):
        raise RuntimeError("R2 source provenance failure")
    write_tsv(NEW_POOL, list(new_rows[0]), new_rows)
    if sha(OLD_POOL) != OLD_POOL_SHA or sha(OLD_LEDGER) != OLD_LEDGER_SHA:
        raise RuntimeError("R1 history changed during R2 build")
    result = "\n".join((
        "REALISTIC_V3_R2_FINAL500_DOMAIN_POOL_READY",
        f"old_domain={OLD_DOMAIN}", f"old_rank={OLD_RANK}", f"old_bucket={OLD_BUCKET}",
        f"old_failure={OLD_FAILURE}", f"new_domain={NEW_DOMAIN}", f"new_rank={NEW_RANK}",
        "same_bucket=true", "actionability=3/3 PASS", "cross_mode_sanity=8/8 PASS",
        f"replacement_candidates_tested={len(records)}", f"replacement_candidates_rejected={len(records)-1}",
        "TOTAL=500", "A=350", "B=100", "C=50", "duplicate=0", "missing=0",
        f"formal_domain_pool_v3_r2_sha256={sha(NEW_POOL)}",
        f"domain_replacement_ledger_v3_r2_sha256={sha(NEW_LEDGER)}",
        f"historical_r1_pool_sha256={OLD_POOL_SHA}", f"historical_r1_ledger_sha256={OLD_LEDGER_SHA}", "",
    ))
    RESULT.write_text(result, encoding="utf-8")
    print(result, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
