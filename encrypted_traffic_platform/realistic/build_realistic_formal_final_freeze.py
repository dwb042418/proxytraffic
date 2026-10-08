#!/usr/bin/env python3
"""Build auditable metadata for the Realistic Formal final dataset freeze."""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import re
from collections import Counter, defaultdict
from pathlib import Path
from typing import Iterable


CANONICAL_INFRASTRUCTURE_ROOT_CAUSE = "UNRESOLVED_NONREPRODUCED_INFRASTRUCTURE_EVENT"
MODES = ("direct", "shadowsocks", "trojan", "vless")
METADATA_NAMES = (
    "final_dataset_manifest.tsv",
    "final_pair_group_manifest.tsv",
    "final_mode_counts.json",
    "final_attempt_retry_summary.json",
    "final_remote_integrity_summary.json",
    "final_failure_provenance_registry.tsv",
    "final_reacquisition_registry.tsv",
    "final_freeze_summary.json",
)


def load_json(path: Path) -> dict:
    return json.loads(path.read_text())


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def write_json(path: Path, value: object) -> None:
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")


def write_tsv(path: Path, fieldnames: list[str], rows: Iterable[dict]) -> None:
    with path.open("w", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames, delimiter="\t", lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows)


def nested_objects(value: object) -> Iterable[dict]:
    if isinstance(value, dict):
        yield value
        for child in value.values():
            yield from nested_objects(child)
    elif isinstance(value, list):
        for child in value:
            yield from nested_objects(child)


def eligible_rows(dataset_root: Path) -> list[dict]:
    rows = []
    for sample_root in (dataset_root / "samples").iterdir():
        if not sample_root.is_dir():
            continue
        metadata_path = sample_root / "sample_metadata.json"
        remote_path = sample_root / "remote_sha_verification.json"
        sample_complete_path = sample_root / "SAMPLE_COMPLETE"
        artifact_manifest_path = sample_root / "SHA256SUMS.txt"
        final_metadata_manifest_path = sample_root / "FINAL_METADATA_SHA256SUMS.txt"
        metadata = load_json(metadata_path)
        remote = load_json(remote_path)
        if metadata.get("formal_manifest_eligible") is not True:
            continue
        if metadata.get("final_result", {}).get("status") != "PASS":
            continue
        rows.append({
            "sequence_id": int(metadata["sequence_id"]),
            "sample_id": metadata["sample_id"],
            "pair_group_id": metadata["pair_group_id"],
            "mode": metadata["mode"],
            "split": metadata["split"],
            "intensity": metadata["intensity"],
            "plan_sha256": metadata["plan_sha256"],
            "final_attempt": metadata["final_attempt"],
            "attempt_count": metadata["attempt_count"],
            "final_status": metadata["final_result"]["status"],
            "formal_manifest_eligible": "true",
            "model_input": metadata["model_input"],
            "acquisition_instance": metadata.get("acquisition_instance", ""),
            "sample_metadata_path": str(metadata_path),
            "sample_metadata_sha256": sha256(metadata_path),
            "remote_verification_path": str(remote_path),
            "remote_verification_sha256": sha256(remote_path),
            "sample_complete_sha256": sha256(sample_complete_path),
            "artifact_sha256_manifest_path": str(artifact_manifest_path),
            "artifact_sha256_manifest_sha256": sha256(artifact_manifest_path),
            "final_metadata_sha256_manifest_path": str(final_metadata_manifest_path),
            "final_metadata_sha256_manifest_sha256": sha256(final_metadata_manifest_path),
            "remote_path": remote["remote_path"],
            "remote_upload_pass": str(remote.get("remote_upload_pass") is True).lower(),
            "remote_sha_pass": str(remote.get("remote_sha_pass") is True).lower(),
            "remote_completeness_pass": str(remote.get("remote_completeness_pass") is True).lower(),
            "remote_metadata_pass": str(remote.get("remote_metadata_pass") is True).lower(),
            "eligibility_disposition": "MODEL_ELIGIBLE_FINAL",
        })
    return sorted(rows, key=lambda row: row["sequence_id"])


def failure_rows(dataset_root: Path, provenance_root: Path, eligible: list[dict]) -> list[dict]:
    eligible_ids = {row["sample_id"] for row in eligible}
    rows = []
    seen = set()
    evidence_seen: set[Path] = set()
    relocated_attempts: dict[tuple[str, str], list[Path]] = defaultdict(list)
    if provenance_root.is_dir():
        for path in provenance_root.glob("**/failed_artifacts/*/attempt_*"):
            if path.is_dir():
                relocated_attempts[(path.parent.name, path.name)].append(path)

    def add_attempt(attempt: dict, source_path: Path, source_type: str) -> None:
        if attempt.get("final_status") != "FAIL":
            return
        artifact_value = attempt.get("artifact_path", "")
        if not artifact_value:
            raise SystemExit(
                f"AUDIT_FAIL failed-attempt artifact missing: {attempt.get('sample_id', '')} "
                f"{attempt.get('attempt', '')}"
            )
        artifact_path = Path(artifact_value)
        if not artifact_path.exists():
            candidates = relocated_attempts.get((attempt.get("sample_id", ""), artifact_path.name), [])
            if len(candidates) == 1:
                artifact_path = candidates[0]
            elif len(candidates) > 1:
                raise SystemExit(
                    f"AUDIT_FAIL ambiguous relocated failed-attempt artifact: {attempt.get('sample_id', '')}"
                )
        if not artifact_path.exists():
            raise SystemExit(
                f"AUDIT_FAIL failed-attempt artifact missing: {attempt.get('sample_id', '')} "
                f"{attempt.get('attempt', '')}"
            )
        key = (
            attempt.get("sample_id", ""),
            str(attempt.get("sequence_id", "")),
            str(attempt.get("attempt", "")),
            attempt.get("attempt_start_utc", ""),
            attempt.get("attempt_end_utc", ""),
            attempt.get("failure_class", ""),
        )
        if key in seen:
            return
        seen.add(key)
        rows.append({
            "record_type": "FAILED_ATTEMPT",
            "sample_id": attempt.get("sample_id", ""),
            "sequence_id": attempt.get("sequence_id", ""),
            "pair_group_id": attempt.get("pair_group_id", ""),
            "mode": attempt.get("mode", ""),
            "attempt": attempt.get("attempt", ""),
            "failure_class": attempt.get("failure_class", ""),
            "failure_stage": attempt.get("failure_stage", ""),
            "url": attempt.get("url", ""),
            "attempt_start_utc": attempt.get("attempt_start_utc", ""),
            "attempt_end_utc": attempt.get("attempt_end_utc", ""),
            "artifact_path": str(artifact_path),
            "source_record_type": source_type,
            "source_record_path": str(source_path),
            "source_record_sha256": sha256(source_path),
            "eligibility_disposition": (
                "FINAL_SAMPLE_RETRY_PROVENANCE" if attempt.get("sample_id") in eligible_ids
                else "PROVENANCE_ONLY_SUPERSEDED_ACQUISITION"
            ),
        })

    def add_evidence(path: Path) -> None:
        path = path.resolve()
        if path in evidence_seen or not path.is_file():
            return
        evidence_seen.add(path)
        rows.append({
            "record_type": "INFRASTRUCTURE_EVIDENCE",
            "sample_id": "",
            "sequence_id": "",
            "pair_group_id": "",
            "mode": "",
            "attempt": "",
            # Evidence is retained without assigning the campaign-level historical
            # root cause to each individual file.  That attribution remains scoped
            # to the freeze summary and is deliberately not broadened here.
            "failure_class": "",
            "failure_stage": "",
            "url": "",
            "attempt_start_utc": "",
            "attempt_end_utc": "",
            "artifact_path": str(path),
            "source_record_type": "REFERENCED_INFRASTRUCTURE_EVIDENCE",
            "source_record_path": str(path),
            "source_record_sha256": sha256(path),
            "eligibility_disposition": "PROVENANCE_ONLY_INFRASTRUCTURE_EVIDENCE",
        })

    def find_referenced_evidence(value: object, key: str = "") -> None:
        if isinstance(value, dict):
            for child_key, child in value.items():
                find_referenced_evidence(child, child_key)
        elif isinstance(value, list):
            for child in value:
                find_referenced_evidence(child, key)
        elif isinstance(value, str) and any(
            marker in key.lower() for marker in ("diagnostic", "evidence", "recovery", "process_hook")
        ):
            add_evidence(Path(value))

    for activation_path in sorted((dataset_root / "acquisitions").glob("*/activation.json")):
        activation = load_json(activation_path)
        for candidate in nested_objects(activation):
            if candidate.get("final_status") == "FAIL" and candidate.get("sample_id"):
                add_attempt(candidate, activation_path, "REACQUISITION_ACTIVATION")
        find_referenced_evidence(activation)
    ledger_paths = set(dataset_root.rglob("*retry_ledger*.tsv"))
    if provenance_root.is_dir():
        ledger_paths.update(provenance_root.rglob("*retry_ledger*.tsv"))
    for ledger_path in sorted(ledger_paths):
        for attempt in read_tsv(ledger_path):
            add_attempt(attempt, ledger_path, "RETRY_LEDGER")
    for pattern in (
        "boundary_recovery_*.json",
        "*recovery_state.json",
        "post*_recovery.json",
        "revision_hard_stop*.json",
    ):
        for evidence_path in sorted(dataset_root.glob(pattern)):
            add_evidence(evidence_path)
    return sorted(
        rows,
        key=lambda row: (
            row["record_type"], int(row["sequence_id"] or 0), row["sample_id"],
            int(row["attempt"] or 0), row["attempt_start_utc"], row["artifact_path"]
        ),
    )


def pair_group_rows(eligible: list[dict]) -> list[dict]:
    grouped = defaultdict(list)
    for row in eligible:
        grouped[row["pair_group_id"]].append(row)
    rows = []
    for pair_group_id, members in sorted(grouped.items(), key=lambda item: min(r["sequence_id"] for r in item[1])):
        members.sort(key=lambda row: row["sequence_id"])
        modes = {row["mode"] for row in members}
        by_mode = {row["mode"]: row for row in members}
        rows.append({
            "pair_group_id": pair_group_id,
            "sequence_ids": ",".join(str(row["sequence_id"]) for row in members),
            "sample_ids": ",".join(row["sample_id"] for row in members),
            "mode_count": len(modes),
            "modes": ",".join(sorted(modes)),
            "direct_sample_id": by_mode.get("direct", {}).get("sample_id", ""),
            "vless_sample_id": by_mode.get("vless", {}).get("sample_id", ""),
            "shadowsocks_sample_id": by_mode.get("shadowsocks", {}).get("sample_id", ""),
            "trojan_sample_id": by_mode.get("trojan", {}).get("sample_id", ""),
            "complete_four_mode_group": str(len(members) == 4 and modes == set(MODES)).lower(),
        })
    return rows


def reacquisition_rows(dataset_root: Path, eligible: list[dict]) -> list[dict]:
    eligible_by_instance = defaultdict(list)
    for row in eligible:
        if row["acquisition_instance"]:
            eligible_by_instance[row["acquisition_instance"]].append(row)
    rows = []
    for activation_path in sorted((dataset_root / "acquisitions").glob("*/activation.json")):
        activation = load_json(activation_path)
        instance = activation.get("acquisition_instance", activation_path.parent.name)
        members = sorted(eligible_by_instance.get(instance, []), key=lambda row: row["sequence_id"])
        rows.append({
            "acquisition_instance": instance,
            "group": activation.get("group", ""),
            "rule": activation.get("rule", ""),
            "status": activation.get("status", ""),
            "reacquisition_number": activation.get("reacquisition_number", ""),
            "eligible_sequence_ids": ",".join(str(row["sequence_id"]) for row in members),
            "eligible_sample_ids": ",".join(row["sample_id"] for row in members),
            "activation_path": str(activation_path),
            "activation_sha256": sha256(activation_path),
            "historical_attempt_count": sum(
                candidate.get("final_status") in {"PASS", "FAIL"} and candidate.get("sample_id") is not None
                for candidate in nested_objects(activation)
            ),
            "eligibility_disposition": "ELIGIBLE_REACQUISITION" if members else "HISTORICAL_REACQUISITION_PROVENANCE",
        })
    datasets_root = next((parent for parent in dataset_root.parents if parent.name == "datasets"), None)
    diagnostics_root = datasets_root / "diagnostics" if datasets_root else dataset_root.parent / "diagnostics"
    if diagnostics_root.is_dir():
        for diagnostic_root in sorted(diagnostics_root.glob("*pair_group_*reacquisition*")):
            if not diagnostic_root.is_dir():
                continue
            match = re.search(r"pair_group_(\d+)", diagnostic_root.name)
            source = diagnostic_root / "diagnostic_result.json"
            if not source.is_file():
                source = diagnostic_root / "NON_FORMAL_FINAL_DATASET_INELIGIBLE"
            if not source.is_file():
                continue
            rows.append({
                "acquisition_instance": diagnostic_root.name,
                "group": int(match.group(1)) if match else "",
                "rule": "NON_FORMAL_REACQUISITION_DIAGNOSTIC",
                "status": "NON_FORMAL_FINAL_DATASET_INELIGIBLE",
                "reacquisition_number": "",
                "eligible_sequence_ids": "",
                "eligible_sample_ids": "",
                "activation_path": str(source),
                "activation_sha256": sha256(source),
                "historical_attempt_count": "",
                "eligibility_disposition": "PROVENANCE_ONLY_DIAGNOSTIC",
            })
    return rows


def read_tsv(path: Path) -> list[dict[str, str]]:
    with path.open(newline="") as handle:
        return list(csv.DictReader(handle, delimiter="\t"))


def reject_duplicate_sequences(eligible: list[dict]) -> None:
    counts = Counter(row["sequence_id"] for row in eligible)
    duplicates = sorted(sequence_id for sequence_id, count in counts.items() if count != 1)
    if duplicates:
        raise SystemExit(f"AUDIT_FAIL duplicate sequence_id: {duplicates[0]}")


def reject_incomplete_pair_groups(groups: list[dict]) -> None:
    for group in groups:
        if group["complete_four_mode_group"] != "true":
            raise SystemExit(
                f"AUDIT_FAIL pair group {group['pair_group_id']} does not contain exactly four modes"
            )


def reject_failed_remote_audit(remote_audit: dict, eligible_count: int) -> None:
    if remote_audit.get("status") != "PASS":
        raise SystemExit("AUDIT_FAIL remote independent audit is not PASS")
    required_counts = (
        remote_audit.get("expected_samples"),
        remote_audit.get("audited_samples"),
        remote_audit.get("remote_sample_directories"),
        remote_audit.get("control_sha_pass"),
        remote_audit.get("referenced_artifacts_present"),
        remote_audit.get("remote_metadata_pass"),
    )
    if (
        any(value != eligible_count for value in required_counts)
        or remote_audit.get("issue_count") != 0
        or remote_audit.get("issues")
    ):
        raise SystemExit("AUDIT_FAIL remote independent audit count or issue mismatch")


def reject_required_recovery(eligible: list[dict], failures: list[dict]) -> None:
    expected_sequences = (1173, 1174, 1175, 1176)
    expected_instance = "pair_group_0294_isolated_recovery1"
    recovery = sorted(
        (row for row in eligible if row["sequence_id"] in expected_sequences),
        key=lambda row: row["sequence_id"],
    )
    expected_ids = [
        f"formal_t0_v3_sample{sequence:04d}_{expected_instance}"
        for sequence in expected_sequences
    ]
    if (
        [row["sequence_id"] for row in recovery] != list(expected_sequences)
        or [row["sample_id"] for row in recovery] != expected_ids
        or any(row["acquisition_instance"] != expected_instance for row in recovery)
        or len({row["pair_group_id"] for row in recovery}) != 1
    ):
        raise SystemExit("AUDIT_FAIL required 1173-1176 recovery quartet mismatch")
    historical = [
        row for row in failures
        if row["record_type"] == "FAILED_ATTEMPT"
        and row["sample_id"] == "formal_t0_v3_sample1176"
    ]
    if not historical:
        raise SystemExit("AUDIT_FAIL sample1176 historical failure provenance missing")
    if any(
        row["eligibility_disposition"] != "PROVENANCE_ONLY_SUPERSEDED_ACQUISITION"
        for row in historical
    ):
        raise SystemExit("AUDIT_FAIL sample1176 historical failure is not provenance-only")


def reject_campaign_mismatches(
    campaign: dict, eligible: list[dict], groups: list[dict], active_ledger: list[dict[str, str]]
) -> None:
    eligible_count = len(eligible)
    if eligible_count != campaign.get("VALID_SAMPLES"):
        raise SystemExit(
            f"AUDIT_FAIL eligible sample count {eligible_count} != campaign {campaign.get('VALID_SAMPLES')}"
        )
    if len(groups) != campaign.get("COMPLETE_PAIR_GROUPS"):
        raise SystemExit("AUDIT_FAIL complete pair-group count mismatch")
    sample_ids = [row["sample_id"] for row in eligible]
    duplicate_ids = sorted(sample_id for sample_id, count in Counter(sample_ids).items() if count != 1)
    if duplicate_ids:
        raise SystemExit(f"AUDIT_FAIL duplicate sample_id: {duplicate_ids[0]}")
    counts = Counter(row["mode"] for row in eligible)
    expected_mode_counts = {mode: eligible_count // 4 for mode in MODES}
    if dict(counts) != expected_mode_counts or campaign.get("mode_counts") != expected_mode_counts:
        raise SystemExit("AUDIT_FAIL mode counts do not match exact four-mode balance")
    if any(
        row["formal_manifest_eligible"] != "true"
        or row["model_input"] != "observed.pcap"
        or row["final_status"] != "PASS"
        or row["remote_upload_pass"] != "true"
        or row["remote_sha_pass"] != "true"
        or row["remote_completeness_pass"] != "true"
        or row["remote_metadata_pass"] != "true"
        for row in eligible
    ):
        raise SystemExit("AUDIT_FAIL final sample eligibility or remote receipt mismatch")
    pass_rows = [row for row in active_ledger if row.get("final_status") == "PASS"]
    if len(active_ledger) != campaign.get("FINAL_DATASET_ACQUISITION_ATTEMPTS"):
        raise SystemExit("AUDIT_FAIL active final-dataset ledger row count mismatch")
    if Counter(row.get("sample_id") for row in pass_rows) != Counter(sample_ids):
        raise SystemExit("AUDIT_FAIL active ledger PASS membership differs from final eligible manifest")
    expected_scalars = {
        "PASS_MARKER": "REALISTIC_FORMAL_FINAL_COLLECTION_PASS",
        "REMOTE_COMPLETE": f"{eligible_count}/{eligible_count}",
        "REMOTE_INTEGRITY": "PASS",
        "REMOTE_SHA_PASS": eligible_count,
        "INTEGRITY_ISSUES": 0,
        "FINAL_DATASET_ELIGIBLE": True,
        "FINAL_METADATA": "PASS",
        "HISTORICAL_INFRASTRUCTURE_EVENT": CANONICAL_INFRASTRUCTURE_ROOT_CAUSE,
    }
    for key, expected in expected_scalars.items():
        if campaign.get(key) != expected:
            raise SystemExit(f"AUDIT_FAIL campaign {key} mismatch")


def build(args: argparse.Namespace) -> None:
    dataset_root = args.dataset_root.resolve()
    output_dir = args.output_dir.resolve()
    campaign = load_json(dataset_root / "campaign_result.json")
    remote_audit = load_json(args.remote_audit_result)
    eligible = eligible_rows(dataset_root)
    reject_duplicate_sequences(eligible)
    failures = failure_rows(dataset_root, args.provenance_root.resolve(), eligible)
    reject_required_recovery(eligible, failures)
    groups = pair_group_rows(eligible)
    reject_incomplete_pair_groups(groups)
    reacquisitions = reacquisition_rows(dataset_root, eligible)
    active_ledger = read_tsv(Path(campaign["ACTIVE_RETRY_LEDGER"]))
    reject_campaign_mismatches(campaign, eligible, groups, active_ledger)
    reject_failed_remote_audit(remote_audit, len(eligible))
    output_dir.mkdir(parents=True, exist_ok=False)

    dataset_fields = list(eligible[0])
    write_tsv(output_dir / "final_dataset_manifest.tsv", dataset_fields, eligible)
    write_tsv(output_dir / "final_pair_group_manifest.tsv", list(groups[0]), groups)
    counts = Counter(row["mode"] for row in eligible)
    write_json(output_dir / "final_mode_counts.json", {
        "counts": {mode: counts[mode] for mode in MODES},
        "expected_per_mode": campaign["VALID_SAMPLES"] // 4,
        "status": "PASS",
    })
    write_json(output_dir / "final_attempt_retry_summary.json", {
        "TOTAL_ATTEMPTS": campaign["TOTAL_ATTEMPTS"],
        "TOTAL_RETRIES": campaign["TOTAL_RETRIES"],
        "RETRY_COUNT": campaign["RETRY_COUNT"],
        "FINAL_DATASET_ACQUISITION_ATTEMPTS": campaign["FINAL_DATASET_ACQUISITION_ATTEMPTS"],
        "HISTORICAL_ACQUISITION_ATTEMPTS": campaign["HISTORICAL_ACQUISITION_ATTEMPTS"],
        "active_final_dataset_ledger_rows": len(active_ledger),
        "active_final_dataset_failed_attempt_rows": sum(row["final_status"] == "FAIL" for row in active_ledger),
        "active_final_dataset_pass_rows": sum(row["final_status"] == "PASS" for row in active_ledger),
        "status": "PASS",
    })
    write_json(output_dir / "final_remote_integrity_summary.json", {
        **remote_audit,
        "campaign_REMOTE_COMPLETE": campaign["REMOTE_COMPLETE"],
        "campaign_REMOTE_INTEGRITY": campaign["REMOTE_INTEGRITY"],
        "campaign_REMOTE_SHA_PASS": campaign["REMOTE_SHA_PASS"],
        "local_remote_receipts_pass": sum(
            row["remote_sha_pass"] == "true" and row["remote_completeness_pass"] == "true"
            for row in eligible
        ),
    })
    failure_fields = list(failures[0])
    write_tsv(output_dir / "final_failure_provenance_registry.tsv", failure_fields, failures)
    write_tsv(output_dir / "final_reacquisition_registry.tsv", list(reacquisitions[0]), reacquisitions)
    sample1176_eligible = next((row for row in eligible if row["sequence_id"] == 1176), None)
    sample1176_group = (
        [row for row in eligible if row["pair_group_id"] == sample1176_eligible["pair_group_id"]]
        if sample1176_eligible else []
    )
    exclusion_audit = {
        "diagnostic_artifacts_in_eligible_manifest": sum(
            "/diagnostics/" in row["sample_metadata_path"] for row in eligible
        ),
        "historical_failed_attempts_in_eligible_manifest": sum(
            row["final_status"] != "PASS" for row in eligible
        ),
        "provenance_only_artifacts_in_eligible_manifest": sum(
            row["eligibility_disposition"] != "MODEL_ELIGIBLE_FINAL" for row in eligible
        ),
        "superseded_acquisitions_in_eligible_manifest": sum(
            row["sample_id"] not in {ledger_row["sample_id"] for ledger_row in active_ledger
                                     if ledger_row["final_status"] == "PASS"}
            for row in eligible
        ),
        "status": "PASS",
    }
    write_json(output_dir / "final_freeze_summary.json", {
        "audit_status": "PASS",
        "campaign_id": campaign["campaign_id"],
        "dataset_track": campaign["dataset_track"],
        "freeze_utc": args.freeze_utc,
        "PASS_MARKER": campaign["PASS_MARKER"],
        "eligible_samples": len(eligible),
        "valid_samples": len(eligible),
        "complete_pair_groups": len(groups),
        "exact_modes_per_pair_group": 4,
        "duplicate_sequence_memberships": 0,
        "duplicate_sample_memberships": 0,
        "duplicate_pair_mode_memberships": 0,
        "mode_counts": {mode: counts[mode] for mode in MODES},
        "remote_complete": campaign["REMOTE_COMPLETE"],
        "remote_independent_integrity": remote_audit["status"],
        "integrity_issues": campaign["INTEGRITY_ISSUES"] + len(remote_audit.get("issues", [])),
        "total_attempts": campaign["TOTAL_ATTEMPTS"],
        "retries": campaign["TOTAL_RETRIES"],
        "remote_audit_status": remote_audit["status"],
        "HISTORICAL_INFRASTRUCTURE_ROOT_CAUSE": CANONICAL_INFRASTRUCTURE_ROOT_CAUSE,
        "failure_provenance_records": sum(row["record_type"] == "FAILED_ATTEMPT" for row in failures),
        "infrastructure_evidence_records": sum(
            row["record_type"] == "INFRASTRUCTURE_EVIDENCE" for row in failures
        ),
        "reacquisition_registry_records": len(reacquisitions),
        "exclusion_audit": exclusion_audit,
        "sample1176": {
            "historical_sample_id": "formal_t0_v3_sample1176",
            "historical_sample_disposition": "PROVENANCE_ONLY",
            "eligible_sample_id": sample1176_eligible["sample_id"] if sample1176_eligible else "",
            "eligible_quartet_sequences": sorted(row["sequence_id"] for row in sample1176_group),
            "eligible_acquisition_instance": (
                sample1176_eligible["acquisition_instance"] if sample1176_eligible else ""
            ),
        },
        "source_campaign_result": str(dataset_root / "campaign_result.json"),
        "source_campaign_result_sha256": sha256(dataset_root / "campaign_result.json"),
        "source_active_retry_ledger": campaign["ACTIVE_RETRY_LEDGER"],
        "source_active_retry_ledger_sha256": sha256(Path(campaign["ACTIVE_RETRY_LEDGER"])),
        "immutability": "SHA256_REGISTRY_PLUS_LOCAL_GIT_COMMIT_AND_ANNOTATED_TAG",
        "feature_extraction_status": "NOT_STARTED",
        "model_training_status": "NOT_STARTED",
    })
    (output_dir / "FINAL_FREEZE_METADATA_SHA256SUMS.txt").write_text("".join(
        f"{sha256(output_dir / name)}  {name}\n" for name in METADATA_NAMES
    ))


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--dataset-root", type=Path, required=True)
    parser.add_argument("--provenance-root", type=Path, required=True)
    parser.add_argument("--remote-audit-result", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--freeze-utc", required=True)
    return parser.parse_args()


if __name__ == "__main__":
    build(parse_args())
