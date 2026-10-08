#!/usr/bin/env python3
"""Synthetic tests for the Realistic Formal final-freeze builder."""

from __future__ import annotations

import csv
import hashlib
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


SOURCE_DIR = Path(__file__).resolve().parent
if SOURCE_DIR.name == "__pycache__":
    SOURCE_DIR = SOURCE_DIR.parent
BUILDER = SOURCE_DIR / "build_realistic_formal_final_freeze.py"
MODES = ("vless", "shadowsocks", "trojan", "direct")


def write_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")


class FinalFreezeBuilderTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="NON_FORMAL_final_freeze_")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.dataset = self.root / "dataset"
        self.provenance = self.root / "provenance"
        self.output = self.root / "freeze"
        self.ledger = self.dataset / "active_retry_ledger.tsv"
        self.dataset.mkdir()
        self.provenance.mkdir()

        sample_ids = []
        for offset, mode in enumerate(MODES, start=1173):
            sample_id = f"formal_t0_v3_sample{offset:04d}_pair_group_0294_isolated_recovery1"
            sample_ids.append(sample_id)
            sample = self.dataset / "samples" / sample_id
            sample.mkdir(parents=True)
            write_json(sample / "sample_metadata.json", {
                "sample_id": sample_id,
                "sequence_id": offset,
                "campaign_sequence_id": offset,
                "source_schedule_sequence_id": offset,
                "pair_group_id": "seed098_heavy",
                "source_pair_group_id": "seed098_heavy",
                "mode": mode,
                "split": "test",
                "intensity": "heavy",
                "plan_sha256": "a" * 64,
                "source_plan_sha": "a" * 64,
                "formal_manifest_eligible": True,
                "model_input": "observed.pcap",
                "attempt_count": 1,
                "final_attempt": 1,
                "final_result": {"status": "PASS", "mode": mode},
                "acquisition_instance": "pair_group_0294_isolated_recovery1",
                "historical_acquisition_record": str(
                    self.dataset / "acquisitions/pair_group_0294_isolated_recovery1/activation.json"
                ),
            })
            write_json(sample / "remote_sha_verification.json", {
                "sample_id": sample_id,
                "remote_path": f"/remote/samples/{sample_id}",
                "remote_upload_pass": True,
                "remote_sha_pass": True,
                "remote_completeness_pass": True,
                "remote_metadata_pass": True,
                "verified_utc": "2026-10-07T09:12:29Z",
            })
            (sample / "SAMPLE_COMPLETE").write_text("SAMPLE_COMPLETE\n")
            (sample / "SHA256SUMS.txt").write_text("fixture\n")
            (sample / "FINAL_METADATA_SHA256SUMS.txt").write_text("fixture\n")

        header = [
            "sample_id", "sequence_id", "pair_group_id", "mode", "attempt",
            "failure_class", "event_index", "url", "retry_authorized", "retry_reason",
            "failure_stage", "workload_started", "mode_purity", "bypass_observed",
            "plan_sha", "git_head", "attempt_start_utc", "attempt_end_utc",
            "browser_attempt_consumed", "final_status", "artifact_path",
            "campaign_sequence_id", "source_schedule_sequence_id", "source_pair_group_id",
            "source_plan_id", "source_plan_sha", "campaign_manifest_sha",
        ]
        with self.ledger.open("w", newline="") as handle:
            writer = csv.DictWriter(handle, fieldnames=header, delimiter="\t")
            writer.writeheader()
            for offset, (sample_id, mode) in enumerate(zip(sample_ids, MODES), start=1173):
                writer.writerow({
                    "sample_id": sample_id,
                    "sequence_id": offset,
                    "pair_group_id": "seed098_heavy",
                    "mode": mode,
                    "attempt": 1,
                    "retry_authorized": "false",
                    "retry_reason": "ATTEMPT_PASS",
                    "workload_started": "true",
                    "mode_purity": "PASS",
                    "bypass_observed": "false",
                    "plan_sha": "a" * 64,
                    "final_status": "PASS",
                    "artifact_path": str(self.dataset / "samples" / sample_id / "attempts/attempt_1"),
                    "campaign_sequence_id": offset,
                    "source_schedule_sequence_id": offset,
                    "source_pair_group_id": "seed098_heavy",
                    "source_plan_sha": "a" * 64,
                })

        old_failure = {
            "sample_id": "formal_t0_v3_sample1176",
            "sequence_id": "1176",
            "pair_group_id": "seed098_heavy",
            "mode": "direct",
            "attempt": "1",
            "failure_class": "ACTION_TIMEOUT",
            "event_index": "2",
            "url": "https://yandex.ru/",
            "retry_authorized": "false",
            "retry_reason": "NON_RETRYABLE_FAILURE_CLASS:ACTION_TIMEOUT",
            "failure_stage": "SCROLL_0_START",
            "workload_started": "true",
            "mode_purity": "PASS",
            "bypass_observed": "false",
            "plan_sha": "a" * 64,
            "git_head": "b" * 40,
            "attempt_start_utc": "2026-10-07T08:07:35Z",
            "attempt_end_utc": "2026-10-07T08:08:46Z",
            "browser_attempt_consumed": "true",
            "final_status": "FAIL",
            "artifact_path": str(
                self.provenance / "pair_group_0294_isolated_recovery1/original_acquisition/"
                "failed_artifacts/formal_t0_v3_sample1176/attempt_1_ACTION_TIMEOUT"
            ),
            "campaign_sequence_id": "1176",
            "source_schedule_sequence_id": "1176",
            "source_pair_group_id": "seed098_heavy",
            "source_plan_id": "formal_t0_v3_seed098_heavy",
            "source_plan_sha": "a" * 64,
            "campaign_manifest_sha": "c" * 64,
        }
        Path(old_failure["artifact_path"]).mkdir(parents=True)
        acquisition = self.dataset / "acquisitions/pair_group_0294_isolated_recovery1"
        write_json(acquisition / "activation.json", {
            "acquisition_instance": "pair_group_0294_isolated_recovery1",
            "campaign_id": "t0_v3_r11",
            "group": 294,
            "rule": "PAIR_GROUP_REACQUISITION_AFTER_CLEAN_NONRETRYABLE_NONREPRODUCIBLE_FAILURE",
            "status": "ACTIVE",
            "reacquisition_number": 1,
            "original_attempts": [old_failure],
            "new_rows": [{"schedule_id": value} for value in sample_ids],
        })
        write_json(self.dataset / "campaign_result.json", {
            "campaign_id": "t0_v3_r11",
            "dataset_track": "REALISTIC_FORMAL_T0_V3_R11",
            "artifact_class": "FORMAL_PRODUCTION",
            "PASS_MARKER": "REALISTIC_FORMAL_FINAL_COLLECTION_PASS",
            "VALID_SAMPLES": 4,
            "COMPLETE_PAIR_GROUPS": 1,
            "mode_counts": {mode: 1 for mode in MODES},
            "REMOTE_COMPLETE": "4/4",
            "REMOTE_INTEGRITY": "PASS",
            "REMOTE_SHA_PASS": 4,
            "INTEGRITY_ISSUES": 0,
            "TOTAL_ATTEMPTS": 5,
            "TOTAL_RETRIES": 0,
            "RETRY_COUNT": 0,
            "FINAL_DATASET_ACQUISITION_ATTEMPTS": 4,
            "HISTORICAL_ACQUISITION_ATTEMPTS": 1,
            "HISTORICAL_INFRASTRUCTURE_EVENT": "UNRESOLVED_NONREPRODUCED_INFRASTRUCTURE_EVENT",
            "FINAL_DATASET_ELIGIBLE": True,
            "FINAL_METADATA": "PASS",
            "ACTIVE_RETRY_LEDGER": str(self.ledger),
        })
        write_json(self.root / "remote_audit.json", {
            "status": "PASS",
            "audited_samples": 4,
            "expected_samples": 4,
            "remote_sample_directories": 4,
            "control_sha_pass": 4,
            "referenced_artifacts_present": 4,
            "remote_metadata_pass": 4,
            "issue_count": 0,
            "issues": [],
            "method": "synthetic immutable receipt audit",
            "audited_utc": "2026-10-08T00:00:00Z",
        })

    def run_builder(self) -> subprocess.CompletedProcess[str]:
        return subprocess.run([
            sys.executable,
            str(BUILDER),
            "--dataset-root", str(self.dataset),
            "--provenance-root", str(self.provenance),
            "--remote-audit-result", str(self.root / "remote_audit.json"),
            "--output-dir", str(self.output),
            "--freeze-utc", "2026-10-08T00:00:00Z",
        ], text=True, capture_output=True)

    def test_superseded_failure_stays_provenance_only(self) -> None:
        """Catches a builder that admits an old failed sample after reacquisition."""
        result = self.run_builder()
        self.assertEqual(result.returncode, 0, result.stderr)

        with (self.output / "final_dataset_manifest.tsv").open(newline="") as handle:
            eligible = list(csv.DictReader(handle, delimiter="\t"))
        self.assertEqual(len(eligible), 4)
        self.assertEqual(
            [row["sample_id"] for row in eligible],
            [
                "formal_t0_v3_sample1173_pair_group_0294_isolated_recovery1",
                "formal_t0_v3_sample1174_pair_group_0294_isolated_recovery1",
                "formal_t0_v3_sample1175_pair_group_0294_isolated_recovery1",
                "formal_t0_v3_sample1176_pair_group_0294_isolated_recovery1",
            ],
        )
        self.assertNotIn("formal_t0_v3_sample1176", {row["sample_id"] for row in eligible})
        self.assertEqual(eligible[0].get("remote_metadata_pass"), "true")
        self.assertEqual(len(eligible[0].get("sample_complete_sha256", "")), 64)
        self.assertEqual(len(eligible[0].get("artifact_sha256_manifest_sha256", "")), 64)
        self.assertEqual(len(eligible[0].get("final_metadata_sha256_manifest_sha256", "")), 64)

        with (self.output / "final_failure_provenance_registry.tsv").open(newline="") as handle:
            failures = list(csv.DictReader(handle, delimiter="\t"))
        old = [row for row in failures if row["sample_id"] == "formal_t0_v3_sample1176"]
        self.assertEqual(len(old), 1)
        self.assertEqual(old[0]["eligibility_disposition"], "PROVENANCE_ONLY_SUPERSEDED_ACQUISITION")

        summary = json.loads((self.output / "final_freeze_summary.json").read_text())
        self.assertEqual(summary["audit_status"], "PASS")
        self.assertEqual(
            summary["HISTORICAL_INFRASTRUCTURE_ROOT_CAUSE"],
            "UNRESOLVED_NONREPRODUCED_INFRASTRUCTURE_EVENT",
        )

    def test_writes_complete_hashed_freeze_metadata_set(self) -> None:
        """Catches an incomplete freeze or a registry that omits metadata."""
        result = self.run_builder()
        self.assertEqual(result.returncode, 0, result.stderr)

        metadata_names = {
            "final_dataset_manifest.tsv",
            "final_pair_group_manifest.tsv",
            "final_mode_counts.json",
            "final_attempt_retry_summary.json",
            "final_remote_integrity_summary.json",
            "final_failure_provenance_registry.tsv",
            "final_reacquisition_registry.tsv",
            "final_freeze_summary.json",
        }
        self.assertEqual(
            {path.name for path in self.output.iterdir()},
            metadata_names | {"FINAL_FREEZE_METADATA_SHA256SUMS.txt"},
        )

        with (self.output / "final_pair_group_manifest.tsv").open(newline="") as handle:
            groups = list(csv.DictReader(handle, delimiter="\t"))
        self.assertEqual(len(groups), 1)
        self.assertEqual(groups[0]["pair_group_id"], "seed098_heavy")
        self.assertEqual(groups[0]["sequence_ids"], "1173,1174,1175,1176")
        self.assertEqual(groups[0]["mode_count"], "4")
        self.assertEqual(groups[0]["complete_four_mode_group"], "true")

        mode_counts = json.loads((self.output / "final_mode_counts.json").read_text())
        self.assertEqual(mode_counts["counts"], {mode: 1 for mode in sorted(MODES)})
        self.assertEqual(mode_counts["status"], "PASS")

        attempts = json.loads((self.output / "final_attempt_retry_summary.json").read_text())
        self.assertEqual(attempts["TOTAL_ATTEMPTS"], 5)
        self.assertEqual(attempts["TOTAL_RETRIES"], 0)
        self.assertEqual(attempts["active_final_dataset_ledger_rows"], 4)

        remote = json.loads((self.output / "final_remote_integrity_summary.json").read_text())
        self.assertEqual(remote["status"], "PASS")
        self.assertEqual(remote["audited_samples"], 4)

        with (self.output / "final_reacquisition_registry.tsv").open(newline="") as handle:
            reacquisitions = list(csv.DictReader(handle, delimiter="\t"))
        self.assertEqual(len(reacquisitions), 1)
        self.assertEqual(reacquisitions[0]["acquisition_instance"], "pair_group_0294_isolated_recovery1")
        self.assertEqual(reacquisitions[0]["eligible_sequence_ids"], "1173,1174,1175,1176")

        registry = {}
        for line in (self.output / "FINAL_FREEZE_METADATA_SHA256SUMS.txt").read_text().splitlines():
            digest, name = line.split(maxsplit=1)
            registry[name] = digest
        self.assertEqual(set(registry), metadata_names)
        for name, digest in registry.items():
            self.assertEqual(hashlib.sha256((self.output / name).read_bytes()).hexdigest(), digest)

        summary = json.loads((self.output / "final_freeze_summary.json").read_text())
        expected_summary = {
            "valid_samples": 4,
            "complete_pair_groups": 1,
            "exact_modes_per_pair_group": 4,
            "duplicate_sequence_memberships": 0,
            "duplicate_sample_memberships": 0,
            "duplicate_pair_mode_memberships": 0,
            "mode_counts": {mode: 1 for mode in sorted(MODES)},
            "remote_complete": "4/4",
            "remote_independent_integrity": "PASS",
            "integrity_issues": 0,
            "total_attempts": 5,
            "retries": 0,
        }
        self.assertEqual({key: summary.get(key) for key in expected_summary}, expected_summary)
        self.assertEqual(summary.get("exclusion_audit"), {
            "diagnostic_artifacts_in_eligible_manifest": 0,
            "historical_failed_attempts_in_eligible_manifest": 0,
            "provenance_only_artifacts_in_eligible_manifest": 0,
            "superseded_acquisitions_in_eligible_manifest": 0,
            "status": "PASS",
        })
        sample1176 = summary.get("sample1176", {})
        self.assertEqual(sample1176.get("historical_sample_disposition"), "PROVENANCE_ONLY")
        self.assertEqual(sample1176.get("eligible_sample_id"),
                         "formal_t0_v3_sample1176_pair_group_0294_isolated_recovery1")
        self.assertEqual(sample1176.get("eligible_quartet_sequences"), [1173, 1174, 1175, 1176])

    def test_rejects_duplicate_sequences_before_writing_freeze(self) -> None:
        """Catches duplicate final membership hidden behind distinct sample IDs."""
        sample = self.dataset / "samples/formal_t0_v3_sample1174_pair_group_0294_isolated_recovery1"
        metadata_path = sample / "sample_metadata.json"
        metadata = json.loads(metadata_path.read_text())
        metadata["sequence_id"] = 1173
        write_json(metadata_path, metadata)

        result = self.run_builder()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("duplicate sequence_id: 1173", result.stderr)
        self.assertFalse(self.output.exists())

    def test_rejects_pair_group_without_exactly_four_modes(self) -> None:
        """Catches a quartet containing a duplicated mode and a missing mode."""
        sample = self.dataset / "samples/formal_t0_v3_sample1174_pair_group_0294_isolated_recovery1"
        metadata_path = sample / "sample_metadata.json"
        metadata = json.loads(metadata_path.read_text())
        metadata["mode"] = "vless"
        metadata["final_result"]["mode"] = "vless"
        write_json(metadata_path, metadata)

        result = self.run_builder()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("pair group seed098_heavy does not contain exactly four modes", result.stderr)
        self.assertFalse(self.output.exists())

    def test_rejects_failed_remote_independent_audit(self) -> None:
        """Catches a local freeze that ignores a failed remote audit."""
        remote_path = self.root / "remote_audit.json"
        remote = json.loads(remote_path.read_text())
        remote["status"] = "FAIL"
        remote["issues"] = ["remote control mismatch"]
        write_json(remote_path, remote)

        result = self.run_builder()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("remote independent audit is not PASS", result.stderr)
        self.assertFalse(self.output.exists())

    def test_rejects_incomplete_remote_independent_audit_counts(self) -> None:
        """Catches a PASS label whose independent remote counts are incomplete."""
        remote_path = self.root / "remote_audit.json"
        remote = json.loads(remote_path.read_text())
        remote["remote_metadata_pass"] = 3
        write_json(remote_path, remote)

        result = self.run_builder()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("remote independent audit count or issue mismatch", result.stderr)
        self.assertFalse(self.output.exists())

    def test_rejects_campaign_count_mismatch(self) -> None:
        """Catches a freeze whose recomputed eligibility contradicts campaign totals."""
        campaign_path = self.dataset / "campaign_result.json"
        campaign = json.loads(campaign_path.read_text())
        campaign["VALID_SAMPLES"] = 5
        campaign["REMOTE_COMPLETE"] = "5/5"
        campaign["REMOTE_SHA_PASS"] = 5
        write_json(campaign_path, campaign)

        result = self.run_builder()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("eligible sample count 4 != campaign 5", result.stderr)
        self.assertFalse(self.output.exists())

    def test_registers_active_retry_failure_as_noneligible_provenance(self) -> None:
        """Catches loss of failed-attempt provenance from the active final ledger."""
        with self.ledger.open(newline="") as handle:
            rows = list(csv.DictReader(handle, delimiter="\t"))
            fieldnames = list(rows[0])
        failure = dict(rows[0])
        failure.update({
            "attempt": "0",
            "failure_class": "MAIN_NAVIGATION_TIMEOUT",
            "failure_stage": "NAVIGATION",
            "retry_authorized": "true",
            "retry_reason": "AUTHORIZED_TRANSIENT:MAIN_NAVIGATION_TIMEOUT",
            "final_status": "FAIL",
            "artifact_path": str(self.dataset / "failed_artifacts" / failure["sample_id"] / "attempt_0"),
            "attempt_start_utc": "2026-10-07T09:00:00Z",
            "attempt_end_utc": "2026-10-07T09:01:00Z",
        })
        Path(failure["artifact_path"]).mkdir(parents=True)
        with self.ledger.open("w", newline="") as handle:
            writer = csv.DictWriter(handle, fieldnames=fieldnames, delimiter="\t", lineterminator="\n")
            writer.writeheader()
            writer.writerow(failure)
            writer.writerows(rows)
        campaign_path = self.dataset / "campaign_result.json"
        campaign = json.loads(campaign_path.read_text())
        campaign["FINAL_DATASET_ACQUISITION_ATTEMPTS"] = 5
        campaign["TOTAL_ATTEMPTS"] = 6
        campaign["TOTAL_RETRIES"] = 1
        campaign["RETRY_COUNT"] = 1
        write_json(campaign_path, campaign)

        result = self.run_builder()
        self.assertEqual(result.returncode, 0, result.stderr)
        with (self.output / "final_failure_provenance_registry.tsv").open(newline="") as handle:
            failures = list(csv.DictReader(handle, delimiter="\t"))
        active = [row for row in failures if row["failure_class"] == "MAIN_NAVIGATION_TIMEOUT"]
        self.assertEqual(len(active), 1)
        self.assertEqual(active[0]["eligibility_disposition"], "FINAL_SAMPLE_RETRY_PROVENANCE")

    def test_registers_referenced_diagnostic_as_infrastructure_provenance(self) -> None:
        """Catches a freeze that drops infrastructure evidence referenced by recovery governance."""
        diagnostic = self.root / "diagnostics/sample1176/attribution_review.json"
        write_json(diagnostic, {"status": "NONREPRODUCED", "attribution": "UNRESOLVED"})
        activation_path = self.dataset / "acquisitions/pair_group_0294_isolated_recovery1/activation.json"
        activation = json.loads(activation_path.read_text())
        activation["diagnostic_review"] = str(diagnostic)
        activation["diagnostic_review_sha256"] = hashlib.sha256(diagnostic.read_bytes()).hexdigest()
        write_json(activation_path, activation)

        result = self.run_builder()
        self.assertEqual(result.returncode, 0, result.stderr)
        with (self.output / "final_failure_provenance_registry.tsv").open(newline="") as handle:
            provenance = list(csv.DictReader(handle, delimiter="\t"))
        evidence = [row for row in provenance if row["record_type"] == "INFRASTRUCTURE_EVIDENCE"]
        self.assertEqual(len(evidence), 1)
        self.assertEqual(evidence[0]["artifact_path"], str(diagnostic))
        self.assertEqual(evidence[0]["source_record_sha256"], hashlib.sha256(diagnostic.read_bytes()).hexdigest())
        self.assertEqual(evidence[0]["failure_class"], "")
        self.assertEqual(evidence[0]["eligibility_disposition"], "PROVENANCE_ONLY_INFRASTRUCTURE_EVIDENCE")

    def test_prefers_existing_relocated_failure_artifact_path(self) -> None:
        """Catches a registry that freezes a stale pre-relocation failure path."""
        activation_path = self.dataset / "acquisitions/pair_group_0294_isolated_recovery1/activation.json"
        activation = json.loads(activation_path.read_text())
        original = activation["original_attempts"][0]
        relocated = Path(original["artifact_path"])
        original["artifact_path"] = str(
            self.dataset / "failed_artifacts/formal_t0_v3_sample1176/attempt_1_ACTION_TIMEOUT"
        )
        activation["closed_entries"] = {"attempts": activation.pop("original_attempts")}
        write_json(activation_path, activation)

        stale = dict(original)
        stale_ledger = self.dataset / "acquisitions/stale_snapshot/active_retry_ledger.tsv"
        stale_ledger.parent.mkdir(parents=True)
        with stale_ledger.open("w", newline="") as handle:
            writer = csv.DictWriter(handle, fieldnames=list(stale), delimiter="\t", lineterminator="\n")
            writer.writeheader()
            writer.writerow(stale)

        result = self.run_builder()
        self.assertEqual(result.returncode, 0, result.stderr)
        with (self.output / "final_failure_provenance_registry.tsv").open(newline="") as handle:
            failures = list(csv.DictReader(handle, delimiter="\t"))
        old = [row for row in failures if row["sample_id"] == "formal_t0_v3_sample1176"]
        self.assertEqual(len(old), 1)
        self.assertEqual(old[0]["artifact_path"], str(relocated))
        self.assertEqual(old[0]["source_record_type"], "REACQUISITION_ACTIVATION")

    def test_rejects_wrong_final_recovery_quartet(self) -> None:
        """Catches a freeze that does not select the required fresh 1173-1176 quartet."""
        sample = self.dataset / "samples/formal_t0_v3_sample1176_pair_group_0294_isolated_recovery1"
        metadata_path = sample / "sample_metadata.json"
        metadata = json.loads(metadata_path.read_text())
        metadata["acquisition_instance"] = "wrong_recovery_instance"
        write_json(metadata_path, metadata)

        result = self.run_builder()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("required 1173-1176 recovery quartet mismatch", result.stderr)
        self.assertFalse(self.output.exists())

    def test_rejects_missing_sample1176_historical_failure(self) -> None:
        """Catches a freeze that drops the original sample1176 failure provenance."""
        activation_path = self.dataset / "acquisitions/pair_group_0294_isolated_recovery1/activation.json"
        activation = json.loads(activation_path.read_text())
        activation["original_attempts"] = []
        write_json(activation_path, activation)

        result = self.run_builder()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("sample1176 historical failure provenance missing", result.stderr)
        self.assertFalse(self.output.exists())

    def test_rejects_missing_failed_attempt_artifact(self) -> None:
        """Catches a provenance row that does not resolve to preserved evidence."""
        activation_path = self.dataset / "acquisitions/pair_group_0294_isolated_recovery1/activation.json"
        activation = json.loads(activation_path.read_text())
        activation["original_attempts"][0]["artifact_path"] = ""
        write_json(activation_path, activation)

        result = self.run_builder()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("failed-attempt artifact missing: formal_t0_v3_sample1176 1", result.stderr)
        self.assertFalse(self.output.exists())

    def test_registers_nonformal_reacquisition_diagnostic_as_provenance_only(self) -> None:
        """Catches omission or accidental eligibility of a diagnostic reacquisition."""
        diagnostic = self.root / "diagnostics/t0_v3_r11_pair_group_0259_reacquisition_diagnostic"
        diagnostic.mkdir(parents=True)
        (diagnostic / "NON_FORMAL_FINAL_DATASET_INELIGIBLE").write_text("PROVENANCE_ONLY\n")
        write_json(diagnostic / "diagnostic_result.json", {
            "campaign_id": "t0_v3_r11",
            "pair_group": 259,
            "status": "PASS",
            "final_dataset_eligible": False,
        })

        result = self.run_builder()
        self.assertEqual(result.returncode, 0, result.stderr)
        with (self.output / "final_reacquisition_registry.tsv").open(newline="") as handle:
            rows = list(csv.DictReader(handle, delimiter="\t"))
        diagnostics = [row for row in rows if row["eligibility_disposition"] == "PROVENANCE_ONLY_DIAGNOSTIC"]
        self.assertEqual(len(diagnostics), 1)
        self.assertEqual(diagnostics[0]["group"], "259")
        self.assertEqual(diagnostics[0]["eligible_sample_ids"], "")


if __name__ == "__main__":
    unittest.main()
