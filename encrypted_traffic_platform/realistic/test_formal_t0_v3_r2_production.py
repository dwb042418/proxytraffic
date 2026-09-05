#!/usr/bin/env python3
"""Synthetic, NON_FORMAL tests for Formal T0 v3 R2 resume decisions."""

from __future__ import annotations

import importlib.util
import json
import tempfile
import unittest
from pathlib import Path


MODULE_PATH = Path(__file__).with_name("run_formal_t0_v3_r2_production.py")
SPEC = importlib.util.spec_from_file_location("formal_production", MODULE_PATH)
formal = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(formal)

FROZEN_HEAD = "f" * 40


def row(sequence: int = 1) -> dict[str, str]:
    return {
        "schedule_id": f"formal_t0_v3_sample{sequence:04d}",
        "sequence_id": str(sequence),
        "pair_group_id": "seed001_light",
        "seed": "seed001",
        "split": "train",
        "intensity": "light",
        "mode_order": "direct",
        "plan_path": "/tmp/immutable-plan.json",
        "plan_sha256": "a" * 64,
    }


class ResumeDecisionTests(unittest.TestCase):
    def test_empty_state_starts_sequence_one(self) -> None:
        with tempfile.TemporaryDirectory(prefix="NON_FORMAL_formal_resume_") as temporary:
            decision = formal.resume_decision(row(), Path(temporary), False, [], FROZEN_HEAD)
            self.assertEqual(decision, "RUN_ATTEMPT1")

    def test_local_valid_complete_is_skipped(self) -> None:
        with tempfile.TemporaryDirectory(prefix="NON_FORMAL_formal_resume_") as temporary:
            root = Path(temporary)
            sample = root / "samples" / row()["schedule_id"]
            sample.mkdir(parents=True)
            metadata = {
                **formal.row_identity(row()),
                "dataset_track": formal.DATASET_TRACK,
                "artifact_class": formal.ARTIFACT_CLASS,
                "formal_manifest_eligible": True,
                "frozen_git_head": FROZEN_HEAD,
                "frozen_sha256": {
                    "final500": formal.FROZEN_SHA256[formal.POOL],
                    "split": formal.FROZEN_SHA256[formal.SPLIT],
                    "plan_registry": formal.FROZEN_SHA256[formal.REGISTRY],
                    "schedule": formal.FROZEN_SHA256[formal.SCHEDULE],
                    "retry_policy": formal.FROZEN_SHA256[formal.RETRY_POLICY],
                    "health_definition": formal.FROZEN_SHA256[formal.HEALTH_DEFINITION],
                    "production_root_amendment": formal.FROZEN_SHA256[formal.ROOT_AMENDMENT],
                },
            }
            (sample / "sample_metadata.json").write_text(json.dumps(metadata) + "\n")
            verification = {"remote_sha_pass": True, "remote_completeness_pass": True}
            (sample / "remote_sha_verification.json").write_text(json.dumps(verification) + "\n")
            (sample / "SAMPLE_COMPLETE").write_text("SAMPLE_COMPLETE\n")
            formal.create_checksum_manifest(
                sample, "SHA256SUMS.txt",
                {"SHA256SUMS.txt", "FINAL_METADATA_SHA256SUMS.txt", "SAMPLE_COMPLETE",
                 "remote_sha_verification.json"},
            )
            formal.create_checksum_manifest(sample, "FINAL_METADATA_SHA256SUMS.txt", {"FINAL_METADATA_SHA256SUMS.txt"})
            decision = formal.resume_decision(row(), root, True, [], FROZEN_HEAD)
            self.assertEqual(decision, "SKIP_VALID_COMPLETE")

    def test_remote_only_valid_complete_is_skipped(self) -> None:
        with tempfile.TemporaryDirectory(prefix="NON_FORMAL_formal_resume_") as temporary:
            decision = formal.resume_decision(row(), Path(temporary), True, [], FROZEN_HEAD)
            self.assertEqual(decision, "SKIP_VALID_COMPLETE_REMOTE_ONLY")

    def test_completed_ledger_without_remote_proof_never_resamples(self) -> None:
        ledger = [{
            "sample_id": row()["schedule_id"], "attempt": "1",
            "retry_authorized": "false", "final_status": "PASS",
        }]
        with tempfile.TemporaryDirectory(prefix="NON_FORMAL_formal_resume_") as temporary:
            decision = formal.resume_decision(row(), Path(temporary), False, ledger, FROZEN_HEAD)
            self.assertEqual(decision, "REVIEW_REQUIRED_REMOTE_COMPLETE_NOT_VALIDATED")

    def test_incomplete_sample_requires_review(self) -> None:
        with tempfile.TemporaryDirectory(prefix="NON_FORMAL_formal_resume_") as temporary:
            root = Path(temporary)
            (root / "in_progress" / row()["schedule_id"]).mkdir(parents=True)
            decision = formal.resume_decision(row(), root, False, [], FROZEN_HEAD)
            self.assertEqual(decision, "REVIEW_REQUIRED")

    def test_retryable_attempt_one_allows_attempt_two(self) -> None:
        ledger = [{
            "sample_id": row()["schedule_id"], "attempt": "1",
            "retry_authorized": "true", "final_status": "FAIL",
        }]
        with tempfile.TemporaryDirectory(prefix="NON_FORMAL_formal_resume_") as temporary:
            decision = formal.resume_decision(row(), Path(temporary), False, ledger, FROZEN_HEAD)
            self.assertEqual(decision, "RUN_ATTEMPT2")

    def test_failed_attempt_two_is_hard_stop(self) -> None:
        ledger = [{
            "sample_id": row()["schedule_id"], "attempt": "2",
            "retry_authorized": "false", "final_status": "FAIL",
        }]
        with tempfile.TemporaryDirectory(prefix="NON_FORMAL_formal_resume_") as temporary:
            decision = formal.resume_decision(row(), Path(temporary), False, ledger, FROZEN_HEAD)
            self.assertEqual(decision, "HARD_STOP_ATTEMPT2_FAILED")


if __name__ == "__main__":
    unittest.main()
