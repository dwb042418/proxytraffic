#!/usr/bin/env python3
"""Synthetic, NON_FORMAL tests for Formal T0 v3 R4 resume decisions."""

from __future__ import annotations

import importlib.util
import json
import tempfile
import unittest
import copy
from unittest.mock import patch
from contextlib import ExitStack
from types import SimpleNamespace

import test_formal_failure_classifier_v2 as classifier_fixtures
from pathlib import Path


MODULE_PATH = Path(__file__).with_name("run_formal_t0_v3_r4_production.py")
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

    def test_failed_attempt_three_is_hard_stop(self) -> None:
        ledger = [{
            "sample_id": row()["schedule_id"], "attempt": "3",
            "retry_authorized": "false", "final_status": "FAIL",
        }]
        with tempfile.TemporaryDirectory(prefix="NON_FORMAL_formal_resume_") as temporary:
            decision = formal.resume_decision(row(), Path(temporary), False, ledger, FROZEN_HEAD)
            self.assertEqual(decision, "HARD_STOP_ATTEMPT3_FAILED")


class ProductionRetryV3Tests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="NON_FORMAL_R4_production_retry_")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.plan = self.root / "immutable-plan.json"
        self.plan.write_text('{"events":[{"url":"https://duckdns.org/","navigation_timeout_ms":30000,"dwell_ms":1000}]}\n')
        self.plan_bytes = self.plan.read_bytes()
        self.schedule = {**row(), "plan_path": str(self.plan), "plan_sha256": formal.sha256(self.plan),
                         "plan_id": "formal_t0_v3_seed001_light", "quartet_index": "1", "seed_assignment_id": "train001"}
        self.registry = {self.plan: self.schedule["plan_sha256"]}
        self.retry = formal.configure_execution_components()
        self.calls = []
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.stack.enter_context(patch.object(formal, "LOCAL_PRODUCTION_ROOT", self.root))
        self.stack.enter_context(patch.object(formal, "configure_execution_components", return_value=self.retry))
        self.stack.enter_context(patch.object(formal, "prepare_remote_inputs"))
        self.archive = self.stack.enter_context(patch.object(formal, "archive_sample"))
        self.stack.enter_context(patch.object(formal, "synthetic_component_failure", side_effect=AssertionError("unexpected component error in synthetic test")))
        self.stack.enter_context(patch.object(formal, "verify_sample_precheck", side_effect=self.check_plan))

    def check_plan(self, schedule, head, registry):
        self.assertEqual(schedule, self.schedule)
        self.assertEqual(head, FROZEN_HEAD)
        self.assertEqual(registry, self.registry)
        self.assertEqual(self.plan.read_bytes(), self.plan_bytes)

    def result(self, failure, number, artifact):
        return dict(status="FAIL" if failure else "PASS", mode="direct", attempt=number,
                    failure_class=failure, failure_event_index=0, failure_url="https://duckdns.org/",
                    pre_health="PASS", post_health="PASS", mode_purity="PASS",
                    redsocks_actual_conn_max="NOT_APPLICABLE", redsocks_conn_max_hits=0,
                    infrastructure_health_lost=0, server_egress_degraded=0, trojan_public_path_degraded=0,
                    plan_sha256=self.schedule["plan_sha256"], artifact_dir=str(artifact), residual=0,
                    capture=dict(status="PASS", executor_bounded=True, executor_watchdog_timeout=False,
                                 pcap_stable_size=True, active_health_probe_during_capture=0, oom=0, unexpected_process_exit=0),
                    browser=dict(outcome="PASS" if not failure else "FAIL", hard_failure_count=int(bool(failure)),
                                 success_count=int(not failure), event_count=1),
                    attempt_finished_utc=formal.utc_now())

    def fake_attempt(self, mode, number, selection, attempts_root, remote, **kwargs):
        self.assertEqual(mode, "direct")
        self.assertEqual(selection["plan_sha256"], self.schedule["plan_sha256"])
        self.assertEqual(selection["plan_path"], str(self.plan))
        self.assertIn("formal-t0-r4/", remote)
        self.assertLessEqual(number, 3)
        if self.calls:
            previous = self.ledger()[-1]
            self.assertTrue(Path(previous["artifact_path"]).is_dir())
            self.assertIn("failed_artifacts", previous["artifact_path"])
        self.calls.append(number)
        artifact = attempts_root / f"attempt_{number}"
        artifact.mkdir()
        (artifact / "workload").mkdir()
        (artifact / "workload/workload_plan.json").write_bytes(self.plan_bytes)
        for name in ("observed.pcap", "original.pcap", "egress.pcap"):
            (artifact / name).write_bytes(f"synthetic-capture-{number}".encode())
        (artifact / "browser_lifecycle.txt").write_text(f"fresh lifecycle {number}; cleanup browser/capture/proxy; residual=0")
        failure = self.failures[number - 1]
        (artifact / "failure.txt").write_text(failure)
        result = self.result(failure, number, artifact)
        formal.atomic_write_json(artifact / "validation_attempt_result.json", result)
        return result

    def ledger(self):
        return formal.read_ledger(self.root / "formal_t0_v3_r4_retry_ledger.tsv")

    def exercise(self, failures, final_pass):
        self.failures = failures
        with patch.object(self.retry, "run_attempt", side_effect=self.fake_attempt):
            if final_pass:
                sample = formal.run_formal_sample(self.schedule, FROZEN_HEAD, self.registry, 1)
                metadata = formal.load_json(sample / "sample_metadata.json")
                self.assertEqual(metadata["final_attempt"], len(failures))
                self.assertEqual(metadata["attempt_count"], len(failures))
                self.assertEqual(metadata["dataset_track"], "realistic_t0_v3_r4")
                self.archive.assert_called_once()
            else:
                with self.assertRaises(formal.HardStop):
                    formal.run_formal_sample(self.schedule, FROZEN_HEAD, self.registry, 1)
                self.archive.assert_not_called()
        self.assertEqual(self.calls, list(range(1, len(failures) + 1)))
        self.assertFalse(list(self.root.rglob("attempt_4*")))
        ledger = self.ledger()
        self.assertEqual([int(x["attempt"]) for x in ledger], self.calls)
        for number, item in enumerate(ledger, 1):
            self.assertEqual(item["failure_class"], failures[number-1])
            self.assertEqual(item["retry_authorized"], str(number < len(failures)).lower())
            self.assertEqual(item["final_status"], "FAIL" if failures[number-1] else "PASS")
            self.assertEqual(item["sequence_id"], "1")
            self.assertEqual(item["sample_id"], self.schedule["schedule_id"])
            self.assertEqual(item["pair_group_id"], self.schedule["pair_group_id"])
            self.assertEqual(item["mode"], "direct")
            self.assertEqual(item["event_index"], "0")
            self.assertEqual(item["url"], "https://duckdns.org/")
            self.assertEqual(item["plan_sha"], self.schedule["plan_sha256"])
            self.assertEqual(item["git_head"], FROZEN_HEAD)
            self.assertTrue(item["attempt_start_utc"])
            self.assertTrue(item["attempt_end_utc"])
            artifact = Path(item["artifact_path"])
            self.assertEqual((artifact / "failure.txt").read_text(), failures[number-1])
            self.assertEqual((artifact / "observed.pcap").read_bytes(), f"synthetic-capture-{number}".encode())
            self.assertEqual((artifact / "workload/workload_plan.json").read_bytes(), self.plan_bytes)
            if failures[number-1]:
                self.assertIn("failed_artifacts", str(artifact))
            if final_pass:
                self.assertEqual(metadata["attempt_history"][number-1]["artifact_path"], str(artifact))

    def test_a_fail_pass(self): self.exercise(["MAIN_NAVIGATION_TIMEOUT", ""], True)
    def test_b_fail_fail_pass(self): self.exercise(["MAIN_NAVIGATION_TIMEOUT"]*2 + [""], True)
    def test_c_three_transient_failures(self): self.exercise(["MAIN_NAVIGATION_TIMEOUT"]*3, False)
    def test_d_no_attempt4(self):
        with self.assertRaises(formal.PrecheckFail):
            formal.run_formal_sample(self.schedule, FROZEN_HEAD, self.registry, 4)
        with self.assertRaises(formal.HardStop):
            formal.enforce_failed_attempt_stop(3, "sample", {"failure_class":"MAIN_NAVIGATION_TIMEOUT"}, True)
        self.assertEqual(self.calls, [])
    def test_e_http429(self): self.exercise(["HTTP_STATUS_429"], False)
    def test_f_purity(self): self.exercise(["MODE_PURITY_FAIL"], False)
    def test_g_conn_max(self): self.exercise(["REDSOCKS_CONN_MAX_HIT"], False)
    def test_h_context_destroyed(self):
        result = classifier_fixtures.resolve(workload=None, executor_rc=1, rows=classifier_fixtures.CONTEXT_ROWS)
        self.assertEqual(result["failure_class"], "EXECUTION_CONTEXT_DESTROYED_DUE_TO_NAVIGATION")
        self.exercise([result["failure_class"]]*2 + [""], True)
    def test_i_failed_artifacts_preserved(self): self.exercise(["ERR_EMPTY_RESPONSE", "CONNECTION_CLOSED", ""], True)

    def test_retryable_attempt2_resumes_attempt3(self):
        ledger = [{"sample_id": self.schedule["schedule_id"], "attempt":"2", "retry_authorized":"true", "final_status":"FAIL"}]
        self.assertEqual(formal.resume_decision(self.schedule, self.root, False, ledger, FROZEN_HEAD), "RUN_ATTEMPT3")
        pending = self.root / "in_progress" / self.schedule["schedule_id"] / "attempts" / "attempt_3"
        pending.mkdir(parents=True)
        self.assertEqual(formal.resume_decision(self.schedule, self.root, False, ledger, FROZEN_HEAD), "REVIEW_REQUIRED")

    def test_real_resume_after_two_failed_attempts(self):
        self.failures = ["MAIN_NAVIGATION_TIMEOUT", "CONNECTION_CLOSED", ""]
        original = formal.enforce_failed_attempt_stop
        def stop_between_attempts(number, *args):
            original(number, *args)
            if number == 2: raise formal.HardStop("synthetic interruption between attempts")
        with patch.object(self.retry, "run_attempt", side_effect=self.fake_attempt):
            with patch.object(formal, "enforce_failed_attempt_stop", side_effect=stop_between_attempts):
                with self.assertRaisesRegex(formal.HardStop, "synthetic interruption"):
                    formal.run_formal_sample(self.schedule, FROZEN_HEAD, self.registry, 1)
            decision = formal.resume_decision(self.schedule, self.root, False, self.ledger(), FROZEN_HEAD)
            self.assertEqual(decision, "RUN_ATTEMPT3")
            sample = formal.run_formal_sample(self.schedule, FROZEN_HEAD, self.registry, 3)
        self.assertEqual(self.calls, [1,2,3])
        meta = formal.load_json(sample / "sample_metadata.json")
        self.assertEqual(meta["attempt_count"], 3)
        self.assertTrue(all(Path(x["artifact_path"]).exists() for x in meta["attempt_history"]))

    def test_empty_scan_next_sequence_one(self):
        state = formal.scan_resume_state([self.schedule], self.root, FROZEN_HEAD, remote_probe=lambda *_:False)
        self.assertEqual(state["next_sequence_id"], 1)
        self.assertEqual(state["valid_samples"], 0)

    def test_atomic_ledger_replace_failure_preserves_previous(self):
        ledger = self.root / "formal_t0_v3_r4_retry_ledger.tsv"
        formal.atomic_write_rows(ledger, formal.LEDGER_FIELDS, [])
        before = ledger.read_bytes()
        with patch.object(formal.os, "replace", side_effect=OSError("synthetic replace failure")):
            with self.assertRaises(OSError):
                formal.append_ledger_atomic(ledger, [{"attempt":1}])
        self.assertEqual(ledger.read_bytes(), before)
        self.assertEqual(formal.read_ledger(ledger), [])

    def test_policy_is_loaded_and_sha_enforced(self):
        policy = formal.verify_retry_policy()
        self.assertEqual(policy["max_attempts"], 3)
        self.assertEqual(self.retry.RETRYABLE, policy["retryable_classes"])
        fake = self.root / "tampered_policy.txt"
        fake.write_text(formal.RETRY_POLICY.read_text().replace("MAX_ATTEMPTS_PER_SAMPLE=3", "MAX_ATTEMPTS_PER_SAMPLE=4"))
        expected = formal.FROZEN_SHA256[formal.RETRY_POLICY]
        with patch.object(formal, "RETRY_POLICY", fake), patch.dict(formal.FROZEN_SHA256, {fake:expected}):
            with self.assertRaisesRegex(formal.PrecheckFail, "SHA mismatch"):
                formal.verify_retry_policy()

    def test_nonretryable_attempt2_stops(self):
        self.exercise(["MAIN_NAVIGATION_TIMEOUT", "HTTP_STATUS_429"], False)

    def test_dry_run_starts_no_lifecycle_and_writes_no_root_data(self):
        def read_only_remote(command, *args, **kwargs):
            self.assertEqual(command[0], "ssh")
            remote = command[-1]
            if remote.startswith("df -B1"):
                return SimpleNamespace(returncode=0, stdout="Avail\n999999999999\n", stderr="")
            if remote.startswith("find ") and "SAMPLE_COMPLETE" in remote:
                return SimpleNamespace(returncode=0, stdout="0\n", stderr="")
            if remote.startswith("test -e "):
                return SimpleNamespace(returncode=1, stdout="", stderr="")
            if remote.startswith("if test -d ") and "find " in remote:
                return SimpleNamespace(returncode=0, stdout="", stderr="")
            raise AssertionError(f"unexpected dry-run command: {command}")
        before = sorted(str(p.relative_to(self.root)) for p in self.root.rglob("*"))
        with patch.object(formal, "verify_git", return_value={"local_head":FROZEN_HEAD}), \
             patch.object(formal, "verify_root_amendment"), \
             patch.object(formal, "verify_remote_connectivity"), \
             patch.object(formal, "verify_redsocks_unit_definitions", return_value={}), \
             patch.object(formal, "run_command", side_effect=read_only_remote), \
             patch.object(self.retry, "run_attempt", side_effect=AssertionError("dry-run started lifecycle")):
            result = formal.dry_run(FROZEN_HEAD)
        self.assertFalse(result["formal_sample_started"])
        self.assertEqual(result["resume_state"]["next_sequence_id"], 1)
        self.assertEqual(result["max_attempts_per_sample"], 3)
        self.assertEqual(result["local_sample_count"], 0)
        self.assertEqual(result["remote_sample_count"], 0)
        self.assertEqual(before, sorted(str(p.relative_to(self.root)) for p in self.root.rglob("*")))


if __name__ == "__main__":
    suite = unittest.defaultTestLoader.loadTestsFromModule(__import__(__name__))
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    if not result.wasSuccessful(): raise SystemExit(1)
    print("R4_PRODUCTION_RETRY_V3_SYNTHETIC_PASS")
