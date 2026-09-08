#!/usr/bin/env python3
"""Synthetic, NON_FORMAL tests for Formal T0 v3 R8 resume decisions."""

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


MODULE_PATH = Path(__file__).with_name("run_formal_t0_v3_r8_production.py")
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


class ProductionRetryV4Tests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="NON_FORMAL_R8_production_retry_")
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
        self.stack.enter_context(patch.object(formal, "update_hotspot_monitor"))
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
        self.assertIn("formal-t0-r8/", remote)
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
        if failure == "PLAYWRIGHT_DRIVER_CONNECTION_CLOSED":
            result.update(failure_stage="EXECUTOR_INITIALIZATION", workload_started=False,
                          mode_purity="NOT_EVALUABLE", packet_counts={"original":0,"observed":0,"egress":0},
                          executor_initialization_health=dict(status="PASS", oom=0, kernel_kill=0,
                            segfault=0, persistent_service_failure=0, system_resource_exhaustion=0,
                            persistent_driver_failure=0))
        formal.atomic_write_json(artifact / "validation_attempt_result.json", result)
        return result

    def ledger(self):
        return formal.read_ledger(self.root / "formal_t0_v3_r8_retry_ledger.tsv")

    def exercise(self, failures, final_pass):
        self.failures = failures
        with patch.object(self.retry, "run_attempt", side_effect=self.fake_attempt):
            if final_pass:
                sample = formal.run_formal_sample(self.schedule, FROZEN_HEAD, self.registry, 1)
                metadata = formal.load_json(sample / "sample_metadata.json")
                self.assertEqual(metadata["final_attempt"], len(failures))
                self.assertEqual(metadata["attempt_count"], len(failures))
                self.assertEqual(metadata["dataset_track"], "realistic_t0_v3_r8")
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

    def test_real_bypass_recorded_with_mode_purity_primary(self):
        result = self.result("MODE_PURITY_FAIL", 1, self.root)
        result["mode_purity_issues"] = ["proxy_public_443_bypass"]
        import run_24_sample_smoke_v3_retry_v4 as smoke
        self.assertEqual(smoke.aggregate_failures([result])["bypass_failures"], 1)
        self.assertIn("bypass_observed", formal.LEDGER_FIELDS)

    def test_driver_fail_then_pass(self): self.exercise(["PLAYWRIGHT_DRIVER_CONNECTION_CLOSED", ""], True)
    def test_driver_fail_fail_pass(self): self.exercise(["PLAYWRIGHT_DRIVER_CONNECTION_CLOSED"]*2 + [""], True)
    def test_driver_three_failures_stop(self): self.exercise(["PLAYWRIGHT_DRIVER_CONNECTION_CLOSED"]*3, False)

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
        ledger = self.root / "formal_t0_v3_r8_retry_ledger.tsv"
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
             patch.object(formal, "free_disk_bytes", return_value=formal.MIN_FREE_BYTES + 1), \
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

    def test_dry_run_low_disk_fails_before_lifecycle(self):
        before = sorted(str(p.relative_to(self.root)) for p in self.root.rglob("*"))
        with patch.object(formal, "verify_git", return_value={"local_head": FROZEN_HEAD}), \
             patch.object(formal, "free_disk_bytes", return_value=formal.MIN_FREE_BYTES - 1), \
             patch.object(formal, "verify_root_amendment"), \
             patch.object(formal, "verify_remote_connectivity"), \
             patch.object(formal, "verify_redsocks_unit_definitions", return_value={}), \
             patch.object(self.retry, "run_attempt", side_effect=AssertionError("dry-run started lifecycle")):
            with self.assertRaisesRegex(formal.PrecheckFail, "free disk below 20 GiB"):
                formal.dry_run(FROZEN_HEAD)
        self.assertEqual(before, sorted(str(p.relative_to(self.root)) for p in self.root.rglob("*")))


REAL_MONITOR_UPDATE = formal.update_hotspot_monitor


def baseline_failures(domain='duckdns.org'):
    return [dict(domain=domain, plan_id='historical_plan', plan_sha='a'*64, event_index='0',
                 mode='shadowsocks', failure_class='MAIN_NAVIGATION_TIMEOUT', run_class='R7_VALIDATION',
                 run_id='frozen_validation', sample_id='historical_sample', attempt=str(a),
                 final_result='SAMPLE_PASS_ATTEMPT3', infra_clean='true') for a in (1,2)]


class HotspotGovernanceTests(unittest.TestCase):
    def setUp(self):
        self.f = ProductionRetryV4Tests('test_policy_is_loaded_and_sha_enforced')
        self.f.setUp()
        self.addCleanup(self.f.doCleanups)
        self.stack = ExitStack(); self.addCleanup(self.stack.close)
        self.stack.enter_context(patch.object(formal, 'update_hotspot_monitor', side_effect=REAL_MONITOR_UPDATE))
        self.stack.enter_context(patch.object(formal, 'verify_hotspot_baseline', return_value=baseline_failures()))
        self.stack.enter_context(patch.object(formal, 'read_tsv', return_value=[self.f.schedule]))
        self.no_signal = self.stack.enter_context(patch.object(formal.os, 'kill', side_effect=AssertionError('SIGINT forbidden')))

    def test_H1_baseline_two_plus_production_one(self):
        self.f.exercise(['MAIN_NAVIGATION_TIMEOUT',''], True)
        state=formal.load_json(formal.monitor_path())
        self.assertTrue(state['pending_hotspot_review'])
        trigger=state['trigger_evidence'][0]
        self.assertEqual(trigger['failure_count'],3)
        self.assertTrue(trigger['clause_results']['RULE_B'])

    def test_H2_isolated_transient(self):
        self.assertEqual(formal.evaluate_rule_v2(baseline_failures()[:1]),[])

    def test_H3_retry_attempt_two_not_interrupted(self):
        self.f.exercise(['MAIN_NAVIGATION_TIMEOUT',''], True)
        self.assertEqual(self.f.calls,[1,2]); self.no_signal.assert_not_called()
        self.assertFalse(formal.load_json(formal.monitor_path())['safe_boundary_reached'])

    def test_H4_safe_boundary_blocks_next_sample(self):
        self.f.exercise(['MAIN_NAVIGATION_TIMEOUT',''], True)
        result=formal.load_json(self.f.root/'samples'/self.f.schedule['schedule_id']/'sample_metadata.json')['final_result']
        with self.assertRaisesRegex(formal.HardStop,'R8_SAFE_BOUNDARY_HARD_STOP'):
            formal.mark_monitor_boundary(self.f.schedule,result)
        state=formal.load_json(formal.monitor_path())
        self.assertTrue(state['safe_boundary_reached']);self.assertTrue(state['next_sample_blocked'])
        with self.assertRaisesRegex(formal.PrecheckFail,'REVIEW_REQUIRED'):
            formal.execute_production(FROZEN_HEAD,resume=True)
        self.assertEqual(self.f.calls,[1,2])

    def test_H5_attempt_three_natural_failure_preserved(self):
        self.f.exercise(['MAIN_NAVIGATION_TIMEOUT']*3,False)
        state=formal.load_json(formal.monitor_path())
        self.assertTrue(state['safe_boundary_reached']); self.assertTrue(state['natural_hard_stop'])
        self.assertEqual(len(self.f.ledger()),3)
        for entry in self.f.ledger(): self.assertTrue(Path(entry['artifact_path']).is_dir())

    def test_H6_pending_resume_no_lifecycle(self):
        formal.atomic_write_json(formal.monitor_path(),{'pending_hotspot_review':True})
        with patch.object(formal,'run_formal_sample',side_effect=AssertionError('sample started')):
            with self.assertRaisesRegex(formal.PrecheckFail,'REVIEW_REQUIRED'):
                formal.execute_production(FROZEN_HEAD,resume=True)

    def test_H7_no_pool_replacement_or_plan_modification(self):
        before={p:formal.sha256(p) for p in (formal.POOL,formal.SPLIT,formal.SCHEDULE,formal.REGISTRY,self.f.plan)}
        self.f.exercise(['MAIN_NAVIGATION_TIMEOUT',''],True)
        self.assertEqual(before,{p:formal.sha256(p) for p in before})

    def test_rule_A_terminal_requires_independent_run(self):
        rows=baseline_failures(); rows[0]['final_result']='MAX_ATTEMPTS_REACHED';rows[1]['final_result']='IN_PROGRESS'
        self.assertEqual(formal.evaluate_rule_v2(rows),[])
        rows[1]['run_id']='independent'; trigger=formal.evaluate_rule_v2(rows)[0]
        self.assertTrue(trigger['clause_results']['RULE_A'])

    def test_unclean_failures_do_not_count(self):
        rows=baseline_failures();rows.append({**rows[0],'run_id':'production','sample_id':'new','infra_clean':'false'})
        self.assertEqual(formal.evaluate_rule_v2(rows),[])


class StorageGovernanceTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(prefix='NON_FORMAL_R8_storage_');self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name);self.schedule={**row(),'plan_id':'synthetic_plan','mode_position':'1'}
        self.stack=ExitStack();self.addCleanup(self.stack.close)
        self.stack.enter_context(patch.object(formal,'LOCAL_PRODUCTION_ROOT',self.root))
        for name in ('verify_git','verify_orchestrator_at_head','verify_frozen_sha','verify_root_amendment','verify_remote_connectivity'):
            self.stack.enter_context(patch.object(formal,name))
        self.stack.enter_context(patch.object(formal,'configure_execution_components',side_effect=AssertionError('housekeeping lifecycle import')))
        self.stack.enter_context(patch.object(formal,'run_formal_sample',side_effect=AssertionError('housekeeping sample start')))
        self.remote=self.stack.enter_context(patch.object(formal,'remote_complete_valid',return_value=True))
        self.stack.enter_context(patch.object(formal,'audit_schedule_and_plans',return_value=([self.schedule],{},{})))
        self.sample=self.root/'samples'/self.schedule['schedule_id'];self.sample.mkdir(parents=True)
        metadata={**formal.row_identity(self.schedule),'dataset_track':formal.DATASET_TRACK,'artifact_class':formal.ARTIFACT_CLASS,
                  'formal_manifest_eligible':True,'frozen_git_head':FROZEN_HEAD,
                  'frozen_sha256':{k:formal.FROZEN_SHA256[v] for k,v in dict(final500=formal.POOL,split=formal.SPLIT,
                      plan_registry=formal.REGISTRY,schedule=formal.SCHEDULE,retry_policy=formal.RETRY_POLICY,
                      health_definition=formal.HEALTH_DEFINITION,production_root_amendment=formal.ROOT_AMENDMENT).items()}}
        formal.atomic_write_json(self.sample/'sample_metadata.json',metadata)
        formal.atomic_write_json(self.sample/'remote_sha_verification.json',dict(remote_upload_pass=True,remote_sha_pass=True,remote_completeness_pass=True))
        (self.sample/'SAMPLE_COMPLETE').write_text('SAMPLE_COMPLETE\n')
        for name in ('observed','original','egress'):(self.sample/(name+'.pcap')).write_bytes(b'synthetic-pcap')
        (self.sample/'retained-plan.json').write_text('{}\n')
        formal.create_checksum_manifest(self.sample,'SHA256SUMS.txt',{'SHA256SUMS.txt','FINAL_METADATA_SHA256SUMS.txt'})
        formal.create_checksum_manifest(self.sample,'FINAL_METADATA_SHA256SUMS.txt',{'FINAL_METADATA_SHA256SUMS.txt'})
        self.count=sum(f.is_file() for f in self.sample.rglob('*'))
        self.stack.enter_context(patch.object(formal,'remote_file_count',return_value=self.count))
        self.stack.enter_context(patch.object(formal,'scan_resume_state',return_value=dict(next_sequence_id=5,next_action='RUN_ATTEMPT1')))

    def test_S1_full_preflight_high_space(self):
        self.stack.close()
        f=ProductionRetryV4Tests('test_dry_run_starts_no_lifecycle_and_writes_no_root_data')
        f.setUp()
        try:f.test_dry_run_starts_no_lifecycle_and_writes_no_root_data()
        finally:f.doCleanups()

    def test_S2_full_preflight_low_space_blocks(self):
        self.stack.close()
        f=ProductionRetryV4Tests('test_dry_run_low_disk_fails_before_lifecycle');f.setUp()
        try:f.test_dry_run_low_disk_fails_before_lifecycle()
        finally:f.doCleanups()

    def test_S3_low_space_housekeeping_allowed(self):
        with patch.object(formal,'free_disk_bytes',return_value=1):
            self.assertEqual(formal.housekeeping_eviction_preflight(FROZEN_HEAD)['status'],'PASS')

    def test_S4_completed_verified_sample_eviction(self):
        formal.evict_complete_through(FROZEN_HEAD,1)
        self.assertFalse(list(self.sample.glob('*.pcap')))
        self.assertTrue((self.sample/'sample_metadata.json').exists())
        self.assertEqual(formal.read_evictions()[self.schedule['schedule_id']]['status'],'COMPLETE')

    def test_S5_eviction_restores_full_preflight(self):
        with patch.object(formal,'free_disk_bytes',side_effect=lambda:1 if list(self.sample.glob('*.pcap')) else formal.MIN_FREE_BYTES+1), \
             patch.object(formal,'dry_run',return_value={'status':'PASS'}) as full:
            formal.storage_recover(FROZEN_HEAD)
            full.assert_called_once_with(FROZEN_HEAD)
        self.assertFalse(list(self.sample.glob('*.pcap')))

    def test_S6_insufficient_space_remains_blocked(self):
        with patch.object(formal,'free_disk_bytes',return_value=1),patch.object(formal,'dry_run') as full:
            with self.assertRaisesRegex(formal.HardStop,'R8_STORAGE_RECOVERY_INSUFFICIENT'):
                formal.storage_recover(FROZEN_HEAD)
            full.assert_not_called()

    def test_S7_remote_sha_mismatch_never_deletes(self):
        self.remote.return_value=False
        with self.assertRaisesRegex(formal.HardStop,'remote independent SHA'):
            formal.perform_eviction(self.schedule,FROZEN_HEAD)
        self.assertEqual(len(list(self.sample.glob('*.pcap'))),3)
        self.assertFalse(formal.eviction_ledger_path().exists())

    def test_S8_evicted_sample_resume_skip(self):
        formal.perform_eviction(self.schedule,FROZEN_HEAD)
        self.assertEqual(formal.resume_decision(self.schedule,self.root,True,[],FROZEN_HEAD),'SKIP_VALID_COMPLETE_LOCAL_EVICTED')
        self.assertEqual(formal.resume_decision(self.schedule,self.root,False,[],FROZEN_HEAD),'REVIEW_REQUIRED')

    def crash_case(self,after):
        original=Path.unlink;calls=[]
        def crash(path,*args,**kwargs):
            if path.suffix=='.pcap':
                if len(calls)==after:raise OSError('simulated eviction crash')
                calls.append(path)
            return original(path,*args,**kwargs)
        with patch.object(Path,'unlink',crash):
            with self.assertRaisesRegex(OSError,'simulated eviction crash'):
                formal.perform_eviction(self.schedule,FROZEN_HEAD)
        self.assertEqual(formal.read_evictions()[self.schedule['schedule_id']]['status'],'PREPARED')
        self.assertEqual(formal.resume_decision(self.schedule,self.root,True,[],FROZEN_HEAD),'SKIP_VALID_COMPLETE_LOCAL_EVICTED')
        formal.perform_eviction(self.schedule,FROZEN_HEAD)
        self.assertFalse(list(self.sample.glob('*.pcap')))

    def test_S9_partial_eviction_crash(self): self.crash_case(1)
    def test_ledger_written_before_delete_crash(self): self.crash_case(0)

    def test_S10_housekeeping_never_starts_workload(self):
        with patch.object(formal,'free_disk_bytes',return_value=1):
            result=formal.housekeeping_eviction_preflight(FROZEN_HEAD)
            formal.evict_complete_through(FROZEN_HEAD,1)
        self.assertFalse(result['browser_started']);self.assertFalse(result['tcpdump_started'])

    def test_retained_metadata_tamper_fails_closed(self):
        formal.perform_eviction(self.schedule,FROZEN_HEAD)
        (self.sample/'sample_metadata.json').write_text('{}')
        with self.assertRaisesRegex(formal.HardStop,'metadata/local SHA mismatch'):
            formal.resume_decision(self.schedule,self.root,True,[],FROZEN_HEAD)


if __name__=='__main__':
    suite=unittest.defaultTestLoader.loadTestsFromModule(__import__(__name__))
    result=unittest.TextTestRunner(verbosity=2).run(suite)
    if not result.wasSuccessful():raise SystemExit(1)
    for name,cls in [('HOTSPOT_TESTS',HotspotGovernanceTests),('STORAGE_TESTS',StorageGovernanceTests)]:
        n=unittest.defaultTestLoader.loadTestsFromTestCase(cls).countTestCases();print(f'{name}={n}/{n} PASS')
    print(f'TOTAL_PRODUCTION_TESTS={result.testsRun}/{result.testsRun} PASS')
    print('R8_PRODUCTION_GOVERNANCE_TESTS_PASS')
