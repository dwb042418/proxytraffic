#!/usr/bin/env python3
"""Read-only regression against the preserved Formal R2 sample0006 attempt1 evidence."""

from __future__ import annotations

import json
import subprocess
import unittest
from pathlib import Path

import formal_failure_classifier_v2 as classifier
import run_single_quartet_v3_validation_retry_v2 as retry


EVIDENCE = Path(
    "/home/etip/datasets/staging/realistic_v1/t0_v3_r2/failed_artifacts/"
    "formal_t0_v3_sample0006/attempt_1_20260905T16271002570_MODE_PURITY_FAIL"
)


def tshark_count(pcap: Path, display_filter: str | None = None) -> int:
    command = ["tshark", "-r", str(pcap)]
    if display_filter:
        command += ["-Y", display_filter]
    command += ["-T", "fields", "-e", "frame.number"]
    result = subprocess.run(
        command, check=True, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    )
    return sum(bool(line.strip()) for line in result.stdout.splitlines())


class Sample0006Regression(unittest.TestCase):
    def test_preserved_attempt_reclassifies_without_modifying_evidence(self) -> None:
        self.assertTrue(EVIDENCE.is_dir())
        original = json.loads((EVIDENCE / "validation_attempt_result.json").read_text(encoding="utf-8"))
        supervisor = json.loads((EVIDENCE / "executor_supervisor/result.json").read_text(encoding="utf-8"))
        phase_rows = classifier.read_phase_rows(EVIDENCE / "executor_phase.jsonl")
        stderr_text = (EVIDENCE / "executor_supervisor/stderr.log").read_text(encoding="utf-8")
        purity = classifier.audit_mode_purity(EVIDENCE, "shadowsocks", tshark_count)
        self.assertEqual(purity["status"], "PASS")
        self.assertEqual(
            purity["observed_tunnel_syn_counts"],
            {"21001": 0, "21002": 131, "21003": 0},
        )
        self.assertEqual(purity["observed_direct_public_443_syn_count"], 0)

        failure = classifier.resolve_attempt_failure(
            executor_local_timeout=False,
            supervisor=supervisor,
            browser_residual=int(original["capture"]["browser_residual"]),
            conn_max_hits=int(original["redsocks_conn_max_hits"]),
            oom_count=int(original["capture"]["oom"]),
            unexpected_exit=int(original["capture"]["unexpected_process_exit"]),
            infrastructure_lost=int(original["infrastructure_health_lost"]),
            mode_purity=purity,
            capture_status=str(original["capture"]["status"]),
            workload=None,
            executor_rc=int(supervisor["executor_exit_code"]),
            plan_sha_matches=True,
            expected_event_count=4,
            phase_rows=phase_rows,
            stderr_text=stderr_text,
        )
        self.assertEqual(failure["failure_class"], classifier.EXECUTION_CONTEXT_DESTROYED)
        self.assertEqual(failure["failure_event_index"], 3)
        self.assertEqual(failure["failure_url"], "https://interia.pl/")
        self.assertEqual(failure["failure_action_type"], "DETERMINISTIC_BOUNDED_VIEWPORT_SCROLL")

        revised = {
            **original,
            **failure,
            "status": "FAIL",
            "mode_purity": "PASS",
            "mode_purity_issues": [],
        }
        allowed, reason = retry.retry_authorized(revised, attempt=1)
        self.assertTrue(allowed)
        self.assertEqual(
            reason,
            "AUTHORIZED_TRANSIENT:EXECUTION_CONTEXT_DESTROYED_DUE_TO_NAVIGATION",
        )


if __name__ == "__main__":
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(Sample0006Regression)
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    if not result.wasSuccessful():
        raise SystemExit(1)
    print("SAMPLE0006_CLASSIFICATION_REGRESSION_PASS")
