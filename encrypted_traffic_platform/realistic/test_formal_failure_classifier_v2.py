#!/usr/bin/env python3
"""Synthetic NON_FORMAL tests for Formal v3 failure classifier revision 2."""

from __future__ import annotations

import unittest

import formal_failure_classifier_v2 as classifier
import run_formal_t0_v3_r3_production as production
import run_single_quartet_v3_validation_retry_v2 as retry


PURITY_PASS = classifier.evaluate_mode_purity(
    "shadowsocks",
    {"original": 10, "observed": 10, "egress": 10},
    {"21001": 0, "21002": 3, "21003": 0},
    0,
    0,
)
CONTEXT_ROWS = [
    {
        "phase": "SCROLL_0_START", "event_index": 3, "url": "https://interia.pl/",
        "primitive": "DETERMINISTIC_BOUNDED_VIEWPORT_SCROLL",
    },
    {
        "phase": "EXECUTOR_EXIT", "exit_code": 1,
        "error": "Error: Page.evaluate: Execution context was destroyed, most likely because of a navigation",
    },
]
TRACEBACK = (
    "playwright._impl._errors.Error: Page.evaluate: Execution context was destroyed, "
    "most likely because of a navigation\n"
)


def resolve(
    *, workload: dict[str, object] | None, executor_rc: int,
    purity: dict[str, object] = PURITY_PASS,
    rows: list[dict[str, object]] | None = None,
) -> dict[str, object]:
    return classifier.resolve_attempt_failure(
        executor_local_timeout=False,
        supervisor={"timed_out": False, "residual_count": 0},
        browser_residual=0,
        conn_max_hits=0,
        oom_count=0,
        unexpected_exit=0,
        infrastructure_lost=0,
        mode_purity=purity,
        capture_status="PASS",
        workload=workload,
        executor_rc=executor_rc,
        plan_sha_matches=True,
        expected_event_count=4,
        phase_rows=rows or [],
        stderr_text=TRACEBACK if rows else "",
    )


class FailureClassifierV2Tests(unittest.TestCase):
    def test_a_browser_pass_purity_pass_is_pass(self) -> None:
        workload = {
            "hard_failure_count": 0, "success_count": 4, "event_count": 4,
            "workload_plan_sha256": "a" * 64,
        }
        self.assertEqual(resolve(workload=workload, executor_rc=0)["failure_class"], "")

    def test_b_context_destroyed_with_purity_pass_keeps_browser_failure(self) -> None:
        result = resolve(workload=None, executor_rc=1, rows=CONTEXT_ROWS)
        self.assertEqual(result["failure_class"], classifier.EXECUTION_CONTEXT_DESTROYED)
        self.assertEqual(result["failure_event_index"], 3)
        self.assertEqual(result["failure_url"], "https://interia.pl/")
        self.assertEqual(result["failure_action_type"], "DETERMINISTIC_BOUNDED_VIEWPORT_SCROLL")
        self.assertEqual(result["failure_exception_type"], "playwright._impl._errors.Error")

    def test_c_browser_pass_wrong_tunnel_port_is_mode_purity_fail(self) -> None:
        purity = classifier.evaluate_mode_purity(
            "shadowsocks",
            {"original": 10, "observed": 10, "egress": 10},
            {"21001": 2, "21002": 0, "21003": 0},
            0,
            0,
        )
        workload = {"hard_failure_count": 0, "success_count": 4, "event_count": 4}
        result = resolve(workload=workload, executor_rc=0, purity=purity)
        self.assertEqual(result["failure_class"], "MODE_PURITY_FAIL")

    def test_d_missing_quality_report_does_not_imply_mode_purity_fail(self) -> None:
        rows = [{"phase": "EXECUTOR_EXIT", "exit_code": 1, "error": "Error: browser action failed"}]
        result = resolve(workload=None, executor_rc=1, rows=rows)
        self.assertEqual(result["failure_class"], "WORKLOAD_HARD_FAILURE")
        self.assertNotEqual(result["failure_class"], "MODE_PURITY_FAIL")

    def test_e_context_destroyed_attempt_one_is_retry_authorized(self) -> None:
        attempt = {
            "status": "FAIL",
            "failure_class": classifier.EXECUTION_CONTEXT_DESTROYED,
            "pre_health": "PASS",
            "post_health": "PASS",
            "mode_purity": "PASS",
            "redsocks_conn_max_hits": 0,
            "infrastructure_health_lost": 0,
            "server_egress_degraded": 0,
            "trojan_public_path_degraded": 0,
            "capture": {"status": "PASS", "unexpected_process_exit": 0, "oom": 0},
            "residual": 0,
        }
        self.assertEqual(
            retry.retry_authorized(attempt, attempt=1),
            (True, "AUTHORIZED_TRANSIENT:EXECUTION_CONTEXT_DESTROYED_DUE_TO_NAVIGATION"),
        )

    def test_f_same_failure_attempt_two_is_hard_stop(self) -> None:
        attempt = {
            "status": "FAIL",
            "failure_class": classifier.EXECUTION_CONTEXT_DESTROYED,
            "pre_health": "PASS",
            "post_health": "PASS",
            "mode_purity": "PASS",
            "redsocks_conn_max_hits": 0,
            "infrastructure_health_lost": 0,
            "server_egress_degraded": 0,
            "trojan_public_path_degraded": 0,
            "capture": {"status": "PASS", "unexpected_process_exit": 0, "oom": 0},
            "residual": 0,
        }
        allowed, reason = retry.retry_authorized(attempt, attempt=2)
        self.assertFalse(allowed)
        self.assertEqual(reason, "MAX_ATTEMPTS_REACHED")
        with self.assertRaisesRegex(production.HardStop, "attempt2 failure"):
            production.enforce_failed_attempt_stop(2, "synthetic_sample", attempt, allowed)


if __name__ == "__main__":
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(FailureClassifierV2Tests)
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    if not result.wasSuccessful():
        raise SystemExit(1)
    print("FORMAL_V3_FAILURE_CLASSIFIER_V2_PASS")
