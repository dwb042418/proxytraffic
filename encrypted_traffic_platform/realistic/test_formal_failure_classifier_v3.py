#!/usr/bin/env python3
"""NON-FORMAL exact-evidence and fail-closed classifier/policy regression."""
import copy
import json
from pathlib import Path
import subprocess
import unittest
from unittest.mock import patch
import formal_failure_classifier_v3 as classifier
import run_single_quartet_v3_validation_retry_v4 as retry

EVIDENCE = Path('/home/etip/datasets/diagnostics/sample0021_executor_forensic_20260907/sample0021_forensic.json')

def fixture():
    evidence = json.loads(EVIDENCE.read_text())
    root = Path(evidence['evidence_root'])
    def count(path, expression=None):
        cmd = ['tshark', '-r', str(path)]
        if expression: cmd += ['-Y', expression]
        cmd += ['-T', 'fields', '-e', 'frame.number']
        return len(subprocess.run(cmd, check=True, capture_output=True, text=True).stdout.splitlines())
    purity = classifier.audit_mode_purity(root, 'vless', count,
        workload=None, phase_rows=evidence['phase_rows'])
    args = dict(executor_local_timeout=False, supervisor=evidence['supervisor'], browser_residual=0,
                conn_max_hits=0, oom_count=0, unexpected_exit=0, infrastructure_lost=0,
                mode_purity=purity, capture_status=evidence['capture_finalization']['status'],
                workload=None, executor_rc=evidence['supervisor']['executor_exit_code'],
                plan_sha_matches=True, expected_event_count=10, phase_rows=evidence['phase_rows'],
                stderr_text=evidence['supervisor_stderr'])
    result = copy.deepcopy(evidence['frozen_result'])
    result.update(classifier.resolve_attempt_failure(**args))
    result['mode_purity'] = purity['status']
    result['mode_purity_issues'] = purity['issues']
    # Feed the saved historical journal command responses through the production evidence parser.
    def saved_command(cmd, timeout):
        from types import SimpleNamespace
        host = cmd[4] if cmd[0] == 'ssh' else 'collector'
        # SSH vector is ssh -o BatchMode=yes HOST COMMAND.
        if cmd[0] == 'ssh': host = cmd[3]
        text = ' '.join(cmd)
        kind = 'kernel' if ' -k ' in text else 'warnings'
        return SimpleNamespace(**evidence['journals'][f'{host}_{kind}'])
    with patch.object(retry.base, 'run', side_effect=saved_command), patch.object(retry.base, 'write_json'):
        result['executor_initialization_health'] = retry.executor_initialization_health(
            result['attempt_started_utc'], evidence['supervisor_stderr'], root)
    return evidence, args, purity, result

class ClassifierPolicyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.evidence, cls.args, cls.purity, cls.result = fixture()

    def test_sample0021_exact_evidence(self):
        self.assertEqual(self.evidence['frozen_result']['failure_class'], 'MODE_PURITY_FAIL')
        self.assertEqual(self.result['failure_class'], classifier.DRIVER_CONNECTION_CLOSED)
        self.assertEqual(self.result['failure_stage'], 'EXECUTOR_INITIALIZATION')
        self.assertIs(self.result['workload_started'], False)
        self.assertEqual(self.purity['status'], 'NOT_EVALUABLE')
        self.assertTrue(retry.retry_authorized(self.result)[0])

    def test_oom_blocks_retry(self):
        args = {**self.args, 'oom_count': 1}
        self.assertEqual(classifier.resolve_attempt_failure(**args)['failure_class'], 'OOM')
        result = copy.deepcopy(self.result); result['capture']['oom'] = 1
        self.assertFalse(retry.retry_authorized(result)[0])

    def test_infrastructure_loss_blocks_retry(self):
        args = {**self.args, 'infrastructure_lost': 1}
        self.assertEqual(classifier.resolve_attempt_failure(**args)['failure_class'], 'INFRASTRUCTURE_HEALTH_LOST')
        result = {**self.result, 'pre_health': 'FAIL'}
        self.assertFalse(retry.retry_authorized(result)[0])

    def test_empty_capture_not_evaluable(self):
        self.assertEqual(self.purity['issues'], [])
        self.assertEqual(self.purity['evaluation_reason'], 'NO_WORKLOAD_TRAFFIC_DUE_TO_EXECUTOR_STARTUP_FAILURE')

    def test_real_wrong_mode_traffic(self):
        purity = classifier.evaluate_mode_purity('vless', dict(original=10, observed=10, egress=10),
            {'21001': 0, '21002': 1, '21003': 0}, 0, 0, workload_started=True)
        self.assertEqual(purity['status'], 'FAIL')
        args = {**self.args, 'phase_rows': [{'phase': 'NAV_START'}], 'mode_purity': purity}
        self.assertEqual(classifier.resolve_attempt_failure(**args)['failure_class'], 'MODE_PURITY_FAIL')

    def test_public443_bypass(self):
        purity = classifier.evaluate_mode_purity('vless', dict(original=10, observed=10, egress=10),
            {'21001': 1, '21002': 0, '21003': 0}, 1, 0, workload_started=True)
        args = {**self.args, 'phase_rows': [{'phase': 'NAV_START'}], 'mode_purity': purity}
        self.assertEqual(classifier.resolve_attempt_failure(**args)['failure_class'], 'MODE_PURITY_FAIL')
        self.assertFalse(retry.retry_authorized({**self.result, 'mode_purity': 'FAIL'})[0])

    def test_existing_navigation_timeout_and_http429(self):
        for error, expected, allowed in [('Page.goto: Timeout 30000ms exceeded.', 'MAIN_NAVIGATION_TIMEOUT', True),
                                       ('unacceptable main HTTP status: 429', 'HTTP_STATUS_429', False)]:
            rows = [{'phase': 'NAV_START', 'event_index': 0, 'url': 'https://example.org/'},
                    {'phase': 'EXECUTOR_EXIT', 'error': error}]
            args = {**self.args, 'phase_rows': rows, 'mode_purity': {'status': 'PASS', 'issues': []}}
            failure = classifier.resolve_attempt_failure(**args)
            self.assertEqual(failure['failure_class'], expected)
            self.assertEqual(retry.retry_authorized({**self.result, **failure, 'mode_purity': 'PASS'})[0], allowed)

    def test_each_driver_gate_fails_closed(self):
        for key in ['oom', 'kernel_kill', 'segfault', 'persistent_service_failure', 'system_resource_exhaustion', 'persistent_driver_failure']:
            result = copy.deepcopy(self.result); result['executor_initialization_health'][key] = 1
            with self.subTest(gate=key): self.assertFalse(retry.retry_authorized(result)[0])
        for change in [{'workload_started': True}, {'failure_stage': 'NAVIGATION'}, {'residual': 1},
                       {'executor_initialization_health': {}}, {'redsocks_actual_conn_max': 128}]:
            self.assertFalse(retry.retry_authorized({**self.result, **change})[0])

    def test_generic_executor_crash_not_retryable(self):
        args = {**self.args, 'stderr_text': 'segmentation fault',
                'phase_rows': [{'phase': 'EXECUTOR_START'}, {'phase': 'EXECUTOR_EXIT', 'error': 'segmentation fault'}]}
        failure = classifier.resolve_attempt_failure(**args)
        self.assertEqual(failure['failure_class'], 'EXECUTOR_INITIALIZATION_FAILURE')
        self.assertFalse(retry.retry_authorized({**self.result, **failure})[0])

    def test_attempt3_stop_and_no_attempt4(self):
        self.assertTrue(retry.retry_authorized(self.result, 1)[0])
        self.assertTrue(retry.retry_authorized(self.result, 2)[0])
        self.assertFalse(retry.retry_authorized(self.result, 3)[0])
        self.assertFalse(retry.retry_authorized(self.result, 4)[0])

if __name__ == '__main__':
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(ClassifierPolicyTests)
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    if not result.wasSuccessful(): raise SystemExit(1)
    print('SAMPLE0021_CLASSIFICATION_REGRESSION_PASS')
    print('FORMAL_V3_FAILURE_CLASSIFIER_V3_PASS')
    print('FORMAL_TRANSIENT_RETRY_POLICY_V4_PASS')
