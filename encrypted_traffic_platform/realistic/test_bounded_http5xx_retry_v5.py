import copy
import json
import unittest
from pathlib import Path
from unittest.mock import Mock

from bounded_http5xx_retry_v5 import authorize_http5xx, extend_retry_authorized


class BoundedHTTP5xxTests(unittest.TestCase):
    def setUp(self):
        evidence = Path('/home/etip/datasets/staging/realistic_v1/non_formal_production_readiness_r10_v3/failed_artifacts/formal_t0_v3_sample0005/attempt_1_20260909T07014736386_HTTP_STATUS_500/validation_attempt_result.json')
        self.result = json.loads(evidence.read_text())

    def test_exact_sample0005_main_document_http500(self):
        original = copy.deepcopy(self.result)
        self.assertEqual(self.result['failure_event_index'], 1)
        self.assertEqual(self.result['failure_url'], 'https://www.gov.br/')
        self.assertEqual(authorize_http5xx(self.result, 1), (True, 'AUTHORIZED_TRANSIENT:HTTP_STATUS_500'))
        self.assertTrue(authorize_http5xx(self.result, 2)[0])
        self.assertEqual(authorize_http5xx(self.result, 3), (False, 'MAX_ATTEMPTS_REACHED'))
        self.assertEqual(authorize_http5xx(self.result, 4), (False, 'INVALID_ATTEMPT_NUMBER'))
        self.assertEqual(self.result, original)

    def test_only_four_selected_main_statuses(self):
        previous = Mock(return_value=(False, 'EXISTING_POLICY_DECISION'))
        decide = extend_retry_authorized(previous)
        for status in (500, 502, 503, 504):
            with self.subTest(status=status):
                self.assertTrue(decide({**self.result, 'failure_class':f'HTTP_STATUS_{status}'}, 1)[0])
        previous.assert_not_called()
        for failure in ('HTTP_STATUS_403', 'HTTP_STATUS_429', 'HTTP_STATUS_501',
                        'HTTP_STATUS_505', 'HTTP_STATUS_404', 'MAIN_NAVIGATION_TIMEOUT'):
            with self.subTest(failure=failure):
                value = {**self.result, 'failure_class':failure}
                self.assertEqual(decide(value, 1), (False, 'EXISTING_POLICY_DECISION'))
                previous.assert_called_with(value, attempt=1)

    def test_unclean_or_non_main_document_cannot_retry(self):
        for key, value in (
            ('pre_health','FAIL'), ('post_health','FAIL'), ('mode_purity','FAIL'),
            ('redsocks_conn_max_hits',1), ('infrastructure_health_lost',1),
            ('server_egress_degraded',1), ('trojan_public_path_degraded',1),
            ('residual',1), ('redsocks_actual_conn_max',128),
            ('observed_direct_public_443_syn_count',1),
            ('failure_action_type','SUBRESOURCE'), ('failure_stage','HEALTH'),
        ):
            with self.subTest(gate=key):
                self.assertFalse(authorize_http5xx({**self.result,key:value},1)[0])
        for key, value in (('status','FAIL'), ('oom',1), ('unexpected_process_exit',1)):
            with self.subTest(capture=key):
                invalid = {**self.result, 'capture':{**self.result['capture'], key:value}}
                self.assertFalse(authorize_http5xx(invalid,1)[0])


if __name__ == '__main__':
    unittest.main(verbosity=2)
