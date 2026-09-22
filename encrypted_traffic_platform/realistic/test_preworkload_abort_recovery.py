import unittest
from preworkload_abort_recovery import validate_abort

class PreworkloadAbortTest(unittest.TestCase):
    def setUp(self):
        self.entry=dict(browser_attempt_consumed='false',attempt='1',final_status='FAIL',
                        failure_class='INFRASTRUCTURE_HEALTH_LOST',plan_sha='same',workload_started='unknown')
        self.result=dict(status='FAIL',attempt=1,failure_class='INFRASTRUCTURE_HEALTH_LOST',
                         plan_sha256='same',pre_health='FAIL',post_health='NOT_RUN_PRE_HEALTH_FAIL',
                         capture={'status':'NOT_STARTED'},residual=0)

    def test_unstarted_infrastructure_abort_is_not_scientific_attempt(self):
        self.assertEqual(validate_abort(self.entry,self.result,['pre_sample_health_check.json']),
                         'PRE_WORKLOAD_INFRASTRUCTURE_ABORT')

    def test_started_browser_or_workload_is_rejected(self):
        for field,value in [('browser_attempt_consumed','true'),('workload_started','true')]:
            with self.subTest(field=field),self.assertRaises(ValueError):
                validate_abort({**self.entry,field:value},self.result,[])

    def test_capture_or_executor_evidence_is_rejected(self):
        for file in ('original.pcap','executor_phase.jsonl','executor_supervisor/state.json','workload/result.json'):
            with self.subTest(file=file),self.assertRaises(ValueError):
                validate_abort(self.entry,self.result,[file])

    def test_post_workload_failure_cannot_be_relabelled(self):
        with self.assertRaises(ValueError):
            validate_abort(self.entry,{**self.result,'pre_health':'PASS','post_health':'FAIL'},[])

if __name__=='__main__':unittest.main()
