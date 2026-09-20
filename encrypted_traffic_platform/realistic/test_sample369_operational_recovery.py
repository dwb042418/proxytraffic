import copy
import unittest
from sample369_operational_recovery import retry_decision, recovery_counts, CLAUSE, SAMPLE


class PrehealthRecoveryTest(unittest.TestCase):
    def setUp(self):
        self.retained = dict(attempt=1, mode='direct', status='FAIL',
            artifact_dir='/retained/sample369/attempt_1', pre_health='FAIL',
            failure_class='INFRASTRUCTURE_HEALTH_LOST', capture={'status':'NOT_STARTED'})
        self.ordinary = lambda result, attempt=None: (False, 'FROZEN_NON_RETRYABLE')

    def test_authorizes_exact_retained_failure_once(self):
        self.assertEqual(retry_decision(copy.deepcopy(self.retained),1,self.retained,self.ordinary), (True,CLAUSE))

    def test_refuses_other_sample_or_changed_failure_evidence(self):
        for field,value in [('artifact_dir','/other/attempt_1'),('pre_health','PASS')]:
            changed={**self.retained,field:value}
            self.assertEqual(retry_decision(changed,1,self.retained,self.ordinary),(False,'FROZEN_NON_RETRYABLE'))

    def test_later_infrastructure_attempt_never_uses_exception(self):
        for attempt in (2,3,4):
            self.assertEqual(retry_decision(self.retained,attempt,self.retained,self.ordinary),(False,'FROZEN_NON_RETRYABLE'))

    def test_ordinary_transient_delegates_to_frozen_policy(self):
        result={'attempt':2,'failure_class':'MAIN_NAVIGATION_TIMEOUT'}
        policy=lambda result,attempt=None: (attempt==2,'FROZEN_TRANSIENT')
        self.assertEqual(retry_decision(result,2,self.retained,policy),(True,'FROZEN_TRANSIENT'))

    def test_recovery_retains_prior_infrastructure_statistics(self):
        prior=dict(TOTAL_ATTEMPTS=383,RETRY_COUNT=10,OPERATIONAL_INFRASTRUCTURE_INTERRUPTION_COUNT=1,OPERATIONAL_INFRASTRUCTURE_RECOVERY_COUNT=1)
        authorized=dict(sample_id=SAMPLE,attempt='1',retry_reason=CLAUSE)
        before=recovery_counts(prior,[authorized],authorized)
        self.assertEqual((before['TOTAL_ATTEMPTS'],before['RETRY_COUNT']), (383,10))
        self.assertEqual(before['OPERATIONAL_INFRASTRUCTURE_INTERRUPTION_COUNT'],2)
        after=recovery_counts(prior,[authorized,dict(sample_id=SAMPLE,attempt='2')],authorized)
        self.assertEqual((after['TOTAL_ATTEMPTS'],after['RETRY_COUNT']), (383,9))
        self.assertEqual(after['OPERATIONAL_INFRASTRUCTURE_RECOVERY_COUNT'],2)


if __name__=='__main__':unittest.main()
