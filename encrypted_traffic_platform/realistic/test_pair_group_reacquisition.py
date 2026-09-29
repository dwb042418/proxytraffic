import copy
import unittest
from pair_group_reacquisition import eligible, reacquisition_rows, ReacquisitionRefused, bind_acquisition_ledger, add_closed_attempt_counts


class BoundedReacquisitionTest(unittest.TestCase):
    def setUp(self):
        self.row = dict(sequence_id='366', schedule_id='old366', plan_sha256='plan', mode_order='direct')
        self.entries = [dict(sample_id='old366', attempt=str(n), final_status='FAIL', plan_sha='plan') for n in (1, 2, 3)]
        result = dict(plan_sha256='plan', mode='direct', pre_health='PASS', post_health='PASS', mode_purity='PASS',
            redsocks_conn_max_hits=0, infrastructure_health_lost=0, server_egress_degraded=0,
            trojan_public_path_degraded=0, residual=0, observed_direct_public_443_syn_count=0,
            capture=dict(status='PASS', pcap_stable_size=True, executor_bounded=True,
                active_health_probe_during_capture=0, archive_control_packets_during_capture=0,
                oom=0, unexpected_process_exit=0, conntrack_exhausted_observations=0))
        self.failures = [{**copy.deepcopy(result), 'status':'FAIL', 'attempt':n} for n in (1,2,3)]
        self.diagnostic = dict(results=[dict(mode=m, trial=n, attempt=1, retry=False,
            infrastructure_issues=[], valid_for_endpoint_judgment=True, full_workload_pass=True,
            artifact_dir=f'{m}/{n}', result={**copy.deepcopy(result), 'status':'PASS', 'attempt':1,
                'mode':m, 'redsocks_actual_conn_max':2048})
            for m in ('direct','vless','shadowsocks','trojan') for n in (1,2,3)])

    def check(self, used=0, triggers=()):
        return eligible(self.row, self.entries, self.failures, self.diagnostic, used, triggers, 2048)

    def test_exact_fixed_diagnostic_authorizes_one_new_acquisition(self):
        self.assertEqual(self.check(), 364)

    def test_refuses_second_acquisition(self):
        with self.assertRaisesRegex(ReacquisitionRefused, 'BUDGET_EXHAUSTED'): self.check(used=1)

    def test_rejects_incomplete_attempt_budget(self):
        self.entries.pop()
        with self.assertRaises(ReacquisitionRefused): self.check()

    def test_rejects_repeated_diagnostic_lifecycle(self):
        self.diagnostic['results'][-1] = self.diagnostic['results'][-2]
        with self.assertRaises(ReacquisitionRefused): self.check()

    def test_rejects_plan_drift_and_infrastructure_loss_and_retirement(self):
        for mutate in (lambda: self.failures[0].update(plan_sha256='different'),
                       lambda: self.failures[0]['capture'].update(oom=1),
                       lambda: self.diagnostic['results'][0].update(retry=True)):
            old=copy.deepcopy((self.failures,self.diagnostic)); mutate()
            with self.assertRaises(ReacquisitionRefused): self.check()
            self.failures,self.diagnostic=old
        with self.assertRaises(ReacquisitionRefused): self.check(triggers=['retirement'])

    def test_identity_changes_only_acquisition_namespace(self):
        rows=[{**self.row,'sequence_id':str(n),'schedule_id':f'old{n}'} for n in range(365,369)]
        fresh=reacquisition_rows(rows,92)
        self.assertEqual(len({r['schedule_id'] for r in fresh}),4)
        for old,new in zip(rows,fresh):
            self.assertNotEqual(old['schedule_id'],new['schedule_id'])
            self.assertEqual({k:v for k,v in old.items() if k!='schedule_id'},
                             {k:v for k,v in new.items() if k!='schedule_id'})

    def test_later_domain_amendment_retains_its_active_ledger(self):
        self.assertFalse(bind_acquisition_ledger({'carry_forward':{'valid_samples':364}},368))
        self.assertTrue(bind_acquisition_ledger({'carry_forward':{'valid_samples':368}},368))
        self.assertTrue(bind_acquisition_ledger({'carry_forward':{'valid_samples':400}},368))

    def test_closed_pair_attempts_do_not_recount_domain_history(self):
        # Current aggregate already includes the three retired rt.ru attempts.
        current = {'TOTAL_ATTEMPTS':377, 'RETRY_COUNT':8}
        closed = [dict(sample_id='old365', attempt='1')]
        closed += [dict(sample_id='old366', attempt=str(n)) for n in (1,2,3)]
        result = add_closed_attempt_counts(current, closed)
        self.assertEqual(result['TOTAL_ATTEMPTS'],381)
        self.assertEqual(result['RETRY_COUNT'],10)  # sample85 recovery adjustment is installed last.

    def test_preworkload_abort_is_not_counted_as_scientific_attempt(self):
        current = {'TOTAL_ATTEMPTS': 544, 'RETRY_COUNT': 18}
        closed = [
            dict(sample_id='sample513', attempt='1', browser_attempt_consumed='true'),
            dict(sample_id='sample514', attempt='1', browser_attempt_consumed='true'),
            dict(sample_id='sample515', attempt='1', browser_attempt_consumed='false'),
        ]
        result = add_closed_attempt_counts(current, closed)
        self.assertEqual(result['TOTAL_ATTEMPTS'], 546)
        self.assertEqual(result['RETRY_COUNT'], 18)


if __name__=='__main__': unittest.main()
