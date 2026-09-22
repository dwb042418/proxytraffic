import copy
import unittest
import infrastructure_pair_group_recovery as recovery

class InfrastructureRecoveryTest(unittest.TestCase):
    def setUp(self):
        self.rows=[dict(sequence_id=str(n),schedule_id=f'sample{n}',plan_sha256='same-plan',mode_order=m)
                   for n,m in zip(range(393,397),('shadowsocks','trojan','direct','vless'))]
        self.entries=[dict(sequence_id=str(n),sample_id=f'sample{n}',attempt='1',plan_sha='same-plan',
                           final_status='FAIL' if n==396 else 'PASS',
                           failure_class='INFRASTRUCTURE_HEALTH_LOST' if n==396 else '',retry_authorized='false')
                      for n in range(393,397)]
        self.health={'status':'PASS','rounds':2,'definition_unchanged':True,'retry':False,
                     'classification':'RECOVERED_OPERATIONAL_INFRASTRUCTURE_FAILURE'}

    def test_recovered_nonretryable_attempt_closes_whole_group(self):
        self.assertEqual(recovery.authorize(self.rows,self.entries,self.health,0),392)

    def test_refuses_unresolved_health_and_second_reacquisition(self):
        for status,used in [('FAIL',0),('PASS',1)]:
            with self.subTest(status=status,used=used), self.assertRaises(ValueError):
                recovery.authorize(self.rows,self.entries,{**self.health,'status':status},used)

    def test_no_domain_failure_or_old_attempt2(self):
        for changes in ({'failure_class':'HTTP_STATUS_403'},{'attempt':'2'}):
            entries=copy.deepcopy(self.entries);entries[-1].update(changes)
            with self.assertRaises(ValueError):recovery.authorize(self.rows,entries,self.health,0)

    def test_new_namespace_changes_no_scientific_identity(self):
        rows=recovery.fresh_rows(self.rows,99)
        for old,new in zip(self.rows,rows):
            self.assertEqual(new['schedule_id'],old['schedule_id']+'_pair_group_0099_infra_recovery1')
            self.assertEqual({k:v for k,v in old.items() if k!='schedule_id'},
                             {k:v for k,v in new.items() if k!='schedule_id'})

    def test_rejects_plan_drift(self):
        self.rows[0]['plan_sha256']='other-plan'
        with self.assertRaises(ValueError):recovery.authorize(self.rows,self.entries,self.health,0)

if __name__=='__main__':unittest.main()
