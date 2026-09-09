import contextlib
import copy
import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import run_realistic_campaign as c
from stress_terminal_taxonomy import SamplePolicyHardStop

c.configure(Path(__file__).parents[2]/'docs/realistic_v1/formal_t0_v3/autonomous_mission/r10_stress_v4/campaign_config.json')
f = c.f


class MissionTests(unittest.TestCase):
    def setUp(self):
        self.stack = contextlib.ExitStack();self.addCleanup(self.stack.close)
        self.temp = Path(self.stack.enter_context(tempfile.TemporaryDirectory()))
        self.stack.enter_context(patch.object(c.cfg,'LOCAL_BASE',self.temp))
        self.root = c.CONFIG.local_root;self.root.mkdir()
        self.stack.enter_context(patch.object(f,'LOCAL_PRODUCTION_ROOT',self.root))
        self.row = c.IDENTITY.lookup(5)
        source = Path('/home/etip/datasets/staging/realistic_v1/non_formal_production_readiness_r10_v3/failed_artifacts/formal_t0_v3_sample0005/attempt_1_20260909T07014736386_HTTP_STATUS_500/validation_attempt_result.json')
        self.result = json.loads(source.read_text())

    def sample(self, fail_until=1, archive_pending=False):
        component = f.configure_execution_components();calls=[]
        def execute(mode,attempt,selection,attempts_root,remote,**kwargs):
            calls.append((attempt,remote,selection['plan_sha256']))
            path=attempts_root/f'attempt_{attempt}';path.mkdir()
            result=copy.deepcopy(self.result);result.update(attempt=attempt,artifact_dir=str(path),retry_policy='FORMAL_T0_V3_TRANSIENT_RETRY_POLICY_V5')
            if attempt>fail_until:
                result.update(status='PASS',failure_class='',failure_event_index='',failure_url='')
                result['browser'].update(success_count=4,hard_failure_count=0,outcome='PASS')
            (path/'workload').mkdir();(path/'workload/workload_plan.json').write_bytes(Path(self.row['plan_path']).read_bytes())
            for name in ('original.pcap','observed.pcap','egress.pcap'):(path/name).write_bytes(b'SYNTHETIC_TEST_ONLY')
            (path/'validation_attempt_result.json').write_text(json.dumps(result))
            return result
        self.stack.enter_context(patch.object(component,'run_attempt',side_effect=execute))
        self.stack.enter_context(patch.object(f,'configure_execution_components',return_value=component))
        for name in ('verify_git','verify_orchestrator_at_head','verify_frozen_sha','prepare_remote_inputs'):
            self.stack.enter_context(patch.object(f,name))
        archive=self.stack.enter_context(patch.object(f,'archive_sample',side_effect=f.RemoteArchivePending('Broken pipe') if archive_pending else None))
        if fail_until>=3:
            with self.assertRaises(SamplePolicyHardStop):f.run_formal_sample(self.row,c.HEAD,{Path(self.row['plan_path']):self.row['plan_sha256']},1)
        elif archive_pending:
            with self.assertRaises(f.RemoteArchivePending):f.run_formal_sample(self.row,c.HEAD,{Path(self.row['plan_path']):self.row['plan_sha256']},1)
        else:
            f.run_formal_sample(self.row,c.HEAD,{Path(self.row['plan_path']):self.row['plan_sha256']},1)
        return calls, f.read_ledger(c.CONFIG.retry_ledger), archive

    def test_exact_500_whole_sample_retry_preserves_failure(self):
        calls,ledger,_=self.sample()
        self.assertEqual([x[0] for x in calls],[1,2]);self.assertNotEqual(calls[0][1],calls[1][1])
        self.assertEqual(calls[0][2],calls[1][2])
        self.assertEqual([x['final_status'] for x in ledger],['FAIL','PASS'])
        self.assertEqual(ledger[0]['failure_class'],'HTTP_STATUS_500')
        self.assertEqual(Path(ledger[0]['artifact_path'],'observed.pcap').read_bytes(),b'SYNTHETIC_TEST_ONLY')
        self.assertEqual(ledger[0]['event_index'],'1')

    def test_attempt3_is_terminal_no_attempt4(self):
        calls,ledger,archive=self.sample(fail_until=3)
        self.assertEqual([x[0] for x in calls],[1,2,3]);archive.assert_not_called()
        self.assertEqual(ledger[-1]['retry_authorized'],'false')
        self.assertTrue(all(Path(e['artifact_path'],'validation_attempt_result.json').exists() for e in ledger))

    def test_archive_pending_resumes_upload_only(self):
        calls,ledger,_=self.sample(fail_until=0,archive_pending=True)
        self.assertEqual(len(calls),1)
        self.assertEqual(f.resume_decision(self.row,self.root,False,ledger,c.HEAD),'RESUME_REMOTE_ARCHIVE_ONLY')
        self.assertEqual(ledger[0]['final_status'],'PASS')

    def test_source_identity_and_ssh_taxonomy(self):
        self.assertEqual(c.IDENTITY.lookup(85)['source_schedule_sequence_id'],'389')
        with patch.object(f,'run_command',return_value=SimpleNamespace(returncode=255,stdout='',stderr='Broken pipe')):
            with self.assertRaises(f.RemoteArchivePending):f.remote_complete_valid(self.row,c.HEAD)

    def test_96_boundary_exits_before97(self):
        calls=[]
        def collect(row,*args):
            calls.append(int(row['sequence_id']));p=c.CONFIG.local_sample_root/row['schedule_id'];p.mkdir(parents=True)
            (p/'sample_metadata.json').write_text('{"final_result":{}}')
        state={'next_action':'RUN_ATTEMPT1','next_sequence_id':1,'valid_samples':0,'complete_pair_groups':0,'mode_counts':{m:0 for m in f.MODES}}
        for name in ('dry_run','require_no_pending_hotspot','verify_orchestrator_at_head','verify_no_out_of_order_artifacts','mark_monitor_boundary','verify_frozen_sha'):
            self.stack.enter_context(patch.object(f,name))
        self.stack.enter_context(patch.object(f,'run_command',return_value=SimpleNamespace(stdout='')))
        self.stack.enter_context(patch.object(f,'scan_resume_state',return_value=state))
        self.stack.enter_context(patch.object(f,'free_disk_bytes',return_value=30*1024**3))
        self.stack.enter_context(patch.object(f,'run_formal_sample',side_effect=collect))
        self.stack.enter_context(patch.object(f,'BOUNDARY_HOOK',None))
        self.stack.enter_context(patch.object(f,'STOP_AFTER_SAMPLES',96))
        self.stack.enter_context(patch.object(f,'progress_from_schedule',side_effect=lambda *a:{'VALID_SAMPLES':max(calls),'COMPLETE_PAIR_GROUPS':max(calls)//4,'NEXT_SEQUENCE_ID':max(calls)+1}))
        self.stack.enter_context(patch.object(f,'write_progress_incremental',side_effect=lambda v,g,n,m:{'VALID_SAMPLES':v,'COMPLETE_PAIR_GROUPS':g,'NEXT_SEQUENCE_ID':n}))
        self.assertEqual(f.execute_production(c.HEAD,resume=False),76)
        self.assertEqual(calls,list(range(1,97)))
        self.assertIn('process_id',json.loads(c.CONFIG.restart_record.read_text()))


if __name__=='__main__':unittest.main(verbosity=2)
