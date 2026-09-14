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

    def sample(self, fail_until=1, archive_pending=False, start_attempt=1):
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
            with self.assertRaises(SamplePolicyHardStop):f.run_formal_sample(self.row,c.HEAD,{Path(self.row['plan_path']):self.row['plan_sha256']},start_attempt)
        elif archive_pending:
            with self.assertRaises(f.RemoteArchivePending):f.run_formal_sample(self.row,c.HEAD,{Path(self.row['plan_path']):self.row['plan_sha256']},start_attempt)
        else:
            f.run_formal_sample(self.row,c.HEAD,{Path(self.row['plan_path']):self.row['plan_sha256']},start_attempt)
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

    def test_exact_v4_archive_control_contamination(self):
        component=f.configure_execution_components()
        artifact=Path('/home/etip/datasets/staging/realistic_v1/non_formal_production_readiness_r10_v4/samples/formal_t0_v3_sample0001/attempts/attempt_1')
        count=component.archive_control_packet_count(artifact)
        self.assertEqual(count,43)
        result=json.loads((artifact/'validation_attempt_result.json').read_text())
        workload=json.loads((artifact/'workload/workload_report.json').read_text())
        purity=json.loads((artifact/'mode_purity_report_v3.json').read_text())
        classified=component.resolve_attempt_failure(executor_local_timeout=False,supervisor={'timed_out':False,'residual_count':0},
            browser_residual=0,conn_max_hits=0,oom_count=0,unexpected_exit=0,infrastructure_lost=0,
            mode_purity=purity,capture_status='FAIL' if count else result['capture']['status'],
            workload=workload,executor_rc=0,plan_sha_matches=True,expected_event_count=workload['event_count'],
            phase_rows=component.classifier.read_phase_rows(artifact/'executor_phase.jsonl'))
        self.assertEqual(classified['failure_class'],'CAPTURE_FINALIZATION_FAIL')

    def test_exact_component_exception_saves_standard_result(self):
        component=f.configure_execution_components()
        with patch.object(component.base,'cleanup_mode'),patch.object(component.base,'run',return_value=SimpleNamespace(stdout='0')):
            result=f.synthetic_component_failure(component,self.row,1,self.root,KeyboardInterrupt())
        path=Path(result['artifact_dir'])/'validation_attempt_result.json'
        self.assertEqual(json.loads(path.read_text()),result)
        self.assertIn('KeyboardInterrupt',result['terminal_implementation_exception'])

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


class BoundaryResumeTests(unittest.TestCase):
    setUp = MissionTests.setUp

    def boundary_state(self, n):
        evidence=Path('/home/etip/datasets/staging/realistic_v1/non_formal_production_readiness_r10_v8')
        c.CONFIG.telemetry_root.mkdir(exist_ok=True)
        baseline=json.loads((evidence/'resource_telemetry/boundary_0000.json').read_text())
        for i in range(n):
            c.f.atomic_write_json(c.CONFIG.telemetry_root/f'boundary_{i:04d}.json',{**baseline,'sequence_id':i})
        for milestone in (24,64,128):
            if milestone<n:
                c.f.atomic_write_json(c.CONFIG.checkpoint_path(milestone),{'status':'PASS','VALID_SAMPLES':milestone})
        if n>24:c.CONFIG.smoke_marker.write_text('24/24 PASS\n')
        row=c.IDENTITY.lookup(n)
        result=json.loads((evidence/'samples/formal_t0_v3_sample0080/sample_metadata.json').read_text())['final_result']
        result.update(plan_sha256=row['plan_sha256'],redsocks_actual_conn_max='NOT_APPLICABLE' if row['mode_order']=='direct' else 256)
        sample=c.CONFIG.local_sample_root/row['schedule_id'];sample.mkdir(parents=True,exist_ok=True)
        c.f.atomic_write_json(sample/'sample_metadata.json',{'final_result':result})
        return {'valid_samples':n,'complete_pair_groups':n//4,'next_sequence_id':n+1,
                'next_action':'RUN_ATTEMPT1','mode_counts':{m:n//4 for m in f.MODES},
                'decisions':[{'sequence_id':i,'decision':'SKIP_VALID_COMPLETE_REMOTE_ONLY'} for i in range(1,n+1)]}

    def test_exact_v8_storage_disconnect_recovers_boundary80_without_resampling(self):
        state=self.boundary_state(80);collected=[]
        before={p:p.read_bytes() for p in c.CONFIG.telemetry_root.iterdir()}
        old={**state,'valid_samples':79,'next_sequence_id':80,'complete_pair_groups':19}
        old['mode_counts']=dict(state['mode_counts']);old['mode_counts'][c.IDENTITY.lookup(80)['mode_order']]-=1
        for name in ('dry_run','require_no_pending_hotspot','verify_orchestrator_at_head','verify_no_out_of_order_artifacts','mark_monitor_boundary'):
            self.stack.enter_context(patch.object(f,name))
        self.stack.enter_context(patch.object(f,'scan_resume_state',return_value=old))
        self.stack.enter_context(patch.object(f,'free_disk_bytes',side_effect=lambda:19*1024**3 if collected else 30*1024**3))
        self.stack.enter_context(patch.object(f,'run_formal_sample',side_effect=lambda row,*a:collected.append(int(row['sequence_id']))))
        self.stack.enter_context(patch.object(f,'storage_recover',side_effect=f.RemoteArchivePending('SSH unavailable during remote completeness verification')))
        self.stack.enter_context(patch.object(f,'BOUNDARY_HOOK',c.boundary))
        with self.assertRaises(f.RemoteArchivePending):f.execute_production(c.HEAD,resume=True)
        self.assertEqual(collected,[80])
        self.assertFalse((c.CONFIG.telemetry_root/'boundary_0080.json').exists())
        def telemetry(n):f.atomic_write_json(c.CONFIG.telemetry_root/f'boundary_{n:04d}.json',{'sequence_id':n})
        with patch.object(c,'telemetry',side_effect=telemetry) as collect:
            def continue_production(*args,**kwargs):
                self.assertTrue((c.CONFIG.telemetry_root/'boundary_0080.json').exists())
                self.assertEqual(collected,[80])
                return 0
            with patch.object(c,'configure'),patch.object(c,'prestart_remote_commands',return_value=contextlib.nullcontext()),patch.object(c,'remote_path_preflight'),patch.object(f,'dry_run',return_value={'resume_state':state}),patch.object(f,'free_disk_bytes',return_value=30*1024**3),patch.object(f,'execute_production',side_effect=continue_production),patch.object(c,'final_report'):
                self.assertEqual(c.main(['--config',str(c.CONFIG.config_record),'--resume']),0)
            self.assertIsNone(c.recover_completed_boundary(state))
            collect.assert_called_once_with(80)
        self.assertEqual(collected,[80])
        self.assertTrue(all(p.read_bytes()==data for p,data in before.items()))
        self.assertEqual(json.loads((self.root/'boundary_recovery_0080.json').read_text())['status'],'COMPLETE')

    def test_pending_smoke_checkpoint_and_real_restart_boundaries(self):
        for n in (24,64,96):
            with self.subTest(sequence=n),tempfile.TemporaryDirectory() as temp,patch.object(c.cfg,'LOCAL_BASE',Path(temp)):
                c.CONFIG.local_root.mkdir();state=self.boundary_state(n)
                # Telemetry was already written before the interrupted remote check.
                path=c.CONFIG.telemetry_root/f'boundary_{n:04d}.json';path.write_text(json.dumps({'sequence_id':n}))
                original=path.read_bytes()
                progress={'VALID_SAMPLES':n,'COMPLETE_PAIR_GROUPS':n//4,'NEXT_SEQUENCE_ID':n+1,
                          'REMOTE_SHA_PASS':n,'mode_counts':{m:n//4 for m in f.MODES},'residual':0}
                def checkpoint(sequence):f.atomic_write_json(c.CONFIG.checkpoint_path(sequence),{'status':'PASS',**progress})
                with patch.object(c,'telemetry') as telemetry,patch.object(c,'checkpoint',side_effect=checkpoint),patch.object(f,'progress_from_schedule',return_value=progress):
                    code=c.recover_completed_boundary(state)
                    telemetry.assert_not_called()
                self.assertEqual(path.read_bytes(),original)
                if n==96:
                    self.assertEqual(code,76)
                    self.assertTrue(c.CONFIG.restart_record.exists())
                    self.assertFalse(c.CONFIG.resume_marker.exists())
                else:
                    self.assertIsNone(code);self.assertTrue(c.CONFIG.checkpoint_path(n).exists())
                    if n==24:self.assertTrue(c.CONFIG.smoke_marker.exists())

    def test_reject_historical_gap_or_later_consumed_attempt(self):
        state=self.boundary_state(80)
        earlier=c.CONFIG.telemetry_root/'boundary_0079.json';saved=earlier.read_bytes();earlier.unlink()
        with patch.object(c,'telemetry') as telemetry:
            with self.assertRaises(f.HardStop):c.recover_completed_boundary(state)
            telemetry.assert_not_called()
        earlier.write_bytes(saved)
        with patch.object(c,'ledger_audit',return_value=[{}]),patch.object(c.IDENTITY,'validate_ledger',return_value=c.IDENTITY.lookup(81)),patch.object(c,'telemetry') as telemetry:
            with self.assertRaises(f.HardStop):c.recover_completed_boundary(state)
            telemetry.assert_not_called()


class HostRestartRecoveryTests(MissionTests):
    def prepare_interruption(self):
        from external_host_restart_recovery import FAILURE_CLASS, FINAL_RESULT, CLAUSE, GATES
        path = c.CONFIG.failed_artifact_root/self.row['schedule_id']/'attempt_1_host_restart'
        path.mkdir(parents=True)
        (path/'original_raw.pcap').write_bytes(b'RETAIN_INTERRUPTED_EVIDENCE')
        result = copy.deepcopy(self.result)
        result.update(status=FINAL_RESULT, failure_class=FAILURE_CLASS, failure_event_index='',
                      failure_url='', artifact_dir=str(path), attempt=1,
                      plan_sha256=self.row['plan_sha256'], workload_started=True)
        f.atomic_write_json(path/'validation_attempt_result.json', result)
        f.formalize_attempt(path, self.row, result, 1, 'start', 'reboot', c.HEAD)
        entry = f.ledger_row_for_attempt(self.row,result,1,True,CLAUSE,'start','reboot',c.HEAD,FINAL_RESULT)
        f.append_ledger_atomic(c.CONFIG.retry_ledger,[entry])
        proof = dict(clause=CLAUSE,campaign_id=c.CONFIG.campaign_id,sample_id=self.row['schedule_id'],
                     attempt=1,plan_sha256=self.row['plan_sha256'],frozen_git_head=c.HEAD,
                     failure_class=FAILURE_CLASS,final_result=FINAL_RESULT,attempt_consumed=True,
                     max_attempts=3,gates={k:True for k in GATES},remote_evidence_path='/verified/test-only',
                     evidence_manifest_sha256='0'*64)
        f.atomic_write_json(path/'external_host_restart_recovery.json',proof)
        return path, entry, proof

    def test_consumed_restart_resumes_attempt2_then_normal_retry3(self):
        from external_host_restart_recovery import attempt_counts
        path,entry,_ = self.prepare_interruption()
        self.assertEqual(f.resume_decision(self.row,self.root,False,[entry],c.HEAD),'RUN_ATTEMPT2')
        calls,ledger,_ = self.sample(fail_until=2,start_attempt=2)
        self.assertEqual([x[0] for x in calls],[2,3])
        self.assertEqual(attempt_counts(ledger),dict(TOTAL_ATTEMPTS=3,RETRY_COUNT=1,
                         OPERATIONAL_INTERRUPTION_COUNT=1,OPERATIONAL_RECOVERY_COUNT=1))
        self.assertEqual((path/'original_raw.pcap').read_bytes(),b'RETAIN_INTERRUPTED_EVIDENCE')
        self.assertFalse(any(e.get('failure_class')=='EXTERNAL_HOST_RESTART_INTERRUPTED_ATTEMPT'
                             for e in f.hotspot_evidence(c.HEAD)))
        c.ledger_audit()

    def test_interrupted_attempt_budget_never_allows_attempt4(self):
        self.prepare_interruption()
        calls,ledger,archive=self.sample(fail_until=3,start_attempt=2)
        self.assertEqual([x[0] for x in calls],[2,3])
        self.assertEqual([int(e['attempt']) for e in ledger],[1,2,3])
        archive.assert_not_called()

    def test_verified_receipt_reuse_and_missing_remote_artifact(self):
        self.sample(fail_until=0)
        sample=c.CONFIG.local_sample_root/self.row['schedule_id']
        (sample/'SAMPLE_COMPLETE').write_text('complete')
        f.atomic_write_json(sample/'remote_sha_verification.json',dict(remote_sha_pass=True,remote_completeness_pass=True))
        (sample/'FINAL_METADATA_SHA256SUMS.txt').write_text('retained control fixture')
        f._REMOTE_RECEIPT_CACHE.clear()
        with patch.object(f,'run_command',return_value=SimpleNamespace(returncode=0)) as remote:
            self.assertTrue(f.remote_complete_valid(self.row,c.HEAD))
            self.assertTrue(f.remote_complete_valid(self.row,c.HEAD))
            remote.assert_called_once()
            self.assertNotIn('sha256sum -c',str(remote.call_args))
        f._REMOTE_RECEIPT_CACHE.clear()
        with patch.object(f,'run_command',return_value=SimpleNamespace(returncode=1)):
            self.assertFalse(f.remote_complete_valid(self.row,c.HEAD))

    def test_incomplete_restart_gates_reject_resume(self):
        path,entry,proof=self.prepare_interruption()
        proof['gates']['four_mode_health_pass']=False
        f.atomic_write_json(path/'external_host_restart_recovery.json',proof)
        with self.assertRaises(ValueError):
            f.resume_decision(self.row,self.root,False,[entry],c.HEAD)


if __name__=='__main__':unittest.main(verbosity=2)
