#!/usr/bin/env python3
"""Apply the authorized bounded rule after independent evidence review."""
import argparse
import collections
import fcntl
import importlib.util
import json
import os
from pathlib import Path
import shlex
import shutil
import subprocess
import sys

from pair_group_reacquisition import (RULE, EXHAUSTED, MODES, ReacquisitionRefused,
                                     require, eligible, reacquisition_rows, state_path, clean)

DIAGNOSTICS = Path('/home/etip/datasets/diagnostics')


def support(name, path):
    spec = importlib.util.spec_from_file_location(name,path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def no_runner():
    for process in Path('/proc').glob('[0-9]*'):
        try:
            args=(process/'cmdline').read_bytes().split(b'\0')
            require(not any(Path(a.decode()).name in ('run_realistic_campaign.py',
                'run_formal_r11_amended_continuation.py') for a in args if a), 'collection runner is still active')
        except (FileNotFoundError,PermissionError,ProcessLookupError):
            pass


def exact_diagnostic(c, row, root, storage):
    """One fixed trial per mode/ordinal; never repeat a started diagnostic trial."""
    f,cfg=c.f,c.CONFIG
    root.mkdir(parents=True,exist_ok=True)
    result_path=root/'diagnostic_result.json'
    started=root/'started.json'
    ledger_sha=f.sha256(cfg.retry_ledger)
    inputs=root/'input'
    if started.exists():
        prior=f.load_json(started)
        require(prior['source_schedule_row']==row and prior['source_ledger_sha256']==ledger_sha,
                'diagnostic does not match the exhausted acquisition')
        require(prior['input_digests']['workload_plan.json']==row['plan_sha256']
                and prior['input_digests']['realistic_browser_v3.py']==f.sha256(f.EXECUTOR),
                'diagnostic input implementation drift')
    else:
        health=root/'prestart_health';health.mkdir()
        support('reacquisition_health',DIAGNOSTICS/'apnews_delta_readiness_20260915/storage_guard.py').fixed_health(health)
        inputs.mkdir()
        for source,name in ((Path(row['plan_path']),'workload_plan.json'),(f.EXECUTOR,'realistic_browser_v3.py')):
            shutil.copyfile(source,inputs/name);(inputs/name).chmod(0o444)
        f.atomic_write_json(started,dict(source_schedule_row=row,source_ledger_sha256=ledger_sha,
            total_trials=12,trials_per_mode=3,max_attempts_per_trial=1,retry=False,
            formal_dataset_eligible=False,input_digests={p.name:f.sha256(p) for p in inputs.iterdir()},
            started_utc=f.utc_now()))
        f.atomic_write_text(root/'NON_FORMAL_FINAL_DATASET_INELIGIBLE',RULE+'\n')
    if result_path.exists():
        return f.load_json(result_path)
    retry=f.configure_execution_components();base=retry.base
    selection=f.selection_from_row(row);selection['plan_path']=str(inputs/'workload_plan.json')
    expected=f.load_json(started)['input_digests']
    results=[]
    for mode in MODES:
        for number in (1,2,3):
            trial=root/f'{mode}_trial{number}'
            if (trial/'trial_result.json').exists():
                results.append(f.load_json(trial/'trial_result.json'));continue
            require(not trial.exists(),'interrupted independent diagnostic lifecycle requires evidence reconciliation')
            require(f.sha256(cfg.retry_ledger)==ledger_sha,'Formal ledger changed during independent diagnostic')
            storage.ensure_space(f)
            remote=f'/home/etip/.cache/pair-group-diagnostics/{cfg.campaign_id}/{root.name}/{mode}_trial{number}'
            base.run(['ssh','-o','BatchMode=yes',base.USER_HOST,'mkdir -p '+shlex.quote(str(Path(remote).parent))+
                ' && mkdir '+shlex.quote(remote)+' && mkdir '+shlex.quote(remote+'/input')],30,True)
            base.run(['scp','-q',str(inputs/'workload_plan.json'),str(inputs/'realistic_browser_v3.py'),
                base.USER_HOST+':'+remote+'/input/'],120,True)
            proof=base.run(['ssh','-o','BatchMode=yes',base.USER_HOST,'sha256sum',
                remote+'/input/workload_plan.json',remote+'/input/realistic_browser_v3.py'],30,True).stdout
            require({Path(line.split()[1]).name:line.split()[0] for line in proof.splitlines()}==expected,'diagnostic staged input mismatch')
            base.run(['ssh','-o','BatchMode=yes',base.USER_HOST,'chmod','444',
                remote+'/input/workload_plan.json',remote+'/input/realistic_browser_v3.py'],30,True)
            print(f'PAIR_GROUP_FIXED_DIAGNOSTIC mode={mode} trial={number}/3',flush=True)
            try:
                result=retry.run_attempt(mode,1,selection,trial/'lifecycle',remote,
                    classification='NON_FORMAL_EXACT_CONTEXT_REACQUISITION_DIAGNOSTIC')
            except Exception as exc:
                result=retry.synthetic_attempt_failure(exc,mode,1,selection,trial/'lifecycle',RULE)
            issues=[]
            try:clean(result,row['plan_sha256'],c.CAPACITY_AMENDMENT['new_conn_max'])
            except ReacquisitionRefused as exc:issues.append(str(exc))
            record=dict(mode=mode,trial=number,attempt=1,retry=False,infrastructure_issues=issues,
                valid_for_endpoint_judgment=not issues,full_workload_pass=not issues and result.get('status')=='PASS',
                result=result,artifact_dir=result['artifact_dir'],formal_dataset_eligible=False)
            f.atomic_write_json(trial/'trial_result.json',record);results.append(record)
            require(not issues,'diagnostic infrastructure failure; endpoint attribution unavailable')
    diagnostic=dict(status='FINITE_CONTEXT_DIAGNOSTIC_COMPLETE',total=12,results=results,retry=False,
        valid_trials=sum(t['valid_for_endpoint_judgment'] for t in results),
        full_workload_passes_by_mode=dict(collections.Counter(t['mode'] for t in results if t['full_workload_pass'])),
        formal_dataset_eligible=False,formal_ledger_unchanged=f.sha256(cfg.retry_ledger)==ledger_sha,
        completed_utc=f.utc_now())
    f.atomic_write_json(result_path,diagnostic)
    return diagnostic


def audit_completed(c, rows):
    """Reuse SHA receipts; inspect all remote controls/presence in one SSH call."""
    f,cfg=c.f,c.CONFIG;expected={};ledger=c.ledger_audit()
    controls=('SAMPLE_COMPLETE','sample_metadata.json','remote_sha_verification.json','SHA256SUMS.txt','FINAL_METADATA_SHA256SUMS.txt')
    for row in rows:
        local=cfg.local_sample_root/row['schedule_id']
        require(all((local/name).is_file() for name in controls),'completed controls missing')
        metadata=f.load_json(local/'sample_metadata.json');receipt=f.load_json(local/'remote_sha_verification.json')
        require(f.validate_metadata(metadata,row,c.HEAD),'carried metadata mismatch')
        f.assert_final_attempt(metadata['final_result'],row)
        require(all(receipt.get(k) is True for k in ('remote_sha_pass','remote_completeness_pass',
            'remote_metadata_pass','remote_upload_pass')),'carried receipt incomplete')
        require(sum(e['sample_id']==row['schedule_id'] and e['final_status']=='PASS' for e in ledger)==1,'carried ledger PASS mismatch')
        require(f.eviction_resume_valid(row,c.HEAD) or f.local_complete_valid(local,row,c.HEAD), 'carried local integrity')
        expected[str(cfg.remote_sample_root/row['schedule_id'])]={name:f.sha256(local/name) for name in controls}
    code='''import hashlib,json,pathlib,sys
expected=json.load(sys.stdin)
for remote,controls in expected.items():
 p=pathlib.Path(remote)
 for name,digest in controls.items():
  assert (p/name).is_file() and hashlib.sha256((p/name).read_bytes()).hexdigest()==digest,(remote,name)
 for manifest in ('SHA256SUMS.txt','FINAL_METADATA_SHA256SUMS.txt'):
  for line in (p/manifest).read_text().splitlines():
   if not line.strip():continue
   q=(p/line.split(maxsplit=1)[1].lstrip('* ')).resolve()
   assert q.is_relative_to(p.resolve()) and q.is_file(),str(q)
   assert q.suffix!='.pcap' or q.stat().st_size>24,str(q)
print(json.dumps({'remote_complete':len(expected),'integrity':'PASS'}))
'''
    check=subprocess.run(['ssh','-o','BatchMode=yes','-o','ConnectTimeout=10',f.UPLOAD_HOST,
        'python3 -c '+shlex.quote(code)],input=json.dumps(expected),text=True,capture_output=True,timeout=120)
    if check.returncode==255:raise f.RemoteArchivePending(check.stderr)
    require(check.returncode==0,'remote receipt/control verification failed: '+check.stderr[-1000:])
    return dict(status='PASS',valid_samples=len(rows),remote_complete=len(rows),integrity='PASS',
        complete_pair_groups=len(rows)//4,health='CLEAN',purity='CLEAN',capture='CLEAN',
        remote_controls=expected,verified_utc=f.utc_now())


def finish_activation(c, journal):
    """Idempotent renames; neither local nor remote destinations are overwritten."""
    f,cfg=c.f,c.CONFIG;record=journal['record']
    for move in record['relocations']:
        if move['host']=='local':
            source,target=Path(move['source']),Path(move['target'])
            require(source.exists()!=target.exists(),'ambiguous local relocation: '+str(source))
            if source.exists():target.parent.mkdir(parents=True,exist_ok=True);source.rename(target)
        else:
            code='''import pathlib,sys
s,t=map(pathlib.Path,sys.argv[1:]);assert s.exists()!=t.exists(),str(s)
if s.exists():t.parent.mkdir(parents=True,exist_ok=True);s.rename(t)
'''
            remote=f.run_command(['ssh','-o','BatchMode=yes',f.UPLOAD_HOST,
                'python3 -c '+shlex.quote(code)+' '+shlex.quote(move['source'])+' '+shlex.quote(move['target'])],timeout=60)
            if remote.returncode==255:raise f.RemoteArchivePending(remote.stderr)
            require(remote.returncode==0,'remote relocation failed: '+remote.stderr)
    # Recheck control receipts at their new remote locations without rehashing captures.
    for item in record['remote_retention']:
        code='''import hashlib,json,pathlib,sys
p=pathlib.Path(sys.argv[1]);controls=json.loads(sys.argv[2])
for n,d in controls.items():assert hashlib.sha256((p/n).read_bytes()).hexdigest()==d
for n in controls:
 if n.endswith('SHA256SUMS.txt'):
  for line in (p/n).read_text().splitlines():
   q=(p/line.split(maxsplit=1)[1].lstrip('* ')).resolve()
   assert q.is_relative_to(p.resolve()) and q.is_file()
'''
        check=f.run_command(['ssh','-o','BatchMode=yes',f.UPLOAD_HOST,'python3 -c '+shlex.quote(code)+
            ' '+shlex.quote(item['remote'])+' '+shlex.quote(json.dumps(item['controls']))],timeout=60)
        if check.returncode==255:raise f.RemoteArchivePending(check.stderr)
        require(check.returncode==0,'relocated archive control mismatch')
    activation=Path(record['record_path'])
    if activation.exists():require(f.load_json(activation)==record,'activation record collision')
    else:f.atomic_write_json(activation,record)
    state=journal['previous_state']
    updated={**state,'acquisitions':state['acquisitions']+[dict(path=str(activation),sha256=f.sha256(activation))]}
    if state_path(cfg).exists():require(f.load_json(state_path(cfg)) in (state,updated),'reacquisition state diverged')
    f.atomic_write_json(state_path(cfg),updated)
    # Preserve every original stop before allowing the manager to resume.
    for name in ('revision_hard_stop.json','mission_hard_stop_sample366_policy.json'):
        source=cfg.local_root/name;target=activation.parent/'closed_controls'/name
        if source.exists():
            require(not target.exists(),'stop record collision')
            target.parent.mkdir(parents=True,exist_ok=True);source.rename(target)
    disposition=f.load_json(cfg.local_root/'campaign_disposition.json')
    f.atomic_write_json(cfg.local_root/'campaign_disposition.json',{**disposition,
        'carry_forward_samples':f"1-{record['carry_forward']['valid_samples']}",
        'next_sequence':record['group']*4-3,'active_acquisition_instance':record['acquisition_instance'],
        'active_retry_ledger':record['active_ledger'],'pair_group_reacquisition_rule':record['rule'],
        'historical_acquisition_record':record['record_path']})
    c.archive_controls()
    pending=cfg.local_root/'pending_pair_group_reacquisition.json'
    target=activation.parent/'activation_transaction.json'
    if pending.exists():
        require(not target.exists(),'activation transaction collision');pending.rename(target)
    c.archive_controls()
    print(json.dumps(dict(status='PAIR_GROUP_REACQUISITION_ACTIVATED',acquisition_instance=record['acquisition_instance'],
        CARRY_FORWARD_BOUNDARY=record['carry_forward']['valid_samples'],NEXT_SEQUENCE=record['group']*4-3,
        OLD_ACQUISITION='INCOMPLETE_PAIR_GROUP_HISTORICAL_PROVENANCE',MAX_ATTEMPTS_PER_SAMPLE=3)),flush=True)
    return 76


def resolve(c, diagnostic_root=None):
    f,cfg=c.f,c.CONFIG
    no_runner()
    lock=(cfg.local_root/'.pair_group_reacquisition.lock').open('a')
    fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
    f.verify_git(c.HEAD,verify_origin=False);f.verify_frozen_sha()
    pending=cfg.local_root/'pending_pair_group_reacquisition.json'
    if pending.exists():return finish_activation(c,f.load_json(pending))
    stop=f.load_json(cfg.hard_stop_record)
    require(stop.get('category')=='SAMPLE_POLICY_HARD_STOP','not an exhausted sample policy stop')
    ledger=c.ledger_audit();last=ledger[-1];row=c.IDENTITY.validate_ledger(last)
    f.verify_no_out_of_order_artifacts(c.IDENTITY.rows,int(row['sequence_id']))
    for running in cfg.in_progress_root.glob('*/attempts'):
        require(not any(running.iterdir()),'unsettled in-progress scientific attempt')
    group=(int(row['sequence_id'])-1)//4+1;boundary=(group-1)*4
    state=f.load_json(state_path(cfg)) if state_path(cfg).exists() else dict(campaign_id=cfg.campaign_id,acquisitions=[])
    require(not any(r['group']==group for r in getattr(c,'PAIR_GROUP_REACQUISITIONS',[])),EXHAUSTED)
    require(stop['reason'].startswith('attempt3 failure: '+row['schedule_id']+':'), 'stop is not this exhausted sample')
    entries=[e for e in ledger if e['sample_id']==row['schedule_id']]
    require([e['attempt'] for e in entries]==['1','2','3'] and all(e['final_status']=='FAIL' for e in entries),'unexhausted budget')
    failures=[f.load_json(Path(e['artifact_path'])/'validation_attempt_result.json') for e in entries]
    from stress_terminal_taxonomy import SamplePolicyHardStop, sample_terminal_exception
    for result in failures:
        require(isinstance(sample_terminal_exception(result['attempt'],row['schedule_id'],result,exhausted=True),SamplePolicyHardStop)
                and f.clean_navigation_failure(result),'implementation or unclean failure requires separate review')
        clean(result,row['plan_sha256'],c.CAPACITY_AMENDMENT['new_conn_max'])
    historical=f.hotspot_evidence(c.HEAD)
    triggers=f.unresolved_hotspots(f.evaluate_rule_v2(historical))
    require(not triggers,'existing domain retirement/replacement trigger')
    storage=support('reacquisition_storage',DIAGNOSTICS/'netcraze_context_20260916/storage_support.py')
    for entry in entries:
        artifact=Path(entry['artifact_path'])
        storage.archive_new(f,artifact,str(cfg.remote_root/artifact.relative_to(cfg.local_root)))
    diagnostic_root=diagnostic_root or DIAGNOSTICS/f'{cfg.campaign_id}_pair_group_{group:04d}_reacquisition_diagnostic'
    diagnostic=exact_diagnostic(c,row,diagnostic_root,storage)
    receipt,_=storage.archive_new(f,diagnostic_root)
    require(receipt['remote_integrity']=='PASS','diagnostic not archived')
    eligible(row,entries,failures,diagnostic,0,triggers,c.CAPACITY_AMENDMENT['new_conn_max'])
    for trial in diagnostic['results']:f.assert_final_attempt(trial['result'],{**row,'mode_order':trial['mode']})
    require(all(int(e['sequence_id']) <= int(row['sequence_id']) for e in ledger),'later attempt evidence exists')
    completed=c.IDENTITY.rows[:boundary]
    carry=audit_completed(c,completed)
    require(all({r['mode_order'] for r in completed[n:n+4]}==set(MODES)
        and len({r['plan_sha256'] for r in completed[n:n+4]})==1 for n in range(0,boundary,4)), 'carry-forward incomplete matched group')
    original_rows=[dict(c.IDENTITY.lookup(n)) for n in range(boundary+1,boundary+5)]
    closed=[e for e in ledger if int(e['sequence_id'])>boundary]
    for entry in closed:
        if entry['final_status']=='FAIL':
            artifact=Path(entry['artifact_path'])
            storage.archive_new(f,artifact,str(cfg.remote_root/artifact.relative_to(cfg.local_root)))
    passed_rows=[r for r in original_rows if any(e['sample_id']==r['schedule_id'] and e['final_status']=='PASS' for e in closed)]
    passed_audit=audit_completed(c,passed_rows)
    instance=f'pair_group_{group:04d}_reacq1'
    controls=cfg.local_root/'acquisitions'/instance
    controls.mkdir(parents=True,exist_ok=True)
    local_history=Path('/home/etip/datasets/provenance/realistic_v1')/cfg.campaign_id/instance/'original_acquisition'
    remote_history=cfg.remote_root.parent/'protocol_history'/cfg.campaign_id/instance/'original_acquisition'
    relocations=[];remote_retention=[]
    for old in original_rows:
        for namespace in ('samples','failed_artifacts','in_progress'):
            source=cfg.local_root/namespace/old['schedule_id']
            if source.exists():
                relocations.append(dict(host='local',source=str(source),target=str(local_history/namespace/source.name)))
                if namespace=='samples':
                    remote=str(cfg.remote_root/namespace/source.name)
                    remote_retention.append(dict(remote=str(remote_history/namespace/source.name),controls=passed_audit['remote_controls'][remote]))
                if namespace in ('samples','failed_artifacts'):
                    relocations.append(dict(host='remote',source=str(cfg.remote_root/namespace/source.name),target=str(remote_history/namespace/source.name)))
        telemetry=cfg.telemetry_root/f"boundary_{int(old['sequence_id']):04d}.json"
        if telemetry.exists():relocations.append(dict(host='local',source=str(telemetry),target=str(controls/'closed_controls'/telemetry.name)))
    for entry in closed:
        if entry['final_status']=='FAIL':
            old=Path(entry['artifact_path']);relative=old.relative_to(cfg.local_root)
            manifest=old/'REMOTE_ARCHIVE_SHA256SUMS.txt'
            require(manifest.is_file(),'failed artifact archive missing')
            remote_retention.append(dict(remote=str(remote_history/relative),controls={manifest.name:f.sha256(manifest)}))
    def relocated(path):
        path=Path(path)
        for move in relocations:
            source=Path(move['source'])
            if move['host']=='local' and path.is_relative_to(source):return str(Path(move['target'])/path.relative_to(source))
        return str(path)
    retained=[dict(path=relocated(Path(e['artifact_path'])/'validation_attempt_result.json'),
                   sha256=f.sha256(Path(e['artifact_path'])/'validation_attempt_result.json')) for e in closed]
    closed_ids={r['schedule_id'] for r in original_rows}
    historical=[{**e,'evidence_path':relocated(e['evidence_path'])} for e in historical
                if e.get('sample_id') in closed_ids and e.get('run_id')==str(cfg.local_root)]
    active=controls/'active_retry_ledger.tsv'
    prefix=[e for e in ledger if int(e['sequence_id'])<=boundary]
    if active.exists():require(f.read_ledger(active)==prefix,'new acquisition already consumed attempts')
    else:f.atomic_write_rows(active,f.LEDGER_FIELDS,prefix)
    evictions=f.load_json(cfg.storage_ledger)
    evictions={**evictions,'samples':{k:v for k,v in evictions['samples'].items() if k not in closed_ids}}
    active_evictions=controls/'active_eviction_ledger.json'
    f.atomic_write_json(active_evictions,evictions)
    for name in ('progress.json','campaign_disposition.json','hotspot_evidence_export.json'):
        source=cfg.local_root/name;target=controls/'closed_controls'/name
        if source.exists() and not target.exists():
            target.parent.mkdir(parents=True,exist_ok=True);shutil.copy2(source,target)
    record=dict(rule=RULE,acquisition_instance=instance,group=group,reacquisition_number=1,
        status='INCOMPLETE_PAIR_GROUP_HISTORICAL_PROVENANCE',record_path=str(controls/'activation.json'),
        original_rows=original_rows,new_rows=reacquisition_rows(original_rows,group),
        original_ledger=str(cfg.retry_ledger),original_ledger_sha256=f.sha256(cfg.retry_ledger),
        original_eviction_ledger=str(cfg.storage_ledger),active_eviction_ledger=str(active_evictions),
        active_ledger=str(active),closed_entries=closed,carry_forward=carry,retained_result_files=retained,
        diagnostic_controls=[dict(path=str(diagnostic_root/name),sha256=f.sha256(diagnostic_root/name))
            for name in ('started.json','diagnostic_result.json','remote_archive_receipt.json')],
        diagnostic_root=str(diagnostic_root),diagnostic_passes=12,trigger='BUDGET_EXHAUSTED_NONREPRODUCIBLE_FAILURE',
        domain_replacement_trigger=False,implementation_defect=False,infrastructure_degradation=False,
        scientific_semantics_changed=False,historical_hotspot_evidence=historical,relocations=relocations,
        remote_retention=remote_retention,activated_utc=f.utc_now())
    journal=dict(previous_state=state,record=record)
    f.atomic_write_json(pending,journal)
    return finish_activation(c,journal)


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--config',required=True,type=Path)
    parser.add_argument('--diagnostic-root',type=Path)
    args=parser.parse_args()
    import run_formal_r11_amended_continuation as amended
    amended.configure(args.config)
    amended.qualification()
    try:return resolve(amended.campaign,args.diagnostic_root)
    except amended.campaign.f.RemoteArchivePending as exc:
        print('REMOTE_ARCHIVE_PENDING '+str(exc),flush=True);return 75
    except ReacquisitionRefused as exc:
        print('PAIR_GROUP_REACQUISITION_REFUSED '+str(exc),flush=True);return 1


if __name__=='__main__':raise SystemExit(main())
