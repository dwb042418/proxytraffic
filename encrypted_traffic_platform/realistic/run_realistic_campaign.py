#!/usr/bin/env python3
"""Shared immutable Stress/Formal runner for the autonomous collection mission."""
import argparse
import collections
import importlib
import json
import os
from pathlib import Path
import shlex
import subprocess

import realistic_campaign_config as cfg
from realistic_campaign_telemetry import TELEMETRY_CODE
from stress_preflight_taxonomy_v3 import (PrestartInfrastructureBlocker, prestart_remote_commands,
    remote_path_preflight, campaign_state_consumed)
from stress_terminal_taxonomy import SamplePolicyHardStop

CONFIG = None
f = None
IDENTITY = None
HEAD = None


def configure(config_path):
    global CONFIG, f, IDENTITY, HEAD
    CONFIG = cfg.load(config_path)
    freeze = json.loads(CONFIG.code_freeze.read_text())
    HEAD = freeze['git_head']
    f = importlib.import_module('realistic_campaign_runtime')
    identity = importlib.import_module('realistic_campaign_identity')
    source, _, _ = f.audit_schedule_and_plans()
    IDENTITY = identity.CampaignIdentity(CONFIG.campaign_manifest, source)
    identity.install(f, IDENTITY)
    if len(IDENTITY.rows) != CONFIG.total_samples or collections.Counter(r['mode_order'] for r in IDENTITY.rows) != {m:CONFIG.total_samples//4 for m in f.MODES}:
        raise f.HardStop('campaign manifest balance invariant')
    f.BOUNDARY_HOOK = boundary
    collect = f.run_formal_sample
    def with_initial_telemetry(row, head, registry, attempt):
        if int(row['sequence_id']) == 1 and not (CONFIG.telemetry_root/'boundary_0000.json').exists():
            telemetry(0)
        return collect(row, head, registry, attempt)
    f.run_formal_sample = with_initial_telemetry
    return IDENTITY.rows


def telemetry(n):
    record = {'sequence_id':n,'time':f.utc_now(),'free_disk_bytes':f.free_disk_bytes(),'hosts':{}}
    for host in ('collector',f.USER_HOST):
        cmd = ['sudo','-n','python3','-B','-c',TELEMETRY_CODE] if host == 'collector' else ['ssh','-o','BatchMode=yes',host,'sudo -n python3 -B -c '+shlex.quote(TELEMETRY_CODE)]
        record['hosts'][host] = json.loads(f.run_command(cmd,timeout=30,check=True).stdout)
    CONFIG.telemetry_root.mkdir(parents=True,exist_ok=True)
    f.atomic_write_json(CONFIG.telemetry_root/f'boundary_{n:04d}.json',record)
    return record


def ledger_audit():
    ledger = f.read_ledger(CONFIG.retry_ledger)
    by_sample = collections.defaultdict(list)
    for entry in ledger:
        row = IDENTITY.validate_ledger(entry)
        n = int(entry['attempt'])
        if not 1 <= n <= 3 or entry['git_head'] != HEAD:
            raise f.HardStop('ledger attempt/Git invariant')
        by_sample[entry['sample_id']].append(n)
        artifact = Path(entry['artifact_path'])
        result = f.load_json(artifact/'validation_attempt_result.json')
        if result['plan_sha256'] != row['plan_sha256'] or result['status'] != entry['final_status']:
            raise f.HardStop('ledger result identity invariant')
        if entry['final_status'] == 'FAIL' and not artifact.is_relative_to(CONFIG.failed_artifact_root):
            raise f.HardStop('failed artifact outside retained failed root')
    if any(ns != list(range(1,len(ns)+1)) for ns in by_sample.values()):
        raise f.HardStop('ledger consecutive attempts invariant')
    return ledger


def checkpoint(n):
    f.verify_git(HEAD,verify_origin=False)
    f.verify_frozen_sha()
    state = f.progress_from_schedule(IDENTITY.rows,HEAD)
    if state['VALID_SAMPLES'] != n or state['COMPLETE_PAIR_GROUPS'] != n//4 or state['mode_counts'] != {m:n//4 for m in f.MODES}:
        raise f.HardStop('checkpoint completeness invariant')
    ledger_audit()
    f.atomic_write_json(CONFIG.checkpoint_path(n), {'status':'PASS',**state})
    return state


def boundary(row, progress, head):
    n = int(row['sequence_id'])
    telemetry(n)
    if n % 4 == 0:
        print(f'{CONFIG.kind}={n}/{CONFIG.total_samples} PAIRS={n//4}/{CONFIG.total_samples//4} RETRIES={progress["RETRY_COUNT"]} REMOTE={progress["REMOTE_SHA_PASS"]}/{n} DISK_GIB={f.free_disk_bytes()/1024**3:.2f} HEALTH/PURITY/CAPTURE=CLEAN HOTSPOT=NONE',flush=True)
    if CONFIG.kind == 'STRESS':
        if n == 24:
            checkpoint(24)
            f.atomic_write_text(CONFIG.smoke_marker,'24/24 PASS\n')
            print('SMOKE_COMPATIBILITY_SEGMENT_PASS',flush=True)
        if n in (64,128):
            checkpoint(n)
            print(f'STRESS_CHECKPOINT_{n}_PASS',flush=True)


def archive_controls():
    remote = str(CONFIG.final_metadata_root)
    mkdir = f.run_command(['ssh','-o','BatchMode=yes',f.UPLOAD_HOST,'mkdir -p '+shlex.quote(remote)],timeout=30)
    if mkdir.returncode:
        raise f.RemoteArchivePending('final metadata root unavailable: '+mkdir.stderr[-1000:])
    # Existing per-sample manifests remain the authority for large artifacts.
    files = [p for p in CONFIG.local_root.rglob('*') if p.is_file()
        and p.relative_to(CONFIG.local_root).parts[0] not in ('samples','in_progress','failed_artifacts')
        and p != CONFIG.metadata_checksums]
    f.atomic_write_text(CONFIG.metadata_checksums,''.join(f'{f.sha256(p)}  {p.relative_to(CONFIG.local_root)}\n' for p in sorted(files)))
    listing = '\0'.join(str(p.relative_to(CONFIG.local_root)) for p in files+[CONFIG.metadata_checksums])+'\0'
    result = subprocess.run(['rsync','-a','--partial','--from0','--files-from=-',str(CONFIG.local_root)+'/',f'{f.UPLOAD_HOST}:{remote}/'],input=listing,text=True,capture_output=True,timeout=900)
    if result.returncode:
        raise f.RemoteArchivePending('final metadata upload: '+result.stderr[-1000:])
    check = f.run_command(['ssh','-o','BatchMode=yes',f.UPLOAD_HOST,'cd '+shlex.quote(remote)+' && sha256sum -c FINAL_CAMPAIGN_METADATA_SHA256SUMS.txt >/dev/null'],timeout=900)
    if check.returncode:
        raise f.RemoteArchivePending('final metadata verification: '+check.stderr[-1000:])


def final_report():
    # execute_production's final write_progress just performed a full local/remote
    # integrity scan, including evicted samples. Do not repeat that full scan here.
    progress = f.load_json(CONFIG.progress_state)
    if progress['VALID_SAMPLES'] != CONFIG.total_samples or progress['COMPLETE_PAIR_GROUPS'] != CONFIG.total_samples//4:
        raise f.HardStop('final completeness invariant')
    ledger = ledger_audit()
    resource_rows = [f.load_json(p) for p in sorted(CONFIG.telemetry_root.glob('boundary_*.json'))]
    if len(resource_rows) != CONFIG.total_samples+1:
        raise f.HardStop('resource boundary evidence incomplete')
    leaks = {}
    for host in ('collector',f.USER_HOST):
        data = [r['hosts'][host] for r in resource_rows]
        fd = [r['fd_total'] for r in data]
        leaks[host] = {
            'process_leak':data[-1]['browser_executor_processes'] > data[0]['browser_executor_processes'],
            'zombie_leak':data[-1]['zombies'] > data[0]['zombies'],
            'fd_monotonic_leak':fd[-1] > fd[0] and all(a<=b for a,b in zip(fd,fd[1:])),
        }
    if any(value for host in leaks.values() for value in host.values()):
        raise f.HardStop('RESOURCE_GROWTH_INTERNAL_REVIEW_REQUIRED: '+str(leaks))
    for row in IDENTITY.rows:
        meta = f.load_json(CONFIG.local_sample_root/row['schedule_id']/'sample_metadata.json')
        if not f.validate_metadata(meta,row,HEAD):
            raise f.HardStop('final metadata revision mismatch')
        f.assert_final_attempt(meta['final_result'],row)
    retry_component = f.configure_execution_components()
    for entry in ledger:
        if entry['final_status'] != 'FAIL': continue
        result = f.load_json(Path(entry['artifact_path'])/'validation_attempt_result.json')
        allowed, _ = retry_component.retry_authorized(result,attempt=int(entry['attempt']))
        if not allowed or entry['retry_authorized'] != 'true':
            raise f.HardStop('unclean or unclassified failed attempt in completed campaign')
    f.require_no_pending_hotspot()
    evictions = f.read_evictions()
    if any(e['status'] != 'COMPLETE' for e in evictions.values()):
        raise f.HardStop('unfinished eviction transaction')
    retries = sum(int(e['attempt']) > 1 for e in ledger)
    if retries / CONFIG.total_samples > .2:
        raise f.HardStop('HIGH_TRANSIENT_RATE_INTERNAL_REVIEW_REQUIRED')
    if CONFIG.kind == 'STRESS' and not (CONFIG.smoke_marker.exists() and CONFIG.resume_marker.exists()):
        raise f.HardStop('required smoke/resume milestone missing')
    report = {**progress,'campaign_id':CONFIG.campaign_id,'kind':CONFIG.kind,
        'TOTAL_ATTEMPTS':len(ledger),'TOTAL_RETRIES':retries,'FINAL_RETRY_RATE':retries/CONFIG.total_samples,
        'REMOTE_COMPLETE':f'{CONFIG.total_samples}/{CONFIG.total_samples}',
        'REMOTE_INTEGRITY':'PASS','FINAL_METADATA':'PASS','INTEGRITY_ISSUES':0,
        'FINAL_DATASET_ELIGIBLE':CONFIG.kind=='FORMAL','git_head':HEAD,
        'RESOURCE_LEAK_AUDIT':leaks,'PROCESS_LEAK':'NO','FD_MONOTONIC_LEAK':'NO','ZOMBIE_LEAK':'NO',
        'IMPLEMENTATION_FAILURES':0,'IDENTITY_FAILURES':0,'ROOT_BINDING_FAILURES':0,'UNCLASSIFIED_FAILURES':0,
        'HEALTH_FAILURES':0,'PURITY_FAILURES':0,'CAPTURE_FAILURES':0,'CONN_MAX_HITS':0,
        'BYPASS':0,'OOM':0,'UNEXPECTED_EXIT':0,'UNSAFE_RESUME':0,'RESIDUAL':0,
        'HOTSPOT':'NONE','EVICTED_SAMPLES':len(evictions),'REMOTE_GIT_PUSH_DEFERRED':'YES',
        'PASS_MARKER':'PRODUCTION_READINESS_STRESS_PASS' if CONFIG.kind=='STRESS' else 'REALISTIC_FORMAL_FINAL_COLLECTION_PASS'}
    f.atomic_write_json(CONFIG.report_path,report)
    export_hotspot_evidence()
    archive_controls()
    f.atomic_write_text(CONFIG.local_root/report['PASS_MARKER'],report['PASS_MARKER']+'\n')
    print(json.dumps(report,sort_keys=True),flush=True)
    print(report['PASS_MARKER'],flush=True)


def export_hotspot_evidence():
    f.atomic_write_json(CONFIG.local_root/'hotspot_evidence_export.json', {
        'campaign_id':CONFIG.campaign_id, 'git_head':HEAD,
        'evidence':f.hotspot_evidence(HEAD)})


def formal_qualification_check():
    if CONFIG.kind != 'FORMAL': return
    proof = Path(CONFIG.stress_qualification)
    report = f.load_json(proof/'campaign_result.json')
    if report.get('PASS_MARKER') != 'PRODUCTION_READINESS_STRESS_PASS' or not (proof/'PRODUCTION_READINESS_STRESS_PASS').exists() or report['VALID_SAMPLES'] != 192:
        raise f.PrecheckFail('full Stress qualification missing')
    # Every shared implementation and methodology file must match the qualified
    # Stress freeze; only campaign config/manifest and preregistration differ.
    stress_doc = Path('/home/etip/Tunnel/proxytraffic/docs/realistic_v1/formal_t0_v3/autonomous_mission')/report['campaign_id']
    stress_files = f.load_json(stress_doc/'campaign_freeze.json')['files']
    for path,digest in stress_files.items():
        if Path(path).is_relative_to(stress_doc): continue
        if f.FROZEN_SHA256.get(Path(path)) != digest:
            raise f.PrecheckFail('Formal differs from qualified Stress implementation/methodology: '+path)


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument('--config',required=True,type=Path)
    parser.add_argument('--resume',action='store_true')
    parser.add_argument('--preflight',action='store_true')
    parser.add_argument('--archive-only',action='store_true')
    args = parser.parse_args(argv)
    try:
        configure(args.config)
        if CONFIG.hard_stop_record.exists() or CONFIG.prestart_implementation_stop.exists():
            print('REVISION_HARD_STOP: closed campaign cannot restart',flush=True)
            return 1
        formal_qualification_check()
        with prestart_remote_commands(f,CONFIG):
            if args.archive_only:
                archive_controls()
                return 0
            remote_path_preflight(f,CONFIG)
            if args.resume and f.free_disk_bytes() < f.MIN_FREE_BYTES:
                f.storage_recover(HEAD)
            report = f.dry_run(HEAD)
            if args.preflight:
                print(json.dumps(report,sort_keys=True),flush=True)
                return 0
            if args.resume and CONFIG.kind == 'STRESS' and CONFIG.restart_record.exists() and not CONFIG.resume_marker.exists():
                restart = f.load_json(CONFIG.restart_record)
                state = report['resume_state']
                if restart['process_id'] == os.getpid() or state['valid_samples'] != 96 or state['next_sequence_id'] != 97 or not all(d['decision'].startswith('SKIP_VALID_COMPLETE') for d in state['decisions'][:96]):
                    raise f.HardStop('real process resume invariant')
                f.atomic_write_json(CONFIG.resume_verification,{'old_process':restart['process_id'],'new_process':os.getpid(),**state})
                f.atomic_write_text(CONFIG.resume_marker,'96 SKIPPED; NEXT=97; NEW_PROCESS\n')
                print('STRESS_REAL_RESUME_PASS',flush=True)
            f.STOP_AFTER_SAMPLES = 96 if CONFIG.kind == 'STRESS' and not CONFIG.resume_marker.exists() else None
            code = f.execute_production(HEAD,resume=args.resume)
            if code: return code
        final_report()
        return 0
    except PrestartInfrastructureBlocker as exc:
        if CONFIG is None or campaign_state_consumed(CONFIG): raise
        CONFIG.prestart_history_root.mkdir(parents=True,exist_ok=True)
        f.atomic_write_json(CONFIG.prestart_history_root/(f.safe_stamp()+'.json'),{'status':'PRESTART_INFRASTRUCTURE_BLOCKER','class':exc.blocker_class,'reason':str(exc),'campaign_started':False})
        print('PRESTART_INFRASTRUCTURE_BLOCKER '+str(exc),flush=True)
        return 78
    except Exception as exc:
        if f is not None and isinstance(exc,f.RemoteArchivePending):
            print('REMOTE_ARCHIVE_PENDING '+str(exc),flush=True)
            return 75
        if CONFIG is not None and f is not None:
            category = 'SAMPLE_POLICY_HARD_STOP' if isinstance(exc,SamplePolicyHardStop) else 'IMPLEMENTATION_FAILURE'
            record = {'status':'REVISION_HARD_STOP','category':category,'reason':str(exc),'exception':type(exc).__name__,
                'campaign_id':CONFIG.campaign_id,'time':f.utc_now(),'MISSION_HARD_STOP':False}
            target = CONFIG.hard_stop_record if campaign_state_consumed(CONFIG) else CONFIG.prestart_implementation_stop
            if not target.exists(): f.atomic_write_json(target,record)
            if campaign_state_consumed(CONFIG):
                try:
                    export_hotspot_evidence()
                except Exception as export_error:
                    f.atomic_write_json(CONFIG.local_root/'hotspot_export_error.json',
                        {'error':str(export_error),'requires_internal_review':True})
            print(json.dumps(record,sort_keys=True),flush=True)
        raise


if __name__ == '__main__':
    raise SystemExit(main())
