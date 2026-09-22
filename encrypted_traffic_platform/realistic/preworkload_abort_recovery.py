"""Retain an authorized PRE-health abort without consuming a scientific attempt."""
from pathlib import Path

CLASSIFICATION='PRE_WORKLOAD_INFRASTRUCTURE_ABORT'

def validate_abort(entry,result,files):
    clean=(entry['browser_attempt_consumed']=='false' and entry.get('workload_started') in ('unknown','false','')
           and entry['final_status']==result['status']=='FAIL'
           and entry['failure_class']==result['failure_class']=='INFRASTRUCTURE_HEALTH_LOST'
           and int(entry['attempt'])==result['attempt']
           and entry['plan_sha']==result['plan_sha256']
           and result['pre_health']=='FAIL' and result['post_health']=='NOT_RUN_PRE_HEALTH_FAIL'
           and result['capture']['status']=='NOT_STARTED' and result['residual']==0
           and result.get('workload_started',False) is False)
    launched=any('.pcap' in name or 'executor_phase' in name or 'executor_supervisor' in name
                 or name.startswith('workload/') or 'capture_started' in name for name in files)
    if not clean or launched:
        raise ValueError('PRE_WORKLOAD_ABORT_IDENTITY_AMBIGUOUS_OR_ATTEMPT_CONSUMED')
    return CLASSIFICATION

def install(c):
    f,cfg=c.f,c.CONFIG
    path=cfg.documentation_root/'preworkload_abort_recovery.json'
    if not path.exists():return
    proof=f.load_json(path)
    if (proof['classification']!=CLASSIFICATION or proof['campaign_id']!=cfg.campaign_id
            or proof['scientific_attempt_consumed'] is not False
            or proof['retry_policy_changed'] is not False
            or f.FROZEN_SHA256.get(path)!=f.sha256(path)):
        raise f.PrecheckFail('unfrozen pre-workload abort recovery')
    artifact=Path(proof['retained_artifact'])
    result=f.load_json(artifact/'validation_attempt_result.json')
    validate_abort(proof['original_entry'],result,[str(p.relative_to(artifact)) for p in artifact.rglob('*') if p.is_file()])
    gate=f.load_json(Path(proof['recovery_gate']))
    if (gate['status']!='PASS' or gate['server_consecutive_full_pass']!=3 or gate['four_mode_full_pass_rounds']!=2
            or gate['remote_integrity']!='PASS'):
        raise f.PrecheckFail('pre-workload recovery health gate')
    verify=f.verify_frozen_sha
    def frozen():
        verify()
        original=Path(proof['original_ledger'])
        if f.sha256(original)!=proof['original_ledger_sha256']:
            raise f.HardStop('pre-workload original ledger changed')
        before=f.read_ledger(original)
        expected=[e for e in before if e!=proof['original_entry']]
        current=f.read_ledger(cfg.retry_ledger)
        if current[:len(expected)]!=expected or any(e['artifact_path']==proof['original_entry']['artifact_path'] for e in current):
            raise f.HardStop('pre-workload correction altered unrelated history or reused aborted artifact')
    f.verify_frozen_sha=frozen
    counts=f.attempt_counts
    def attempt_counts(ledger):
        return {**counts(ledger),'PRE_WORKLOAD_INFRASTRUCTURE_ABORT_COUNT':1,
                'PRE_WORKLOAD_ABORT_SCIENTIFIC_ATTEMPTS':0}
    f.attempt_counts=c.attempt_counts=attempt_counts
