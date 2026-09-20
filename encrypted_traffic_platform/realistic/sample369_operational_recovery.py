"""Explicit one-time recovery of sample369's retained PRE-health failure."""
from pathlib import Path

CLAUSE = 'SAMPLE369_PRE_HEALTH_OPERATIONAL_RECOVERY_EXCEPTION'
SAMPLE = 'formal_t0_v3_sample0369_rt_replacement_5'


def retry_decision(result, attempt, retained, ordinary):
    if attempt == 1 and result == retained:
        return True, CLAUSE
    return ordinary(result, attempt=attempt)


def recovery_counts(value, ledger, authorized):
    interruption = int(authorized in ledger)
    recovery = int(bool(interruption) and any(
        e['sample_id'] == SAMPLE and int(e['attempt']) == 2 for e in ledger))
    return {**value, 'RETRY_COUNT':value['RETRY_COUNT']-recovery,
            'OPERATIONAL_INFRASTRUCTURE_INTERRUPTION_COUNT':value.get('OPERATIONAL_INFRASTRUCTURE_INTERRUPTION_COUNT',0)+interruption,
            'OPERATIONAL_INFRASTRUCTURE_RECOVERY_COUNT':value.get('OPERATIONAL_INFRASTRUCTURE_RECOVERY_COUNT',0)+recovery}


def install(campaign):
    f, cfg = campaign.f, campaign.CONFIG
    path = cfg.documentation_root/'sample369_operational_recovery.json'
    if not path.exists():return
    proof = f.load_json(path)
    if (cfg.campaign_id != 't0_v3_r11' or proof['exception'] != CLAUSE
            or proof['scope'] != SAMPLE+'_only' or proof['global_retry_policy_changed'] is not False
            or proof['max_attempts'] != 3 or f.MAX_ATTEMPTS_PER_SAMPLE != 3
            or f.FROZEN_SHA256.get(path) != f.sha256(path)):
        raise f.PrecheckFail('sample369 recovery authorization mismatch')
    gate_path = Path(proof['recovery_gate']);gate = f.load_json(gate_path)
    if (f.FROZEN_SHA256.get(gate_path) != f.sha256(gate_path) or gate['status'] != 'PASS'
            or gate['remote_evidence']['remote_integrity'] != 'PASS'
            or gate['four_mode_health'] != 'PASS'):
        raise f.PrecheckFail('sample369 recovery gate missing')
    original = gate['original_ledger_entry']
    result_path = Path(original['artifact_path'])/'validation_attempt_result.json'
    if (original['sample_id'] != SAMPLE or original['attempt'] != '1'
            or original['failure_class'] != 'INFRASTRUCTURE_HEALTH_LOST'
            or original['final_status'] != 'FAIL' or original['browser_attempt_consumed'] != 'false'
            or f.sha256(result_path) != gate['attempt1_result_sha256']):
        raise f.PrecheckFail('sample369 retained failure identity mismatch')
    retained = f.load_json(result_path)
    if retained['pre_health'] != 'FAIL' or retained['capture']['status'] != 'NOT_STARTED':
        raise f.PrecheckFail('sample369 is not the approved PRE-health-only failure')
    authorized = {**original,'retry_authorized':'true','retry_reason':CLAUSE}
    audit = campaign.ledger_audit
    def ledger_audit():
        ledger = audit()
        if [e for e in ledger if e['sample_id']==SAMPLE and e['attempt']=='1'] != [authorized]:
            raise f.HardStop('sample369 exception ledger differs from authorization')
        return ledger
    campaign.ledger_audit = ledger_audit
    ledger_audit()
    verify = f.verify_frozen_sha
    def frozen():
        verify()
        old = f.read_ledger(Path(proof['original_retry_ledger']))
        expected = [{**e,'retry_authorized':'true','retry_reason':CLAUSE} if e==original else e for e in old]
        if f.read_ledger(cfg.retry_ledger)[:len(expected)] != expected:
            raise f.HardStop('sample369 recovery changed unrelated ledger history')
    f.verify_frozen_sha = frozen
    collect = f.run_formal_sample
    def run_sample(row, head, registry, start_attempt):
        if int(row['sequence_id'])<=368 or (row['schedule_id']==SAMPLE and start_attempt==1):
            raise f.PrecheckFail('sample369 recovery cannot restart the retained boundary/attempt1')
        return collect(row,head,registry,start_attempt)
    f.run_formal_sample = run_sample
    configure = f.configure_execution_components
    def components():
        component = configure();ordinary = component.retry_authorized
        component.retry_authorized = lambda result,attempt=None: retry_decision(result,attempt,retained,ordinary)
        return component
    f.configure_execution_components = components
    counts = f.attempt_counts
    f.attempt_counts = campaign.attempt_counts = lambda ledger: recovery_counts(counts(ledger),ledger,authorized)
    hotspot = f.hotspot_evidence
    def hotspot_evidence(head):
        from external_host_restart_recovery import hotspot_final_result
        evidence = hotspot(head)
        ordinary = [e for e in f.read_ledger(cfg.retry_ledger) if e['sample_id']==SAMPLE and e!=authorized]
        for item in evidence:
            if item.get('sample_id')==SAMPLE and item.get('run_id')==str(cfg.local_root):
                item['final_result'] = hotspot_final_result(ordinary) if ordinary else 'OPERATIONAL_PRE_HEALTH_RECOVERY_PENDING'
        return evidence
    f.hotspot_evidence = hotspot_evidence
    write = f.atomic_write_json
    def write_json(target,value):
        if Path(target) in (cfg.progress_state,cfg.report_path):
            value = {**value,'SAMPLE369_PRE_HEALTH_RECOVERY_EXCEPTION':CLAUSE}
        return write(target,value)
    f.atomic_write_json = write_json
