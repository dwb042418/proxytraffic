"""One authorized recovery of the retained r11 sample85 attempt1 only."""
from pathlib import Path

CLAUSE = 'SAMPLE85_TRANSIENT_INFRASTRUCTURE_RECOVERY_EXCEPTION'
SAMPLE = 'formal_t0_v3_sample0085'


def install(campaign):
    f, config = campaign.f, campaign.CONFIG
    path = config.documentation_root/'sample85_operational_recovery.json'
    if not path.exists():
        return
    proof = f.load_json(path)
    if (config.campaign_id != 't0_v3_r11' or proof['exception'] != CLAUSE
            or proof['scope'] != 'sample85_only'
            or proof['global_retry_policy_changed'] is not False
            or proof['max_attempts'] != 3 or f.MAX_ATTEMPTS_PER_SAMPLE != 3
            or f.FROZEN_SHA256.get(path) != f.sha256(path)):
        raise f.PrecheckFail('sample85 recovery authorization mismatch')
    gate_path = Path(proof['recovery_gate'])
    gate = f.load_json(gate_path)
    if (f.FROZEN_SHA256.get(gate_path) != f.sha256(gate_path)
            or gate['status'] != 'PASS' or gate['consecutive_four_mode_health_pass'] < 2
            or gate['remote_evidence']['remote_integrity'] != 'PASS'):
        raise f.PrecheckFail('sample85 recovery gate missing')
    original = gate['original_ledger_entry']
    result_path = Path(original['artifact_path'])/'validation_attempt_result.json'
    if (original['sample_id'] != SAMPLE or original['attempt'] != '1'
            or original['failure_class'] != 'INFRASTRUCTURE_HEALTH_LOST'
            or original['final_status'] != 'FAIL'
            or original['browser_attempt_consumed'] != 'true'
            or f.sha256(result_path) != gate['attempt1_result_sha256']):
        raise f.PrecheckFail('sample85 retained failure identity mismatch')
    retained = f.load_json(result_path)
    authorized = {**original, 'retry_authorized': 'true', 'retry_reason': CLAUSE}
    audit = campaign.ledger_audit
    def ledger_audit():
        ledger = audit()
        matches = [e for e in ledger if e['sample_id'] == SAMPLE and e['attempt'] == '1']
        if matches != [authorized]:
            raise f.HardStop('sample85 exception ledger differs from authorized evidence')
        return ledger
    campaign.ledger_audit = ledger_audit
    ledger_audit()
    collect = f.run_formal_sample
    def run_sample(row, head, registry, start_attempt):
        if int(row['sequence_id']) <= 84 or (row['schedule_id'] == SAMPLE and start_attempt == 1):
            raise f.PrecheckFail('preserved boundary84/consumed sample85 attempt1 cannot restart')
        return collect(row, head, registry, start_attempt)
    f.run_formal_sample = run_sample
    # Original classifier/policy remains unchanged. The final campaign audit must
    # recognize exactly the authorized, already settled result, including its bytes.
    configure = f.configure_execution_components
    def components():
        component = configure()
        decide = component.retry_authorized
        def retry_authorized(result, attempt=None):
            if attempt == 1 and result == retained:
                return True, CLAUSE
            return decide(result, attempt=attempt)
        component.retry_authorized = retry_authorized
        return component
    f.configure_execution_components = components
    counts = f.attempt_counts
    def attempt_counts(ledger):
        value = counts(ledger)
        interruption = sum(e == authorized for e in ledger)
        recovery = int(bool(interruption) and any(
            e['sample_id'] == SAMPLE and int(e['attempt']) == 2 for e in ledger))
        return {**value, 'RETRY_COUNT': value['RETRY_COUNT'] - recovery,
                'OPERATIONAL_INFRASTRUCTURE_INTERRUPTION_COUNT': interruption,
                'OPERATIONAL_INFRASTRUCTURE_RECOVERY_COUNT': recovery}
    f.attempt_counts = campaign.attempt_counts = attempt_counts
    hotspot = f.hotspot_evidence
    def hotspot_evidence(head):
        from external_host_restart_recovery import hotspot_final_result
        evidence = hotspot(head)
        ordinary = [e for e in f.read_ledger(config.retry_ledger)
                    if e['sample_id'] == SAMPLE and e != authorized]
        for item in evidence:
            if (item.get('sample_id') == SAMPLE
                    and item.get('run_id') == str(config.local_root)):
                item['final_result'] = hotspot_final_result(ordinary)
        return evidence
    f.hotspot_evidence = hotspot_evidence
    stop = f.enforce_failed_attempt_stop
    def enforce(attempt, sample_id, result, allowed):
        if (sample_id == SAMPLE and attempt == 2
                and result.get('failure_class') == 'INFRASTRUCTURE_HEALTH_LOST'):
            print('RECURRENT_INFRASTRUCTURE_HEALTH_DEGRADATION', flush=True)
        return stop(attempt, sample_id, result, allowed)
    f.enforce_failed_attempt_stop = enforce
    write = f.atomic_write_json
    def write_json(target, value):
        if Path(target) in (config.progress_state, config.report_path):
            value = {**value, 'SAMPLE85_OPERATIONAL_RECOVERY_EXCEPTION': CLAUSE}
            if Path(target) == config.report_path:
                # Never erase the historical infrastructure loss in final reporting.
                value = {**value, 'HEALTH_FAILURES': value.get('health_failures', 0),
                         'ACCEPTED_SAMPLE_HEALTH_FAILURES': 0}
        return write(target, value)
    f.atomic_write_json = write_json
