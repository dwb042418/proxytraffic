"""Bounded acquisition governance; the scientific sample runtime is unchanged."""
from pathlib import Path

RULE = 'PAIR_GROUP_REACQUISITION_AFTER_EXHAUSTED_NONREPRODUCIBLE_FAILURE'
EXHAUSTED = 'PAIR_GROUP_REACQUISITION_BUDGET_EXHAUSTED'
MODES = ('direct', 'vless', 'shadowsocks', 'trojan')


class ReacquisitionRefused(RuntimeError):
    pass


def require(condition, reason):
    if not condition:
        raise ReacquisitionRefused(reason)


def clean(result, plan_sha, capacity):
    require(result.get('plan_sha256') == plan_sha, 'workload context changed')
    require(all(result.get(k) == 'PASS' for k in ('pre_health','post_health','mode_purity')),
            'health/purity failure')
    require(all(result.get(k) == 0 for k in ('redsocks_conn_max_hits','infrastructure_health_lost',
            'server_egress_degraded','trojan_public_path_degraded','residual')), 'infrastructure degradation')
    capture = result.get('capture', {})
    require(capture.get('status') == 'PASS' and capture.get('pcap_stable_size') is True
            and capture.get('executor_bounded') is True, 'capture corruption or unbounded executor')
    require(all(capture.get(k) == 0 for k in ('oom','unexpected_process_exit',
            'active_health_probe_during_capture','archive_control_packets_during_capture',
            'conntrack_exhausted_observations')), 'capture/implementation health failure')
    require(not result.get('bypass_observed', False), 'bypass')
    if result.get('mode') != 'direct':
        require(result.get('mode') in MODES and result.get('redsocks_actual_conn_max') == capacity
                and result.get('observed_direct_public_443_syn_count') == 0, 'capacity or bypass')


def eligible(row, entries, failures, diagnostic, used, triggers, capacity):
    require(used == 0, EXHAUSTED)
    require(not triggers, 'domain/contextual replacement or implementation review required')
    require([e['attempt'] for e in entries] == ['1','2','3']
            and all(e['sample_id'] == row['schedule_id'] and e['final_status'] == 'FAIL'
                    and e['plan_sha'] == row['plan_sha256'] for e in entries), 'sample budget not exhausted')
    require(len(failures) == 3, 'missing Formal evidence')
    for n, result in enumerate(failures, 1):
        require(result.get('status') == 'FAIL' and result.get('attempt') == n
                and result.get('mode') == row['mode_order'], 'Formal result identity')
        clean(result, row['plan_sha256'], capacity)
    trials = diagnostic.get('results', [])
    require(len(trials) == 12 and {(t['mode'],t['trial']) for t in trials}
            == {(m,n) for m in MODES for n in (1,2,3)}, 'fixed 12-trial diagnostic incomplete')
    require(len({t['artifact_dir'] for t in trials}) == 12, 'diagnostic lifecycle reused')
    for trial in trials:
        result = trial['result']
        require(trial.get('attempt') == 1 and trial.get('retry') is False
                and trial.get('valid_for_endpoint_judgment') is True
                and trial.get('full_workload_pass') is True and trial.get('infrastructure_issues') == []
                and result.get('status') == 'PASS' and result.get('mode') == trial['mode']
                and result.get('attempt') == 1, 'diagnostic is not 12/12 valid fresh PASS')
        clean(result, row['plan_sha256'], capacity)
    return (int(row['sequence_id'])-1)//4*4


def reacquisition_rows(rows, group):
    require([int(r['sequence_id']) for r in rows] == list(range((group-1)*4+1,group*4+1)),
            'matched group identity')
    return [{**r, 'schedule_id':r['schedule_id']+f'_pair_group_{group:04d}_reacq1'} for r in rows]


def state_path(config):
    return config.local_root/'pair_group_reacquisition_state.json'


def install(c):
    f, cfg = c.f, c.CONFIG
    amendment_path = cfg.documentation_root/'pair_group_reacquisition_amendment.json'
    if not amendment_path.exists():
        return
    amendment = f.load_json(amendment_path)
    require(amendment['rule'] == RULE and amendment['campaign_id'] == cfg.campaign_id
            and amendment['MAX_ATTEMPTS_PER_SAMPLE'] == f.MAX_ATTEMPTS_PER_SAMPLE == 3
            and amendment['MAX_PAIR_GROUP_REACQUISITIONS_AFTER_EXHAUSTED_DIAGNOSTIC_PASS'] == 1
            and f.FROZEN_SHA256.get(amendment_path) == f.sha256(amendment_path), 'unfrozen governance amendment')
    if not state_path(cfg).exists():
        return
    state = f.load_json(state_path(cfg))
    records = []
    groups = set()
    for reference in state['acquisitions']:
        path = Path(reference['path'])
        require(f.sha256(path) == reference['sha256'], 'activation record changed')
        record = f.load_json(path)
        group = record['group']
        require(group not in groups and record['rule'] == RULE and record['reacquisition_number'] == 1,
                'duplicate or unbounded reacquisition')
        groups.add(group)
        require(f.sha256(Path(record['original_ledger'])) == record['original_ledger_sha256'],
                'historical ledger changed')
        require(record['carry_forward']['status'] == 'PASS'
                and record['carry_forward']['valid_samples'] == (group-1)*4
                and record['carry_forward']['remote_complete'] == (group-1)*4,
                'incomplete carry-forward proof')
        for artifact in record['retained_result_files']:
            require(f.sha256(Path(artifact['path'])) == artifact['sha256'], 'retained attempt result changed')
        for proof in record['diagnostic_controls']:
            require(f.sha256(Path(proof['path'])) == proof['sha256'], 'diagnostic evidence changed')
        old = [c.IDENTITY.lookup(n) for n in range((group-1)*4+1, group*4+1)]
        require(old == record['original_rows'], 'scientific plan or configuration identity changed')
        fresh = reacquisition_rows(old, group)
        require(fresh == record['new_rows'], 'acquisition namespace differs')
        c.IDENTITY.rows[(group-1)*4:group*4] = fresh
        records.append(record)
    c.IDENTITY.by_campaign = {r['sequence_id']:r for r in c.IDENTITY.rows}
    c.IDENTITY.by_sample = {r['schedule_id']:r for r in c.IDENTITY.rows}
    f.CAMPAIGN_SCHEDULE = c.IDENTITY.rows
    ledger_path = Path(records[-1]['active_ledger'])
    require(ledger_path.is_relative_to(cfg.local_root/'acquisitions'), 'active ledger namespace')
    object.__setattr__(cfg, 'retry_ledger', ledger_path)
    object.__setattr__(cfg, 'storage_ledger', Path(records[-1]['active_eviction_ledger']))
    c.PAIR_GROUP_REACQUISITIONS = records
    by_id = {r['schedule_id']:record for record in records for r in record['new_rows']}
    counts = f.attempt_counts
    closed = [e for record in records for e in record['closed_entries']]
    def attempt_counts(ledger):
        current = counts(ledger)
        historical = counts(closed)
        return {**current, 'TOTAL_ATTEMPTS':current['TOTAL_ATTEMPTS']+historical['TOTAL_ATTEMPTS'],
                'RETRY_COUNT':current['RETRY_COUNT']+historical['RETRY_COUNT'],
                'FINAL_DATASET_ACQUISITION_ATTEMPTS':len(ledger),
                'HISTORICAL_ACQUISITION_ATTEMPTS':len(closed),
                'HISTORICAL_ACQUISITION_FAILURES':sum(e['final_status']=='FAIL' for e in closed),
                'PAIR_GROUP_REACQUISITION_COUNT':len(records)}
    f.attempt_counts = c.attempt_counts = attempt_counts
    build, validate = f.build_sample_metadata, f.validate_metadata
    def metadata(row, *args):
        result = build(row, *args)
        if row['schedule_id'] in by_id:
            record = by_id[row['schedule_id']]
            result.update(acquisition_instance=record['acquisition_instance'],
                pair_group_reacquisition_rule=RULE, historical_acquisition_record=record['record_path'])
        return result
    def valid(metadata, row, head):
        if row['schedule_id'] in by_id and metadata.get('acquisition_instance') != by_id[row['schedule_id']]['acquisition_instance']:
            return False
        return validate(metadata,row,head)
    f.build_sample_metadata, f.validate_metadata = metadata, valid
    hotspot = f.hotspot_evidence
    f.hotspot_evidence = lambda head: hotspot(head)+[e for r in records for e in r['historical_hotspot_evidence']]
    verify = f.verify_frozen_sha
    def frozen():
        verify()
        for record in records:
            require(f.sha256(Path(record['original_ledger'])) == record['original_ledger_sha256'], 'historical ledger mutated')
        prefix = [e for e in f.read_ledger(Path(records[-1]['original_ledger']))
                  if int(e['sequence_id']) <= records[-1]['carry_forward']['valid_samples']]
        require(f.read_ledger(cfg.retry_ledger)[:len(prefix)] == prefix, 'carried active ledger mutated')
    f.verify_frozen_sha = frozen
    before = f.verify_sample_precheck
    def precheck(row, *args):
        require(int(row['sequence_id']) > records[-1]['carry_forward']['valid_samples'], 'cannot recollect carried samples')
        for record in records:
            if int(row['sequence_id']) > record['group']*4:
                delta_pass(c, record)
        return before(row,*args)
    f.verify_sample_precheck = precheck
    boundary = f.BOUNDARY_HOOK
    def at_boundary(row, progress, head):
        value = boundary(row,progress,head)
        for record in records:
            if int(row['sequence_id']) == record['group']*4:
                delta_pass(c,record)
        return value
    f.BOUNDARY_HOOK = at_boundary
    stop = f.enforce_failed_attempt_stop
    def enforce(attempt, sample_id, result, allowed):
        if attempt >= 3 and sample_id in by_id:
            from stress_terminal_taxonomy import SamplePolicyHardStop
            raise SamplePolicyHardStop(EXHAUSTED+': '+sample_id,
                                       result=result,attempt=attempt,sample_id=sample_id)
        return stop(attempt,sample_id,result,allowed)
    f.enforce_failed_attempt_stop = enforce
    write = f.atomic_write_json
    def write_json(path,value):
        if Path(path) in (cfg.progress_state,cfg.report_path):
            value = {**value, 'PAIR_GROUP_REACQUISITION_RULE':RULE,
                'PAIR_GROUP_REACQUISITION_CARRY_FORWARD_BOUNDARY':records[-1]['carry_forward']['valid_samples'],
                'HISTORICAL_ACQUISITIONS':[r['record_path'] for r in records],
                'ACTIVE_RETRY_LEDGER':str(cfg.retry_ledger),
                'MAX_PAIR_GROUP_REACQUISITIONS_AFTER_EXHAUSTED_DIAGNOSTIC_PASS':1}
        return write(path,value)
    f.atomic_write_json = write_json


def delta_pass(c, record):
    f, cfg = c.f, c.CONFIG
    marker = cfg.local_root/'acquisitions'/record['acquisition_instance']/'delta_pass.json'
    if marker.exists():
        proof = f.load_json(marker)
        require(proof['status'] == 'PAIR_GROUP_REACQUISITION_DELTA_PASS'
                and proof['acquisition_instance'] == record['acquisition_instance'], 'delta identity')
        return
    rows = [c.IDENTITY.lookup(n) for n in range((record['group']-1)*4+1,record['group']*4+1)]
    require(len({r['plan_sha256'] for r in rows}) == 1 and {r['mode_order'] for r in rows} == set(MODES), 'matched plan drift')
    for row in rows:
        sample = cfg.local_sample_root/row['schedule_id']
        metadata = f.load_json(sample/'sample_metadata.json')
        require((sample/'SAMPLE_COMPLETE').is_file() and f.validate_metadata(metadata,row,c.HEAD), 'delta incomplete')
        f.assert_final_attempt(metadata['final_result'],row)
        require(f.remote_complete_valid(row,c.HEAD), 'delta remote incomplete')
    f.atomic_write_json(marker,dict(status='PAIR_GROUP_REACQUISITION_DELTA_PASS',
        acquisition_instance=record['acquisition_instance'],samples=[int(r['sequence_id']) for r in rows],
        remote_complete=4,remote_integrity='PASS',completed_utc=f.utc_now()))
    c.archive_controls()
    print(f"PAIR_GROUP_{record['group']:04d}_REACQUISITION_PASS",flush=True)
    print('PAIR_GROUP_REACQUISITION_DELTA_PASS',flush=True)
