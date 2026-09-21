"""Carry 388 samples across the qualified chess.com URL-only domain amendment."""
import json
from pathlib import Path

ASSETS = ('POOL','SPLIT','MANIFEST','REGISTRY','SCHEDULE','RETIREMENT_LEDGER')


def replacement_mapping(previous, manifest, source):
    from realistic_campaign_identity import CampaignIdentity
    from context369_protocol_continuation import carry_completed_mapping
    mapping = CampaignIdentity(manifest, source)
    carry_completed_mapping(mapping, previous, 388)
    for row in mapping.rows[388:392]:
        row['schedule_id'] += '_chess_replacement_6'
    mapping.by_campaign = {r['sequence_id']: r for r in mapping.rows}
    mapping.by_sample = {r['schedule_id']: r for r in mapping.rows}
    return mapping


def historical_counts(value, closed):
    from pair_group_reacquisition import add_closed_attempt_counts
    return {**add_closed_attempt_counts(value, closed),
            'HISTORICAL_CHESS_ACQUISITION_FAILURES': len(closed)}


def install(c):
    f,cfg=c.f,c.CONFIG
    path=cfg.documentation_root/'context389_protocol_amendment.json'
    if not path.exists():return
    proof=f.load_json(path)
    if (proof['campaign_id']!='t0_v3_r11' or proof['carry_forward_boundary']!=388
            or proof['old_domain']!='chess.com' or proof['retry_policy_changed']
            or f.FROZEN_SHA256.get(path)!=f.sha256(path)):
        raise f.PrecheckFail('context389 amendment identity')
    c.CONTEXT389_PROTOCOL_AMENDMENT=proof
    f.PRESERVED_BOUNDARY=388
    old_assets={k:getattr(f,k) for k in ASSETS}
    c.CONTEXT389_PREVIOUS_ASSETS=old_assets
    for key,value in proof['assets'].items():setattr(f,key,Path(value))
    f.CAMPAIGN_SCHEDULE=None;source,_,_=f.audit_schedule_and_plans()
    mapping=replacement_mapping(c.IDENTITY,proof['campaign_manifest'],source)
    c.IDENTITY.__dict__.update(mapping.__dict__);f.CAMPAIGN_SCHEDULE=c.IDENTITY.rows
    object.__setattr__(cfg,'retry_ledger',Path(proof['active_retry_ledger']))
    object.__setattr__(cfg,'storage_ledger',Path(proof['active_eviction_ledger']))
    validate=f.validate_metadata
    def valid(metadata,row,head):
        if int(row['sequence_id'])>388:
            return validate(metadata,row,head) and metadata.get('context389_amendment_sha256')==f.sha256(path)
        current={k:getattr(f,k) for k in ASSETS}
        try:
            for key,value in old_assets.items():setattr(f,key,value)
            return validate(metadata,row,head)
        finally:
            for key,value in current.items():setattr(f,key,value)
    f.validate_metadata=valid
    build=f.build_sample_metadata
    def metadata(row,*args):
        if int(row['sequence_id'])<=388:raise f.PrecheckFail('carried boundary388 cannot be recollected')
        return {**build(row,*args),'context389_amendment_sha256':f.sha256(path),
                'protocol_epoch':proof['protocol_epoch'],'domain_replacement_acquisition':'CHESS_REPLACEMENT_6'}
    f.build_sample_metadata=metadata
    helper=f.load_staging_helper();revision=proof['executor_namespace_revision']
    f.executor_namespace=lambda row,attempt:str(helper.namespace_path(cfg.executor_cache_root,revision,cfg.run_class,'',row['schedule_id'],attempt))
    staging=f.staging_request
    f.staging_request=lambda row,attempt,action:{**staging(row,attempt,action),'revision':revision}
    def separation():
        cfg.assert_invariant()
        if revision!='t0_v3_r11_protocol_chess_6':raise f.PrecheckFail('context389 namespace collision')
    f.verify_namespace_separation=separation
    verify=f.verify_frozen_sha
    def freeze():
        verify()
        original=Path(proof['original_retry_ledger'])
        if f.sha256(original)!=proof['original_retry_ledger_sha256']:raise f.HardStop('original chess.com ledger changed')
        prefix=[e for e in f.read_ledger(original) if int(e['sequence_id'])<=388]
        if f.read_ledger(cfg.retry_ledger)[:len(prefix)]!=prefix:raise f.HardStop('carried boundary388 ledger changed')
    f.verify_frozen_sha=freeze
    counts=f.attempt_counts
    def attempt_counts(ledger):
        return historical_counts(counts(ledger),proof['excluded_attempts'])
    f.attempt_counts=c.attempt_counts=attempt_counts
    hotspot=f.hotspot_evidence
    f.hotspot_evidence=lambda head:hotspot(head)+proof['historical_hotspot_evidence']
    check=f.verify_sample_precheck
    def precheck(row,*args):
        if int(row['sequence_id'])<=388:raise f.PrecheckFail('carried boundary388 cannot be recollected')
        if int(row['sequence_id'])>=393:quartet_pass(c)
        return check(row,*args)
    f.verify_sample_precheck=precheck
    boundary=f.BOUNDARY_HOOK
    def at_boundary(row,progress,head):
        value=boundary(row,progress,head)
        if int(row['sequence_id'])==392:quartet_pass(c)
        return value
    f.BOUNDARY_HOOK=at_boundary
    write=f.atomic_write_json
    def write_json(target,value):
        if Path(target) in (cfg.progress_state,cfg.report_path):
            value={**value,'CONTEXT389_AMENDMENT_SHA256':f.sha256(path),
                   'CURRENT_DOMAIN_CARRY_FORWARD_BOUNDARY':388,'ACTIVE_RETRY_LEDGER':str(cfg.retry_ledger),
                   'CHESS_CONTEXTUAL_HTTP403_REPRODUCED':True,'CONTEXT389_QUALIFIED_DELTA':'PASS'}
        result=write(target,value)
        if Path(target) in (cfg.progress_state,cfg.report_path):
            actual=f.load_json(Path(target))
            actual.update(CURRENT_DOMAIN_CARRY_FORWARD_BOUNDARY=388,ACTIVE_RETRY_LEDGER=str(cfg.retry_ledger))
            f.atomic_write_text(Path(target),json.dumps(actual,indent=2,sort_keys=True)+'\n')
        return result
    f.atomic_write_json=write_json


def qualified(c,previous):
    if not hasattr(c,'CONTEXT389_PROTOCOL_AMENDMENT'):return previous()
    f=c.f;proof=c.CONTEXT389_PROTOCOL_AMENDMENT
    current={k:getattr(f,k) for k in ASSETS}
    try:
        for key,value in c.CONTEXT389_PREVIOUS_ASSETS.items():setattr(f,key,value)
        previous()
    finally:
        for key,value in current.items():setattr(f,key,value)
    review=f.load_json(Path(proof['retirement_review']))
    if (review['status']!='CHESS_CONTEXTUAL_HTTP403_REPRODUCED'
            or review['valid_diagnostic_trials']!=12 or review['http403']!=12):
        raise f.PrecheckFail('context389 retirement proof')
    for key in ('diagnostic_remote_receipt','diagnostic_original_remote_receipt','qualification_remote_receipt','delta_remote_receipt'):
        if f.load_json(Path(proof[key]))['remote_integrity']!='PASS':
            raise f.PrecheckFail('context389 unarchived evidence '+key)
    selected=f.load_json(Path(proof['qualification_result']))['selected']
    if len(selected)!=1 or selected[0]['candidate']['domain']!=proof['replacement_domain']:
        raise f.PrecheckFail('context389 qualified candidate identity')
    for stage,count in (('actionability',3),('cross_mode',8),('contextual',12)):
        trials=selected[0][stage]['trials']
        if len(trials)!=count or not all(t['trial_pass'] and t['retry'] is False for t in trials):
            raise f.PrecheckFail('context389 qualification incomplete '+stage)
    delta=f.load_json(Path(proof['delta_result']))
    if delta['status']!='DELTA_READINESS_VALIDATION_PASS' or delta['completed']!=proof['delta_trials']:
        raise f.PrecheckFail('context389 delta incomplete')
    delta_source={r['sequence_id']:r for r in f.read_tsv(f.SCHEDULE)}
    for trial in delta['results']:
        row=delta_source[str(trial['source_sequence'])]
        if not trial['trial_pass'] or not trial['valid'] or trial['retry'] or trial['plan_sha256']!=row['plan_sha256']:
            raise f.PrecheckFail('context389 delta context mismatch')
        c.CAPACITY_NEW_ASSERT(trial['result'],row)
    boundary=f.load_json(Path(proof['boundary_verification']))
    if boundary['remote_complete']!=388 or boundary['integrity']!='PASS' or boundary['complete_pair_groups']!=97:
        raise f.PrecheckFail('context389 carry verification incomplete')


def quartet_pass(c):
    f,cfg=c.f,c.CONFIG;marker=cfg.local_root/'context389_amendment_quartet.json'
    digest=f.sha256(cfg.documentation_root/'context389_protocol_amendment.json')
    if marker.exists():
        value=f.load_json(marker)
        if value['status']!='CHESS_REPLACEMENT_PAIR_GROUP_0098_PASS' or value['amendment_sha256']!=digest:
            raise f.HardStop('context389 quartet identity')
        return
    rows=[c.IDENTITY.lookup(n) for n in (389,390,391,392)]
    if len({r['plan_sha256'] for r in rows})!=1 or {r['mode_order'] for r in rows}!=set(f.MODES):
        raise f.HardStop('context389 matched plan mismatch')
    for row in rows:
        sample=cfg.local_sample_root/row['schedule_id'];metadata=f.load_json(sample/'sample_metadata.json')
        if not (sample/'SAMPLE_COMPLETE').exists() or not f.validate_metadata(metadata,row,c.HEAD):
            raise f.HardStop('context389 quartet incomplete')
        f.assert_final_attempt(metadata['final_result'],row)
        if not f.remote_complete_valid(row,c.HEAD):raise f.HardStop('context389 quartet remote incomplete')
    f.atomic_write_json(marker,dict(status='CHESS_REPLACEMENT_PAIR_GROUP_0098_PASS',samples=[389,390,391,392],
        amendment_sha256=digest,remote_complete=4,remote_integrity='PASS',time=f.utc_now()))
    c.archive_controls();print('CHESS_REPLACEMENT_PAIR_GROUP_0098_PASS NEXT_SEQUENCE=393',flush=True)
