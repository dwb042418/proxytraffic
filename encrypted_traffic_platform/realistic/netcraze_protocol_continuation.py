"""Explicit second protocol epoch; carry only complete, unaffected groups 1–92."""
from pathlib import Path

ASSETS = ('POOL','SPLIT','MANIFEST','REGISTRY','SCHEDULE','RETIREMENT_LEDGER')


def install(campaign):
    f,config=campaign.f,campaign.CONFIG
    path=config.documentation_root/'netcraze_protocol_amendment.json'
    if not path.exists():return
    proof=f.load_json(path)
    if (proof['campaign_id']!='t0_v3_r11' or proof['carry_forward_samples']!=[1,92]
            or proof['status']!='FORMAL_PROTOCOL_AMENDED_CONTINUATION'
            or f.FROZEN_SHA256.get(path)!=f.sha256(path)):
        raise f.PrecheckFail('netcraze complete-pair amendment identity mismatch')
    old_assets={k:getattr(f,k) for k in ASSETS}
    old_rows=[dict(r) for r in campaign.IDENTITY.rows]
    if set(proof['assets'])!=set(ASSETS):raise f.PrecheckFail('netcraze asset set')
    for key,value in proof['assets'].items():setattr(f,key,Path(value))
    f.CAMPAIGN_SCHEDULE=None
    source,_,_=f.audit_schedule_and_plans()
    if source[:92]!=f.read_tsv(old_assets['SCHEDULE'])[:92]:
        raise f.PrecheckFail('netcraze amendment changed carried source rows')
    from realistic_campaign_identity import CampaignIdentity
    mapping=CampaignIdentity(proof['campaign_manifest'],source)
    mapping.rows[:92]=old_rows[:92]
    mapping.by_campaign={r['sequence_id']:r for r in mapping.rows}
    mapping.by_sample={r['schedule_id']:r for r in mapping.rows}
    campaign.IDENTITY.__dict__.update(mapping.__dict__);f.CAMPAIGN_SCHEDULE=campaign.IDENTITY.rows
    validate=f.validate_metadata
    def validate_metadata(metadata,row,head):
        if int(row['sequence_id'])>92:
            return (validate(metadata,row,head)
                    and metadata.get('netcraze_protocol_amendment_sha256')==f.sha256(path))
        current={k:getattr(f,k) for k in ASSETS}
        try:
            for key,value in old_assets.items():setattr(f,key,value)
            return validate(metadata,row,head)
        finally:
            for key,value in current.items():setattr(f,key,value)
    f.validate_metadata=validate_metadata
    build=f.build_sample_metadata
    def build_metadata(row,*args):
        if int(row['sequence_id'])<=92:raise f.HardStop('carried complete pair groups cannot be recollected')
        return {**build(row,*args),'netcraze_protocol_amendment_sha256':f.sha256(path),
                'protocol_epoch':proof['protocol_epoch']}
    f.build_sample_metadata=build_metadata
    precheck=f.verify_sample_precheck
    def sample_precheck(row,*args):
        if int(row['sequence_id'])<=92:raise f.PrecheckFail('carried complete pair groups cannot be recollected')
        return precheck(row,*args)
    f.verify_sample_precheck=sample_precheck
    revision=proof['executor_namespace_revision'];helper=f.load_staging_helper()
    def namespace(row,attempt):
        return str(helper.namespace_path(config.executor_cache_root,revision,config.run_class,'',row['schedule_id'],attempt))
    f.executor_namespace=namespace
    staging=f.staging_request
    f.staging_request=lambda row,attempt,action:{**staging(row,attempt,action),'revision':revision}
    def separation():
        config.assert_invariant();row={'schedule_id':'formal_t0_v3_sample0093'}
        actual=helper.namespace_path(config.executor_cache_root,revision,config.run_class,'',row['schedule_id'],1)
        if str(actual)!=namespace(row,1) or revision==campaign.PROTOCOL_AMENDMENT['executor_namespace_revision']:
            raise f.PrecheckFail('netcraze executor namespace collision')
    f.verify_namespace_separation=separation
    verify=f.verify_frozen_sha
    def verify_frozen_sha():
        verify()
        original=f.read_ledger(Path(proof['original_retry_ledger']))
        prefix=[e for e in original if int(e['sequence_id'])<=92]
        current=f.read_ledger(config.retry_ledger)
        if current[:len(prefix)]!=prefix:raise f.HardStop('netcraze carried ledger prefix changed')
        for entry in current:
            if int(entry['sequence_id'])>=93:campaign.IDENTITY.validate_ledger(entry)
    f.verify_frozen_sha=verify_frozen_sha
    write=f.atomic_write_json
    def write_json(target,value):
        if Path(target) in (config.progress_state,config.report_path):
            value={**value,'CARRY_FORWARD_SAMPLES':('1-360' if hasattr(campaign,'CONTEXT361_PROTOCOL_AMENDMENT') else ('1-128' if hasattr(campaign,'CAPACITY_AMENDMENT') else '1-92')),'CARRY_FORWARD_COMPLETE_PAIR_GROUPS':(90 if hasattr(campaign,'CONTEXT361_PROTOCOL_AMENDMENT') else (32 if hasattr(campaign,'CAPACITY_AMENDMENT') else 23)),
                'NETCRAZE_PROTOCOL_AMENDMENT_SHA256':f.sha256(path),
                'EXCLUDED_NETCRAZE_PROTOCOL_ATTEMPTS':proof['excluded_attempt_count'],
                'EXCLUDED_HISTORICAL_COMPLETE_SAMPLES':([93,94,129] if hasattr(campaign,'CAPACITY_AMENDMENT') else [93,94])}
        return write(target,value)
    f.atomic_write_json=write_json
    campaign.NETCRAZE_PROTOCOL_AMENDMENT=proof


def qualification(campaign):
    if not hasattr(campaign,'NETCRAZE_PROTOCOL_AMENDMENT'):return
    f=campaign.f;proof=campaign.NETCRAZE_PROTOCOL_AMENDMENT
    review=f.load_json(Path(proof['retirement_review']))
    if review['decision']!='RETIRE_FROM_FORMAL_POOL' or review['rule']!='RULE_A' or review['existing_rule_v2_changed']:
        raise f.PrecheckFail('netcraze retirement evidence missing')
    selected=f.load_json(Path(proof['qualification_result']))['selected']
    if len(selected)!=1 or selected[0]['candidate']['domain']!=proof['replacement_domain']:
        raise f.PrecheckFail('netcraze qualified candidate mismatch')
    for stage,count in (('actionability',3),('cross_mode',8),('contextual',12)):
        trials=selected[0][stage]['trials']
        if len(trials)!=count or not all(t['trial_pass'] and t['retry'] is False for t in trials):
            raise f.PrecheckFail('netcraze qualification incomplete: '+stage)
    delta=f.load_json(Path(proof['delta_result']))
    if delta['status']!='DELTA_READINESS_VALIDATION_PASS' or delta['completed']!=12:
        raise f.PrecheckFail('netcraze delta incomplete')
    for trial in delta['results']:
        row=campaign.IDENTITY.lookup(trial['source_sequence'])
        if not trial['trial_pass'] or not trial['valid'] or trial['retry'] or trial['plan_sha256']!=row['plan_sha256']:
            raise f.PrecheckFail('netcraze delta context differs from scheduled plan')
        f.assert_final_attempt(trial['result'],row)
    boundary=f.load_json(Path(proof['boundary92_verification']))
    if boundary['remote_complete']!=92 or boundary['integrity']!='PASS' or boundary['complete_pair_groups']!=23:
        raise f.PrecheckFail('netcraze carry-forward boundary is not verified')
