"""Explicit protocol identity bookkeeping; invokes the unchanged scientific runtime."""
import json
from pathlib import Path
import run_realistic_campaign as campaign

ORIGINAL_CONFIGURE = campaign.configure
ORIGINAL_QUALIFICATION = campaign.formal_qualification_check
ASSET_KEYS = ('POOL', 'SPLIT', 'MANIFEST', 'REGISTRY', 'SCHEDULE', 'RETIREMENT_LEDGER')


def configure(config_path):
    ORIGINAL_CONFIGURE(config_path)
    from realistic_campaign_identity import CampaignIdentity
    f = campaign.f
    record_path = campaign.CONFIG.documentation_root/'protocol_amendment.json'
    amendment = f.load_json(record_path)
    if amendment['status'] != 'FORMAL_PROTOCOL_AMENDED_CONTINUATION':
        raise f.PrecheckFail('amended continuation not activated')
    if amendment['campaign_id'] != campaign.CONFIG.campaign_id or amendment['carry_forward_samples'] != [1, 48]:
        raise f.PrecheckFail('amendment campaign/boundary mismatch')
    if f.FROZEN_SHA256.get(record_path) != f.sha256(record_path):
        raise f.PrecheckFail('protocol amendment is not frozen')
    original_assets = {key: getattr(f, key) for key in ASSET_KEYS}
    original_rows = [dict(r) for r in campaign.IDENTITY.rows]
    original_freeze = f.load_json(Path(amendment['original_freeze']))
    for path,digest in original_freeze['files'].items():
        if '/encrypted_traffic_platform/' in path and f.FROZEN_SHA256.get(Path(path)) != digest:
            raise f.PrecheckFail('scientific implementation freeze changed across carry-forward')
    if set(amendment['assets']) != set(ASSET_KEYS):
        raise f.PrecheckFail('incomplete amendment assets')
    for key, path in amendment['assets'].items():
        if key not in ASSET_KEYS:
            raise f.PrecheckFail('unexpected amendment asset')
        setattr(f, key, Path(path))
    f.CAMPAIGN_SCHEDULE = None
    source, _, _ = f.audit_schedule_and_plans()
    if source[:48] != f.read_tsv(original_assets['SCHEDULE'])[:48]:
        raise f.PrecheckFail('amended schedule changed carried rows')
    mapping = CampaignIdentity(amendment['campaign_manifest'], source)
    # The old prefix retains its original manifest identity and source paths.
    mapping.rows[:48] = original_rows[:48]
    mapping.by_campaign = {r['sequence_id']:r for r in mapping.rows}
    mapping.by_sample = {r['schedule_id']:r for r in mapping.rows}
    # install() has already bound closures to this object. Preserve those closures.
    campaign.IDENTITY.__dict__.update(mapping.__dict__)
    f.CAMPAIGN_SCHEDULE = campaign.IDENTITY.rows
    validate = f.validate_metadata
    def validate_metadata(metadata, row, head):
        if int(row['sequence_id']) > 48:
            return (validate(metadata,row,head)
                    and metadata.get('protocol_amendment_sha256') == f.sha256(record_path))
        current = {key:getattr(f,key) for key in ASSET_KEYS}
        try:
            for key,path in original_assets.items():setattr(f,key,path)
            return validate(metadata,row,head)
        finally:
            for key,path in current.items():setattr(f,key,path)
    f.validate_metadata = validate_metadata
    build = f.build_sample_metadata
    def build_metadata(row, *args):
        if int(row['sequence_id']) <= 48:
            raise f.HardStop('carried samples cannot be recollected')
        return {**build(row,*args),'protocol_amendment_sha256':f.sha256(record_path),
                'protocol_status':amendment['status'],'protocol_epoch':amendment['protocol_epoch']}
    f.build_sample_metadata = build_metadata
    precheck = f.verify_sample_precheck
    def sample_precheck(row,*args):
        if int(row['sequence_id']) <= 48:
            raise f.HardStop('carried samples cannot be recollected')
        return precheck(row,*args)
    f.verify_sample_precheck = sample_precheck
    # A new protocol sample49 uses a distinct immutable executor input namespace.
    # This does not alter attempts 1..3 or the browser lifecycle.
    namespace_revision = amendment['executor_namespace_revision']
    helper = f.load_staging_helper()
    def namespace(row,attempt):
        return str(helper.namespace_path(campaign.CONFIG.executor_cache_root,namespace_revision,
            campaign.CONFIG.run_class,'',row['schedule_id'],attempt))
    f.executor_namespace = namespace
    staging = f.staging_request
    def staging_request(row,attempt,action):
        return {**staging(row,attempt,action),'revision':namespace_revision}
    f.staging_request = staging_request
    def namespace_separation():
        campaign.CONFIG.assert_invariant()
        row={'schedule_id':'formal_t0_v3_sample0049'}
        actual=helper.namespace_path(campaign.CONFIG.executor_cache_root,namespace_revision,
            campaign.CONFIG.run_class,'',row['schedule_id'],1)
        if str(actual)!=namespace(row,1) or actual.is_relative_to(campaign.CONFIG.executor_namespace):
            raise f.PrecheckFail('protocol executor namespace collision')
    f.verify_namespace_separation = namespace_separation
    decision = f.resume_decision
    def resume_decision(row,local_root,remote_valid,ledger,head):
        normal=decision(row,local_root,remote_valid,ledger,head)
        if int(row['sequence_id'])!=49 or normal!='REVIEW_REQUIRED':return normal
        if any(e['sample_id']==row['schedule_id'] for e in ledger):return normal
        if (campaign.CONFIG.local_sample_root/row['schedule_id']).exists() or (campaign.CONFIG.in_progress_root/row['schedule_id']).exists():return normal
        failed=campaign.CONFIG.failed_artifact_root/row['schedule_id']
        if sorted(str(p) for p in failed.iterdir()) != amendment['excluded_failed_artifacts']:
            raise f.HardStop('unexpected sample49 evidence outside original protocol')
        # Exact original failed evidence is retained; it is not a retry of that plan.
        return 'RUN_ATTEMPT1'
    f.resume_decision = resume_decision
    verify = f.verify_frozen_sha
    def verify_frozen_sha():
        verify()
        old_ledger = f.read_ledger(Path(amendment['original_retry_ledger']))
        current = f.read_ledger(campaign.CONFIG.retry_ledger)
        prefix = [r for r in old_ledger if int(r['sequence_id'])<=48]
        if current[:len(prefix)] != prefix:
            raise f.HardStop('carried attempt ledger changed')
        if any(r['plan_sha']==amendment['excluded_plan_sha256'] and int(r['sequence_id'])==49 for r in current):
            raise f.HardStop('retired sample49 entered active ledger')
    f.verify_frozen_sha = verify_frozen_sha
    write_json = f.atomic_write_json
    def write_with_protocol(path,value):
        if Path(path) in (campaign.CONFIG.report_path, campaign.CONFIG.progress_state):
            value = {**value,'PROTOCOL_STATUS':amendment['status'],
                'PROTOCOL_AMENDMENT_SHA256':f.sha256(record_path),
                'CARRY_FORWARD_SAMPLES':('1-360' if hasattr(campaign,'CONTEXT361_PROTOCOL_AMENDMENT') else ('1-128' if hasattr(campaign,'CAPACITY_AMENDMENT') else ('1-92' if hasattr(campaign,'NETCRAZE_PROTOCOL_AMENDMENT') else '1-48'))),'EXCLUDED_ORIGINAL_PROTOCOL_ATTEMPTS':1,
                'ALL_PROTOCOL_ATTEMPTS':value['TOTAL_ATTEMPTS']+1+getattr(campaign,'NETCRAZE_PROTOCOL_AMENDMENT',{}).get('excluded_attempt_count',0)+getattr(campaign,'CAPACITY_AMENDMENT',{}).get('excluded_attempt_count',0)+getattr(campaign,'CONTEXT361_PROTOCOL_AMENDMENT',{}).get('excluded_attempt_count',0)}
        return write_json(path,value)
    f.atomic_write_json = write_with_protocol
    campaign.PROTOCOL_AMENDMENT = amendment
    import netcraze_protocol_continuation
    netcraze_protocol_continuation.install(campaign)
    import capacity2048_protocol_continuation
    capacity2048_protocol_continuation.install(campaign)
    import context361_protocol_continuation
    context361_protocol_continuation.install(campaign)
    import pair_group_reacquisition
    pair_group_reacquisition.install(campaign)
    # This installation audits the entire ledger. Restore every approved plan
    # identity first, including samples collected after the context361 amendment.
    from sample85_operational_recovery import install
    install(campaign)
    return campaign.IDENTITY.rows


def legacy_qualification():
    import capacity2048_protocol_continuation
    capacity2048_protocol_continuation.qualified_stress(campaign,ORIGINAL_QUALIFICATION)
    f=campaign.f;amendment=campaign.PROTOCOL_AMENDMENT
    delta=f.load_json(Path(amendment['delta_result']))
    if (delta['status']!='DELTA_READINESS_VALIDATION_PASS' or delta['completed']!=20
            or not all(r['trial_pass'] and r['valid'] and r['retry'] is False for r in delta['results'])):
        raise f.PrecheckFail('finite delta qualification missing')
    selected=f.load_json(Path(amendment['qualification_result']))['selected']
    if len(selected)!=1 or selected[0]['candidate']['domain']!='tailscale.com':
        raise f.PrecheckFail('deterministic replacement qualification identity')
    for stage,count in (('actionability',3),('cross_mode',8),('contextual',12)):
        evidence=selected[0][stage]
        if evidence['status']!='PASS' or len(evidence['trials'])!=count or not all(t['trial_pass'] and t['retry'] is False for t in evidence['trials']):
            raise f.PrecheckFail('replacement qualification incomplete: '+stage)
    for trial in delta['results']:
        row=campaign.IDENTITY.lookup(trial['source_sequence'])
        if trial['plan_sha256']!=row['plan_sha256'] or trial['mode']!=row['mode_order'] or not trial['full_context_pass']:
            raise f.PrecheckFail('delta context differs from amended sample')
        f.assert_final_attempt(trial['result'],row)
    proof=f.load_json(Path(amendment['boundary48_verification']))
    if proof['valid_samples']!=48 or proof['remote_complete']!=48 or proof['integrity']!='PASS':
        raise f.PrecheckFail('carried boundary verification missing')
    f.verify_frozen_sha()
    import netcraze_protocol_continuation
    netcraze_protocol_continuation.qualification(campaign)


def qualification():
    import capacity2048_protocol_continuation
    import context361_protocol_continuation
    return context361_protocol_continuation.qualified(campaign,lambda: capacity2048_protocol_continuation.qualified(campaign,legacy_qualification))


def main(argv=None):
    campaign.configure=configure
    campaign.formal_qualification_check=qualification
    return campaign.main(argv)


if __name__=='__main__':raise SystemExit(main())
