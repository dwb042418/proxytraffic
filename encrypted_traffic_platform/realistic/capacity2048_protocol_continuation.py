"""Authorized capacity epoch; unchanged workload, failure classes and gates."""
import ast,inspect,re,textwrap
from pathlib import Path

def derive(function,replacements,extra=None):
    source=textwrap.dedent(inspect.getsource(function))
    for old,new in replacements.items():
        if source.count(old)!=1:raise RuntimeError('capacity adaptation source mismatch: '+old)
        source=source.replace(old,new)
    namespace={**function.__globals__,**(extra or {})}
    exec(compile(source,'<authorized_capacity2048:'+function.__name__+'>','exec'),namespace)
    return namespace[function.__name__]

def profile_component(retry):
    """Replace only expected configuration values, never a measured result."""
    retry.EXPECTED_REDSOCKS_CONN_MAX=2048
    retry.redsocks_capacity_precheck=derive(retry.redsocks_capacity_precheck,
        {'soft_nofile == 2048':'soft_nofile == 32768'},{'EXPECTED_REDSOCKS_CONN_MAX':2048})
    old_policy=retry.retry_authorized
    tree=ast.parse(Path(retry.__file__).read_text())
    node=next(x for x in tree.body if isinstance(x,ast.FunctionDef) and x.name=='retry_authorized')
    source=ast.get_source_segment(Path(retry.__file__).read_text(),node)
    assert source.count('== 256')==1
    namespace=dict(retry.__dict__)
    exec(compile(source.replace('== 256','== EXPECTED_REDSOCKS_CONN_MAX'),'<capacity2048_retry_configuration>','exec'),namespace)
    new_base=namespace['retry_authorized']
    from bounded_http5xx_retry_v5 import authorize_http5xx
    http=derive(authorize_http5xx,{'== 256':'== 2048'})
    def decide(result,attempt=None):
        match=re.search(r'formal_t0_v3_sample(\d+)',str(result.get('artifact_dir','')))
        if match and int(match.group(1))<=128:return old_policy(result,attempt=attempt)
        choice=http(result,attempt)
        return new_base(result,attempt=attempt) if choice is None else choice
    retry.retry_authorized=decide
    return retry

def install(c):
    f,cfg=c.f,c.CONFIG;path=cfg.documentation_root/'capacity2048_protocol_amendment.json'
    if not path.exists():return
    proof=f.load_json(path)
    if (proof['campaign_id']!='t0_v3_r11' or proof['carry_forward_boundary']!=128
        or proof['new_conn_max']!=2048 or proof['new_nofile_soft']!=32768
        or proof['nofile_hard']!=524288 or f.FROZEN_SHA256.get(path)!=f.sha256(path)):
        raise f.PrecheckFail('capacity amendment identity mismatch')
    c.CAPACITY_AMENDMENT=proof;c.CAPACITY_ORIGINAL_ASSERT=f.assert_final_attempt
    capacity_assert=derive(f.assert_final_attempt,{'else 256':'else 2048'})
    c.CAPACITY_NEW_ASSERT=capacity_assert
    f.verify_redsocks_unit_definitions=derive(f.verify_redsocks_unit_definitions,
        {'values.get("LimitNOFILESoft") != "2048"':'values.get("LimitNOFILESoft") != "32768"',
         '"soft_nofile": 2048':'"soft_nofile": 32768'})
    f.assert_final_attempt=lambda result,row: (c.CAPACITY_ORIGINAL_ASSERT if int(row['sequence_id'])<=128 else capacity_assert)(result,row)
    configure=f.configure_execution_components
    f.configure_execution_components=lambda:profile_component(configure())
    # Existing storage supervisor imports this standalone module for health only.
    import run_single_quartet_v3_validation_retry_v5 as health
    health.EXPECTED_REDSOCKS_CONN_MAX=2048
    health.redsocks_capacity_precheck=derive(health.redsocks_capacity_precheck,
        {'soft_nofile == 2048':'soft_nofile == 32768'},{'EXPECTED_REDSOCKS_CONN_MAX':2048})
    validate=f.validate_metadata
    def metadata_valid(metadata,row,head):
        return validate(metadata,row,head) and (int(row['sequence_id'])<=128 or (
            metadata.get('capacity_amendment_sha256')==f.sha256(path)
            and metadata.get('capacity_profile')=={'conn_max':2048,'nofile_soft':32768,'nofile_hard':524288}))
    f.validate_metadata=metadata_valid
    build=f.build_sample_metadata
    def build_metadata(row,*args):
        if int(row['sequence_id'])<=128:raise f.PrecheckFail('carried boundary128 cannot be recollected')
        return {**build(row,*args),'protocol_epoch':'CAPACITY2048_3','capacity_amendment_sha256':f.sha256(path),
            'capacity_profile':{'conn_max':2048,'nofile_soft':32768,'nofile_hard':524288}}
    f.build_sample_metadata=build_metadata
    helper=f.load_staging_helper();revision=proof['executor_namespace_revision']
    f.executor_namespace=lambda row,attempt:str(helper.namespace_path(cfg.executor_cache_root,revision,cfg.run_class,'',row['schedule_id'],attempt))
    staging=f.staging_request
    f.staging_request=lambda row,attempt,action:{**staging(row,attempt,action),'revision':revision}
    def separation():
        cfg.assert_invariant()
        if revision in ('t0_v3_r11_protocol_netcraze_2','t0_v3_r11_protocol_apnews_1'):raise f.PrecheckFail('capacity namespace collision')
    f.verify_namespace_separation=separation
    verify=f.verify_frozen_sha
    def verify_freeze():
        verify()
        prefix=[r for r in f.read_ledger(Path(proof['original_retry_ledger'])) if int(r['sequence_id'])<=128]
        if f.read_ledger(cfg.retry_ledger)[:len(prefix)]!=prefix:raise f.HardStop('capacity carried ledger prefix mismatch')
    f.verify_frozen_sha=verify_freeze
    precheck=f.verify_sample_precheck
    def sample_precheck(row,*args):
        if int(row['sequence_id'])<=128:raise f.PrecheckFail('carried boundary128 cannot be recollected')
        if int(row['sequence_id'])>=133:delta(c)
        return precheck(row,*args)
    f.verify_sample_precheck=sample_precheck
    boundary=f.BOUNDARY_HOOK
    def at_boundary(row,progress,head):
        result=boundary(row,progress,head)
        if int(row['sequence_id'])==132:delta(c)
        return result
    f.BOUNDARY_HOOK=at_boundary
    write=f.atomic_write_json
    def write_json(target,value):
        if Path(target) in (cfg.progress_state,cfg.report_path):
            value={**value,'CAPACITY_AMENDMENT_SHA256':f.sha256(path),'PRODUCTION_CONN_MAX':2048,
                'PRODUCTION_NOFILE_SOFT':32768,'PRODUCTION_NOFILE_HARD':524288,
                'EXCLUDED_CAPACITY_PROTOCOL_ATTEMPTS':2,
                'CAPACITY_AMENDMENT_DELTA':'PASS' if (cfg.local_root/'capacity_amendment_delta.json').exists() else 'PENDING'}
        return write(target,value)
    f.atomic_write_json=write_json

def qualified_stress(c,original):
    if not hasattr(c,'CAPACITY_AMENDMENT'):return original()
    proof=c.CAPACITY_AMENDMENT
    approved={Path(p):v['old_sha256'] for p,v in proof['system_files'].items()}
    check=derive(original,{'if f.FROZEN_SHA256.get(Path(path)) != digest:':
        'if f.FROZEN_SHA256.get(Path(path)) != digest and CAPACITY_APPROVED_STRESS_DIFFERENCES.get(Path(path)) != digest:'},
        {'CAPACITY_APPROVED_STRESS_DIFFERENCES':approved})
    return check()

def qualified(c,previous):
    if not hasattr(c,'CAPACITY_AMENDMENT'):return previous()
    f=c.f;active=f.assert_final_attempt
    try:
        f.assert_final_attempt=c.CAPACITY_ORIGINAL_ASSERT;previous()
    finally:f.assert_final_attempt=active
    proof=c.CAPACITY_AMENDMENT;validation=f.load_json(Path(proof['validation_result']))
    if validation['status']!='CAPACITY_2048_VALIDATION_PASS' or len(validation['results'])!=3:raise f.PrecheckFail('capacity qualification missing')
    row=c.IDENTITY.lookup(130)
    for trial in validation['results']:
        if not trial['pass_all'] or trial['retry'] is not False:raise f.PrecheckFail('capacity qualification failed')
        c.CAPACITY_NEW_ASSERT(trial['result'],row)
    boundary=f.load_json(Path(proof['boundary_verification']))
    if boundary['remote_complete']!=128 or boundary['integrity']!='PASS' or boundary['complete_pair_groups']!=32:raise f.PrecheckFail('capacity carry boundary missing')
    for path,entry in proof['system_files'].items():
        actual=f.run_command(['sudo','-n','sha256sum',path],timeout=15,check=True).stdout.split()[0]
        if actual!=entry['new_sha256']:raise f.PrecheckFail('capacity system configuration differs: '+path)

def delta(c):
    f,cfg=c.f,c.CONFIG;marker=cfg.local_root/'capacity_amendment_delta.json'
    if marker.exists():
        record=f.load_json(marker)
        if record['status']!='CAPACITY_AMENDMENT_DELTA_PASS' or record['amendment_sha256']!=f.sha256(cfg.documentation_root/'capacity2048_protocol_amendment.json'):raise f.HardStop('capacity delta identity')
        return
    rows=[c.IDENTITY.lookup(n) for n in (129,130,131,132)]
    if len({r['plan_sha256'] for r in rows})!=1 or {r['mode_order'] for r in rows}!=set(f.MODES):raise f.HardStop('capacity matched quartet differs')
    for row in rows:
        sample=cfg.local_sample_root/row['schedule_id'];metadata=f.load_json(sample/'sample_metadata.json')
        if not (sample/'SAMPLE_COMPLETE').exists() or not f.validate_metadata(metadata,row,c.HEAD):raise f.HardStop('capacity quartet incomplete')
        f.assert_final_attempt(metadata['final_result'],row)
        if not f.remote_complete_valid(row,c.HEAD):raise f.HardStop('capacity quartet remote incomplete')
    f.atomic_write_json(marker,dict(status='CAPACITY_AMENDMENT_DELTA_PASS',samples=[129,130,131,132],
        amendment_sha256=f.sha256(cfg.documentation_root/'capacity2048_protocol_amendment.json'),remote_complete=4,time=f.utc_now()))
    c.archive_controls();print('CAPACITY_AMENDMENT_DELTA_PASS',flush=True)
