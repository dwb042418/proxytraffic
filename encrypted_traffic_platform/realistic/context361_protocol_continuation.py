"""Carry 90 unchanged groups; qualify the documented URL-only context amendment."""
from pathlib import Path
ASSETS=('POOL','SPLIT','MANIFEST','REGISTRY','SCHEDULE','RETIREMENT_LEDGER')
def install(c):
 f,cfg=c.f,c.CONFIG;path=cfg.documentation_root/'context361_protocol_amendment.json'
 if not path.exists():return
 proof=f.load_json(path)
 if (proof['campaign_id']!='t0_v3_r11' or proof['carry_forward_boundary']!=360
     or proof['old_domain']!='pikabu.ru' or proof['retry_policy_changed']
     or f.FROZEN_SHA256.get(path)!=f.sha256(path)):raise f.PrecheckFail('context361 amendment identity')
 old_assets={k:getattr(f,k) for k in ASSETS};old_rows=[dict(r) for r in c.IDENTITY.rows]
 assert set(proof['assets'])==set(ASSETS)
 for key,value in proof['assets'].items():setattr(f,key,Path(value))
 f.CAMPAIGN_SCHEDULE=None;source,_,_=f.audit_schedule_and_plans()
 if source[:360]!=f.read_tsv(old_assets['SCHEDULE'])[:360]:raise f.PrecheckFail('carried schedule rows changed')
 from realistic_campaign_identity import CampaignIdentity
 mapping=CampaignIdentity(proof['campaign_manifest'],source);mapping.rows[:360]=old_rows[:360]
 mapping.by_campaign={r['sequence_id']:r for r in mapping.rows};mapping.by_sample={r['schedule_id']:r for r in mapping.rows}
 c.IDENTITY.__dict__.update(mapping.__dict__);f.CAMPAIGN_SCHEDULE=c.IDENTITY.rows
 validate=f.validate_metadata
 def valid(metadata,row,head):
  if int(row['sequence_id'])>360:return validate(metadata,row,head) and metadata.get('context361_amendment_sha256')==f.sha256(path)
  current={k:getattr(f,k) for k in ASSETS}
  try:
   for key,value in old_assets.items():setattr(f,key,value)
   return validate(metadata,row,head)
  finally:
   for key,value in current.items():setattr(f,key,value)
 f.validate_metadata=valid
 build=f.build_sample_metadata
 def metadata(row,*args):
  if int(row['sequence_id'])<=360:raise f.PrecheckFail('carried boundary360 cannot be recollected')
  return {**build(row,*args),'context361_amendment_sha256':f.sha256(path),'protocol_epoch':proof['protocol_epoch']}
 f.build_sample_metadata=metadata
 helper=f.load_staging_helper();revision=proof['executor_namespace_revision']
 f.executor_namespace=lambda row,attempt:str(helper.namespace_path(cfg.executor_cache_root,revision,cfg.run_class,'',row['schedule_id'],attempt))
 staging=f.staging_request
 f.staging_request=lambda row,attempt,action:{**staging(row,attempt,action),'revision':revision}
 def separation():
  cfg.assert_invariant()
  if revision!='t0_v3_r11_protocol_context361_4':raise f.PrecheckFail('context361 namespace collision')
 f.verify_namespace_separation=separation
 verify=f.verify_frozen_sha
 def freeze():
  verify();prefix=[e for e in f.read_ledger(Path(proof['original_retry_ledger'])) if int(e['sequence_id'])<=360]
  if f.read_ledger(cfg.retry_ledger)[:len(prefix)]!=prefix:raise f.HardStop('carried boundary360 ledger changed')
 f.verify_frozen_sha=freeze
 check=f.verify_sample_precheck
 def precheck(row,*args):
  if int(row['sequence_id'])<=360:raise f.PrecheckFail('carried boundary360 cannot be recollected')
  if int(row['sequence_id'])>=365:quartet_pass(c)
  return check(row,*args)
 f.verify_sample_precheck=precheck
 boundary=f.BOUNDARY_HOOK
 def at_boundary(row,progress,head):
  value=boundary(row,progress,head)
  if int(row['sequence_id'])==364:quartet_pass(c)
  return value
 f.BOUNDARY_HOOK=at_boundary
 write=f.atomic_write_json
 def write_json(target,value):
  if Path(target) in (cfg.progress_state,cfg.report_path):
   value={**value,'CONTEXT361_AMENDMENT_SHA256':f.sha256(path),'EXCLUDED_CONTEXT361_PROTOCOL_ATTEMPTS':1,
    'CONTEXT361_QUALIFIED_DELTA':'PASS','SAVEFROM_SOCKET_RETRY_POLICY_CHANGED':False}
  return write(target,value)
 f.atomic_write_json=write_json;c.CONTEXT361_PROTOCOL_AMENDMENT=proof

def qualified(c,previous):
 previous()
 if not hasattr(c,'CONTEXT361_PROTOCOL_AMENDMENT'):return
 f=c.f;proof=c.CONTEXT361_PROTOCOL_AMENDMENT
 review=f.load_json(Path(proof['retirement_review']))
 if review['domain']!='pikabu.ru' or review['decision']!='RETIRE_FROM_FORMAL_POOL' or review['rule']!='RECURRENT_ENDPOINT_INSTABILITY':raise f.PrecheckFail('context361 retirement proof')
 socket=f.load_json(Path(proof['savefrom_review']))
 if socket['decision']!='RETAIN_DOMAIN_RETRY_POLICY_UNCHANGED' or socket['socket_error_count']!=0:raise f.PrecheckFail('savefrom review mismatch')
 selected=f.load_json(Path(proof['qualification_result']))['selected']
 if len(selected)!=1 or selected[0]['candidate']['domain']!=proof['replacement_domain']:raise f.PrecheckFail('context361 candidate identity')
 for stage,count in (('actionability',3),('cross_mode',8),('contextual',12)):
  trials=selected[0][stage]['trials']
  if len(trials)!=count or not all(t['trial_pass'] and t['retry'] is False for t in trials):raise f.PrecheckFail('context361 qualification incomplete '+stage)
 delta=f.load_json(Path(proof['delta_result']))
 if delta['status']!='DELTA_READINESS_VALIDATION_PASS' or delta['completed']!=12:raise f.PrecheckFail('context361 delta missing')
 for trial in delta['results']:
  row=c.IDENTITY.lookup(trial['source_sequence'])
  if not trial['trial_pass'] or not trial['valid'] or trial['retry'] or trial['plan_sha256']!=row['plan_sha256']:raise f.PrecheckFail('context361 delta identity')
  f.assert_final_attempt(trial['result'],row)
 carry=f.load_json(Path(proof['boundary_verification']))
 if carry['remote_complete']!=360 or carry['integrity']!='PASS' or carry['complete_pair_groups']!=90:raise f.PrecheckFail('context361 carry verification')

def quartet_pass(c):
 f,cfg=c.f,c.CONFIG;marker=cfg.local_root/'context361_amendment_quartet.json'
 amendment_sha=f.sha256(cfg.documentation_root/'context361_protocol_amendment.json')
 if marker.exists():
  record=f.load_json(marker)
  if record['status']!='CONTEXT361_AMENDMENT_QUARTET_PASS' or record['amendment_sha256']!=amendment_sha:raise f.HardStop('context361 quartet identity')
  return
 rows=[c.IDENTITY.lookup(n) for n in (361,362,363,364)]
 if len({r['plan_sha256'] for r in rows})!=1 or {r['mode_order'] for r in rows}!=set(f.MODES):raise f.HardStop('context361 quartet matched plan')
 for row in rows:
  sample=cfg.local_sample_root/row['schedule_id'];metadata=f.load_json(sample/'sample_metadata.json')
  if not (sample/'SAMPLE_COMPLETE').exists() or not f.validate_metadata(metadata,row,c.HEAD):raise f.HardStop('context361 quartet incomplete')
  f.assert_final_attempt(metadata['final_result'],row)
  if not f.remote_complete_valid(row,c.HEAD):raise f.HardStop('context361 quartet remote incomplete')
 f.atomic_write_json(marker,dict(status='CONTEXT361_AMENDMENT_QUARTET_PASS',samples=[361,362,363,364],remote_complete=4,amendment_sha256=amendment_sha,time=f.utc_now()))
 c.archive_controls();print('CONTEXT361_AMENDMENT_QUARTET_PASS NEXT_SEQUENCE=365',flush=True)
