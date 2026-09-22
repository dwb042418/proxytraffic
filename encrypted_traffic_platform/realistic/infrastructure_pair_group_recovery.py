"""Explicitly authorized, once-only quartet recovery after infrastructure loss."""
RULE = 'PAIR_GROUP_REACQUISITION_AFTER_RECOVERED_INFRASTRUCTURE_FAILURE'
MODES = {'direct','vless','shadowsocks','trojan'}

def require(condition, reason):
    if not condition:
        raise ValueError('INFRASTRUCTURE_ROOT_CAUSE_UNRESOLVED: '+reason)

def authorize(rows, entries, health, used):
    require(used == 0, 'no repeated infrastructure reacquisition')
    group=(int(rows[0]['sequence_id'])-1)//4+1
    boundary=(group-1)*4
    require([int(r['sequence_id']) for r in rows] == list(range(boundary+1,boundary+5)), 'incomplete quartet')
    require({r['mode_order'] for r in rows} == MODES and len({r['plan_sha256'] for r in rows}) == 1, 'matched plan drift')
    require(health['status']=='PASS' and health['rounds']==2 and health['definition_unchanged'] is True
            and health['retry'] is False and health['classification']=='RECOVERED_OPERATIONAL_INFRASTRUCTURE_FAILURE',
            'health recovery not qualified')
    by_id={r['schedule_id']:r for r in rows}
    failures=[e for e in entries if e['final_status']=='FAIL']
    require(len(failures)==1 and failures[0]['failure_class']=='INFRASTRUCTURE_HEALTH_LOST'
            and failures[0]['attempt']=='1' and failures[0]['retry_authorized']=='false', 'not the consumed non-retryable infrastructure failure')
    require(entries[-1]==failures[0], 'attempt after non-retryable failure')
    for e in entries:
        require(e['sample_id'] in by_id and e['plan_sha']==by_id[e['sample_id']]['plan_sha256']
                and e['sequence_id']==by_id[e['sample_id']]['sequence_id'] and e['attempt']=='1'
                and e['final_status'] in ('PASS','FAIL'), 'historical attempt identity')
    require(len({e['sample_id'] for e in entries})==len(entries), 'duplicate historical sample')
    return boundary

def fresh_rows(rows, group):
    require([int(r['sequence_id']) for r in rows]==list(range((group-1)*4+1,group*4+1)), 'quartet sequence')
    return [{**r,'schedule_id':r['schedule_id']+f'_pair_group_{group:04d}_infra_recovery1'} for r in rows]

def verify_record(c, record):
    from pathlib import Path
    f,cfg=c.f,c.CONFIG
    path=cfg.documentation_root/'infrastructure_pair_group_recovery_amendment.json'
    require(path.exists() and f.FROZEN_SHA256.get(path)==f.sha256(path), 'unfrozen operational authorization')
    amendment=f.load_json(path)
    require(amendment['rule']==RULE and amendment['campaign_id']==cfg.campaign_id
            and record['group'] in amendment['authorized_groups']
            and amendment['MAX_INFRA_REACQUISITIONS_PER_GROUP']==1
            and amendment['MAX_ATTEMPTS_PER_SAMPLE']==f.MAX_ATTEMPTS_PER_SAMPLE==3,
            'unauthorized infrastructure acquisition')
    health=f.load_json(Path(record['health_qualification']))
    require(authorize(record['original_rows'],record['closed_entries'],health,0)==record['carry_forward']['valid_samples'], 'carry boundary')
    for number in (1,2):
        check=f.load_json(Path(record['health_qualification']).parent/f'health_round{number}'/'health_pass.json')
        require(check['status']=='PASS' and check['residual']==0 and len(check['checks'])==4
                and {x['mode'] for x in check['checks']}==MODES, 'incomplete fixed health round')
        for trial in check['checks']:
            h,capacity=trial['health'],trial['capacity']
            require(h['status']==capacity['status']=='PASS' and h['server_public_pass_count']>=3
                    and h['mode_public_pass_count']>=3, 'failed fixed health control')
            if trial['mode']=='trojan':
                require(h['controlled_canary_pass'] is True, 'failed applicable canary')
            if trial['mode']!='direct':
                require(capacity['actual_conn_max']==2048 and capacity['soft_nofile']==32768
                        and capacity['hard_nofile']==524288, 'approved capacity not effective')
    require(record['reacquisition_number']==1 and record['acquisition_instance']==f"pair_group_{record['group']:04d}_infra_recovery1"
            and record['scientific_semantics_changed'] is False and record['domain_replacement_trigger'] is False,
            'recovery semantics changed')
