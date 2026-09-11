#!/usr/bin/env python3
"""Freeze qualified contextual replacements, preserving parent workload order and timing."""
import collections
import argparse
import re
import copy
import csv
import hashlib
import json
import subprocess
from pathlib import Path

import qualify_contextual_domain_replacement as qualification
import build_formal_t0_v3_split_plans as validator

REPO = qualification.history.REPO
DOC = qualification.history.DOC
EVIDENCE = PLANS = POOL = LEDGER = SPLIT = MANIFEST = REGISTRY = SCHEDULE = SUMMARY = None
REQUEST = None
OLD_REVISION = NEW_REVISION = DOMAIN_ID = None
sha = qualification.sha
read_tsv = qualification.history.read_tsv


def configure(request_path):
    global REQUEST, EVIDENCE, PLANS, POOL, LEDGER, SPLIT, MANIFEST, REGISTRY, SCHEDULE, SUMMARY
    global OLD_REVISION, NEW_REVISION, DOMAIN_ID
    qualification.configure(request_path)
    REQUEST = json.loads(Path(request_path).read_text())
    EVIDENCE = qualification.ROOT
    old = REQUEST['source_plan_revision']; new = REQUEST['new_source_plan_revision']
    assert re.fullmatch(r't0_v3_r[1-9]\d*',old) and re.fullmatch(r't0_v3_r[1-9]\d*',new) and old!=new
    OLD_REVISION = old.removeprefix('t0_v3_'); NEW_REVISION = new.removeprefix('t0_v3_')
    PLANS = Path('/home/etip/datasets/plans/realistic_v1')/new
    POOL = DOC/f'formal_domain_pool_v3_{NEW_REVISION}.tsv'
    LEDGER = DOC/f'domain_replacement_ledger_v3_{NEW_REVISION}.tsv'
    SPLIT = DOC/f'formal_domain_split_v3_{NEW_REVISION}.tsv'
    MANIFEST = DOC/f'formal_t0_v3_plan_manifest_{NEW_REVISION}.tsv'
    REGISTRY = DOC/f'FORMAL_T0_V3_PLAN_SHA256SUMS_{NEW_REVISION.upper()}.txt'
    SCHEDULE = DOC/f'formal_t0_v3_schedule_{NEW_REVISION}.tsv'
    SUMMARY = DOC/f'formal_t0_v3_{NEW_REVISION}_input_summary.json'
    assert qualification.POOL == DOC/f'formal_domain_pool_v3_{OLD_REVISION}.tsv'
    assert qualification.SOURCE_PLAN.parent == Path('/home/etip/datasets/plans/realistic_v1')/old
    DOMAIN_ID = next(r['domain_id'] for r in read_tsv(qualification.POOL) if r['domain']==qualification.OLD_DOMAIN)


def write_tsv(path, rows):
    with path.open('x',newline='') as stream:
        writer = csv.DictWriter(stream,fieldnames=list(rows[0]),delimiter='\t',lineterminator='\n')
        writer.writeheader();writer.writerows(rows)


def replace_plan(original, candidate, old_domain, domain_id):
    plan = copy.deepcopy(original)
    for event in plan['events']:
        if event['domain_id'] == domain_id:
            if event['url'] != 'https://'+old_domain+'/': raise ValueError('retired slot identity mismatch')
            event['url'] = 'https://'+candidate+'/'
    plan['url_sequence'] = [e['url'] for e in plan['events']]
    return plan


def validate_selection(result, records, queue):
    assert result['status']=='PASS' and len(result['selected'])==1
    assert result['tested']==len(records) and result['rejected']==len(records)-1
    assert records[-1]==result['selected'][0]
    for index, record in enumerate(records):
        assert record['candidate']==queue[index] and record['candidate_order']==index+1
        assert record['old_domain']==qualification.OLD_DOMAIN
        assert record['candidate']['bucket']==record['old_bucket']
        if index < len(records)-1:
            assert record['status']=='CANDIDATE_REJECTED'
            assert any(record[s]['status']=='FAIL' for s in ('actionability','cross_mode','contextual'))
    selected = records[-1]
    assert selected['status']=='QUALIFIED'
    assert len(selected['actionability']['trials'])==3 and all(t['trial_pass'] and t['retry'] is False and qualification.qualification.action.infrastructure_pass(t) for t in selected['actionability']['trials'])
    for stage, count in [('cross_mode',8),('contextual',12)]:
        trials = selected[stage]['trials']
        assert len(trials)==count and collections.Counter(t['mode'] for t in trials)=={m:count//4 for m in qualification.MODES}
        assert all(t['trial_pass'] and t['retry'] is False and not t['infrastructure_issues'] and t['all_prefix_events_pass'] for t in trials)
    return selected


def main():
    for path in (PLANS,POOL,LEDGER,SPLIT,MANIFEST,REGISTRY,SCHEDULE,SUMMARY):
        if path.exists(): raise RuntimeError('refusing existing asset output: '+str(path))
    qualification.verify_code()
    result = json.loads((EVIDENCE/'qualification_result.json').read_text())
    records = [json.loads(line) for line in (EVIDENCE/'replacement_ledger.jsonl').read_text().splitlines()]
    selected = validate_selection(result,records,json.loads((EVIDENCE/'candidate_order.json').read_text()))
    closure = json.loads(Path(REQUEST['retirement_evidence']).read_text())
    assert closure['decision']=='RETIRE_FROM_FORMAL_POOL' and closure['domain']==qualification.OLD_DOMAIN and closure['rule']==REQUEST['retirement_rule']
    old_pool = read_tsv(qualification.POOL); pool = copy.deepcopy(old_pool)
    row = next(r for r in pool if r['domain']==qualification.OLD_DOMAIN)
    candidate = selected['candidate']; first=selected['actionability']['trials'][0]
    row.update(rank=str(candidate['rank']),domain=candidate['domain'],main_http_status=str(first['main_http_status']),
        main_commit_success='true',main_commit_latency_ms=str(round(first['navigation_duration_seconds']*1000)),warning_count='',
        audit_timestamp=selected['contextual']['trials'][-1]['attempt_finished_utc'],
        actionability_evidence_type=f'replacement_{NEW_REVISION}_actionability3_crossmode8_contextual12',
        actionability_evidence_reference=str(LEDGER.relative_to(REPO))+'#candidate_domain='+candidate['domain'],
        navigation_pass_count='3',evaluate_pass_count='3',action_pass_count='3',actionability_status='ACTIONABILITY_STABLE',pool_membership='replacement_stable')
    assert sum(a==b for a,b in zip(old_pool,pool))==499
    assert len({r['domain'] for r in pool})==500
    assert collections.Counter(r['rank_bucket'] for r in pool)==validator.POOL_BUCKET_COUNTS
    ledger = read_tsv(DOC/f'domain_replacement_ledger_v3_{OLD_REVISION}.tsv')
    for record in records:
        c = record['candidate']
        entry = dict(old_domain=qualification.OLD_DOMAIN,old_rank=record['old_rank'],bucket=record['old_bucket'],candidate_rank=c['rank'],candidate_domain=c['domain'],
            candidate_order=record['candidate_order'],qualification_status=record['status'],
            actionability=record['actionability']['status'],cross_mode=record['cross_mode']['status'],contextual=record['contextual']['status'],
            contextual_pair_group=record['pair_group'],target_event_index=record['target_event_index'],source_plan_sha=record['source_plan_sha'],
            retirement_rule=REQUEST['retirement_rule'],candidate_retry_count=0,evidence_root=str(EVIDENCE/'candidates'/f'{c["rank"]}_{c["domain"]}'))
        assert set(entry)==set(ledger[0]);ledger.append(entry)
    write_tsv(LEDGER,ledger);write_tsv(POOL,pool)
    pool_sha=sha(POOL)
    split=read_tsv(DOC/f'formal_domain_split_v3_{OLD_REVISION}.tsv')
    for r in split:
        r['final_pool_sha256']=pool_sha
        if r['domain_id']==DOMAIN_ID:
            assert r['domain']==qualification.OLD_DOMAIN
            r.update(domain=candidate['domain'],rank=str(candidate['rank']),https_url='https://'+candidate['domain']+'/')
    manifest=read_tsv(DOC/f'formal_t0_v3_plan_manifest_{OLD_REVISION}.tsv')
    schedule=read_tsv(DOC/f'formal_t0_v3_schedule_{OLD_REVISION}.tsv')
    PLANS.mkdir();registry=[];changed=[];unchanged=0
    for r in manifest:
        source=Path(r['plan_path']);assert sha(source)==r['plan_sha256']
        original=json.loads(source.read_text());plan=replace_plan(original,candidate['domain'],qualification.OLD_DOMAIN,DOMAIN_ID)
        destination=PLANS/source.name
        if plan==original:
            destination.write_bytes(source.read_bytes());unchanged+=1
        else:
            destination.write_text(json.dumps(plan,indent=2,sort_keys=True)+'\n');changed.append(r['pair_group_id'])
        destination.chmod(0o444)
        r.update(plan_path=str(destination),plan_sha256=sha(destination),final_pool_sha256=pool_sha)
        registry.append((r['plan_sha256'],destination))
    assert selected['pair_group'] in changed
    by_group={r['pair_group_id']:r for r in manifest}
    for r in schedule:
        new=by_group[r['pair_group_id']];r.update(plan_path=new['plan_path'],plan_sha256=new['plan_sha256'])
    validator.validate_split(split);validator.validate_plans(split,manifest,schedule,registry,PLANS)
    write_tsv(SPLIT,split);write_tsv(MANIFEST,manifest);write_tsv(SCHEDULE,schedule)
    with REGISTRY.open('x') as stream:
        for digest,path in registry: stream.write(digest+'  '+str(path)+'\n')
    summary=dict(status=NEW_REVISION.upper()+'_QUALIFIED_INPUTS_READY',source_plan_revision=REQUEST['new_source_plan_revision'],parent_plan_revision=REQUEST['source_plan_revision'],
        retired=[qualification.OLD_DOMAIN],replacement=candidate,retirement_rule=REQUEST['retirement_rule'],qualification_root=str(EVIDENCE),
        candidate_rejected=result['rejected'],unchanged_domain_rows=499,unchanged_plan_bytes=unchanged,
        changed_plan_groups=changed,plans=300,schedule_samples=1200,domain_ids_preserved=True,domain_split_preserved=True,
        original_rng_seeds_preserved=True,event_order_preserved=True,actions_and_timing_preserved=True,
        plan_derivation='URL_ONLY_REPLACEMENT_IN_PARENT_PLANS_WITHOUT_RNG_REGENERATION',
        parent_generator_git_head=manifest[0]['generator_git_head'],replacement_builder=str(Path(__file__).resolve()),
        replacement_builder_sha256=sha(Path(__file__).resolve()),
        preparation_git_head=subprocess.check_output(['git','-C',str(REPO),'rev-parse','HEAD'],text=True).strip(),
        qualification_provenance={name:sha(EVIDENCE/name) for name in ('protocol.json','candidate_order.json','exclusion_provenance.json','qualification_result.json','replacement_ledger.jsonl')},
        formal_dataset_eligible=False,sha256={str(p):sha(p) for p in (POOL,LEDGER,SPLIT,MANIFEST,REGISTRY,SCHEDULE)})
    qualification.write(SUMMARY,summary)
    print(f'{NEW_REVISION.upper()}_INPUTS_READY replacement={candidate["domain"]} changed_plans={len(changed)} unchanged_plans={unchanged}',flush=True)


if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('--request',required=True,type=Path)
    configure(parser.parse_args().request)
    main()
