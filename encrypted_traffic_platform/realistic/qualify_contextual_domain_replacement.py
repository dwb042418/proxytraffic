#!/usr/bin/env python3
"""Rank-ordered contextual replacement from an immutable request; no trial retries."""
import csv
import argparse
import json
import shlex
import shutil
from pathlib import Path

import qualify_contextual_replacement_r7 as qualification
import run_single_quartet_v3_validation_retry_v5 as retry

ROOT = None
OLD_DOMAIN = None
history = qualification.history
base = retry.base
CODE = Path(__file__).resolve().parent
EXECUTOR = CODE/'realistic_browser_v3_r10.py'
SOURCE_PLAN = None
POOL = None
MODES = ('direct', 'vless', 'shadowsocks', 'trojan')
CLASS = 'NON_FORMAL_CONTEXTUAL_DOMAIN_REPLACEMENT_QUALIFICATION'
TARGET = None
sha = history.sha
write = qualification.write
append = qualification.append


def configure(request_path):
    global ROOT, OLD_DOMAIN, SOURCE_PLAN, POOL, TARGET
    request = json.loads(Path(request_path).read_text())
    ROOT = Path(request['root'])
    OLD_DOMAIN = request['old_domain']
    SOURCE_PLAN = Path(request['source_plan'])
    POOL = Path(request['source_pool'])
    TARGET = int(request['target_event_index'])
    plan = json.loads(SOURCE_PLAN.read_text())
    slot = next(r for r in history.read_tsv(POOL) if r['domain']==OLD_DOMAIN)
    assert plan['events'][TARGET]['url']=='https://'+OLD_DOMAIN+'/'
    assert plan['events'][TARGET]['domain_id']==slot['domain_id']
    assert request['retirement_decision']=='RETIRE_FROM_FORMAL_POOL'
    assert request['retirement_rule'] in ('RULE_A','RULE_B','RECURRENT_ENDPOINT_INSTABILITY')


def candidate_order():
    if sha(history.SOURCE) != history.SOURCE_SHA or sha(history.SYNTAX) != history.SYNTAX_SHA:
        raise RuntimeError('frozen source/syntax mismatch')
    pool = history.read_tsv(POOL)
    slot = next(r for r in pool if r['domain'] == OLD_DOMAIN)
    low, high = history.BUCKETS[slot['rank_bucket']]
    reasons = {}
    def exclude(domain, reason):
        if domain: reasons.setdefault(domain, []).append(reason)
    for row in pool: exclude(row['domain'], 'CURRENT_POOL')
    for domain in history.historical_unstable(): exclude(domain, 'HISTORICAL_UNSTABLE_AUDIT')
    for path in sorted(history.DOC.glob('domain_replacement_ledger*.tsv')):
        for row in history.read_tsv(path):
            exclude(row.get('old_domain'), 'HISTORICALLY_RETIRED:'+path.name)
            exclude(row.get('candidate_domain'), 'HISTORICALLY_TESTED_OR_USED:'+path.name)
    for row in history.read_tsv(history.DEFAULT_GATE_ROOT/'temporal_domains.tsv'):
        if row['status'] != 'TEMPORAL_FRESHNESS_PASS': exclude(row['domain'], 'TEMPORAL_UNSTABLE')
    candidates = []
    with history.SOURCE.open() as source, history.SYNTAX.open() as syntax:
        for raw, audit in zip(csv.reader(source), csv.DictReader(syntax, delimiter='\t')):
            rank, domain = int(raw[0]), raw[1]
            if rank > high: break
            if rank != int(audit['rank']) or domain != audit['domain']:
                raise RuntimeError('source/syntax alignment mismatch')
            if rank < low: continue
            if audit['eligible'].lower() != 'true': exclude(domain, 'SYNTAX_INELIGIBLE')
            if domain not in reasons:
                candidates.append(dict(rank=rank, domain=domain, bucket=slot['rank_bucket']))
    write(ROOT/'candidate_order.json', candidates)
    write(ROOT/'exclusion_provenance.json', reasons)
    return slot, candidates


def verify_code():
    for name, digest in json.loads((ROOT/'protocol.json').read_text())['execution_files'].items():
        if sha(Path(name)) != digest: raise RuntimeError('qualification execution changed: '+name)


def prepare_inputs(inputs, remote):
    parent = str(Path(remote).parent)
    base.run(['ssh','-o','BatchMode=yes',base.USER_HOST,
              'mkdir -p '+shlex.quote(parent)+' && mkdir '+shlex.quote(remote)+' && mkdir '+shlex.quote(remote+'/input')],30,True)
    paths = [inputs/'workload_plan.json', inputs/'realistic_browser_v3.py']
    base.run(['scp','-q',*[str(p) for p in paths],base.USER_HOST+':'+remote+'/input/'],120,True)
    proof = base.run(['ssh','-o','BatchMode=yes',base.USER_HOST,'sha256sum',
                      *[remote+'/input/'+p.name for p in paths]],30,True).stdout
    if {Path(line.split()[1]).name:line.split()[0] for line in proof.splitlines()} != {p.name:sha(p) for p in paths}:
        raise RuntimeError('remote qualification input mismatch')
    base.run(['ssh','-o','BatchMode=yes',base.USER_HOST,'chmod','444',
              *[remote+'/input/'+p.name for p in paths]],30,True)


def captured_gate(candidate, root, original, contextual):
    stage = 'contextual_prefix' if contextual else 'cross_mode'
    plan = qualification.diagnostic_plan(original, candidate, TARGET, contextual)
    inputs = root/stage/'input'; inputs.mkdir(parents=True)
    path = inputs/'workload_plan.json'; write(path,plan)
    shutil.copyfile(EXECUTOR, inputs/'realistic_browser_v3.py')
    for p in inputs.iterdir(): p.chmod(0o444)
    selection = dict(pair_group_id=plan['pair_group_id'],plan_id=plan['plan_id'],plan_path=str(path),
                     plan_sha256=sha(path),seed=plan['seed_id'],split=plan['split'],intensity=plan['intensity'])
    per_mode = 3 if contextual else 2
    trials = []
    for mode in MODES:
        for number in range(1, per_mode+1):
            verify_code()
            if shutil.disk_usage(ROOT).free < 20*1024**3:
                raise RuntimeError('QUALIFICATION_STORAGE_CHECKPOINT_BEFORE_TRIAL')
            trialroot = root/stage/mode/f'trial_{number}'
            remote = f'/home/etip/.cache/{ROOT.name}/{candidate["rank"]}/{stage}/{mode}/trial_{number}'
            prepare_inputs(inputs,remote)
            append(ROOT/'trial_starts.jsonl',dict(stage=stage,mode=mode,trial=number,candidate=candidate,time=base.utc_now()))
            print(f'GATE_START domain={candidate["domain"]} stage={stage} mode={mode} trial={number}/{per_mode}',flush=True)
            try:
                result = retry.run_attempt(mode,1,selection,trialroot,remote,classification=CLASS)
            except Exception as exc:
                result = retry.synthetic_attempt_failure(exc,mode,1,selection,trialroot,CLASS)
            artifact = Path(result['artifact_dir'])
            capture = result.get('capture',{})
            issues = [k for k in ('pre_health','post_health','mode_purity') if result.get(k) != 'PASS']
            issues += [k for k in ('redsocks_conn_max_hits','infrastructure_health_lost','server_egress_degraded','trojan_public_path_degraded','residual') if result.get(k) != 0]
            if capture.get('status') != 'PASS': issues.append('capture')
            issues += [k for k in ('oom','unexpected_process_exit','active_health_probe_during_capture','conntrack_exhausted_observations','archive_control_packets_during_capture') if capture.get(k,0) != 0]
            if mode != 'direct':
                if result.get('redsocks_actual_conn_max') != 256: issues.append('conn_max_configuration')
                if result.get('observed_direct_public_443_syn_count',0): issues.append('bypass')
            report_path = artifact/'workload/workload_report.json'
            report = json.loads(report_path.read_text()) if report_path.exists() else {}
            events_path = artifact/'workload/workload_events.tsv'
            events = history.read_tsv(events_path) if events_path.exists() else []
            prefix_pass = len(events)==len(plan['events']) and all(e['navigation_hard_failure']=='False' and not e['error'] for e in events)
            passed = result['status']=='PASS' and prefix_pass and not issues and report.get('hard_failure_count')==0
            record = {**result,'trial':number,'stage':stage,'candidate_domain':candidate['domain'],
                      'trial_pass':passed,'all_prefix_events_pass':prefix_pass,'infrastructure_issues':issues,
                      'target_event_index':TARGET if contextual else 0,'retry':False,'formal_dataset_eligible':False}
            write(artifact/'candidate_trial_result.json',record); append(ROOT/'captured_trials.jsonl',record)
            trials.append(record)
            print(f'GATE_DONE domain={candidate["domain"]} stage={stage} mode={mode} trial={number} pass={passed} failure={result.get("failure_class")} infra={issues}',flush=True)
            if issues: raise RuntimeError('qualification infrastructure issue; retain trial: '+str(artifact))
            if not passed: return {'status':'FAIL','trials':trials,'pass_count':sum(t['trial_pass'] for t in trials)}
    return {'status':'PASS','trials':trials,'pass_count':len(trials)}


def main():
    ROOT.mkdir(parents=True,exist_ok=True)
    if (ROOT/'started.json').exists(): raise RuntimeError('qualification already started; no implicit retry')
    verify_code()
    slot, queue = candidate_order()
    original = json.loads(SOURCE_PLAN.read_text())
    assert original['events'][TARGET]['url']=='https://'+OLD_DOMAIN+'/'
    base.EXECUTOR = EXECUTOR
    write(ROOT/'started.json',dict(time=base.utc_now(),classification=CLASS,formal_dataset_eligible=False))
    (ROOT/'NON_FORMAL_FINAL_DATASET_INELIGIBLE').write_text(CLASS+'\n')
    for order, candidate in enumerate(queue,1):
        verify_code()
        root = ROOT/'candidates'/f'{candidate["rank"]}_{candidate["domain"]}'
        root.mkdir(parents=True,exist_ok=False)
        remote = f'/tmp/{ROOT.name}-actionability-{candidate["rank"]}'
        base.run(['ssh',base.USER_HOST,'mkdir',remote],30,True)
        base.run(['ssh',base.USER_HOST,'mkdir',remote+'/input'],30,True)
        base.run(['scp','-q',str(qualification.action.ACTION_SCRIPT),base.USER_HOST+':'+remote+'/input/'],120,True)
        print(f'CANDIDATE_START order={order} old={OLD_DOMAIN} rank={candidate["rank"]} domain={candidate["domain"]}',flush=True)
        action = qualification.actionability(candidate,root,remote)
        cross = {'status':'NOT_RUN','trials':[]}; context = {'status':'NOT_RUN','trials':[]}
        if action['status']=='PASS': cross=captured_gate(candidate,root,original,False)
        if cross['status']=='PASS': context=captured_gate(candidate,root,original,True)
        success = context['status']=='PASS'
        record = dict(old_domain=OLD_DOMAIN,old_rank=int(slot['rank']),old_bucket=slot['rank_bucket'],
                      candidate=candidate,candidate_order=order,source_plan_sha=sha(SOURCE_PLAN),
                      pair_group=original['pair_group_id'],target_event_index=TARGET,
                      actionability=action,cross_mode=cross,contextual=context,
                      status='QUALIFIED' if success else 'CANDIDATE_REJECTED')
        write(root/'candidate_result.json',record); append(ROOT/'replacement_ledger.jsonl',record)
        print(f'CANDIDATE_FINAL domain={candidate["domain"]} status={record["status"]}',flush=True)
        if success:
            write(ROOT/'qualification_result.json',dict(status='PASS',selected=[record],tested=order,rejected=order-1))
            print('CONTEXTUAL_DOMAIN_REPLACEMENT_QUALIFICATION_PASS',flush=True)
            return
    raise RuntimeError('same-bucket candidate queue exhausted')


if __name__ == '__main__':
    parser=argparse.ArgumentParser();parser.add_argument('--request',required=True,type=Path)
    configure(parser.parse_args().request)
    try: main()
    except BaseException as exc:
        write(ROOT/('qualification_interruption_'+base.stamp_now()+'.json'),dict(error=f'{type(exc).__name__}: {exc}',time=base.utc_now()))
        raise
    finally: base.cleanup_mode()
