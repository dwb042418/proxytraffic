#!/usr/bin/env python3
"""Prepare explicit revision records; freeze once at the committed local HEAD."""
import argparse
import csv
import hashlib
import json
import shutil
import subprocess
from pathlib import Path
from realistic_hotspot_history import collect_history
from realistic_campaign_config import CampaignConfig

REPO = Path('/home/etip/Tunnel/proxytraffic')
CODE = REPO/'encrypted_traffic_platform/realistic'
DOC = REPO/'docs/realistic_v1/formal_t0_v3'
MISSION = DOC/'autonomous_mission'
COMMON_CODE = (
    'realistic_campaign_config.py','realistic_campaign_runtime.py','realistic_campaign_identity.py',
    'realistic_campaign_telemetry.py','run_realistic_campaign.py','bounded_http5xx_retry_v5.py',
    'run_single_quartet_v3_validation_retry_v5.py','run_single_quartet_v3_validation.py',
    'formal_failure_classifier_v3.py','formal_failure_classifier_v2.py','realistic_browser_v3_r10.py',
    'stress_terminal_taxonomy.py','stress_preflight_taxonomy_v3.py','executor_input_staging_v1.py',
    'audit_realistic_sample.py','run_formal_t0_v3_r6_production.py',
    'realistic_hotspot_history.py',
    'prepare_realistic_campaign.py','manage_realistic_mission.py',
)


def sha(path): return hashlib.sha256(path.read_bytes()).hexdigest()
def write(path,value): path.write_text(json.dumps(value,indent=2,sort_keys=True)+'\n')


def prepare(campaign_id, kind, *, qualification='', source_plan_revision=None):
    if kind == 'FORMAL':
        qualified_report = json.loads((Path(qualification)/'campaign_result.json').read_text())
        qualified_config = json.loads((MISSION/qualified_report['campaign_id']/'campaign_config.json').read_text())
        qualified_source = qualified_config.get('source_plan_revision','t0_v3_r7')
        if source_plan_revision is not None and source_plan_revision != qualified_source:
            raise ValueError('Formal source revision differs from qualified Stress')
        source_plan_revision = qualified_source
    source_plan_revision = source_plan_revision or 't0_v3_r7'
    root = MISSION/campaign_id
    root.mkdir(parents=True,exist_ok=False)
    storage = 'non_formal_production_readiness_'+campaign_id.replace('_stress','') if kind=='STRESS' else campaign_id
    config = {'campaign_id':campaign_id,'kind':kind,
        'dataset_track':('R10_PRODUCTION_READINESS_STRESS_'+campaign_id.rsplit('_',1)[-1].upper()) if kind=='STRESS' else 'REALISTIC_FORMAL_'+campaign_id.upper(),
        'storage_name':storage,'executor_revision':'t0_v3_r11' if kind=='STRESS' else campaign_id,'total_samples':192 if kind=='STRESS' else 1200,
        'stress_qualification':qualification,'source_plan_revision':source_plan_revision}
    write(root/'campaign_config.json',config)
    write(root/'historical_hotspot_evidence.json', collect_history(
        MISSION, Path('/home/etip/datasets/staging/realistic_v1'), campaign_id))
    assets = CampaignConfig(root/'campaign_config.json',**config).source_assets
    with assets['SCHEDULE'].open() as handle:
        source = list(csv.DictReader(handle,delimiter='\t'))
    entries = campaign_entries(kind,source)
    with (root/'campaign_manifest.tsv').open('w',newline='') as handle:
        writer = csv.DictWriter(handle,fieldnames=list(entries[0]),delimiter='\t',lineterminator='\n')
        writer.writeheader();writer.writerows(entries)
    write(root/'methodology.json',{
        'campaign_id':campaign_id,'kind':kind,'sample_count':config['total_samples'],
        'final_dataset_eligible':kind=='FORMAL','source_plan_revision':source_plan_revision,
        'browser':'realistic_browser_v3_r10.py','retry_policy':'FORMAL_T0_V3_TRANSIENT_RETRY_POLICY_V5',
        'governance':'USER_AUTHORIZED_AUTONOMOUS_MISSION','remote_git_push_deferred':True,
        'max_attempts':3,'failed_evidence_retained':True,'revision_mixing_prohibited':True,
        'whole_sample_fresh_lifecycle_retry':True,'local_free_space_threshold_gib':20,
        'stress_selection':'EXACT_V3_SOURCE_SELECTION_UNCHANGED','stress_resume_boundary':96,
        'formal_requires_full_stress_192':True,'stress_qualification':qualification,
        'historical_hotspot_evidence':'FROZEN_PRIOR_CAMPAIGN_EXPORTS_WITH_IDENTITY_DEDUPLICATION',
        'gov_br':'KEEP_LOW_FREQUENCY_SERVER_SIDE_TRANSIENT_DIAGNOSTIC_12_OF_12_PASS',
    })
    return root


def campaign_entries(kind, source):
    fields = ('campaign_sequence_id','source_schedule_sequence_id','pair_group_id','plan_id','plan_sha','mode','intensity')
    if kind != 'STRESS':
        return [dict(zip(fields,[r['sequence_id'],r['sequence_id'],r['pair_group_id'],r['plan_id'],r['plan_sha256'],r['mode_order'],r['intensity']])) for r in source]
    with (DOC/'r10_production_readiness_stress_v3/stress_campaign_manifest_v3.tsv').open() as handle:
        entries = list(csv.DictReader(handle,delimiter='\t'))
    by_sequence = {r['sequence_id']:r for r in source}
    for entry in entries:
        row = by_sequence[entry['source_schedule_sequence_id']]
        for key, source_key in [('pair_group_id','pair_group_id'),('plan_id','plan_id'),('mode','mode_order'),('intensity','intensity')]:
            if entry[key] != row[source_key]: raise ValueError('Stress source selection changed: '+key)
        entry['plan_sha'] = row['plan_sha256']
    return entries


def freeze(root):
    old = json.loads((DOC/'r10_production_readiness_stress_v3/campaign_code_sha256.json').read_text())['files']
    paths = {Path(p) for p in old if Path(p).parent==DOC and 'retry_policy_v4' not in p and 'candidate_root' not in p}
    paths |= {CODE/name for name in COMMON_CODE}
    config = CampaignConfig(root/'campaign_config.json',**json.loads((root/'campaign_config.json').read_text()))
    assets = config.source_assets
    paths |= set(assets.values())
    revision = config.source_plan_revision.removeprefix('t0_v3_')
    for name in (f'domain_replacement_ledger_v3_{revision}.tsv',f'formal_t0_v3_{revision}_input_summary.json'):
        if (DOC/name).exists(): paths.add(DOC/name)
    paths |= {root/'campaign_config.json',root/'campaign_manifest.tsv',root/'methodology.json',root/'historical_hotspot_evidence.json',
        DOC/'formal_transient_retry_policy_v5.txt',DOC/'formal_transient_retry_policy_v5.sha256',DOC/'autonomous_hotspot_baseline.tsv',
        REPO/'encrypted_traffic_platform/scripts/realistic/realistic-executor-supervisor',
        Path('/etc/systemd/system/redsocks-realistic@.service.d/10-nofile.conf')}
    head = subprocess.check_output(['git','-C',str(REPO),'rev-parse','HEAD'],text=True).strip()
    write(root/'campaign_freeze.json',{'git_head':head,'files':{str(p):sha(p) for p in sorted(paths)},'REMOTE_GIT_PUSH_DEFERRED':'YES'})


if __name__=='__main__':
    parser=argparse.ArgumentParser()
    parser.add_argument('campaign_id');parser.add_argument('--kind',choices=('STRESS','FORMAL'))
    parser.add_argument('--qualification',default='');parser.add_argument('--freeze-only',action='store_true')
    parser.add_argument('--source-plan-revision')
    args=parser.parse_args()
    root=MISSION/args.campaign_id if args.freeze_only else prepare(args.campaign_id,args.kind,qualification=args.qualification,source_plan_revision=args.source_plan_revision)
    freeze(root)
    print(root/'campaign_config.json')
