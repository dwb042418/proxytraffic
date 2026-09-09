"""NON-FORMAL manifest identity adapter. No Formal schedule or runtime edits."""
import csv,hashlib
from realistic_campaign_config import CONFIG
from pathlib import Path
from urllib.parse import urlsplit

FIELDS=('campaign_sequence_id','source_schedule_sequence_id','source_pair_group_id',
        'source_plan_id','source_plan_sha','campaign_manifest_sha')
class IdentityError(RuntimeError):pass

def fail(reason):raise IdentityError('CAMPAIGN_IDENTITY_INVARIANT_FAILURE: '+reason)

class CampaignIdentity:
    def __init__(self,manifest,source_rows):
        self.manifest=Path(manifest);self.digest=hashlib.sha256(self.manifest.read_bytes()).hexdigest()
        self.source={r['sequence_id']:dict(r) for r in source_rows}
        self.rows=[];self.by_campaign={};self.by_sample={};seen_source=set()
        with self.manifest.open() as stream:entries=list(csv.DictReader(stream,delimiter='\t'))
        for item in entries:
            c=item['campaign_sequence_id'];s=item['source_schedule_sequence_id']
            if c in self.by_campaign:fail('duplicate campaign sequence')
            if s in seen_source:fail('duplicate source schedule row')
            seen_source.add(s)
            if s not in self.source:fail('missing source schedule row')
            source=self.source[s]
            for new,old in [('pair_group_id','pair_group_id'),('plan_id','plan_id'),('plan_sha','plan_sha256'),('mode','mode_order'),('intensity','intensity')]:
                if item[new]!=source[old]:fail(new+' differs from source schedule')
            row={**source,'sequence_id':c,'schedule_id':f'formal_t0_v3_sample{int(c):04d}',
                 'quartet_index':str((int(c)-1)//4),'mode_position':str((int(c)-1)%4+1),
                 'campaign_sequence_id':c,'source_schedule_sequence_id':s,
                 'source_pair_group_id':item['pair_group_id'],'source_plan_id':item['plan_id'],
                 'source_plan_sha':item['plan_sha'],'campaign_manifest_sha':self.digest}
            self.rows.append(row);self.by_campaign[c]=row;self.by_sample[row['schedule_id']]=row
        if [int(r['sequence_id']) for r in self.rows]!=list(range(1,len(self.rows)+1)):fail('missing/out-of-order mapping')
    def lookup(self,sequence):
        try:return self.by_campaign[str(sequence)]
        except KeyError:fail('missing campaign mapping')
    def validate(self,row):
        expected=self.lookup(row['sequence_id'])
        for key,value in expected.items():
            if str(row.get(key))!=str(value):fail('runner '+key+' mismatch')
        source=self.source[expected['source_schedule_sequence_id']]
        for k in ['plan_id','plan_sha256','pair_group_id','mode_order']:
            if row[k]!=source[k]:fail('canonical source '+k+' mismatch')
        return expected
    def identity(self,row):
        row=self.validate(row)
        return {k:row[k] for k in FIELDS}
    def validate_ledger(self,entry):
        try:row=self.by_sample[entry['sample_id']]
        except KeyError:fail('ledger sample missing mapping')
        for key,value in {**self.identity(row),'sequence_id':row['sequence_id'],'plan_sha':row['plan_sha256'],'mode':row['mode_order'],'pair_group_id':row['pair_group_id']}.items():
            if str(entry.get(key))!=str(value):fail('ledger '+key+' mismatch')
        return row

def install(f,mapping):
    """Bind only this imported NON-FORMAL runner instance to one frozen mapping."""
    CONFIG.assert_invariant()
    f.CAMPAIGN_SCHEDULE=mapping.rows
    f.LEDGER_FIELDS=tuple(f.LEDGER_FIELDS)+FIELDS
    original_precheck=f.verify_sample_precheck
    def precheck(row,*args):mapping.validate(row);return original_precheck(row,*args)
    f.verify_sample_precheck=precheck
    original_identity=f.row_identity
    f.row_identity=lambda row:{**original_identity(row),**mapping.identity(row)}
    original_ledger=f.ledger_row_for_attempt
    def ledger_row(row,*args,**kwargs):return {**original_ledger(row,*args,**kwargs),**mapping.identity(row)}
    f.ledger_row_for_attempt=ledger_row
    def hotspot_evidence(head):
        evidence=list(f.verify_hotspot_baseline())
        ledger=f.read_ledger(CONFIG.retry_ledger)
        for entry in ledger:
            row=mapping.validate_ledger(entry)
            if not entry['failure_class']:continue
            artifact=Path(entry['artifact_path'])
            if not artifact.resolve().is_relative_to(f.LOCAL_PRODUCTION_ROOT.resolve()):fail('monitor artifact outside campaign root')
            proof=f.load_json(artifact/'formal_attempt_provenance.json');result=proof['component_result']
            if (proof['frozen_git_head']!=head or entry['git_head']!=head
                or result['plan_sha256']!=row['source_plan_sha']
                or entry['failure_class']!=result['failure_class']
                or str(entry['event_index'])!=str(result['failure_event_index'])
                or entry['url']!=result['failure_url']):fail('monitor evidence identity mismatch')
            for key,value in mapping.identity(row).items():
                if str(proof.get(key))!=str(value):fail('attempt provenance '+key+' mismatch')
            if not f.clean_navigation_failure(result):continue
            same=[x for x in ledger if x['sample_id']==entry['sample_id']];last=max(same,key=lambda x:int(x['attempt']))
            final=(f"SAMPLE_PASS_ATTEMPT{last['attempt']}" if last['final_status']=='PASS' else 'MAX_ATTEMPTS_REACHED' if int(last['attempt'])==3 else 'IN_PROGRESS')
            evidence.append({**mapping.identity(row),'domain':urlsplit(entry['url']).hostname,
                'plan_id':row['source_plan_id'],'plan_sha':row['source_plan_sha'],'event_index':entry['event_index'],
                'mode':entry['mode'],'failure_class':entry['failure_class'],'run_class':CONFIG.dataset_track,
                'run_id':str(f.LOCAL_PRODUCTION_ROOT),'sample_id':entry['sample_id'],'attempt':entry['attempt'],
                'final_result':final,'infra_clean':'true','evidence_path':str(artifact/'formal_attempt_provenance.json')})
        return evidence
    f.hotspot_evidence=hotspot_evidence
