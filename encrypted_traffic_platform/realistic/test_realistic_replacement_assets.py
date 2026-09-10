import copy
import csv
import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import prepare_realistic_campaign as prepare
import run_realistic_campaign as campaign
from build_contextual_us_replacement_inputs import replace_plan
from realistic_campaign_config import CampaignConfig, RootIdentityError


class ReplacementAssetsTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if campaign.f is None:
            campaign.configure(prepare.MISSION/'r10_stress_v4/campaign_config.json')

    def test_exact_us_context_url_only_and_stress_source_identity(self):
        from realistic_campaign_identity import CampaignIdentity
        old = json.loads(Path('/home/etip/datasets/plans/realistic_v1/t0_v3_r7/seed067_medium_workload_plan.json').read_text())
        changed = replace_plan(old,'qualified.example')
        self.assertEqual(changed['events'][2]['url'],'https://qualified.example/')
        restored = copy.deepcopy(changed)
        restored['events'][2]['url']='https://us.com/'
        restored['url_sequence'][2]='https://us.com/'
        self.assertEqual(restored,old)
        with (prepare.DOC/'formal_t0_v3_schedule_r7.tsv').open() as stream:
            source = list(csv.DictReader(stream,delimiter='\t'))
        before = prepare.campaign_entries('STRESS',source)
        for row in source:
            if row['pair_group_id']=='seed067_medium': row['plan_sha256']='replacement-sha'
        after = prepare.campaign_entries('STRESS',source)
        self.assertEqual([{k:v for k,v in r.items() if k!='plan_sha'} for r in before],
                         [{k:v for k,v in r.items() if k!='plan_sha'} for r in after])
        with tempfile.TemporaryDirectory() as tmp:
            manifest=Path(tmp)/'manifest.tsv'
            with manifest.open('w') as stream:
                writer=csv.DictWriter(stream,fieldnames=list(after[0]),delimiter='\t');writer.writeheader();writer.writerows(after)
            mapping=CampaignIdentity(manifest,source)
            self.assertEqual(mapping.lookup(108)['source_schedule_sequence_id'],'800')
            self.assertEqual(mapping.lookup(108)['plan_sha256'],'replacement-sha')
        source[799]['mode_order']='direct'
        with self.assertRaisesRegex(ValueError,'source selection changed'):
            prepare.campaign_entries('STRESS',source)

    def test_formal_inherits_qualified_source_and_rejects_override(self):
        with tempfile.TemporaryDirectory() as tmp:
            mission=Path(tmp)/'mission';stress=mission/'r10_stress_v7';stress.mkdir(parents=True)
            proof=Path(tmp)/'proof';proof.mkdir()
            (proof/'campaign_result.json').write_text(json.dumps({'campaign_id':'r10_stress_v7'}))
            (stress/'campaign_config.json').write_text(json.dumps({'source_plan_revision':'t0_v3_r8'}))
            schedule=prepare.DOC/'formal_t0_v3_schedule_r7.tsv'
            with patch.object(prepare,'MISSION',mission),patch.object(prepare,'collect_history',return_value={'sources':[],'evidence':[]}), \
                 patch.object(CampaignConfig,'source_assets',new=property(lambda self:{'SCHEDULE':schedule})):
                root=prepare.prepare('t0_v3_r11','FORMAL',qualification=str(proof))
                self.assertEqual(json.loads((root/'campaign_config.json').read_text())['source_plan_revision'],'t0_v3_r8')
                with self.assertRaisesRegex(ValueError,'differs from qualified Stress'):
                    prepare.prepare('t0_v3_r12','FORMAL',qualification=str(proof),source_plan_revision='t0_v3_r7')
            bad=CampaignConfig(Path(tmp)/'config','r10_stress_v7','STRESS','STRESS','x','t0_v3_r11',192,source_plan_revision='../r8')
            with self.assertRaises(RootIdentityError): bad.source_assets

    def test_exact_v6_terminal_evidence_resolved_only_after_explicit_retirement(self):
        if campaign.f is None:
            campaign.configure(prepare.MISSION/'r10_stress_v4/campaign_config.json')
        f=campaign.f
        root=Path('/home/etip/datasets/staging/realistic_v1/non_formal_production_readiness_r10_v6')
        evidence=json.loads((root/'hotspot_evidence_export.json').read_text())['evidence']
        triggers=f.evaluate_rule_v2(evidence)
        self.assertEqual([(r['domain'],r['rule']) for r in triggers],[('us.com','RULE_A')])
        retired=[{'old_domain':'us.com','qualification_status':'QUALIFIED'}]
        def resolve(active, rows=retired):
            with patch.object(f,'read_tsv',side_effect=lambda p:rows if p==f.RETIREMENT_LEDGER else [{'domain':d} for d in active]), \
                 patch.object(f,'FROZEN_SHA256',{f.RETIREMENT_LEDGER:'verified'}),patch.object(f,'sha256',return_value='verified'):
                return f.unresolved_hotspots(triggers)
        self.assertEqual(resolve({'qualified.example'}),[])
        self.assertEqual(resolve({'us.com'}),triggers)
        self.assertEqual(resolve({'qualified.example'},[]),triggers)
        self.assertEqual(len([r for r in evidence if r['domain']=='us.com']),8)


if __name__=='__main__':unittest.main()
