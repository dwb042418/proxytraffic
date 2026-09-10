import copy
import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import run_realistic_campaign as campaign
from realistic_hotspot_history import collect_history, merge_evidence

REPO = Path(__file__).parents[2]
MISSION = REPO/'docs/realistic_v1/formal_t0_v3/autonomous_mission'
LOCAL = Path('/home/etip/datasets/staging/realistic_v1')


class HistoricalHotspotTests(unittest.TestCase):
    def test_exact_v5_us_com_evidence_survives_new_revision(self):
        if campaign.f is None:
            campaign.configure(MISSION/'r10_stress_v4/campaign_config.json')
        snapshot = collect_history(MISSION, LOCAL, 'r10_stress_v6')
        with tempfile.TemporaryDirectory() as tmp:
            history_path = Path(tmp)/'historical_hotspot_evidence.json'
            history_path.write_text(json.dumps(snapshot))
            f = campaign.f
            frozen = {**f.FROZEN_SHA256, history_path:'fixture-freeze'}
            with patch.object(f,'CONFIG',SimpleNamespace(documentation_root=Path(tmp))), \
                 patch.object(f,'FROZEN_SHA256',frozen), \
                 patch.object(f,'sha256',side_effect=lambda p:frozen[p]):
                history = f.verify_hotspot_baseline()
        previous = [r for r in history if r['domain'] == 'us.com']
        self.assertEqual(len(previous), 3)
        self.assertEqual({r['sample_id'] for r in previous},
                         {'formal_t0_v3_sample0106','formal_t0_v3_sample0107','formal_t0_v3_sample0108'})
        self.assertEqual(campaign.f.evaluate_rule_v2(history), [])
        future = [dict(previous[0], run_id='future-formal', sample_id='future-sample',
                       attempt=str(n), final_result='SAMPLE_PASS_ATTEMPT3') for n in (1,2)]
        # Old behavior loses the prior three failures at the revision boundary.
        self.assertEqual(campaign.f.evaluate_rule_v2(future), [])
        triggers = campaign.f.evaluate_rule_v2(merge_evidence(history, future))
        self.assertEqual([(t['domain'], t['rule']) for t in triggers], [('us.com','RULE_B')])

    def test_deduplication_and_conflicting_identity_fail_closed(self):
        row = {'run_id':'r5','sample_id':'s1','attempt':'1','final_result':'SAMPLE_PASS_ATTEMPT2'}
        self.assertEqual(merge_evidence([row], [copy.deepcopy(row)]), [row])
        with self.assertRaisesRegex(ValueError, 'conflicting'):
            merge_evidence([row], [dict(row, final_result='MAX_ATTEMPTS_REACHED')])

    def test_stress_pass_export_is_inherited_before_formal(self):
        with tempfile.TemporaryDirectory() as tmp:
            mission = Path(tmp)/'docs'; local = Path(tmp)/'data'
            doc = mission/'stress'; doc.mkdir(parents=True)
            root = local/'stress'; root.mkdir(parents=True)
            (doc/'campaign_config.json').write_text(json.dumps({'campaign_id':'stress','storage_name':'stress','dataset_track':'STRESS'}))
            (doc/'campaign_freeze.json').write_text(json.dumps({'git_head':'frozen-head'}))
            (root/'PRODUCTION_READINESS_STRESS_PASS').touch()
            (root/'retry_ledger.tsv').write_text('header\nconsumed\n')
            with self.assertRaises(FileNotFoundError): collect_history(mission, local, 'formal')
            row = {'run_id':str(root),'sample_id':'s1','attempt':'1'}
            export = {'campaign_id':'stress','git_head':'frozen-head','evidence':[row]}
            path = root/'hotspot_evidence_export.json'; path.write_text(json.dumps(export))
            self.assertEqual(collect_history(mission, local, 'formal')['evidence'], [row])
            export['git_head'] = 'wrong-head'; path.write_text(json.dumps(export))
            with self.assertRaisesRegex(ValueError, 'revision mismatch'): collect_history(mission, local, 'formal')


if __name__ == '__main__': unittest.main()
