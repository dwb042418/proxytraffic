"""Protect carried identities and attempt accounting across the chess amendment."""
import copy
import csv
import tempfile
import importlib.util
import unittest
from pathlib import Path

CODE = Path(__file__).parent

class ChessContinuationTest(unittest.TestCase):
    def setUp(self):
        from realistic_campaign_identity import CampaignIdentity
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        root=Path(self.temp.name)
        modes=('vless','direct','shadowsocks','trojan')
        before=[]
        for n in range(1,445):
            group=(n-1)//4
            before.append(dict(sequence_id=str(n),pair_group_id=f'group{group}',
                plan_id=f'plan{group}',plan_sha256=f'original{group}',
                mode_order=modes[(n-1)%4],intensity='medium'))
        def manifest(path,source):
            entries=[dict(campaign_sequence_id=r['sequence_id'],
                source_schedule_sequence_id=r['sequence_id'],pair_group_id=r['pair_group_id'],
                plan_id=r['plan_id'],plan_sha=r['plan_sha256'],mode=r['mode_order'],
                intensity=r['intensity']) for r in source]
            with path.open('w') as stream:
                writer=csv.DictWriter(stream,fieldnames=list(entries[0]),delimiter='\t')
                writer.writeheader();writer.writerows(entries)
        manifest(root/'old.tsv',before)
        self.previous=CampaignIdentity(root/'old.tsv',before)
        for row in self.previous.rows[364:368]:row['schedule_id']+='_pair_group_0092_reacq1'
        self.previous.by_sample={r['schedule_id']:r for r in self.previous.rows}
        self.source=copy.deepcopy(before)
        for row in self.source:
            if int(row['sequence_id']) in (121,122,123,124,389,390,391,392,441,442,443,444):
                row['plan_sha256']='new'+row['pair_group_id']
        self.manifest=root/'new.tsv';manifest(self.manifest,self.source)

    def adapter(self):
        self.assertIsNotNone(importlib.util.find_spec('context389_protocol_continuation'),
                             'Missing chess amendment identity adapter')
        import context389_protocol_continuation
        return context389_protocol_continuation

    def mapping(self):
        return self.adapter().replacement_mapping(self.previous,
            self.manifest, self.source)

    def test_preserves_every_carried_row_including_old_chess_and_reacquisitions(self):
        mapping = self.mapping()
        self.assertEqual(mapping.rows[:388], self.previous.rows[:388])
        for n in (1,121,122,123,124,365,366,367,368,369,388):
            row=mapping.lookup(n)
            self.assertEqual(mapping.validate(row),self.previous.lookup(n))
            self.assertEqual(mapping.source[row['source_schedule_sequence_id']],
                             self.previous.source[row['source_schedule_sequence_id']])

    def test_reacquires_only_first_affected_group_and_updates_future_chess_context(self):
        mapping=self.mapping()
        self.assertEqual([mapping.lookup(n)['schedule_id'] for n in (389,390,391,392)],
            ['formal_t0_v3_sample0389_chess_replacement_6','formal_t0_v3_sample0390_chess_replacement_6',
             'formal_t0_v3_sample0391_chess_replacement_6','formal_t0_v3_sample0392_chess_replacement_6'])
        self.assertNotEqual(mapping.lookup(389)['plan_sha256'],self.previous.lookup(389)['plan_sha256'])
        self.assertNotEqual(mapping.lookup(441)['plan_sha256'],self.previous.lookup(441)['plan_sha256'])
        self.assertEqual(mapping.lookup(441)['schedule_id'],'formal_t0_v3_sample0441')
        self.assertEqual(mapping.lookup(393)['plan_sha256'],self.previous.lookup(393)['plan_sha256'])
        self.assertEqual(len({mapping.lookup(n)['plan_sha256'] for n in (389,390,391,392)}),1)
        self.assertEqual({mapping.lookup(n)['mode_order'] for n in (389,390,391,392)},
                         {'direct','vless','shadowsocks','trojan'})
        for row in mapping.rows:mapping.validate(row)

    def test_retains_one_closed_403_without_recounting_previous_epochs(self):
        result=self.adapter().historical_counts(
            {'TOTAL_ATTEMPTS':401,'RETRY_COUNT':9,'HISTORICAL_ACQUISITION_ATTEMPTS':4},
            [{'sample_id':'formal_t0_v3_sample0389','attempt':'1','final_status':'FAIL'}])
        self.assertEqual(result['TOTAL_ATTEMPTS'],402)
        self.assertEqual(result['RETRY_COUNT'],9)
        self.assertEqual(result['HISTORICAL_ACQUISITION_ATTEMPTS'],4)
        self.assertEqual(result['HISTORICAL_CHESS_ACQUISITION_FAILURES'],1)

if __name__=='__main__':unittest.main()
