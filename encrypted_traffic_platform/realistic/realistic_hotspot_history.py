"""Carry qualified failure evidence across immutable campaign boundaries."""
import json
from pathlib import Path


def merge_evidence(*groups):
    rows = {}
    for group in groups:
        for row in group:
            key = (str(row['run_id']), str(row['sample_id']), int(row['attempt']))
            if key in rows and rows[key] != row:
                raise ValueError('conflicting historical hotspot evidence: '+str(key))
            rows[key] = row
    return list(rows.values())


def collect_history(mission, local_base, current_id):
    evidence = []
    sources = []
    for config_path in sorted(Path(mission).glob('*/campaign_config.json')):
        config = json.loads(config_path.read_text())
        if config['campaign_id'] == current_id:
            continue
        local = Path(local_base)/config['storage_name']
        if not ((local/'revision_hard_stop.json').exists() or
                (local/'PRODUCTION_READINESS_STRESS_PASS').exists() or
                (local/'REALISTIC_FORMAL_FINAL_COLLECTION_PASS').exists()):
            continue
        ledger = local/'retry_ledger.tsv'
        if not ledger.exists() or len(ledger.read_text().splitlines()) <= 1:
            continue
        export_path = local/'hotspot_evidence_export.json'
        export = json.loads(export_path.read_text())  # Missing export fails closed.
        freeze = json.loads((config_path.parent/'campaign_freeze.json').read_text())
        if export['campaign_id'] != config['campaign_id'] or export['git_head'] != freeze['git_head']:
            raise ValueError('historical hotspot export revision mismatch')
        evidence = merge_evidence(evidence, export['evidence'])
        sources.append({'campaign_id':config['campaign_id'],'dataset_track':config['dataset_track'],'git_head':export['git_head'],
                        'export_path':str(export_path)})
    return {'schema':'CAMPAIGN_HOTSPOT_HISTORY_V1','sources':sources,'evidence':evidence}
