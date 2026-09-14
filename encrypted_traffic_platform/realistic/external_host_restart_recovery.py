"""Operational restart accounting; ordinary retry and sample gates are unchanged."""
import json
from pathlib import Path

FAILURE_CLASS = 'EXTERNAL_HOST_RESTART_INTERRUPTED_ATTEMPT'
FINAL_RESULT = 'INTERRUPTED_NOT_SAMPLE_FAILURE'
CLAUSE = 'EXTERNAL_HOST_RESTART_INTERRUPTED_ATTEMPT_RECOVERY'
GATES = ('objective_host_restart_evidence', 'external_lifecycle_interruption',
         'all_existing_evidence_preserved', 'completed_remote_integrity_pass',
         'four_mode_health_pass', 'conn_max_correct',
         'no_bypass_purity_integrity_issue', 'scientific_semantics_unchanged',
         'interrupted_evidence_remote_verified', 'residual_zero')


def is_interruption(entry):
    return entry.get('failure_class') == FAILURE_CLASS


def attempt_counts(ledger):
    by_attempt = {(e['sample_id'], int(e['attempt'])): e for e in ledger}
    recoveries = sum(int(e['attempt']) > 1 and is_interruption(
        by_attempt.get((e['sample_id'], int(e['attempt']) - 1), {})) for e in ledger)
    return {'TOTAL_ATTEMPTS': len(ledger),
            'RETRY_COUNT': sum(int(e['attempt']) > 1 for e in ledger) - recoveries,
            'OPERATIONAL_INTERRUPTION_COUNT': sum(is_interruption(e) for e in ledger),
            'OPERATIONAL_RECOVERY_COUNT': recoveries}


def validate_interruption(entry, row, head, config):
    """Require an explicit evidence-backed settlement, never infer one from exit."""
    artifact = Path(entry['artifact_path'])
    if not artifact.resolve().is_relative_to(config.failed_artifact_root.resolve()):
        raise ValueError('interrupted evidence outside retained campaign artifacts')
    proof = json.loads((artifact/'external_host_restart_recovery.json').read_text())
    expected = {'clause': CLAUSE, 'campaign_id': config.campaign_id,
                'sample_id': row['schedule_id'], 'attempt': int(entry['attempt']),
                'plan_sha256': row['plan_sha256'], 'frozen_git_head': head,
                'failure_class': FAILURE_CLASS, 'final_result': FINAL_RESULT,
                'attempt_consumed': True, 'max_attempts': 3}
    if any(proof.get(k) != v for k, v in expected.items()):
        raise ValueError('host restart settlement identity mismatch')
    if (entry.get('final_status') != FINAL_RESULT or not is_interruption(entry)
            or entry.get('browser_attempt_consumed') != 'true'
            or not 1 <= int(entry['attempt']) <= 3
            or entry.get('retry_authorized') != str(int(entry['attempt']) < 3).lower()
            or not all(proof.get('gates', {}).get(k) is True for k in GATES)
            or not proof.get('remote_evidence_path') or not proof.get('evidence_manifest_sha256')):
        raise ValueError('host restart settlement gates not satisfied')
    if entry.get('url') or entry.get('event_index') or entry.get('bypass_observed') != 'false':
        raise ValueError('host restart must not be classified as a domain failure')
    return proof
