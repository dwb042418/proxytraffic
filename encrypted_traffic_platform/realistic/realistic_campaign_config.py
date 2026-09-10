"""Explicit immutable roots shared by readiness and Formal campaigns."""
from dataclasses import dataclass
import json
import re
from pathlib import Path

LOCAL_BASE = Path('/home/etip/datasets/staging/realistic_v1')
REMOTE_BASE = Path('/home/dataset-assist-0/duwenbiao/Tunnel/proxydata/realistic_v1')
CONFIG = None


class RootIdentityError(RuntimeError):
    pass


@dataclass(frozen=True)
class CampaignConfig:
    config_record: Path
    campaign_id: str
    kind: str
    dataset_track: str
    storage_name: str
    executor_revision: str
    total_samples: int
    stress_qualification: str = ''
    source_plan_revision: str = 't0_v3_r7'

    @property
    def source_assets(self):
        if not re.fullmatch(r't0_v3_r[1-9]\d*', self.source_plan_revision):
            raise RootIdentityError('invalid source plan revision')
        revision = self.source_plan_revision.removeprefix('t0_v3_')
        doc = Path('/home/etip/Tunnel/proxytraffic/docs/realistic_v1/formal_t0_v3')
        return {key:doc/name for key,name in {
            'POOL':f'formal_domain_pool_v3_{revision}.tsv',
            'SPLIT':f'formal_domain_split_v3_{revision}.tsv',
            'MANIFEST':f'formal_t0_v3_plan_manifest_{revision}.tsv',
            'REGISTRY':f'FORMAL_T0_V3_PLAN_SHA256SUMS_{revision.upper()}.txt',
            'SCHEDULE':f'formal_t0_v3_schedule_{revision}.tsv',
            'RETIREMENT_LEDGER':f'domain_replacement_ledger_v3_{revision}.tsv',
        }.items()}

    @property
    def local_root(self): return LOCAL_BASE/self.storage_name
    @property
    def remote_root(self): return REMOTE_BASE/self.storage_name
    @property
    def documentation_root(self): return self.config_record.parent
    @property
    def campaign_manifest(self): return self.documentation_root/'campaign_manifest.tsv'
    @property
    def code_freeze(self): return self.documentation_root/'campaign_freeze.json'
    @property
    def diagnostic_root(self): return Path('/home/etip/datasets/diagnostics')/self.campaign_id
    @property
    def run_class(self): return 'NON_FORMAL_VALIDATION' if self.kind == 'STRESS' else 'FORMAL_PRODUCTION'
    @property
    def executor_cache_root(self): return Path('/home/etip/.cache/proxytraffic-realistic-v3-executor')
    @property
    def executor_namespace(self):
        if self.kind == 'STRESS':
            return self.executor_cache_root/'non_formal'/self.executor_revision/'operational_quartet'/self.campaign_id
        return self.executor_cache_root/'formal'/self.executor_revision

    def __getattr__(self, name):
        local = {'local_sample_root':'samples','in_progress_root':'in_progress','failed_artifact_root':'failed_artifacts',
            'retry_ledger':'retry_ledger.tsv','monitor_state':'monitor_state.json','storage_ledger':'eviction_ledger.json',
            'hard_stop_record':'revision_hard_stop.json','progress_state':'progress.json',
            'counters':'campaign_counters.json','telemetry_root':'resource_telemetry',
            'restart_record':'safe_boundary_restart.json','report_path':'campaign_result.json',
            'metadata_checksums':'FINAL_CAMPAIGN_METADATA_SHA256SUMS.txt','resume_marker':'REAL_RESUME_PASS',
            'resume_verification':'real_resume_verification.json','smoke_marker':'SMOKE_SEGMENT_PASS',
            'started_record':'campaign_started.json'}
        remote = {'remote_sample_root':'samples','remote_incoming_root':'.incoming','final_metadata_root':'final_metadata'}
        diagnostic = {'prestart_history_root':'prestart_blocker_history',
            'prestart_implementation_stop':'prestart_implementation_hard_stop.json'}
        if name in local: return self.local_root/local[name]
        if name in remote: return self.remote_root/remote[name]
        if name in diagnostic: return self.diagnostic_root/diagnostic[name]
        raise AttributeError(name)

    @property
    def local_namespaces(self): return {'samples':self.local_sample_root,'in_progress':self.in_progress_root,'failed_artifacts':self.failed_artifact_root}
    @property
    def remote_namespaces(self): return {'samples':self.remote_sample_root,'.incoming':self.remote_incoming_root}
    def checkpoint_path(self, n): return self.local_root/f'checkpoint_{n:04d}.json'

    def assert_invariant(self):
        self.source_assets
        raw = json.loads(self.config_record.read_text())
        if self != CampaignConfig(self.config_record, **raw):
            raise RootIdentityError('CAMPAIGN_ROOT_IDENTITY_INVARIANT_FAILURE: config changed')
        if self.kind == 'STRESS':
            match = re.fullmatch(r'r(\d+)_stress_v(\d+)', self.campaign_id)
            valid = bool(match and int(match[2]) >= 4 and self.total_samples == 192
                         and self.storage_name == f'non_formal_production_readiness_r{match[1]}_v{match[2]}')
        else:
            valid = self.kind == 'FORMAL' and bool(re.fullmatch(r't0_v3_r\d+', self.campaign_id)) and self.total_samples == 1200 and self.storage_name == self.campaign_id
        if not valid or self.local_root.resolve() != self.local_root:
            raise RootIdentityError('CAMPAIGN_ROOT_IDENTITY_INVARIANT_FAILURE: revision or root')
        if not re.fullmatch(r't0_v3_r\d+', self.executor_revision):
            raise RootIdentityError('CAMPAIGN_ROOT_IDENTITY_INVARIANT_FAILURE: executor revision')
        return True


def load(path):
    global CONFIG
    path = Path(path).resolve()
    CONFIG = CampaignConfig(path, **json.loads(path.read_text()))
    CONFIG.assert_invariant()
    return CONFIG
