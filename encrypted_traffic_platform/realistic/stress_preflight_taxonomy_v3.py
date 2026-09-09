"""Known prestart dependencies are blockers; unknown/runtime faults stay fatal."""
import contextlib
import json
import shlex
import subprocess
from pathlib import Path
from stress_terminal_taxonomy import SamplePolicyHardStop


class PrestartInfrastructureBlocker(Exception):
    def __init__(self, blocker_class, detail, *, command=None):
        self.blocker_class = blocker_class
        self.detail = detail
        self.command = command
        super().__init__(blocker_class + ': ' + detail)


class RemoteCommandFailure(RuntimeError):
    """An unexpected remote command failure, never silently made retryable."""


def ssh_failure_class(returncode, stderr):
    if returncode != 255:
        return None
    text = stderr.lower()
    for fragment, category in (
        ('connection refused', 'REMOTE_SSH_CONNECTION_REFUSED'),
        ('connection timed out', 'REMOTE_SSH_TIMEOUT'),
        ('connection timeout', 'REMOTE_SSH_TIMEOUT'),
        ('could not resolve hostname', 'REMOTE_SSH_DNS_FAILURE'),
        ('host key verification failed', 'REMOTE_SSH_HOST_KEY_FAILURE'),
        ('remote host identification has changed', 'REMOTE_SSH_HOST_KEY_FAILURE'),
        ('permission denied', 'REMOTE_SSH_AUTHENTICATION_FAILURE'),
        ('authentication failed', 'REMOTE_SSH_AUTHENTICATION_FAILURE'),
        ('no route to host', 'REMOTE_STORAGE_UNAVAILABLE'),
        ('network is unreachable', 'REMOTE_STORAGE_UNAVAILABLE'),
        ('connection reset', 'REMOTE_STORAGE_UNAVAILABLE'),
        ('connection closed', 'REMOTE_STORAGE_UNAVAILABLE'),
    ):
        if fragment in text:
            return category
    return None


def campaign_state_consumed(config):
    if config.started_record.exists():
        return True
    for path in (config.local_sample_root, config.in_progress_root, config.failed_artifact_root):
        if path.exists() and any(path.iterdir()):
            return True
    if config.retry_ledger.exists():
        # Schema validation remains the core reader's responsibility. Any row
        # beyond the header is consumed state, including malformed rows.
        if any(line.strip() for line in config.retry_ledger.read_text().splitlines()[1:]):
            return True
    return False


@contextlib.contextmanager
def prestart_remote_commands(core, config):
    original = core.run_command

    def run(command, timeout=30, *, check=False):
        if not command or command[0] != 'ssh' or campaign_state_consumed(config):
            return original(command, timeout=timeout, check=check)
        try:
            result = subprocess.run(command, text=True, stdout=subprocess.PIPE,
                                    stderr=subprocess.PIPE, timeout=timeout, check=False)
        except subprocess.TimeoutExpired as exc:
            raise PrestartInfrastructureBlocker('REMOTE_SSH_TIMEOUT',
                f'SSH preflight deadline {timeout}s', command=command) from exc
        category = ssh_failure_class(result.returncode, result.stderr)
        if category:
            raise PrestartInfrastructureBlocker(category, result.stderr[-2000:], command=command)
        if result.returncode == 255 or (check and result.returncode):
            raise RemoteCommandFailure(
                f'REMOTE_COMMAND_FAILURE rc={result.returncode}: {shlex.join(command)}: {result.stderr[-2000:]}')
        return result

    core.run_command = run
    try:
        yield
    finally:
        core.run_command = original


def remote_path_preflight(core, config):
    code = '''import os,json,sys
from pathlib import Path
p=Path(sys.argv[1])
accessible=p.is_dir() and os.access(p,os.R_OK|os.W_OK|os.X_OK)
writable=accessible and not (os.statvfs(p).f_flag & os.ST_RDONLY)
print(json.dumps(dict(path=str(p),accessible=accessible,filesystem_writable=writable)))
sys.exit(0 if writable else 43)
'''
    command = ['ssh', '-o', 'BatchMode=yes', '-o', 'ConnectTimeout=10', core.UPLOAD_HOST,
               'python3 -B -c ' + shlex.quote(code) + ' ' + shlex.quote(str(config.remote_root))]
    result = core.run_command(command, timeout=20)
    if result.returncode == 43:
        raise PrestartInfrastructureBlocker('REMOTE_PATH_UNAVAILABLE', result.stdout.strip(), command=command)
    if result.returncode:
        raise RemoteCommandFailure('REMOTE_COMMAND_FAILURE: remote path probe: '+result.stderr[-2000:])
    evidence = json.loads(result.stdout)
    if evidence['path'] != str(config.remote_root):
        raise RuntimeError('CAMPAIGN_ROOT_IDENTITY_INVARIANT_FAILURE: remote path response')
    if not evidence['accessible'] or not evidence['filesystem_writable']:
        raise PrestartInfrastructureBlocker('REMOTE_PATH_UNAVAILABLE', str(evidence), command=command)
    return evidence


def historical_stop_reclassified(config):
    if not config.historical_prestart_stop.exists():
        return True
    original = json.loads(config.historical_prestart_stop.read_text())
    if not config.prestart_reclassification.exists():
        return False
    review = json.loads(config.prestart_reclassification.read_text())
    return (
        review.get('original_record') == original
        and review.get('SAME_V3_PREFLIGHT_RETRY_AUTHORIZED') is True
        and review.get('RECLASSIFIED_STATE') == 'PRESTART_INFRASTRUCTURE_BLOCKER'
        and review.get('CAMPAIGN_SAMPLE_STATE_CONSUMED') == 'NO'
        and original.get('browser_started') is False
        and original.get('capture_started') is False
        and original.get('campaign_id') == config.campaign_id
        and ssh_failure_class(255, original.get('reason', '')) == review.get('BLOCKER_CLASS')
    )


def failure_record(exc, config, *, time):
    consumed = campaign_state_consumed(config)
    infrastructure = isinstance(exc, PrestartInfrastructureBlocker) and not consumed
    sample = isinstance(exc, SamplePolicyHardStop)
    category = ('PRESTART_INFRASTRUCTURE_BLOCKER' if infrastructure else
                'SAMPLE_POLICY_HARD_STOP' if sample else 'IMPLEMENTATION_FAILURE')
    return {
        'status': category if infrastructure else 'R10_STRESS_V3_' + category,
        'terminal_category': category,
        'failure_class': getattr(exc, 'result', {}).get('failure_class'),
        'sample_id': getattr(exc, 'sample_id', None),
        'attempt': getattr(exc, 'attempt', None),
        'CAMPAIGN_STARTED': consumed, 'CAMPAIGN_INVALID': category == 'IMPLEMENTATION_FAILURE',
        'PRESTART_BLOCKED': infrastructure, 'BLOCKER_CLASS': exc.blocker_class if infrastructure else None,
        'CAMPAIGN_SAMPLE_STATE_CONSUMED': 'YES' if consumed else 'NO',
        'campaign_id': config.campaign_id, 'exception': type(exc).__name__,
        'reason': str(exc), 'time': time,
    }
