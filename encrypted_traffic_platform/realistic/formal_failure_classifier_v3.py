#!/usr/bin/env python3
"""FORMAL_V3_FAILURE_CLASSIFIER_V3: executor primary attribution and traffic evaluability."""
from __future__ import annotations
import re
from pathlib import Path
import formal_failure_classifier_v2 as v2

EXECUTION_CONTEXT_DESTROYED = v2.EXECUTION_CONTEXT_DESTROYED
DRIVER_CONNECTION_CLOSED = 'PLAYWRIGHT_DRIVER_CONNECTION_CLOSED'
read_phase_rows = v2.read_phase_rows

def workload_started(workload, phase_rows):
    phases = [str(row.get('phase', '')) for row in phase_rows]
    if any(re.fullmatch(r'EVENT_\d+_START', p) or p == 'NAV_START' or p.startswith('SCROLL_') for p in phases):
        return True
    if workload:
        return True
    if 'EXECUTOR_START' in phases and 'EXECUTOR_EXIT' in phases:
        return False
    return None

def classify_browser_failure(workload, phase_rows, stderr_text=''):
    result = v2.classify_browser_failure(workload, phase_rows, stderr_text)
    phases = {row.get('phase') for row in phase_rows}
    if workload_started(workload, phase_rows) is False:
        result['failure_stage'] = 'EXECUTOR_INITIALIZATION'
        text = str(result['failure_error']) + '\n' + stderr_text
        if ('Connection closed while reading from the driver' in text
                and 'await async_playwright().start()' in stderr_text
                and 'BROWSER_START' in phases and 'BROWSER_READY' not in phases):
            result['failure_class'] = DRIVER_CONNECTION_CLOSED
        else:
            # A generic executor crash never inherits navigation CONNECTION_CLOSED eligibility.
            result['failure_class'] = 'EXECUTOR_INITIALIZATION_FAILURE'
    elif result['failure_class'] == 'WORKLOAD_HARD_FAILURE' and 'ERR_EMPTY_RESPONSE' in str(result['failure_error']):
        result['failure_class'] = 'ERR_EMPTY_RESPONSE'
    result['workload_started'] = workload_started(workload, phase_rows)
    return result

def evaluate_mode_purity(mode, packet_counts, tunnel_counts, public_443, original_tunnel_count,
                         *, workload_started=None):
    old = v2.evaluate_mode_purity(mode, packet_counts, tunnel_counts, public_443, original_tunnel_count)
    violations = [issue for issue in old['issues'] if issue == 'original_contains_tunnel_port'
                  or issue == 'proxy_public_443_bypass' or issue.startswith('unexpected_tunnel_')]
    missing = [issue for issue in old['issues'] if issue not in violations]
    if violations:
        status, reason = 'FAIL', 'OBSERVED_MODE_PURITY_VIOLATION'
    elif workload_started is False or not any(packet_counts.values()):
        status = 'NOT_EVALUABLE'
        reason = ('NO_WORKLOAD_TRAFFIC_DUE_TO_EXECUTOR_STARTUP_FAILURE' if workload_started is False
                  else 'NO_EVALUABLE_TRAFFIC')
    elif missing:
        status, reason = 'NOT_EVALUABLE', 'REQUIRED_CAPTURE_TRAFFIC_NOT_ESTABLISHED'
    else:
        status, reason = 'PASS', 'EVALUABLE_TRAFFIC_WITHOUT_MODE_VIOLATION'
    return {**old, 'schema_version': 3, 'status': status, 'issues': violations,
            'traffic_completeness_issues': missing, 'evaluation_reason': reason,
            'workload_started': workload_started}

def audit_mode_purity(sample_dir: Path, mode, tshark_count, *, workload=None, phase_rows=None):
    raw = v2.audit_mode_purity(sample_dir, mode, tshark_count)
    return evaluate_mode_purity(mode, raw['packet_counts'], raw['observed_tunnel_syn_counts'],
        raw['observed_direct_public_443_syn_count'], raw['original_tunnel_packet_count'],
        workload_started=workload_started(workload, phase_rows or []))

def resolve_attempt_failure(**kwargs):
    init = workload_started(kwargs['workload'], kwargs['phase_rows']) is False and kwargs['executor_rc'] != 0
    # Infrastructure, capture integrity and bounded lifecycle remain fail closed.
    protected = (kwargs['executor_local_timeout'] or kwargs['supervisor'].get('timed_out')
                 or kwargs['supervisor'].get('residual_count', 0) or kwargs['browser_residual']
                 or kwargs['conn_max_hits'] or kwargs['oom_count'] or kwargs['unexpected_exit']
                 or kwargs['infrastructure_lost'])
    if init and not protected:
        if kwargs['capture_status'] != 'PASS':
            result = v2.resolve_attempt_failure(**{**kwargs, 'mode_purity': {'status': 'PASS', 'issues': []}})
        elif not kwargs['plan_sha_matches']:
            result = {'failure_class': 'SHA_FAIL'}
        else:
            return classify_browser_failure(kwargs['workload'], kwargs['phase_rows'], kwargs.get('stderr_text', ''))
    else:
        result = v2.resolve_attempt_failure(**kwargs)
        if result['failure_class'] == 'PROXY_BYPASS':
            result['failure_class'] = 'MODE_PURITY_FAIL'
        if result['failure_class'] in {'WORKLOAD_HARD_FAILURE', 'CONNECTION_CLOSED'}:
            result = classify_browser_failure(kwargs['workload'], kwargs['phase_rows'], kwargs.get('stderr_text', ''))
    blank = {key: '' for key in ('failure_event_index', 'failure_url', 'failure_action_type',
             'failure_stage', 'failure_exception_type', 'failure_exception_text', 'failure_error')}
    return {**blank, **result, 'workload_started': workload_started(kwargs['workload'], kwargs['phase_rows'])}
