"""Policy v5's explicit main-document 5xx extension to frozen v4 decisions."""

HTTP5XX_TRANSIENT_CLASSES = frozenset({
    'HTTP_STATUS_500', 'HTTP_STATUS_502', 'HTTP_STATUS_503', 'HTTP_STATUS_504',
})
MAX_ATTEMPTS_PER_SAMPLE = 3


def authorize_http5xx(result, attempt=None):
    """Return None for classes governed by the existing v4 classifier/policy."""
    failure_class = result.get('failure_class')
    if failure_class not in HTTP5XX_TRANSIENT_CLASSES:
        return None
    attempt = int(result.get('attempt', 1)) if attempt is None else attempt
    if not 1 <= attempt <= MAX_ATTEMPTS_PER_SAMPLE:
        return False, 'INVALID_ATTEMPT_NUMBER'
    if result.get('status') == 'PASS':
        return False, 'ATTEMPT_PASS'
    if attempt == MAX_ATTEMPTS_PER_SAMPLE:
        return False, 'MAX_ATTEMPTS_REACHED'
    capture = result.get('capture', {})
    mode = result.get('mode')
    gates = {
        'MAIN_DOCUMENT_NAVIGATION': result.get('failure_action_type') == 'MAIN_NAVIGATION'
            and result.get('failure_stage') in ('NAVIGATION', 'NAV_START')
            and result.get('workload_started') is True,
        'PRE_HEALTH': result.get('pre_health') == 'PASS',
        'POST_HEALTH': result.get('post_health') == 'PASS',
        'MODE_PURITY': result.get('mode_purity') == 'PASS' and not result.get('mode_purity_issues'),
        'CAPTURE': capture.get('status') == 'PASS',
        'CAPACITY': mode == 'direct' or (mode in ('vless', 'shadowsocks', 'trojan')
                                       and result.get('redsocks_actual_conn_max') == 256),
        'NO_BYPASS': not result.get('bypass_observed', False)
            and (mode == 'direct' or result.get('observed_direct_public_443_syn_count') == 0),
    }
    for key in ('redsocks_conn_max_hits', 'infrastructure_health_lost',
                'server_egress_degraded', 'trojan_public_path_degraded', 'residual'):
        gates[key] = result.get(key) == 0
    for key in ('oom', 'unexpected_process_exit'):
        gates[key] = capture.get(key) == 0
    failed = [key for key, value in gates.items() if not value]
    if failed:
        return False, 'RETRY_GATES_FAILED:' + ','.join(failed)
    return True, 'AUTHORIZED_TRANSIENT:' + failure_class


def extend_retry_authorized(previous):
    """Leave every non-selected status and existing transient decision intact."""
    def retry_authorized(result, attempt=None):
        decision = authorize_http5xx(result, attempt)
        return previous(result, attempt=attempt) if decision is None else decision
    return retry_authorized
