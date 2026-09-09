"""Terminal reporting only; retry eligibility remains the frozen policy's decision."""
import re


class HardStop(RuntimeError):
    """A campaign condition requiring human review."""


class SamplePolicyHardStop(HardStop):
    def __init__(self, message, *, result, attempt, sample_id):
        self.result = dict(result)
        self.attempt = attempt
        self.sample_id = sample_id
        super().__init__(message)


class SampleImplementationFailure(HardStop):
    def __init__(self, message, *, result):
        self.result = dict(result)
        super().__init__(message)


# Explicit frozen classifier outcomes, not exception-message guesses. No retry
# authorization is performed here. The caller has already made that decision.
SAMPLE_CLASSES = frozenset({
    'MAIN_NAVIGATION_TIMEOUT', 'CONNECTION_CLOSED', 'ERR_EMPTY_RESPONSE',
    'DNS_NAVIGATION_FAILURE', 'TCP_NAVIGATION_FAILURE', 'TLS_NAVIGATION_FAILURE',
    'EXECUTION_CONTEXT_DESTROYED_DUE_TO_NAVIGATION', 'PLAYWRIGHT_DRIVER_CONNECTION_CLOSED',
    'EVALUATE_TIMEOUT', 'ACTION_TIMEOUT', 'RENDERER_HANG', 'SUPERVISOR_TIMEOUT',
    'UNBOUNDED_LIFECYCLE', 'MODE_PURITY_FAIL', 'PROXY_BYPASS',
    'CAPTURE_FINALIZATION_FAIL', 'REDSOCKS_CAPACITY_PRECHECK_FAIL',
    'REDSOCKS_CONN_MAX_HIT', 'INFRASTRUCTURE_HEALTH_LOST', 'OOM',
    'UNEXPECTED_PROCESS_EXIT', 'WORKLOAD_HARD_FAILURE', 'EXECUTOR_INITIALIZATION_FAILURE',
})


def sample_terminal_exception(attempt, sample_id, result, *, exhausted):
    failure = str(result.get('failure_class') or '')
    detail = '\n'.join(str(result.get(k, '')) for k in (
        'failure_exception_type', 'failure_exception_text', 'failure_error'))
    implementation = (
        result.get('terminal_implementation_exception')
        or failure == 'SHA_FAIL'
        or re.search(r'\b(?:TypeError|ReferenceError|SyntaxError|NameError|AttributeError|KeyError|AssertionError)\b', detail)
    )
    known = failure in SAMPLE_CLASSES or re.fullmatch(r'HTTP_STATUS_[1-5][0-9]{2}', failure)
    message = (f'attempt{attempt} failure' if exhausted else f'non-retryable attempt{attempt}')
    message += f': {sample_id}: {failure}'
    if implementation or not known:
        return SampleImplementationFailure(message, result=result)
    return SamplePolicyHardStop(message, result=result, attempt=attempt, sample_id=sample_id)
