#!/usr/bin/env python3
"""Shared Formal v3 failure classification and mode-purity logic, revision 2."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Callable


TUNNEL_PORTS = (21001, 21002, 21003)
EXPECTED_PORT = {"direct": None, "vless": 21001, "shadowsocks": 21002, "trojan": 21003}
EXECUTION_CONTEXT_DESTROYED = "EXECUTION_CONTEXT_DESTROYED_DUE_TO_NAVIGATION"


def read_phase_rows(path: Path) -> list[dict[str, object]]:
    if not path.is_file():
        return []
    return [
        json.loads(line)
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]


def _last_action(rows: list[dict[str, object]]) -> dict[str, object]:
    for row in reversed(rows):
        phase = str(row.get("phase", ""))
        if re.fullmatch(r"SCROLL_\d+_START", phase):
            return {
                "failure_stage": phase,
                "event_index": row.get("event_index", ""),
                "url": str(row.get("url", "")),
                "action_type": str(row.get("primitive", "DETERMINISTIC_BOUNDED_VIEWPORT_SCROLL")),
            }
        if phase == "NAV_START":
            return {
                "failure_stage": phase,
                "event_index": row.get("event_index", ""),
                "url": str(row.get("url", "")),
                "action_type": "MAIN_NAVIGATION",
            }
    return {"failure_stage": "", "event_index": "", "url": "", "action_type": ""}


def _exception(error: str, stderr_text: str) -> tuple[str, str]:
    exception_type = ""
    exception_text = error
    traceback_lines = [line.strip() for line in stderr_text.splitlines() if line.strip()]
    if traceback_lines and ": " in traceback_lines[-1]:
        candidate, text = traceback_lines[-1].split(": ", 1)
        if "." in candidate or candidate.endswith("Error") or candidate.endswith("Exception"):
            exception_type, exception_text = candidate, text
    if not exception_type and ": " in error:
        candidate, text = error.split(": ", 1)
        exception_type, exception_text = candidate, text
    return exception_type, exception_text


def classify_browser_failure(
    workload: dict[str, object] | None,
    phase_rows: list[dict[str, object]],
    stderr_text: str = "",
) -> dict[str, object]:
    context = _last_action(phase_rows)
    error = ""
    if workload:
        failures = workload.get("hard_failures") or workload.get("failures") or []
        if failures:
            failure = failures[0]
            context["event_index"] = failure.get("event_index", context["event_index"])
            context["url"] = str(failure.get("url", context["url"]))
            context["failure_stage"] = "NAVIGATION"
            context["action_type"] = "MAIN_NAVIGATION"
            error = str(failure.get("error", ""))
    if not error:
        exits = [row for row in phase_rows if row.get("phase") == "EXECUTOR_EXIT"]
        if exits:
            error = str(exits[-1].get("error", ""))

    lowered = error.lower()
    if (
        "page.evaluate" in lowered
        and "execution context was destroyed" in lowered
        and "navigation" in lowered
    ):
        failure_class = EXECUTION_CONTEXT_DESTROYED
    elif "unacceptable main http status: 403" in lowered:
        failure_class = "HTTP_STATUS_403"
    elif "unacceptable main http status: 429" in lowered:
        failure_class = "HTTP_STATUS_429"
    elif "programmatic_scroll_timeout" in lowered or "action_timeout" in lowered:
        failure_class = "ACTION_TIMEOUT"
    elif "evaluate" in lowered and "timeout" in lowered:
        failure_class = "EVALUATE_TIMEOUT"
    elif "renderer" in lowered and ("hang" in lowered or "unresponsive" in lowered):
        failure_class = "RENDERER_HANG"
    elif "err_connection_closed" in lowered or "connection closed" in lowered:
        failure_class = "CONNECTION_CLOSED"
    elif "err_name_not_resolved" in lowered or ("dns" in lowered and "navigation" in lowered):
        failure_class = "DNS_NAVIGATION_FAILURE"
    elif any(token in lowered for token in ("err_cert_", "err_ssl_", "tls handshake", "tls navigation")):
        failure_class = "TLS_NAVIGATION_FAILURE"
    elif any(token in lowered for token in (
        "err_connection_refused", "err_connection_reset", "err_connection_timed_out",
        "err_address_unreachable", "tcp navigation",
    )):
        failure_class = "TCP_NAVIGATION_FAILURE"
    elif "page.goto" in lowered and "timeout 30000ms exceeded" in lowered:
        failure_class = "MAIN_NAVIGATION_TIMEOUT"
    elif "unacceptable main http status:" in lowered:
        suffix = lowered.split("unacceptable main http status:", 1)[1].strip().split()[0]
        failure_class = f"HTTP_STATUS_{suffix}"
    elif "lifecycle_timeout" in lowered:
        failure_class = "UNBOUNDED_LIFECYCLE"
    else:
        failure_class = "WORKLOAD_HARD_FAILURE"

    exception_type, exception_text = _exception(error, stderr_text)
    return {
        "failure_class": failure_class,
        "failure_event_index": context["event_index"],
        "failure_url": context["url"],
        "failure_action_type": context["action_type"],
        "failure_stage": context["failure_stage"],
        "failure_exception_type": exception_type,
        "failure_exception_text": exception_text,
        "failure_error": error,
    }


def evaluate_mode_purity(
    mode: str,
    packet_counts: dict[str, int],
    tunnel_counts: dict[str, int],
    public_443: int,
    original_tunnel_count: int,
) -> dict[str, object]:
    issues: list[str] = []
    for name, count in packet_counts.items():
        if count <= 0:
            issues.append(f"{name}_pcap_empty")
    if original_tunnel_count:
        issues.append("original_contains_tunnel_port")
    expected = EXPECTED_PORT[mode]
    for port in TUNNEL_PORTS:
        count = tunnel_counts[str(port)]
        if port == expected and count <= 0:
            issues.append(f"expected_tunnel_{port}_missing")
        if port != expected and count:
            issues.append(f"unexpected_tunnel_{port}")
    if mode == "direct" and public_443 <= 0:
        issues.append("direct_public_443_missing")
    if mode != "direct" and public_443:
        issues.append("proxy_public_443_bypass")
    return {
        "schema_version": 2,
        "status": "PASS" if not issues else "FAIL",
        "mode": mode,
        "packet_counts": packet_counts,
        "observed_tunnel_syn_counts": tunnel_counts,
        "observed_direct_public_443_syn_count": public_443,
        "original_tunnel_packet_count": original_tunnel_count,
        "issues": issues,
    }


def audit_mode_purity(
    sample_dir: Path,
    mode: str,
    tshark_count: Callable[[Path, str | None], int],
) -> dict[str, object]:
    pcaps = {name: sample_dir / f"{name}.pcap" for name in ("original", "observed", "egress")}
    packet_counts = {name: tshark_count(path, None) for name, path in pcaps.items()}
    syn = "tcp.flags.syn==1 && tcp.flags.ack==0"
    tunnel_counts = {
        str(port): tshark_count(pcaps["observed"], f"{syn} && tcp.dstport=={port}")
        for port in TUNNEL_PORTS
    }
    original_tunnel_count = sum(
        tshark_count(pcaps["original"], f"tcp.port=={port}") for port in TUNNEL_PORTS
    )
    public_443 = tshark_count(
        pcaps["observed"], f"{syn} && tcp.dstport==443 && ip.dst!=192.168.220.20",
    )
    return evaluate_mode_purity(
        mode, packet_counts, tunnel_counts, public_443, original_tunnel_count,
    )


def resolve_attempt_failure(
    *,
    executor_local_timeout: bool,
    supervisor: dict[str, object],
    browser_residual: int,
    conn_max_hits: int,
    oom_count: int,
    unexpected_exit: int,
    infrastructure_lost: int,
    mode_purity: dict[str, object],
    capture_status: str,
    workload: dict[str, object] | None,
    executor_rc: int,
    plan_sha_matches: bool,
    expected_event_count: int,
    phase_rows: list[dict[str, object]],
    stderr_text: str = "",
) -> dict[str, object]:
    blank: dict[str, object] = {
        "failure_class": "", "failure_event_index": "", "failure_url": "",
        "failure_action_type": "", "failure_stage": "",
        "failure_exception_type": "", "failure_exception_text": "", "failure_error": "",
    }
    purity_status = str(mode_purity.get("status", "NOT_ESTABLISHED"))
    purity_issues = list(mode_purity.get("issues", []))
    if executor_local_timeout or supervisor.get("timed_out"):
        blank["failure_class"] = "SUPERVISOR_TIMEOUT"
    elif int(supervisor.get("residual_count", 0)) or browser_residual:
        blank["failure_class"] = "UNBOUNDED_LIFECYCLE"
    elif conn_max_hits:
        blank["failure_class"] = "REDSOCKS_CONN_MAX_HIT"
    elif oom_count:
        blank["failure_class"] = "OOM"
    elif unexpected_exit:
        blank["failure_class"] = "UNEXPECTED_PROCESS_EXIT"
    elif infrastructure_lost:
        blank["failure_class"] = "INFRASTRUCTURE_HEALTH_LOST"
    elif "proxy_public_443_bypass" in purity_issues:
        blank["failure_class"] = "PROXY_BYPASS"
    elif purity_status == "FAIL" and purity_issues:
        blank["failure_class"] = "MODE_PURITY_FAIL"
    elif purity_status != "PASS":
        blank["failure_class"] = "CAPTURE_FINALIZATION_FAIL"
    elif capture_status != "PASS":
        blank["failure_class"] = "CAPTURE_FINALIZATION_FAIL"
    elif workload and not plan_sha_matches:
        blank["failure_class"] = "SHA_FAIL"
    elif not workload or int(workload.get("hard_failure_count", 1)) != 0 or executor_rc != 0:
        return classify_browser_failure(workload, phase_rows, stderr_text)
    elif not (
        int(workload.get("success_count", 0))
        == int(workload.get("event_count", -1))
        == expected_event_count
    ):
        blank["failure_class"] = "WORKLOAD_HARD_FAILURE"
    return blank
