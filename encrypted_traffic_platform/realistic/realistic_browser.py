#!/usr/bin/env python3
"""Replay a pre-generated Realistic workload plan with a fresh Chromium profile."""

from __future__ import annotations

import argparse
import csv
import hashlib
import importlib.metadata
import json
import shutil
import tempfile
import time
from pathlib import Path
from urllib.parse import urlsplit

from playwright.sync_api import sync_playwright


MAIN_NAVIGATION_TIMEOUT_MS = 30000
DOMCONTENTLOADED_OBSERVATION_MS = 10000
ACCEPTABLE_MAIN_STATUS_MIN = 200
ACCEPTABLE_MAIN_STATUS_MAX = 399


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def classify_resource(resource_type: str, domain: str) -> str:
    if any(token in domain for token in ("analytics", "doubleclick", "googletagmanager")):
        return "analytics"
    if resource_type in {"script", "stylesheet", "image", "font"}:
        return resource_type
    return "other"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--plan", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--mode", choices=("direct", "vless", "shadowsocks", "trojan"), required=True)
    args = parser.parse_args()

    plan = json.loads(args.plan.read_text())
    if plan.get("schema_version") != 1 or not plan.get("events"):
        raise SystemExit("unsupported or empty workload plan")
    args.output_dir.mkdir(parents=True, exist_ok=False)
    plan_copy = args.output_dir / "workload_plan.json"
    shutil.copyfile(args.plan, plan_copy)
    plan_hash = sha256(plan_copy)
    rows = []
    hard_failures = []
    subresource_failures = []
    started = time.time()

    with tempfile.TemporaryDirectory(prefix="realistic-browser-profile-") as profile_dir:
        with sync_playwright() as playwright:
            context = playwright.chromium.launch_persistent_context(
                profile_dir,
                headless=True,
                args=plan["browser_args"],
                service_workers="block",
                viewport={"width": 1365, "height": 768},
            )
            browser_version = context.browser.version if context.browser else "unknown"
            request_failures = []

            def record_request_failure(request) -> None:
                failure = request.failure or "unknown"
                domain = urlsplit(request.url).hostname or ""
                request_failures.append({
                    "request_failed": True,
                    "resource_type": classify_resource(request.resource_type, domain),
                    "browser_resource_type": request.resource_type or "other",
                    "url": request.url,
                    "domain": domain,
                    "failure_reason": failure,
                })

            context.on("requestfailed", record_request_failure)
            pages = list(context.pages)
            while len(pages) < plan["tab_count"]:
                pages.append(context.new_page())

            for event in plan["events"]:
                page = pages[event["tab_index"]]
                page.bring_to_front()
                page.wait_for_timeout(event["pre_navigation_idle_ms"])
                event_started = time.monotonic()
                failure_start = len(request_failures)
                main_commit_success = False
                main_http_status = 0
                main_commit_latency_ms = 0
                domcontentloaded = False
                domcontentloaded_timeout = False
                domcontentloaded_latency_ms = 0
                navigation_hard_failure = False
                navigation_warning = ""
                error = ""
                try:
                    response = page.goto(
                        event["url"],
                        wait_until="commit",
                        timeout=MAIN_NAVIGATION_TIMEOUT_MS,
                    )
                    main_commit_latency_ms = int((time.monotonic() - event_started) * 1000)
                    if response is None:
                        raise RuntimeError("main response missing after navigation commit")
                    main_http_status = response.status
                    if not (ACCEPTABLE_MAIN_STATUS_MIN <= main_http_status <= ACCEPTABLE_MAIN_STATUS_MAX):
                        raise RuntimeError(f"unacceptable main HTTP status: {main_http_status}")
                    main_commit_success = True

                    observation_started = time.monotonic()
                    try:
                        page.wait_for_load_state(
                            "domcontentloaded",
                            timeout=DOMCONTENTLOADED_OBSERVATION_MS,
                        )
                        domcontentloaded = True
                        domcontentloaded_latency_ms = int(
                            (time.monotonic() - event_started) * 1000
                        )
                    except Exception as exc:
                        if type(exc).__name__ != "TimeoutError":
                            raise
                        domcontentloaded_timeout = True
                        navigation_warning = "domcontentloaded_timeout"
                    observation_elapsed_ms = int(
                        (time.monotonic() - observation_started) * 1000
                    )
                    if observation_elapsed_ms < DOMCONTENTLOADED_OBSERVATION_MS:
                        page.wait_for_timeout(
                            DOMCONTENTLOADED_OBSERVATION_MS - observation_elapsed_ms
                        )
                except Exception as exc:  # recorded for the quality gate
                    navigation_hard_failure = True
                    error = f"{type(exc).__name__}: {exc}"[:500]
                    hard_failures.append({
                        "event_index": event["event_index"],
                        "url": event["url"],
                        "error": error,
                    })

                if main_commit_success:
                    page.wait_for_timeout(event["post_navigation_idle_ms"])
                    for scroll in event["scrolls"]:
                        page.mouse.wheel(0, scroll["distance_px"])
                        page.wait_for_timeout(scroll["idle_ms"])

                event_subresource_failures = [
                    item for item in request_failures[failure_start:]
                    if item["browser_resource_type"] != "document"
                ]
                subresource_failures.extend(event_subresource_failures)
                if event_subresource_failures and not navigation_warning:
                    navigation_warning = "subresource_request_failed"
                rows.append({
                    "event_index": event["event_index"],
                    "tab_index": event["tab_index"],
                    "url": event["url"],
                    "main_commit_success": main_commit_success,
                    "main_http_status": main_http_status,
                    "main_commit_latency_ms": main_commit_latency_ms,
                    "domcontentloaded": domcontentloaded,
                    "domcontentloaded_timeout": domcontentloaded_timeout,
                    "domcontentloaded_latency_ms": domcontentloaded_latency_ms,
                    "subresource_failed_count": len(event_subresource_failures),
                    "navigation_hard_failure": navigation_hard_failure,
                    "navigation_warning": navigation_warning,
                    "elapsed_ms": int((time.monotonic() - event_started) * 1000),
                    "error": error,
                })
            context.close()

    with (args.output_dir / "workload_events.tsv").open("w", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=rows[0].keys(), delimiter="\t")
        writer.writeheader()
        writer.writerows(rows)
    report = {
        "schema_version": 1,
        "mode": args.mode,
        "seed": plan["seed"],
        "intensity": plan["intensity"],
        "workload_plan_sha256": plan_hash,
        "browser": "chromium",
        "browser_version": browser_version,
        "playwright_version": importlib.metadata.version("playwright"),
        "disable_quic": "--disable-quic" in plan["browser_args"],
        "fresh_profile": True,
        "service_workers_blocked": True,
        "event_count": len(rows),
        "success_count": sum(not row["navigation_hard_failure"] for row in rows),
        "failure_count": len(hard_failures),
        "hard_failure_count": len(hard_failures),
        "warning_count": sum(bool(row["navigation_warning"]) for row in rows),
        "domcontentloaded_timeout_count": sum(
            row["domcontentloaded_timeout"] for row in rows
        ),
        "subresource_failure_count": len(subresource_failures),
        "failures": hard_failures,
        "hard_failures": hard_failures,
        "subresource_failures": subresource_failures,
        "elapsed_ms": int((time.time() - started) * 1000),
    }
    (args.output_dir / "workload_report.json").write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n"
    )
    print(json.dumps(report, sort_keys=True))
    return 0 if not hard_failures else 1


if __name__ == "__main__":
    raise SystemExit(main())
