#!/usr/bin/env python3
"""Audit repeated main-navigation stability without changing collection semantics."""

from __future__ import annotations

import argparse
import csv
import json
import os
import tempfile
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path

from playwright.sync_api import sync_playwright

MAIN_TIMEOUT_MS = 30_000
DCL_OBSERVATION_MS = 10_000
ACCEPTABLE_MIN = 200
ACCEPTABLE_MAX = 399
ATTEMPTS = 4


def truth(value: str) -> bool:
    return value.strip().lower() in {"true", "1", "yes"}


def audit_domain(row: dict[str, str], browser_args: list[str], interval: float) -> dict[str, str]:
    statuses: list[int] = []
    commits: list[bool] = []
    latencies: list[int] = []
    warnings: list[int] = []
    errors: list[str] = []
    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(headless=True, args=browser_args)
        try:
            for index in range(ATTEMPTS):
                context = browser.new_context(
                    service_workers="block", viewport={"width": 1365, "height": 768}
                )
                page = context.new_page()
                request_failures = []
                page.on("requestfailed", lambda request: request_failures.append(request.url))
                started = time.monotonic()
                status = 0
                committed = False
                error = ""
                dcl_warning = 0
                try:
                    response = page.goto(
                        f"https://{row['domain']}/", wait_until="commit", timeout=MAIN_TIMEOUT_MS
                    )
                    if response is None:
                        raise RuntimeError("main response missing after navigation commit")
                    status = response.status
                    committed = True
                    if not (ACCEPTABLE_MIN <= status <= ACCEPTABLE_MAX):
                        raise RuntimeError(f"unacceptable main HTTP status: {status}")
                    try:
                        page.wait_for_load_state("domcontentloaded", timeout=DCL_OBSERVATION_MS)
                    except Exception:
                        dcl_warning = 1
                except Exception as exc:
                    error = f"{type(exc).__name__}: {exc}"
                finally:
                    latency = int((time.monotonic() - started) * 1000)
                    context.close()
                statuses.append(status)
                commits.append(committed)
                latencies.append(latency)
                warnings.append(dcl_warning + len(request_failures))
                errors.append(error)
                if index + 1 < ATTEMPTS:
                    time.sleep(interval)
        finally:
            browser.close()
    hard_failures = sum(
        not committed or not (ACCEPTABLE_MIN <= status <= ACCEPTABLE_MAX)
        for committed, status in zip(commits, statuses)
    )
    result = dict(row)
    for index in range(ATTEMPTS):
        number = index + 1
        result[f"attempt{number}_status"] = str(statuses[index])
        result[f"attempt{number}_commit_success"] = str(commits[index]).lower()
        result[f"attempt{number}_commit_latency_ms"] = str(latencies[index])
        result[f"attempt{number}_warning_count"] = str(warnings[index])
        result[f"attempt{number}_error"] = errors[index]
    result["rate_limit_429_count"] = str(sum(status == 429 for status in statuses))
    result["hard_failure_count"] = str(hard_failures)
    result["warning_count"] = str(sum(warnings))
    result["replay_stable"] = str(hard_failures == 0 and 429 not in statuses).lower()
    result["audit_timestamp"] = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    return result


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--browser-args-plan", type=Path, required=True)
    parser.add_argument("--workers", type=int, default=8)
    parser.add_argument("--interval-seconds", type=float, default=5.0)
    args = parser.parse_args()
    with args.input.open(newline="") as handle:
        reader = csv.DictReader(handle, delimiter="\t")
        required = {"rank", "domain", "rank_bucket"}
        if not required.issubset(reader.fieldnames or []):
            raise SystemExit(f"missing required columns; actual={reader.fieldnames}")
        rows = list(reader)
    if not rows or len({row["domain"] for row in rows}) != len(rows):
        raise SystemExit("empty input or duplicate domain")
    browser_args = json.loads(args.browser_args_plan.read_text())["browser_args"]
    fields = list(rows[0])
    for index in range(1, ATTEMPTS + 1):
        fields += [
            f"attempt{index}_status", f"attempt{index}_commit_success",
            f"attempt{index}_commit_latency_ms", f"attempt{index}_warning_count",
            f"attempt{index}_error",
        ]
    fields += ["rate_limit_429_count", "hard_failure_count", "warning_count", "replay_stable", "audit_timestamp"]
    results = []
    with ThreadPoolExecutor(max_workers=args.workers) as executor:
        futures = {executor.submit(audit_domain, row, browser_args, args.interval_seconds): row for row in rows}
        for completed, future in enumerate(as_completed(futures), 1):
            results.append(future.result())
            print(f"REPLAY_PROGRESS completed={completed} total={len(rows)}", flush=True)
    results.sort(key=lambda row: int(row["rank"]))
    args.output.parent.mkdir(parents=True, exist_ok=True)
    temporary = args.output.with_suffix(args.output.suffix + ".tmp")
    with temporary.open("w", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields, delimiter="\t", lineterminator="\n")
        writer.writeheader()
        writer.writerows(results)
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(temporary, args.output)
    stable = sum(truth(row["replay_stable"]) for row in results)
    rate_limited = sum(int(row["rate_limit_429_count"]) > 0 for row in results)
    print(f"TOTAL_AUDITED={len(results)} REPLAY_STABLE_COUNT={stable} REPLAY_UNSTABLE_COUNT={len(results)-stable} HTTP_429_DOMAIN_COUNT={rate_limited}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
