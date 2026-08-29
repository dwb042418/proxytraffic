#!/usr/bin/env python3
"""Apply single-navigation then four-attempt replay gates to reserve candidates."""

from __future__ import annotations

import argparse
import csv
import importlib.util
import json
import os
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path

from playwright.sync_api import sync_playwright

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("replay", HERE / "audit_replay_stability.py")
replay = importlib.util.module_from_spec(spec)
spec.loader.exec_module(replay)


def single_gate(row: dict[str, str], browser_args: list[str]) -> dict[str, str]:
    started = time.monotonic()
    status = 0
    committed = False
    warning_count = 0
    error = ""
    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(headless=True, args=browser_args)
        context = browser.new_context(service_workers="block", viewport={"width": 1365, "height": 768})
        page = context.new_page()
        failures = []
        page.on("requestfailed", lambda request: failures.append(request.url))
        try:
            response = page.goto(f"https://{row['domain']}/", wait_until="commit", timeout=replay.MAIN_TIMEOUT_MS)
            if response is None:
                raise RuntimeError("main response missing after navigation commit")
            status = response.status
            committed = True
            if not (replay.ACCEPTABLE_MIN <= status <= replay.ACCEPTABLE_MAX):
                raise RuntimeError(f"unacceptable main HTTP status: {status}")
            try:
                page.wait_for_load_state("domcontentloaded", timeout=replay.DCL_OBSERVATION_MS)
            except Exception:
                warning_count += 1
        except Exception as exc:
            error = f"{type(exc).__name__}: {exc}"
        finally:
            warning_count += len(failures)
            context.close()
            browser.close()
    passed = committed and replay.ACCEPTABLE_MIN <= status <= replay.ACCEPTABLE_MAX and status != 429
    return {
        "single_status": str(status), "single_commit_success": str(committed).lower(),
        "single_commit_latency_ms": str(int((time.monotonic() - started) * 1000)),
        "single_warning_count": str(warning_count), "single_error": error,
        "single_reachable": str(passed).lower(),
    }


def audit(row: dict[str, str], browser_args: list[str], interval: float) -> dict[str, str]:
    result = dict(row)
    single = single_gate(row, browser_args)
    result.update(single)
    if replay.truth(single["single_reachable"]):
        result.update(replay.audit_domain(row, browser_args, interval))
    else:
        for index in range(1, replay.ATTEMPTS + 1):
            result.update({
                f"attempt{index}_status": "0", f"attempt{index}_commit_success": "false",
                f"attempt{index}_commit_latency_ms": "0", f"attempt{index}_warning_count": "0",
                f"attempt{index}_error": "SKIPPED_SINGLE_GATE_FAILED",
            })
        result.update({
            "rate_limit_429_count": "0", "hard_failure_count": "4", "warning_count": "0",
            "replay_stable": "false", "audit_timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        })
    result["all_gates_pass"] = str(
        replay.truth(result["single_reachable"]) and replay.truth(result["replay_stable"])
    ).lower()
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
        if not {"rank", "domain", "rank_bucket"}.issubset(reader.fieldnames or []):
            raise SystemExit(f"missing required columns; actual={reader.fieldnames}")
        rows = list(reader)
    browser_args = json.loads(args.browser_args_plan.read_text())["browser_args"]
    results = []
    with ThreadPoolExecutor(max_workers=args.workers) as executor:
        futures = [executor.submit(audit, row, browser_args, args.interval_seconds) for row in rows]
        for completed, future in enumerate(as_completed(futures), 1):
            results.append(future.result())
            print(f"REPLACEMENT_PROGRESS completed={completed} total={len(rows)}", flush=True)
    results.sort(key=lambda row: int(row["rank"]))
    fields = list(results[0])
    args.output.parent.mkdir(parents=True, exist_ok=True)
    temporary = args.output.with_suffix(args.output.suffix + ".tmp")
    with temporary.open("w", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields, delimiter="\t", lineterminator="\n")
        writer.writeheader(); writer.writerows(results); handle.flush(); os.fsync(handle.fileno())
    os.replace(temporary, args.output)
    print(f"REPLACEMENT_AUDITED={len(results)} ALL_GATES_PASS={sum(replay.truth(r['all_gates_pass']) for r in results)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
