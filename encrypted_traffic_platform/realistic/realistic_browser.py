#!/usr/bin/env python3
"""Replay a pre-generated Realistic workload plan with a fresh Chromium profile."""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import shutil
import tempfile
import time
from pathlib import Path

from playwright.sync_api import sync_playwright


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


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
    failures = []
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
            pages = list(context.pages)
            while len(pages) < plan["tab_count"]:
                pages.append(context.new_page())

            for event in plan["events"]:
                page = pages[event["tab_index"]]
                page.bring_to_front()
                page.wait_for_timeout(event["pre_navigation_idle_ms"])
                status = "ok"
                error = ""
                event_started = time.time()
                try:
                    response = page.goto(
                        event["url"],
                        wait_until="domcontentloaded",
                        timeout=event["navigation_timeout_ms"],
                    )
                    http_status = response.status if response else 0
                    page.wait_for_timeout(event["post_navigation_idle_ms"])
                    for scroll in event["scrolls"]:
                        page.mouse.wheel(0, scroll["distance_px"])
                        page.wait_for_timeout(scroll["idle_ms"])
                except Exception as exc:  # recorded for the quality gate
                    status = "error"
                    http_status = 0
                    error = f"{type(exc).__name__}: {exc}"[:500]
                    failures.append({"event_index": event["event_index"], "error": error})
                rows.append({
                    "event_index": event["event_index"],
                    "tab_index": event["tab_index"],
                    "url": event["url"],
                    "status": status,
                    "http_status": http_status,
                    "elapsed_ms": int((time.time() - event_started) * 1000),
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
        "disable_quic": "--disable-quic" in plan["browser_args"],
        "fresh_profile": True,
        "service_workers_blocked": True,
        "event_count": len(rows),
        "success_count": sum(row["status"] == "ok" for row in rows),
        "failure_count": len(failures),
        "failures": failures,
        "elapsed_ms": int((time.time() - started) * 1000),
    }
    (args.output_dir / "workload_report.json").write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n"
    )
    print(json.dumps(report, sort_keys=True))
    return 0 if not failures else 1


if __name__ == "__main__":
    raise SystemExit(main())
