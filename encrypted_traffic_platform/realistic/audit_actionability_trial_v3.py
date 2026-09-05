#!/usr/bin/env python3
"""Run one non-Formal v3 actionability replay in one browser lifecycle."""

from __future__ import annotations

import argparse
import asyncio
import importlib.metadata
import json
import os
import shutil
import tempfile
import time
from pathlib import Path

from playwright.async_api import async_playwright


def atomic_json(path: Path, value: dict) -> None:
    temporary = path.with_suffix(path.suffix + ".tmp")
    with temporary.open("w") as handle:
        json.dump(value, handle, indent=2, sort_keys=True)
        handle.write("\n")
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(temporary, path)


async def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--rank", type=int, required=True)
    parser.add_argument("--domain", required=True)
    parser.add_argument("--bucket", required=True)
    parser.add_argument("--replay", type=int, choices=(1, 2, 3), required=True)
    parser.add_argument("--delay", type=float, required=True)
    parser.add_argument("--result", type=Path, required=True)
    args = parser.parse_args()
    started = time.monotonic()
    result = {
        "rank": args.rank, "domain": args.domain, "bucket": args.bucket,
        "replay": args.replay, "post_commit_delay_seconds": args.delay,
        "navigation_status": "FAIL", "main_http_status": 0,
        "evaluate_status": "NOT_RUN", "action_status": "NOT_RUN",
        "http429": 0, "renderer_unresponsive": 0,
        "ready_state": "", "final_url": "", "error": "",
        "playwright_version": importlib.metadata.version("playwright"),
    }
    playwright = None
    context = None
    profile = tempfile.mkdtemp(prefix="non-formal-v3-actionability-")
    exit_code = 1
    try:
        playwright = await async_playwright().start()
        context = await playwright.chromium.launch_persistent_context(
            profile, headless=True,
            args=["--disable-quic", "--disable-background-networking"],
            service_workers="block", viewport={"width": 1365, "height": 768},
        )
        result["chromium_version"] = context.browser.version if context.browser else "unknown"
        page = context.pages[0]
        nav_started = time.monotonic()
        response = await page.goto(
            f"https://{args.domain}/", wait_until="commit", timeout=30_000
        )
        result["navigation_duration_seconds"] = round(time.monotonic() - nav_started, 6)
        if response is None:
            raise RuntimeError("main response missing after navigation commit")
        result["main_http_status"] = response.status
        result["final_url"] = response.url
        result["http429"] = int(response.status == 429)
        if not 200 <= response.status <= 399 or response.status == 429:
            raise RuntimeError(f"unacceptable main HTTP status: {response.status}")
        result["navigation_status"] = "PASS"
        await asyncio.sleep(args.delay)
        probe_started = time.monotonic()
        try:
            probe = await asyncio.wait_for(
                page.evaluate("() => ({readyState: document.readyState, href: location.href})"),
                timeout=2,
            )
            result["evaluate_status"] = "PASS"
            result["evaluate_duration_seconds"] = round(time.monotonic() - probe_started, 6)
            result["ready_state"] = str(probe.get("readyState", ""))
            result["final_url"] = str(probe.get("href", result["final_url"]))
        except asyncio.TimeoutError:
            result["evaluate_status"] = "TIMEOUT"
            result["evaluate_duration_seconds"] = round(time.monotonic() - probe_started, 6)
            result["renderer_unresponsive"] = 1
            raise RuntimeError("PLAYWRIGHT_EVALUATE_TIMEOUT")
        action_started = time.monotonic()
        try:
            action = await asyncio.wait_for(
                page.evaluate("""() => {
                  const beforeY = window.scrollY;
                  window.scrollBy({top: 960, left: 0, behavior: "instant"});
                  return {beforeY, afterY: window.scrollY};
                }"""), timeout=5,
            )
            result["action_status"] = "PASS"
            result["action_duration_seconds"] = round(time.monotonic() - action_started, 6)
            result["scroll_before"] = action["beforeY"]
            result["scroll_after"] = action["afterY"]
            result["scroll_delta"] = action["afterY"] - action["beforeY"]
            exit_code = 0
        except asyncio.TimeoutError:
            result["action_status"] = "TIMEOUT"
            result["action_duration_seconds"] = round(time.monotonic() - action_started, 6)
            result["renderer_unresponsive"] = 1
            raise RuntimeError("PROGRAMMATIC_SCROLL_TIMEOUT")
    except BaseException as exc:
        result["error"] = f"{type(exc).__name__}: {exc}"[:1000]
    finally:
        if context is not None:
            try:
                await asyncio.wait_for(context.close(), timeout=15)
                result["context_cleanup"] = "PASS"
            except BaseException as exc:
                result["context_cleanup"] = "TIMEOUT_OR_ERROR"
                result["error"] += f"; context.close: {type(exc).__name__}: {exc}"
                exit_code = 1
        if playwright is not None:
            try:
                await asyncio.wait_for(playwright.stop(), timeout=15)
                result["playwright_cleanup"] = "PASS"
            except BaseException as exc:
                result["playwright_cleanup"] = "TIMEOUT_OR_ERROR"
                result["error"] += f"; playwright.stop: {type(exc).__name__}: {exc}"
                exit_code = 1
        shutil.rmtree(profile, ignore_errors=True)
        result["executor_duration_seconds"] = round(time.monotonic() - started, 6)
        result["exit_code"] = exit_code
        atomic_json(args.result, result)
    return exit_code


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
