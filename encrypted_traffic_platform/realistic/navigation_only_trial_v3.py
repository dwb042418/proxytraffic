#!/usr/bin/env python3
"""Run one bounded non-Formal navigation-only browser lifecycle."""

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


def atomic_json(path: Path, value: dict[str, object]) -> None:
    temporary = path.with_suffix(path.suffix + ".tmp")
    with temporary.open("w", encoding="utf-8") as handle:
        json.dump(value, handle, indent=2, sort_keys=True)
        handle.write("\n")
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(temporary, path)


async def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--domain", required=True)
    parser.add_argument("--mode", choices=("direct", "vless", "shadowsocks", "trojan"), required=True)
    parser.add_argument("--trial", type=int, choices=(1, 2), required=True)
    parser.add_argument("--result", type=Path, required=True)
    args = parser.parse_args()
    result: dict[str, object] = {
        "classification": "NON_FORMAL_DIAGNOSTIC",
        "domain": args.domain,
        "mode": args.mode,
        "trial": args.trial,
        "main_navigation": "FAIL",
        "http_status": 0,
        "failure_class": "",
        "navigation_duration_ms": 0,
        "error": "",
        "playwright_version": importlib.metadata.version("playwright"),
        "main_navigation_timeout_ms": 30000,
        "browser_args": ["--disable-quic", "--disable-background-networking"],
    }
    profile = tempfile.mkdtemp(prefix="non-formal-v3-navigation-only-")
    playwright = None
    context = None
    exit_code = 1
    try:
        playwright = await async_playwright().start()
        context = await playwright.chromium.launch_persistent_context(
            profile,
            headless=True,
            args=result["browser_args"],
            service_workers="block",
            viewport={"width": 1365, "height": 768},
        )
        result["chromium_version"] = context.browser.version if context.browser else "unknown"
        page = context.pages[0]
        started = time.monotonic()
        try:
            response = await page.goto(
                f"https://{args.domain}/", wait_until="commit", timeout=30_000
            )
            result["navigation_duration_ms"] = round((time.monotonic() - started) * 1000)
            if response is None:
                raise RuntimeError("main response missing after navigation commit")
            result["http_status"] = response.status
            result["final_url"] = response.url
            if not 200 <= response.status <= 399 or response.status == 429:
                raise RuntimeError(f"unacceptable main HTTP status: {response.status}")
            result["main_navigation"] = "PASS"
            result["failure_class"] = "PASS"
            exit_code = 0
        except BaseException as exc:
            result["navigation_duration_ms"] = round((time.monotonic() - started) * 1000)
            text = f"{type(exc).__name__}: {exc}"
            lowered = text.lower()
            if "timeout 30000ms exceeded" in lowered:
                failure_class = "MAIN_NAVIGATION_TIMEOUT"
            elif "err_connection_closed" in lowered or "connection closed" in lowered:
                failure_class = "CONNECTION_CLOSED"
            elif "err_name_not_resolved" in lowered:
                failure_class = "DNS_NAVIGATION_FAILURE"
            elif any(token in lowered for token in ("err_cert_", "err_ssl_", "tls")):
                failure_class = "TLS_NAVIGATION_FAILURE"
            elif "unacceptable main http status:" in lowered:
                failure_class = f"HTTP_STATUS_{result['http_status']}"
            else:
                failure_class = "MAIN_NAVIGATION_FAILURE"
            result["failure_class"] = failure_class
            result["error"] = text[:1000]
    finally:
        if context is not None:
            try:
                await asyncio.wait_for(context.close(), timeout=15)
                result["context_cleanup"] = "PASS"
            except BaseException as exc:
                result["context_cleanup"] = "FAIL"
                result["error"] = (str(result["error"]) + f"; context.close: {exc}")[:1000]
                exit_code = 1
        if playwright is not None:
            try:
                await asyncio.wait_for(playwright.stop(), timeout=15)
                result["playwright_cleanup"] = "PASS"
            except BaseException as exc:
                result["playwright_cleanup"] = "FAIL"
                result["error"] = (str(result["error"]) + f"; playwright.stop: {exc}")[:1000]
                exit_code = 1
        shutil.rmtree(profile, ignore_errors=True)
        result["exit_code"] = exit_code
        args.result.parent.mkdir(parents=True, exist_ok=True)
        atomic_json(args.result, result)
    return exit_code


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
