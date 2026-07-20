"""Built-in scenario actions."""

from __future__ import annotations

import socket
import time
from pathlib import Path
from typing import Any
from urllib.request import Request, urlopen

from encrypted_traffic_platform.actions.base import ActionContext, ActionResult
from encrypted_traffic_platform.common import NotConfiguredError, run_command


def execute_action(raw_action: Any, context: ActionContext) -> ActionResult:
    action = normalize_action(raw_action)
    action_type = action.get("type", "marker")
    name = str(action.get("name", action_type))
    started = time.time()
    details: dict[str, Any] = {"dry_run": context.dry_run}

    if context.dry_run:
        return ActionResult(name, action_type, "skipped", round(time.time() - started, 3), details)

    if action_type == "marker":
        status = "completed"
    elif action_type == "sleep":
        seconds = min(float(action.get("seconds", 1)), max(0, context.deadline - time.time()))
        time.sleep(max(0, seconds))
        details["seconds"] = seconds
        status = "completed"
    elif action_type == "command":
        command = list(action.get("command") or [])
        if not command:
            raise NotConfiguredError(f"Action '{name}' has no command")
        result = run_command(
            command,
            timeout=int(action.get("timeout", max(1, context.deadline - time.time()))),
            cwd=action.get("cwd"),
            env={**context.env, **dict(action.get("env") or {})},
        )
        details.update(
            {
                "command": command,
                "returncode": result.returncode,
                "stdout": result.stdout[-4000:],
                "stderr": result.stderr[-4000:],
            }
        )
        status = "completed" if result.returncode == 0 else "failed"
    elif action_type in {"http_request", "web_browse", "file_download", "cloud_access", "video_stream"}:
        details.update(_execute_http_action(action, context))
        status = "completed"
    elif action_type == "dns_query":
        details.update(_execute_dns_action(action))
        status = "completed"
    else:
        raise ValueError(f"Unsupported action type: {action_type}")

    return ActionResult(name, action_type, status, round(time.time() - started, 3), details)


def normalize_action(raw_action: Any) -> dict[str, Any]:
    if isinstance(raw_action, str):
        alias_map = {
            "sleep": {"type": "sleep", "name": "sleep", "seconds": 1},
            "browser": {"type": "web_browse", "name": "browser"},
            "download": {"type": "file_download", "name": "download"},
            "cloud": {"type": "cloud_access", "name": "cloud"},
            "streaming": {"type": "video_stream", "name": "streaming"},
            "dns": {"type": "dns_query", "name": "dns"},
        }
        return alias_map.get(raw_action, {"type": "marker", "name": raw_action})
    if isinstance(raw_action, dict):
        action = dict(raw_action)
        action.setdefault("type", "marker")
        action.setdefault("name", action["type"])
        return action
    raise TypeError(f"Unsupported scenario action: {raw_action!r}")


def _execute_http_action(action: dict[str, Any], context: ActionContext) -> dict[str, Any]:
    urls = action.get("urls") or action.get("url") or default_urls(action["type"])
    if isinstance(urls, str):
        urls = [urls]

    repeat = int(action.get("repeat", 1))
    timeout = int(action.get("timeout", 10))
    bytes_read = 0
    requests_made = 0
    failures: list[str] = []

    for index in range(max(1, repeat)):
        if time.time() >= context.deadline:
            break
        url = urls[index % len(urls)]
        request = Request(
            url,
            headers={
                "User-Agent": action.get("user_agent", "ETIP-Benign-Replay/0.2"),
                "Accept": "*/*",
            },
        )
        try:
            with urlopen(request, timeout=timeout) as response:
                payload = response.read(int(action.get("max_bytes", 1024 * 1024)))
            bytes_read += len(payload)
            requests_made += 1
        except Exception as exc:
            failures.append(str(exc))

    return {
        "urls": urls,
        "requests_made": requests_made,
        "bytes_read": bytes_read,
        "failures": failures,
    }


def _execute_dns_action(action: dict[str, Any]) -> dict[str, Any]:
    domains = action.get("domains") or action.get("domain") or ["example.com", "openai.com"]
    if isinstance(domains, str):
        domains = [domains]
    resolved: dict[str, list[str]] = {}
    failures: dict[str, str] = {}
    for domain in domains:
        try:
            resolved[domain] = sorted({item[4][0] for item in socket.getaddrinfo(domain, None)})
        except Exception as exc:
            failures[domain] = str(exc)
    return {"domains": domains, "resolved": resolved, "failures": failures}


def default_urls(action_type: str) -> list[str]:
    defaults = {
        "http_request": ["http://example.com"],
        "web_browse": ["http://example.com", "http://httpbin.org/get"],
        "file_download": ["http://httpbin.org/bytes/2048"],
        "cloud_access": ["http://httpbin.org/json", "http://httpbin.org/uuid"],
        "video_stream": ["http://httpbin.org/stream-bytes/8192"],
    }
    return defaults[action_type]
