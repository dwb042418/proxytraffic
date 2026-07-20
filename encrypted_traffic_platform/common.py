"""Shared helpers for dataset generation commands."""

from __future__ import annotations

import json
import os
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping

try:
    import yaml
except ImportError:  # pragma: no cover - validated at runtime for CLI usage
    yaml = None


C2_LABELS = {"cobaltstrike", "behinder", "antsword", "godzilla"}
PROXY_LABELS = {"v2ray", "shadowsocks", "clash"}
BENIGN_LABELS = {"benign"}
VALID_LABELS = C2_LABELS | PROXY_LABELS | BENIGN_LABELS


class PlatformError(RuntimeError):
    """Base exception for platform command failures."""


class NotConfiguredError(PlatformError):
    """Raised when a generator backend is not configured."""


def project_root() -> Path:
    return Path(__file__).resolve().parent


def infer_category(label: str) -> str:
    normalized = label.lower()
    if normalized in C2_LABELS:
        return "c2"
    if normalized in PROXY_LABELS:
        return "proxy"
    if normalized in BENIGN_LABELS:
        return "benign"
    raise ValueError(f"Unsupported label: {label}")


def utc_now_iso() -> str:
    from datetime import datetime, timezone

    return datetime.now(timezone.utc).isoformat()


def load_config(path: str | os.PathLike[str] | None) -> dict[str, Any]:
    if path is None:
        path = project_root() / "config" / "lab.yaml"

    config_path = Path(path)
    if not config_path.exists():
        raise FileNotFoundError(f"Config file not found: {config_path}")

    if config_path.suffix.lower() == ".json":
        return json.loads(config_path.read_text(encoding="utf-8"))

    if yaml is None:
        raise PlatformError("pyyaml is required to read YAML config files")

    with config_path.open("r", encoding="utf-8") as handle:
        loaded = yaml.safe_load(handle) or {}
    return loaded


@dataclass(frozen=True)
class CommandResult:
    command: list[str]
    returncode: int
    stdout: str
    stderr: str


def run_command(
    command: list[str],
    *,
    timeout: int | None,
    cwd: str | None = None,
    env: Mapping[str, str] | None = None,
) -> CommandResult:
    if not command:
        raise NotConfiguredError("External generator command is empty")

    merged_env = os.environ.copy()
    if env:
        merged_env.update({str(key): str(value) for key, value in env.items()})

    completed = subprocess.run(
        command,
        cwd=cwd,
        env=merged_env,
        timeout=timeout,
        capture_output=True,
        text=True,
        check=False,
    )
    return CommandResult(
        command=command,
        returncode=completed.returncode,
        stdout=completed.stdout,
        stderr=completed.stderr,
    )
