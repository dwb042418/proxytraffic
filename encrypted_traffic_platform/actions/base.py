"""Base action types used by scenario execution."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class ActionContext:
    sample_dir: Path | None
    pcap_path: Path | None
    duration: int
    dry_run: bool
    deadline: float
    env: dict[str, str]


@dataclass(frozen=True)
class ActionResult:
    name: str
    action_type: str
    status: str
    elapsed: float
    details: dict[str, Any]
