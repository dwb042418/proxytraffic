"""Scenario-driven workload execution for traffic generation."""

from __future__ import annotations

import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from encrypted_traffic_platform.actions import ActionContext, execute_action
from encrypted_traffic_platform.common import load_config


def load_scenario(path: str | Path | None) -> dict[str, Any]:
    if path is None:
        return {}
    return load_config(path)


@dataclass(frozen=True)
class ScenarioResult:
    status: str
    actions: list[dict[str, Any]]
    phases: list[dict[str, Any]]


class ScenarioRunner:
    """Run a declarative traffic-generation scenario.

    Supported action types:

    - `sleep`: wait for `seconds`
    - `command`: run an explicitly configured command list
    - `web_browse`, `file_download`, `cloud_access`, `video_stream`
    - `dns_query`

    Plain string actions are recorded as markers. This keeps C2 tooling as an
    external lab concern while preserving reproducible scenario metadata.
    """

    def __init__(
        self,
        scenario: dict[str, Any],
        *,
        duration: int,
        dry_run: bool,
        env: dict[str, str] | None = None,
        sample_dir: str | Path | None = None,
        pcap_path: str | Path | None = None,
    ):
        self.scenario = scenario
        self.duration = duration
        self.dry_run = dry_run
        self.env = env or {}
        self.sample_dir = Path(sample_dir) if sample_dir else None
        self.pcap_path = Path(pcap_path) if pcap_path else None

    def run(self) -> ScenarioResult:
        executed: list[dict[str, Any]] = []
        phases: list[dict[str, Any]] = []
        deadline = time.time() + max(0, self.duration)

        for phase_name, raw_actions in self._iter_phases():
            phase_entry = {"phase": phase_name, "status": "running", "actions": []}
            for raw_action in raw_actions:
                context = ActionContext(
                    sample_dir=self.sample_dir,
                    pcap_path=self.pcap_path,
                    duration=self.duration,
                    dry_run=self.dry_run,
                    deadline=deadline,
                    env={**dict(self.scenario.get("env") or {}), **self.env},
                )
                result = execute_action(raw_action, context)
                action_entry = {
                    "phase": phase_name,
                    "name": result.name,
                    "type": result.action_type,
                    "status": result.status,
                    "elapsed": result.elapsed,
                    **result.details,
                }
                phase_entry["actions"].append(action_entry)
                executed.append(action_entry)
                if result.status == "failed":
                    phase_entry["status"] = "failed"
                    phases.append(phase_entry)
                    return ScenarioResult(status="failed", actions=executed, phases=phases)
                if time.time() >= deadline:
                    break
            if phase_entry["status"] != "failed":
                phase_entry["status"] = "completed"
            phases.append(phase_entry)
            if time.time() >= deadline:
                break

        return ScenarioResult(status="dry_run" if self.dry_run else "completed", actions=executed, phases=phases)

    def _iter_phases(self) -> list[tuple[str, list[Any]]]:
        lifecycle = self.scenario.get("lifecycle")
        if isinstance(lifecycle, dict):
            return [
                (phase_name, list(lifecycle.get(phase_name) or []))
                for phase_name in ["prepare", "deploy", "execute", "finalize"]
                if lifecycle.get(phase_name)
            ]
        return [("execute", list(self.scenario.get("actions") or []))]
