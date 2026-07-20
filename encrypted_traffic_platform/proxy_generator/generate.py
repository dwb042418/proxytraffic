#!/usr/bin/env python3
"""Unified encrypted proxy traffic generation interface."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Any

if __package__ in {None, ""}:  # Allow direct script execution.
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from encrypted_traffic_platform.capture import CaptureOptions, CaptureSession
from encrypted_traffic_platform.common import PROXY_LABELS, NotConfiguredError, load_config
from encrypted_traffic_platform.dataset import SampleRecord
from encrypted_traffic_platform.generators import ScenarioRunner, load_scenario


def _profile(config: dict[str, Any], proxy_type: str) -> dict[str, Any]:
    profiles = config.get("proxy_generators", {})
    return profiles.get(proxy_type, {})


def generate_proxy(
    proxy_type: str,
    duration: int = 300,
    *,
    config_path: str | Path | None = None,
    interface: str | None = None,
    dataset_root: str | Path | None = None,
    scenario_path: str | Path | None = None,
    dry_run: bool = False,
) -> SampleRecord:
    """Generate one labeled encrypted proxy session and capture it."""

    label = proxy_type.lower()
    if label not in PROXY_LABELS:
        raise ValueError(f"Unsupported proxy_type: {proxy_type}")

    config = load_config(config_path)
    capture_cfg = config.get("capture", {})
    dataset_cfg = config.get("dataset", {})
    profile = _profile(config, label)
    scenario = load_scenario(scenario_path)

    command = list(profile.get("command") or [])
    if not scenario and command:
        scenario = {
            "name": f"{label}_external_command",
            "actions": [
                {
                    "type": "command",
                    "name": f"{label}_workload",
                    "command": command,
                    "timeout": profile.get("timeout", duration + 30),
                    "cwd": profile.get("cwd"),
                    "env": profile.get("env", {}),
                }
            ],
        }

    if not dry_run and not scenario:
        raise NotConfiguredError(
            f"No external workload command configured for proxy generator '{label}'. "
            "Set proxy_generators.<label>.command, pass --scenario, or run with --dry-run."
        )

    scenario_duration = int(scenario.get("duration", duration)) if scenario else duration
    options = CaptureOptions(
        interface=interface or capture_cfg.get("interface", "eth0"),
        duration=scenario_duration,
        label=label,
        category="proxy",
        protocol=scenario.get("protocol") or profile.get("protocol", "unknown"),
        tool=scenario.get("tool") or profile.get("tool", label),
        environment=config.get("environment", "lab"),
        dataset_root=Path(dataset_root or dataset_cfg.get("root", "dataset")),
        capture_filter=capture_cfg.get("filter"),
        dry_run=dry_run,
        tcpdump_path=capture_cfg.get("tcpdump_path", "tcpdump"),
        interface_candidates=tuple(capture_cfg.get("interface_candidates", ["eth0", "ens33", "enp0s3", "docker0", "lo"])),
    )

    with CaptureSession(options) as session:
        record = session.record
        if record is None:
            raise RuntimeError("Capture did not create a sample record")

        session.manager.update_session(
            record,
            {
                "generator": "proxy_generator.generate_proxy",
                "proxy_type": label,
                "scenario": scenario.get("name") if scenario else None,
                "actions": scenario.get("actions") if scenario else profile.get("actions", []),
                "external_command": command,
                "status": "dry_run" if dry_run else "running",
            },
        )

        env = dict(profile.get("env") or {})
        env.update(
            {
                "ETIP_LABEL": label,
                "ETIP_CATEGORY": "proxy",
                "ETIP_DURATION": str(scenario_duration),
                "ETIP_SAMPLE_DIR": str(record.sample_dir),
                "ETIP_PCAP_PATH": str(record.pcap_path),
            }
        )
        result = ScenarioRunner(
            scenario,
            duration=scenario_duration,
            dry_run=dry_run,
            env=env,
            sample_dir=record.sample_dir,
            pcap_path=record.pcap_path,
        ).run()
        session.manager.update_session(
            record,
            {
                "status": result.status,
                "executed_actions": result.actions,
                "lifecycle": result.phases,
            },
        )
        if result.status == "failed":
            raise RuntimeError(f"Proxy generator '{label}' failed")

        session.stop()

    return record


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Generate and capture one proxy traffic sample")
    parser.add_argument("--proxy-type", required=True, choices=sorted(PROXY_LABELS))
    parser.add_argument("--duration", type=int, default=300)
    parser.add_argument("--config", default=None)
    parser.add_argument("--interface", default=None)
    parser.add_argument("--dataset-root", default=None)
    parser.add_argument("--scenario", default=None)
    parser.add_argument("--dry-run", action="store_true")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    record = generate_proxy(
        proxy_type=args.proxy_type,
        duration=args.duration,
        config_path=args.config,
        interface=args.interface,
        dataset_root=args.dataset_root,
        scenario_path=args.scenario,
        dry_run=args.dry_run,
    )
    print(record.sample_dir)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
