#!/usr/bin/env python3
"""Generate benign baseline traffic and capture it as labeled PCAP."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Any

if __package__ in {None, ""}:  # Allow direct script execution.
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from encrypted_traffic_platform.capture import CaptureOptions, CaptureSession
from encrypted_traffic_platform.common import load_config
from encrypted_traffic_platform.dataset import SampleRecord
from encrypted_traffic_platform.generators import ScenarioRunner, load_scenario


DEFAULT_BENIGN_SCENARIO: dict[str, Any] = {
    "name": "benign_default",
    "label": "benign",
    "category": "benign",
    "tool": "benign_generator",
    "protocol": "http_https_dns",
    "duration": 300,
    "lifecycle": {
        "prepare": [{"type": "dns_query", "name": "normal_dns", "domains": ["example.com", "httpbin.org"]}],
        "execute": [
            {"type": "web_browse", "name": "web_browsing", "repeat": 2},
            {"type": "file_download", "name": "file_download", "repeat": 1},
            {"type": "cloud_access", "name": "cloud_access", "repeat": 1},
            {"type": "video_stream", "name": "video_streaming", "repeat": 1},
        ],
        "finalize": ["benign_finalize"],
    },
}


def _scenario_from_actions(actions: list[str] | None, duration: int) -> dict[str, Any]:
    if not actions:
        scenario = dict(DEFAULT_BENIGN_SCENARIO)
        scenario["duration"] = duration
        return scenario

    mapped: list[dict[str, Any] | str] = []
    for action in actions:
        if action == "browser":
            mapped.append({"type": "web_browse", "name": "web_browsing", "repeat": 2})
        elif action == "download":
            mapped.append({"type": "file_download", "name": "file_download", "repeat": 1})
        elif action == "cloud":
            mapped.append({"type": "cloud_access", "name": "cloud_access", "repeat": 1})
        elif action in {"streaming", "video"}:
            mapped.append({"type": "video_stream", "name": "video_streaming", "repeat": 1})
        elif action == "dns":
            mapped.append({"type": "dns_query", "name": "normal_dns"})
        else:
            mapped.append(action)

    return {
        "name": "benign_custom",
        "label": "benign",
        "category": "benign",
        "tool": "benign_generator",
        "protocol": "http_https_dns",
        "duration": duration,
        "actions": mapped,
    }


def generate_benign(
    duration: int = 300,
    *,
    config_path: str | Path | None = None,
    interface: str | None = None,
    dataset_root: str | Path | None = None,
    actions: list[str] | None = None,
    scenario_path: str | Path | None = None,
    dry_run: bool = False,
) -> SampleRecord:
    config = load_config(config_path)
    capture_cfg = config.get("capture", {})
    dataset_cfg = config.get("dataset", {})
    benign_cfg = config.get("benign_generator", {})
    scenario = load_scenario(scenario_path) if scenario_path else _scenario_from_actions(actions or benign_cfg.get("actions"), duration)
    scenario_duration = int(scenario.get("duration", duration))

    options = CaptureOptions(
        interface=interface or capture_cfg.get("interface", "eth0"),
        duration=scenario_duration,
        label="benign",
        category="benign",
        protocol=scenario.get("protocol") or benign_cfg.get("protocol", "http_https_dns"),
        tool=scenario.get("tool") or benign_cfg.get("tool", "benign_generator"),
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
                "generator": "benign_generator.generate_benign",
                "scenario": scenario.get("name"),
                "actions": scenario.get("actions") or scenario.get("lifecycle", {}),
                "status": "dry_run" if dry_run else "running",
            },
        )
        result = ScenarioRunner(
            scenario,
            duration=scenario_duration,
            dry_run=dry_run,
            sample_dir=record.sample_dir,
            pcap_path=record.pcap_path,
            env={
                "ETIP_LABEL": "benign",
                "ETIP_CATEGORY": "benign",
                "ETIP_DURATION": str(scenario_duration),
                "ETIP_SAMPLE_DIR": str(record.sample_dir),
                "ETIP_PCAP_PATH": str(record.pcap_path),
            },
        ).run()
        session.manager.update_session(
            record,
            {
                "status": result.status,
                "executed_actions": result.actions,
                "lifecycle": result.phases,
            },
        )
        session.stop()

    return record


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Generate and capture one benign traffic sample")
    parser.add_argument("--duration", type=int, default=300)
    parser.add_argument("--config", default=None)
    parser.add_argument("--interface", default=None)
    parser.add_argument("--dataset-root", default=None)
    parser.add_argument("--actions", default=None, help="Comma-separated actions: browser,download,cloud,streaming,dns")
    parser.add_argument("--scenario", default=None)
    parser.add_argument("--dry-run", action="store_true")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    record = generate_benign(
        duration=args.duration,
        config_path=args.config,
        interface=args.interface,
        dataset_root=args.dataset_root,
        actions=[item.strip() for item in args.actions.split(",") if item.strip()] if args.actions else None,
        scenario_path=args.scenario,
        dry_run=args.dry_run,
    )
    print(record.sample_dir)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
