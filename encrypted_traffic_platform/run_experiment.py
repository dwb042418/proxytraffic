#!/usr/bin/env python3
"""Run one configured ETIP traffic-generation experiment."""

from __future__ import annotations

import argparse
import json
import sys
import tempfile
from pathlib import Path
from typing import Any

import yaml

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from encrypted_traffic_platform.benign_generator import generate_benign
from encrypted_traffic_platform.c2_generator import generate_traffic
from encrypted_traffic_platform.dataset import build_index
from encrypted_traffic_platform.proxy_generator import generate_proxy


PROXY_LABELS = {"v2ray", "shadowsocks", "clash"}
C2_LABELS = {"cobaltstrike", "behinder", "antsword", "godzilla"}


def load(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    value = yaml.safe_load(path.read_text(encoding="utf-8"))
    return value if isinstance(value, dict) else {}


def merge(base: dict[str, Any], updates: dict[str, Any]) -> dict[str, Any]:
    result = dict(base)
    for key, value in updates.items():
        result[key] = merge(result[key], value) if isinstance(value, dict) and isinstance(result.get(key), dict) else value
    return result


def run_experiment(experiment_config: str | Path, lab_config: str | Path | None = None, dataset_root: str | Path | None = None, dry_run: bool = False, build_dataset_index: bool = True):
    experiment_path = Path(experiment_config).expanduser().resolve()
    config = merge(load(Path(lab_config).expanduser()) if lab_config else {}, load(experiment_path))
    label = str(config.get("label", "benign")).lower()
    category = str(config.get("category") or ("proxy" if label in PROXY_LABELS else "c2" if label in C2_LABELS else "benign"))
    duration = int(config.get("duration", 300))
    interface = config.get("interface") or config.get("capture", {}).get("interface")
    root = Path(dataset_root or config.get("dataset", {}).get("root", "dataset")).expanduser().resolve()
    scenario = config.get("scenario")
    with tempfile.NamedTemporaryFile("w", suffix=".json", encoding="utf-8", delete=False) as handle:
        json.dump(config, handle, ensure_ascii=False)
        merged_path = Path(handle.name)
    try:
        if category == "proxy":
            record = generate_proxy(proxy_type=label, duration=duration, config_path=merged_path, interface=interface, dataset_root=root, scenario_path=scenario, dry_run=dry_run)
        elif category == "c2":
            record = generate_traffic(attack_type=label, duration=duration, config_path=merged_path, interface=interface, dataset_root=root, scenario_path=scenario, dry_run=dry_run)
        elif category == "benign":
            record = generate_benign(duration=duration, config_path=merged_path, interface=interface, dataset_root=root, actions=config.get("actions"), scenario_path=scenario, dry_run=dry_run)
        else:
            raise ValueError(f"unsupported experiment category: {category}")
    finally:
        merged_path.unlink(missing_ok=True)
    if build_dataset_index:
        build_index(root)
    print(record.sample_dir)
    return record


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", required=True)
    parser.add_argument("--lab-config", default="encrypted_traffic_platform/config/lab.yaml")
    parser.add_argument("--dataset-root")
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--no-index", action="store_true")
    args = parser.parse_args(argv)
    run_experiment(args.config, args.lab_config, args.dataset_root, args.dry_run, not args.no_index)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
