#!/usr/bin/env python3
"""Run one configured traffic-generation experiment."""

from __future__ import annotations

import argparse
import json
import sys
import tempfile
from pathlib import Path
from typing import Any

if __package__ in {None, ""}:  # Allow direct script execution.
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from encrypted_traffic_platform.benign_generator import generate_benign
from encrypted_traffic_platform.c2_generator import generate_traffic
from encrypted_traffic_platform.common import C2_LABELS, PROXY_LABELS, infer_category, load_config, utc_now_iso
from encrypted_traffic_platform.dataset import DatasetManager, SampleRecord
from encrypted_traffic_platform.dataset.index import build_index
from encrypted_traffic_platform.proxy_generator import generate_proxy


def _deep_update(base: dict[str, Any], updates: dict[str, Any]) -> dict[str, Any]:
    merged = dict(base)
    for key, value in updates.items():
        if isinstance(value, dict) and isinstance(merged.get(key), dict):
            merged[key] = _deep_update(merged[key], value)
        else:
            merged[key] = value
    return merged


def _write_temp_config(config: dict[str, Any]) -> Path:
    handle = tempfile.NamedTemporaryFile("w", suffix=".json", delete=False, encoding="utf-8")
    with handle:
        json.dump(config, handle)
    return Path(handle.name)


def run_experiment(
    experiment_config: str | Path,
    *,
    lab_config: str | Path | None = None,
    dataset_root: str | Path | None = None,
    dry_run: bool = False,
    build_dataset_index: bool = True,
) -> SampleRecord:
    experiment = load_config(experiment_config)
    lab = load_config(lab_config)
    merged_lab = _deep_update(lab, {"capture": experiment.get("capture", {})})
    temp_config = _write_temp_config(merged_lab)

    label = str(experiment["label"]).lower()
    category = str(experiment.get("category") or infer_category(label)).lower()
    duration = int(experiment.get("duration", 300))
    interface = experiment.get("capture", {}).get("interface")
    scenario = experiment.get("scenario")
    dataset_root = dataset_root or merged_lab.get("dataset", {}).get("root", "dataset")

    try:
        if category == "c2" or label in C2_LABELS:
            record = generate_traffic(
                attack_type=label,
                duration=duration,
                config_path=temp_config,
                interface=interface,
                dataset_root=dataset_root,
                scenario_path=scenario,
                dry_run=dry_run,
            )
        elif category == "proxy" or label in PROXY_LABELS:
            record = generate_proxy(
                proxy_type=label,
                duration=duration,
                config_path=temp_config,
                interface=interface,
                dataset_root=dataset_root,
                scenario_path=scenario,
                dry_run=dry_run,
            )
        elif category == "benign" and label == "benign":
            record = generate_benign(
                duration=duration,
                config_path=temp_config,
                interface=interface,
                dataset_root=dataset_root,
                actions=experiment.get("actions"),
                scenario_path=scenario,
                dry_run=dry_run,
            )
        else:
            raise ValueError(f"Unsupported experiment category/label: {category}/{label}")

        manager = DatasetManager(dataset_root)
        manager.update_session(
            record,
            {
                "experiment": experiment.get("name"),
                "experiment_config": str(experiment_config),
                "environment_metadata": _deep_update(
                    dict(merged_lab.get("environment_metadata") or {}),
                    dict(experiment.get("environment_metadata") or {}),
                ),
            },
        )
        label_doc = manager.read_json(record.label_path)
        session_doc = manager.read_json(record.session_path)
        manager.write_report(
            record,
            {
                "sample_id": record.sample_id,
                "experiment": experiment.get("name"),
                "experiment_config": str(experiment_config),
                "generated_at": utc_now_iso(),
                "dry_run": dry_run,
                "label": label_doc,
                "session": session_doc,
                "summary": {
                    "status": session_doc.get("status"),
                    "duration": session_doc.get("duration"),
                    "packet_count": session_doc.get("packet_count"),
                    "byte_count": session_doc.get("byte_count"),
                    "flow_count": session_doc.get("flow_count"),
                    "action_count": len(session_doc.get("executed_actions") or []),
                },
                "lifecycle": session_doc.get("lifecycle") or [],
                "actions": session_doc.get("executed_actions") or [],
            },
        )
        if build_dataset_index:
            build_index(dataset_root)
        return record
    finally:
        try:
            temp_config.unlink()
        except FileNotFoundError:
            pass


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Run one ETIP experiment YAML")
    parser.add_argument("--config", required=True, help="Experiment YAML path")
    parser.add_argument("--lab-config", default="encrypted_traffic_platform/config/lab.yaml")
    parser.add_argument("--dataset-root", default=None)
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--no-index", action="store_true", help="Do not rebuild index.csv after the run")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    record = run_experiment(
        args.config,
        lab_config=args.lab_config,
        dataset_root=args.dataset_root,
        dry_run=args.dry_run,
        build_dataset_index=not args.no_index,
    )
    print(record.sample_dir)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
