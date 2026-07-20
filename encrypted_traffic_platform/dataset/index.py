#!/usr/bin/env python3
"""Build a CSV index for generated traffic samples."""

from __future__ import annotations

import argparse
import csv
import sys
from pathlib import Path
from typing import Any

if __package__ in {None, ""}:  # Allow direct script execution.
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from encrypted_traffic_platform.dataset import DatasetManager


INDEX_FIELDS = [
    "sample_id",
    "label",
    "category",
    "protocol",
    "tool",
    "environment",
    "timestamp",
    "duration",
    "packet_count",
    "byte_count",
    "flow_count",
    "pcap_path",
    "report_path",
    "sample_dir",
]


def iter_samples(dataset_root: str | Path) -> list[dict[str, Any]]:
    root = Path(dataset_root)
    rows: list[dict[str, Any]] = []
    if not root.exists():
        return rows

    for label_dir in sorted(path for path in root.iterdir() if path.is_dir()):
        for sample_dir in sorted(path for path in label_dir.iterdir() if path.is_dir()):
            label_doc = DatasetManager.read_json(sample_dir / "label.json")
            session_doc = DatasetManager.read_json(sample_dir / "session.json")
            pcap_path = sample_dir / "traffic.pcap"
            report_path = sample_dir / "experiment_report.json"
            row = {
                "sample_id": label_doc.get("sample_id") or session_doc.get("sample_id") or sample_dir.name,
                "label": label_doc.get("label") or session_doc.get("label") or label_dir.name,
                "category": label_doc.get("category") or session_doc.get("category"),
                "protocol": label_doc.get("protocol") or session_doc.get("protocol"),
                "tool": label_doc.get("tool") or session_doc.get("tool"),
                "environment": label_doc.get("environment"),
                "timestamp": label_doc.get("timestamp") or session_doc.get("start_time"),
                "duration": session_doc.get("duration"),
                "packet_count": session_doc.get("packet_count"),
                "byte_count": session_doc.get("byte_count") if session_doc.get("byte_count") is not None else (pcap_path.stat().st_size if pcap_path.exists() else None),
                "flow_count": session_doc.get("flow_count"),
                "pcap_path": str(pcap_path),
                "report_path": str(report_path),
                "sample_dir": str(sample_dir),
            }
            rows.append(row)
    return rows


def build_index(dataset_root: str | Path, output: str | Path | None = None) -> Path:
    root = Path(dataset_root)
    output_path = Path(output) if output else root / "index.csv"
    output_path.parent.mkdir(parents=True, exist_ok=True)

    rows = iter_samples(root)
    with output_path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=INDEX_FIELDS)
        writer.writeheader()
        writer.writerows(rows)
    return output_path


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Build dataset/index.csv")
    parser.add_argument("dataset_root", help="Dataset root directory")
    parser.add_argument("--output", default=None, help="Output CSV path")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    path = build_index(args.dataset_root, args.output)
    print(path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
