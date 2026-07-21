#!/usr/bin/env python3
"""Build index.csv from valid sample metadata, ignoring operational directories."""

from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path
from typing import Any


FIELDS = ("sample_id", "label", "category", "protocol", "tool", "environment", "timestamp", "duration", "packet_count", "byte_count", "flow_count", "pcap_path", "report_path", "sample_dir")


def load(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
        return value if isinstance(value, dict) else {}
    except (OSError, json.JSONDecodeError):
        return {}


def build_index(dataset_root: str | Path) -> Path:
    root = Path(dataset_root).expanduser().resolve()
    rows = []
    for session_path in sorted(root.rglob("session.json")):
        if ".batch" in session_path.parts:
            continue
        sample = session_path.parent
        session, label, report = load(session_path), load(sample / "label.json"), load(sample / "experiment_report.json")
        row = {
            "sample_id": session.get("sample_id", sample.name),
            "label": label.get("label", session.get("label", "")),
            "category": label.get("category", session.get("category", "")),
            "protocol": label.get("protocol", session.get("protocol", "")),
            "tool": label.get("tool", session.get("tool", "")),
            "environment": session.get("environment", ""),
            "timestamp": session.get("timestamp", session.get("created_at", "")),
            "duration": report.get("actual_capture_duration", session.get("duration", "")),
            "packet_count": report.get("packet_count", ""),
            "byte_count": report.get("byte_count", ""),
            "flow_count": report.get("flow_count", ""),
            "pcap_path": str(sample / "traffic.pcap"),
            "report_path": str(sample / "experiment_report.json"),
            "sample_dir": str(sample),
        }
        rows.append(row)
    output = root / "index.csv"
    with output.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=FIELDS)
        writer.writeheader()
        writer.writerows(rows)
    return output


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("dataset_root")
    args = parser.parse_args(argv)
    print(build_index(args.dataset_root))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
