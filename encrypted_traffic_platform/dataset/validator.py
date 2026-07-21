#!/usr/bin/env python3
"""Validate generated PCAP dataset samples."""

from __future__ import annotations

import argparse
import json
from collections import Counter
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class ValidationIssue:
    sample_dir: str
    severity: str
    message: str


def read_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError("document is not an object")
    return value


def iter_sample_dirs(root: Path) -> list[Path]:
    return sorted(path.parent for path in root.rglob("session.json") if ".batch" not in path.parts)


def validate_sample(sample: Path, allow_empty_pcap: bool = False) -> list[ValidationIssue]:
    issues: list[ValidationIssue] = []
    def issue(message: str) -> None:
        issues.append(ValidationIssue(str(sample), "error", message))
    documents = {}
    for filename in ("label.json", "session.json", "experiment_report.json"):
        path = sample / filename
        if not path.exists():
            issue(f"missing {filename}")
            continue
        try:
            documents[filename] = read_json(path)
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            issue(f"invalid {filename}: {exc}")
    pcap = sample / "traffic.pcap"
    if not pcap.exists():
        issue("missing traffic.pcap")
    elif pcap.stat().st_size == 0 and not allow_empty_pcap:
        issue("empty traffic.pcap")
    label = documents.get("label.json", {})
    session = documents.get("session.json", {})
    if not label.get("label"):
        issue("missing label")
    if label.get("sample_id") and session.get("sample_id") and label["sample_id"] != session["sample_id"]:
        issue("sample_id mismatch between label/session")
    report = documents.get("experiment_report.json", {})
    if isinstance(report.get("packet_count"), int) and report["packet_count"] < 0:
        issue("negative packet_count")
    return issues


def validate_dataset(root: str | Path, allow_empty_pcap: bool = False):
    samples = iter_sample_dirs(Path(root).expanduser().resolve())
    issues = [issue for sample in samples for issue in validate_sample(sample, allow_empty_pcap)]
    counts = Counter()
    for sample in samples:
        try:
            label = read_json(sample / "label.json")
            counts[str(label.get("category") or label.get("label") or "unknown")] += 1
        except Exception:
            counts["invalid"] += 1
    return samples, issues, counts


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("dataset_root")
    parser.add_argument("--allow-empty-pcap", action="store_true")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)
    samples, issues, counts = validate_dataset(args.dataset_root, args.allow_empty_pcap)
    if args.json:
        print(json.dumps({"total_samples": len(samples), "invalid": len({item.sample_dir for item in issues}), "counts": dict(counts), "issues": [asdict(item) for item in issues]}, ensure_ascii=False, indent=2, sort_keys=True))
    else:
        print(f"Total samples: {len(samples)}")
        print(f"Invalid: {len({item.sample_dir for item in issues})}")
        for name, count in sorted(counts.items()):
            print(f"{name}: {count}")
        for item in issues:
            print(f"[{item.severity}] {item.sample_dir}: {item.message}")
    return 1 if issues else 0


if __name__ == "__main__":
    raise SystemExit(main())
