#!/usr/bin/env python3
"""Validate generated PCAP dataset samples."""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Any

if __package__ in {None, ""}:  # Allow direct script execution.
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from encrypted_traffic_platform.common import VALID_LABELS, infer_category
from encrypted_traffic_platform.dataset import DatasetManager


@dataclass(frozen=True)
class ValidationIssue:
    sample_dir: Path
    severity: str
    message: str


def validate_sample(sample_dir: Path, *, allow_empty_pcap: bool = False) -> list[ValidationIssue]:
    issues: list[ValidationIssue] = []
    label_path = sample_dir / "label.json"
    session_path = sample_dir / "session.json"
    pcap_path = sample_dir / "traffic.pcap"
    report_path = sample_dir / "experiment_report.json"

    if not label_path.exists():
        issues.append(ValidationIssue(sample_dir, "error", "missing label.json"))
        label_doc: dict[str, Any] = {}
    else:
        try:
            label_doc = DatasetManager.read_json(label_path)
        except json.JSONDecodeError as exc:
            issues.append(ValidationIssue(sample_dir, "error", f"invalid label.json: {exc}"))
            label_doc = {}

    if not session_path.exists():
        issues.append(ValidationIssue(sample_dir, "error", "missing session.json"))
        session_doc: dict[str, Any] = {}
    else:
        try:
            session_doc = DatasetManager.read_json(session_path)
        except json.JSONDecodeError as exc:
            issues.append(ValidationIssue(sample_dir, "error", f"invalid session.json: {exc}"))
            session_doc = {}

    if not pcap_path.exists():
        issues.append(ValidationIssue(sample_dir, "error", "missing traffic.pcap"))
    elif pcap_path.stat().st_size == 0 and not allow_empty_pcap:
        issues.append(ValidationIssue(sample_dir, "error", "empty traffic.pcap"))

    if not report_path.exists():
        issues.append(ValidationIssue(sample_dir, "error", "missing experiment_report.json"))
    else:
        try:
            DatasetManager.read_json(report_path)
        except json.JSONDecodeError as exc:
            issues.append(ValidationIssue(sample_dir, "error", f"invalid experiment_report.json: {exc}"))

    label = (label_doc.get("label") or session_doc.get("label") or "").lower()
    if not label:
        issues.append(ValidationIssue(sample_dir, "error", "missing label"))
    elif label not in VALID_LABELS:
        issues.append(ValidationIssue(sample_dir, "error", f"unsupported label: {label}"))
    else:
        expected_category = infer_category(label)
        category = (label_doc.get("category") or session_doc.get("category") or "").lower()
        if category and category != expected_category:
            issues.append(
                ValidationIssue(
                    sample_dir,
                    "error",
                    f"category mismatch: expected {expected_category}, got {category}",
                )
            )

    label_id = label_doc.get("sample_id")
    session_id = session_doc.get("sample_id")
    if label_id and session_id and label_id != session_id:
        issues.append(ValidationIssue(sample_dir, "error", "sample_id mismatch between label/session"))

    packet_count = session_doc.get("packet_count")
    if packet_count is not None and isinstance(packet_count, int) and packet_count < 0:
        issues.append(ValidationIssue(sample_dir, "error", "negative packet_count"))

    return issues


def iter_sample_dirs(dataset_root: str | Path) -> list[Path]:
    root = Path(dataset_root)
    if not root.exists():
        return []
    sample_dirs: list[Path] = []
    for label_dir in sorted(path for path in root.iterdir() if path.is_dir()):
        sample_dirs.extend(sorted(path for path in label_dir.iterdir() if path.is_dir()))
    return sample_dirs


def validate_dataset(dataset_root: str | Path, *, allow_empty_pcap: bool = False) -> tuple[list[Path], list[ValidationIssue], Counter[str]]:
    sample_dirs = iter_sample_dirs(dataset_root)
    issues: list[ValidationIssue] = []
    counts: Counter[str] = Counter()
    for sample_dir in sample_dirs:
        try:
            label_doc = DatasetManager.read_json(sample_dir / "label.json")
        except json.JSONDecodeError:
            label_doc = {}
        label = (label_doc.get("label") or sample_dir.parent.name).lower()
        counts[label] += 1
        issues.extend(validate_sample(sample_dir, allow_empty_pcap=allow_empty_pcap))
    return sample_dirs, issues, counts


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Validate dataset samples")
    parser.add_argument("dataset_root", help="Dataset root directory")
    parser.add_argument("--allow-empty-pcap", action="store_true", help="Allow empty PCAP files for dry-run datasets")
    parser.add_argument("--json", action="store_true", help="Emit JSON report")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    samples, issues, counts = validate_dataset(args.dataset_root, allow_empty_pcap=args.allow_empty_pcap)

    if args.json:
        print(
            json.dumps(
                {
                    "total_samples": len(samples),
                    "invalid": len([issue for issue in issues if issue.severity == "error"]),
                    "counts": dict(counts),
                    "issues": [
                        {
                            "sample_dir": str(issue.sample_dir),
                            "severity": issue.severity,
                            "message": issue.message,
                        }
                        for issue in issues
                    ],
                },
                indent=2,
                ensure_ascii=False,
                sort_keys=True,
            )
        )
    else:
        print(f"Total samples: {len(samples)}")
        print(f"Invalid: {len([issue for issue in issues if issue.severity == 'error'])}")
        for label, count in sorted(counts.items()):
            print(f"{label}: {count}")
        for issue in issues:
            print(f"[{issue.severity}] {issue.sample_dir}: {issue.message}")

    return 1 if any(issue.severity == "error" for issue in issues) else 0


if __name__ == "__main__":
    raise SystemExit(main())
