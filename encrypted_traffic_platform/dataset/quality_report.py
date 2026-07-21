#!/usr/bin/env python3
"""Generate a machine-readable and human-readable ETIP dataset quality report."""

from __future__ import annotations

import argparse
import hashlib
import json
import statistics
from collections import Counter
from pathlib import Path
from typing import Any


def read_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
        return value if isinstance(value, dict) else {}
    except (OSError, json.JSONDecodeError):
        return {}


def digest(path: Path) -> str:
    hasher = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            hasher.update(chunk)
    return hasher.hexdigest()


def describe(values: list[float]) -> dict[str, float | int | None]:
    return {"count": len(values), "min": min(values) if values else None, "max": max(values) if values else None, "mean": statistics.fmean(values) if values else None}


def build_report(root: Path) -> dict[str, Any]:
    samples = sorted(path.parent for path in root.rglob("session.json") if ".batch" not in path.parts)
    labels: Counter[str] = Counter()
    protocols: Counter[str] = Counter()
    hashes: Counter[str] = Counter()
    sizes: list[float] = []
    durations: list[float] = []
    empty, missing, invalid, plaintext_http, no_tls, oversized = [], [], [], [], [], []
    for sample in samples:
        session, label = read_json(sample / "session.json"), read_json(sample / "label.json")
        report = read_json(sample / "experiment_report.json")
        sample_id = str(session.get("sample_id") or label.get("sample_id") or sample.name)
        labels[str(label.get("label", session.get("label", "unknown")))] += 1
        protocols[str(label.get("protocol", session.get("protocol", "unknown")))] += 1
        pcap = sample / "traffic.pcap"
        if not pcap.exists():
            missing.append(sample_id)
            continue
        size = pcap.stat().st_size
        sizes.append(float(size))
        if size == 0:
            empty.append(sample_id)
        else:
            hashes[digest(pcap)] += 1
        duration = report.get("actual_capture_duration", session.get("duration"))
        if isinstance(duration, (int, float)):
            durations.append(float(duration))
        if int(report.get("plaintext_http_request_count", 0) or 0) > 0:
            plaintext_http.append(sample_id)
        if str(label.get("protocol", session.get("protocol", ""))).lower() == "https" and int(report.get("tls_stream_count", 0) or 0) < 1:
            no_tls.append(sample_id)
        if int(report.get("max_frame_len", 0) or 0) > 1518:
            oversized.append(sample_id)
        if not session or not label:
            invalid.append(sample_id)
    duplicates = {value: count for value, count in hashes.items() if count > 1}
    return {"dataset_root": str(root), "total_samples": len(samples), "labels": dict(labels), "protocols": dict(protocols), "invalid_metadata": invalid, "missing_pcaps": missing, "empty_pcaps": empty, "duplicate_pcap_hashes": duplicates, "plaintext_http_samples": plaintext_http, "https_samples_without_tls": no_tls, "oversized_frame_samples": oversized, "pcap_size_bytes": describe(sizes), "duration_seconds": describe(durations)}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("dataset_root", type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--strict", action="store_true")
    args = parser.parse_args(argv)
    root = args.dataset_root.expanduser().resolve()
    report = build_report(root)
    output = args.output or root / "quality_report.json"
    output.write_text(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True))
    issue_keys = ("invalid_metadata", "missing_pcaps", "empty_pcaps", "duplicate_pcap_hashes", "plaintext_http_samples", "https_samples_without_tls", "oversized_frame_samples")
    return 1 if args.strict and any(report[key] for key in issue_keys) else 0


if __name__ == "__main__":
    raise SystemExit(main())
