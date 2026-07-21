#!/usr/bin/env python3
"""Detect obvious label-correlated collection artifacts in an ETIP index."""

from __future__ import annotations

import argparse
import csv
import json
from collections import defaultdict
from pathlib import Path


SENSITIVE_FEATURES = {"src_ip", "dst_ip", "src_port", "dst_port", "sample_path", "sample_dir", "file_name", "filename", "label", "category", "tool_label"}
DEFAULT_ARTIFACTS = ("src_ip", "dst_ip", "src_port", "dst_port", "interface", "client_implementation", "environment_id", "scenario_version")


def read_rows(path: Path) -> list[dict[str, str]]:
    with path.open(newline="", encoding="utf-8") as handle:
        return list(csv.DictReader(handle))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("index", type=Path)
    parser.add_argument("--feature-list", type=Path, help="one model feature name per line")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)
    rows = read_rows(args.index.expanduser().resolve())
    findings = []
    labels = sorted({row.get("label", "") for row in rows if row.get("label")})
    fields = set(rows[0]) if rows else set()
    for field in DEFAULT_ARTIFACTS:
        if field not in fields:
            continue
        value_labels: dict[str, set[str]] = defaultdict(set)
        label_values: dict[str, set[str]] = defaultdict(set)
        for row in rows:
            value, label = row.get(field, ""), row.get("label", "")
            if value and label:
                value_labels[value].add(label)
                label_values[label].add(value)
        exclusive = sorted(value for value, owners in value_labels.items() if len(owners) == 1)
        fixed_per_label = all(len(label_values[label]) == 1 for label in labels) if labels else False
        if exclusive or fixed_per_label:
            findings.append({"type": "label_correlated_artifact", "field": field, "exclusive_values": exclusive, "fixed_per_label": fixed_per_label, "values_by_label": {k: sorted(v) for k, v in label_values.items()}})
    if args.feature_list:
        features = {line.strip() for line in args.feature_list.read_text(encoding="utf-8").splitlines() if line.strip() and not line.lstrip().startswith("#")}
        forbidden = sorted(features & SENSITIVE_FEATURES)
        if forbidden:
            findings.append({"type": "forbidden_model_features", "fields": forbidden})
    result = {"samples": len(rows), "labels": labels, "findings": findings, "passed": not findings}
    if args.json:
        print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))
    else:
        print(f"Leakage check: samples={len(rows)} labels={len(labels)} findings={len(findings)}")
        for finding in findings:
            print(f"WARN {finding}")
    return 1 if findings else 0


if __name__ == "__main__":
    raise SystemExit(main())
