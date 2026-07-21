#!/usr/bin/env python3
"""Build group-isolated train/validation/test manifests from an enriched index."""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
from collections import defaultdict
from pathlib import Path


def stable_bucket(value: str, seed: int) -> int:
    return int.from_bytes(hashlib.sha256(f"{seed}:{value}".encode()).digest()[:8], "big") % 100


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("dataset_root", type=Path)
    parser.add_argument("--index", type=Path)
    parser.add_argument("--output-dir", type=Path)
    parser.add_argument("--group-by", nargs="+", default=["collection_date", "environment_id", "certificate_group"])
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--train-percent", type=int, default=60)
    parser.add_argument("--val-percent", type=int, default=20)
    args = parser.parse_args(argv)
    root = args.dataset_root.expanduser().resolve()
    index = args.index or root / "index_enriched.csv"
    output = args.output_dir or root / "splits"
    if args.train_percent + args.val_percent >= 100:
        raise SystemExit("train-percent + val-percent must be below 100")
    with index.open(newline="", encoding="utf-8") as handle:
        rows = list(csv.DictReader(handle))
    missing = sorted(field for field in args.group_by if not rows or field not in rows[0])
    if missing:
        raise SystemExit(f"index lacks grouping fields: {', '.join(missing)}")
    splits: dict[str, list[str]] = defaultdict(list)
    group_assignments: dict[str, str] = {}
    for row in rows:
        group = "|".join(row.get(field, "") for field in args.group_by)
        if not group.strip("|"):
            raise SystemExit("empty grouping identity would permit source leakage")
        bucket = stable_bucket(group, args.seed)
        split = "train" if bucket < args.train_percent else "val" if bucket < args.train_percent + args.val_percent else "test"
        group_assignments[group] = split
        sample = row.get("sample_id") or row.get("sample_path")
        if sample:
            splits[split].append(sample)
    output.mkdir(parents=True, exist_ok=True)
    for name in ("train", "val", "test", "cross_environment", "adversarial", "unknown_family"):
        (output / f"{name}.txt").write_text("".join(f"{item}\n" for item in sorted(splits[name])), encoding="utf-8")
    (output / "manifest.json").write_text(json.dumps({"seed": args.seed, "group_by": args.group_by, "counts": {key: len(value) for key, value in splits.items()}, "group_assignments": group_assignments}, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"Wrote splits to {output}: train={len(splits['train'])}, val={len(splits['val'])}, test={len(splits['test'])}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
