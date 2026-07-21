#!/usr/bin/env python3
"""Check batch configuration and local collection dependencies without collecting."""

from __future__ import annotations

import argparse
import os
import shutil
import sys
from pathlib import Path

from run_batch import PLATFORM_ROOT, category_entries, load_yaml, prepare_session_config


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", required=True, type=Path)
    parser.add_argument("--dataset-root", required=True, type=Path)
    parser.add_argument("--seed", type=int, default=42)
    args = parser.parse_args(argv)
    checks: list[tuple[bool, str]] = []
    try:
        path = args.config.expanduser().resolve()
        config = load_yaml(path)
        config["_config_dir"] = str(path.parent)
        entries = category_entries(config)
        checks.append((True, f"configuration: {path}"))
        for category, count, overrides in entries:
            if count:
                prepare_session_config(config, category, 1, overrides, args.seed)
            checks.append((True, f"category {category}: {count} session(s)"))
    except Exception as exc:
        checks.append((False, f"configuration: {exc}"))

    for relative in (
        "scripts/run_enriched_experiment.py", "dataset/validator.py",
        "dataset/build_index.py", "dataset/build_enriched_index.py",
    ):
        checks.append(((PLATFORM_ROOT / relative).is_file(), f"required file: {relative}"))
    for command in ("curl", "tcpdump", "tshark"):
        checks.append((shutil.which(command) is not None, f"executable: {command}"))

    root = args.dataset_root.expanduser().resolve()
    probe = root if root.exists() else next((parent for parent in root.parents if parent.exists()), root.parent)
    checks.append((probe.exists() and os.access(probe, os.W_OK), f"dataset path writable: {root}"))
    for passed, message in checks:
        print(f"{'PASS' if passed else 'FAIL'} {message}")
    failures = sum(not passed for passed, _ in checks)
    print(f"Preflight: {len(checks) - failures} passed, {failures} failed")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
