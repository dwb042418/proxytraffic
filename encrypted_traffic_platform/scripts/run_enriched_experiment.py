#!/usr/bin/env python3
"""Run, enrich, validate, and index one ETIP experiment."""

from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path


PLATFORM_ROOT = Path(__file__).resolve().parents[1]
PROJECT_ROOT = PLATFORM_ROOT.parent


def run(command: list[str]) -> None:
    print("+ " + " ".join(command), flush=True)
    subprocess.run(command, cwd=PROJECT_ROOT, check=True)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", required=True)
    parser.add_argument("--dataset-root", required=True)
    parser.add_argument("--lab-config")
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args(argv)
    root = Path(args.dataset_root).expanduser().resolve()
    root.mkdir(parents=True, exist_ok=True)

    command = [sys.executable, str(PLATFORM_ROOT / "run_experiment.py"), "--config", args.config, "--dataset-root", str(root), "--no-index"]
    if args.lab_config:
        command.extend(["--lab-config", args.lab_config])
    if args.dry_run:
        command.append("--dry-run")
    run(command)

    enrich = [sys.executable, str(PLATFORM_ROOT / "dataset" / "enrich_sample.py"), "--dataset-root", str(root), "--experiment-config", args.config]
    run(enrich)
    validator = [sys.executable, str(PLATFORM_ROOT / "dataset" / "validator.py"), str(root)]
    if args.dry_run:
        validator.append("--allow-empty-pcap")
    run(validator)
    run([sys.executable, str(PLATFORM_ROOT / "dataset" / "build_index.py"), str(root)])
    run([sys.executable, str(PLATFORM_ROOT / "dataset" / "build_enriched_index.py"), str(root)])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
