#!/usr/bin/env python3

from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[2]
PLATFORM_ROOT = PROJECT_ROOT / 'encrypted_traffic_platform'


def run(command: list[str]) -> None:
    print('+', ' '.join(command))

    subprocess.run(
        command,
        cwd=PROJECT_ROOT,
        check=True,
    )


def main() -> int:
    parser = argparse.ArgumentParser(
        description='Run, enrich, validate and index one ETIP experiment'
    )

    parser.add_argument(
        '--config',
        required=True,
    )

    parser.add_argument(
        '--dataset-root',
        required=True,
    )

    parser.add_argument(
        '--lab-config',
    )

    parser.add_argument(
        '--dry-run',
        action='store_true',
    )

    args = parser.parse_args()

    dataset_root = Path(
        args.dataset_root
    ).expanduser().resolve()

    dataset_root.mkdir(
        parents=True,
        exist_ok=True,
    )

    run_command = [
        sys.executable,
        str(PLATFORM_ROOT / 'run_experiment.py'),
        '--config',
        args.config,
        '--dataset-root',
        str(dataset_root),
        '--no-index',
    ]

    if args.lab_config:
        run_command.extend([
            '--lab-config',
            args.lab_config,
        ])

    if args.dry_run:
        run_command.append('--dry-run')

    run(run_command)

    run([
        sys.executable,
        str(
            PLATFORM_ROOT
            / 'dataset'
            / 'enrich_sample.py'
        ),
        '--dataset-root',
        str(dataset_root),
        '--experiment-config',
        args.config,
    ])

    validator_command = [
        sys.executable,
        str(
            PLATFORM_ROOT
            / 'dataset'
            / 'validator.py'
        ),
        str(dataset_root),
    ]

    if args.dry_run:
        validator_command.append(
            '--allow-empty-pcap'
        )

    run(validator_command)

    run([
        sys.executable,
        str(
            PLATFORM_ROOT
            / 'dataset'
            / 'build_index.py'
        ),
        str(dataset_root),
    ])

    run([
        sys.executable,
        str(
            PLATFORM_ROOT
            / 'dataset'
            / 'build_enriched_index.py'
        ),
        str(dataset_root),
    ])

    return 0


if __name__ == '__main__':
    raise SystemExit(main())
