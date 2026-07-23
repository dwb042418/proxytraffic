#!/usr/bin/env python3

from __future__ import annotations

import argparse
import hashlib
import json
import shlex
import shutil
import subprocess
import sys
from decimal import Decimal, InvalidOperation
from pathlib import Path
from typing import Any


PLATFORM_ROOT = Path(__file__).resolve().parents[1]
RUN_EXPERIMENT = PLATFORM_ROOT / "run_experiment.py"
DATASET_DIR = PLATFORM_ROOT / "dataset"
ENRICH_SAMPLE = DATASET_DIR / "enrich_sample.py"
VALIDATOR = DATASET_DIR / "validator.py"
BUILD_INDEX = DATASET_DIR / "build_index.py"
BUILD_ENRICHED_INDEX = DATASET_DIR / "build_enriched_index.py"


def run(
    command: list[str],
    *,
    capture_output: bool = False,
) -> str:
    print("+", shlex.join(command), flush=True)

    result = subprocess.run(
        command,
        text=True,
        stdout=subprocess.PIPE if capture_output else None,
        stderr=subprocess.PIPE if capture_output else None,
    )

    if capture_output:
        if result.stdout:
            print(result.stdout, end="")
        if result.stderr:
            print(result.stderr, end="", file=sys.stderr)

    if result.returncode != 0:
        raise subprocess.CalledProcessError(
            result.returncode,
            command,
            output=result.stdout if capture_output else None,
            stderr=result.stderr if capture_output else None,
        )

    return result.stdout or ""


def load_json(path: Path) -> dict[str, Any]:
    with path.open(encoding="utf-8") as handle:
        return json.load(handle)


def save_json(path: Path, value: dict[str, Any]) -> None:
    temporary = Path(str(path) + ".tmp")

    with temporary.open("w", encoding="utf-8") as handle:
        json.dump(
            value,
            handle,
            ensure_ascii=False,
            indent=2,
            sort_keys=True,
        )
        handle.write("\n")

    temporary.replace(path)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()

    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)

    return digest.hexdigest()


def timestamp_order(path: Path) -> tuple[bool, int]:
    if not path.exists() or path.stat().st_size == 0:
        return True, 0

    result = subprocess.run(
        [
            "tshark",
            "-r",
            str(path),
            "-T",
            "fields",
            "-e",
            "frame.time_epoch",
        ],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )

    if result.returncode != 0:
        raise RuntimeError(
            "Unable to inspect packet timestamps:\n"
            + result.stderr
        )

    previous: Decimal | None = None
    regressions = 0

    for raw_line in result.stdout.splitlines():
        value = raw_line.strip()

        if not value:
            continue

        try:
            current = Decimal(value)
        except InvalidOperation as exc:
            raise RuntimeError(
                f"Invalid frame.time_epoch value: {value}"
            ) from exc

        if previous is not None and current < previous:
            regressions += 1

        previous = current

    return regressions == 0, regressions


def resolve_config(value: str) -> Path:
    candidate = Path(value).expanduser()

    if candidate.is_absolute():
        return candidate.resolve()

    from_cwd = (Path.cwd() / candidate).resolve()

    if from_cwd.exists():
        return from_cwd

    from_repo = (PLATFORM_ROOT.parent / candidate).resolve()

    if from_repo.exists():
        return from_repo

    raise FileNotFoundError(f"Experiment config not found: {value}")


def existing_samples(dataset_root: Path) -> set[Path]:
    return {
        path.parent.resolve()
        for path in dataset_root.rglob("session.json")
    }


def locate_sample(
    dataset_root: Path,
    previous_samples: set[Path],
    command_output: str,
) -> Path:
    for line in reversed(command_output.splitlines()):
        candidate = Path(line.strip()).expanduser()

        if (
            candidate.is_dir()
            and (candidate / "session.json").exists()
        ):
            return candidate.resolve()

    current_samples = existing_samples(dataset_root)
    new_samples = current_samples - previous_samples

    if new_samples:
        return max(
            new_samples,
            key=lambda path: (
                path / "session.json"
            ).stat().st_mtime,
        )

    if current_samples:
        return max(
            current_samples,
            key=lambda path: (
                path / "session.json"
            ).stat().st_mtime,
        )

    raise RuntimeError(
        f"Unable to locate generated sample under {dataset_root}"
    )


def normalize_pcap(sample_dir: Path) -> dict[str, Any]:
    raw_pcap = sample_dir / "traffic_raw.pcap"
    ordered_pcap = sample_dir / "traffic.pcap"

    if not ordered_pcap.exists():
        raise FileNotFoundError(
            f"Missing captured PCAP: {ordered_pcap}"
        )

    if raw_pcap.exists():
        raise FileExistsError(
            f"Refusing to overwrite existing raw PCAP: {raw_pcap}"
        )

    ordered_pcap.replace(raw_pcap)

    raw_strict, out_of_order_count = timestamp_order(raw_pcap)

    if raw_pcap.stat().st_size == 0:
        shutil.copyfile(raw_pcap, ordered_pcap)
    else:
        run([
            "reordercap",
            str(raw_pcap),
            str(ordered_pcap),
        ])

    ordered_strict, ordered_regressions = timestamp_order(
        ordered_pcap
    )

    if not ordered_strict or ordered_regressions != 0:
        raise RuntimeError(
            "Ordered PCAP still contains timestamp regressions"
        )

    raw_hash = sha256_file(raw_pcap)
    ordered_hash = sha256_file(ordered_pcap)

    return {
        "raw_pcap": raw_pcap.name,
        "ordered_pcap": ordered_pcap.name,
        "raw_pcap_sha256": raw_hash,
        "ordered_pcap_sha256": ordered_hash,
        "raw_strict_time_order": raw_strict,
        "ordered_strict_time_order": ordered_strict,
        "out_of_order_frame_count": out_of_order_count,
        "normalization_tool": "reordercap",
        "normalization_status": "completed",
    }


def persist_normalization(
    sample_dir: Path,
    normalization: dict[str, Any],
) -> None:
    session_path = sample_dir / "session.json"
    report_path = sample_dir / "experiment_report.json"

    session = load_json(session_path)
    session.update({
        "raw_pcap_sha256": normalization[
            "raw_pcap_sha256"
        ],
        "ordered_pcap_sha256": normalization[
            "ordered_pcap_sha256"
        ],
        "raw_strict_time_order": normalization[
            "raw_strict_time_order"
        ],
        "ordered_strict_time_order": normalization[
            "ordered_strict_time_order"
        ],
        "out_of_order_frame_count": normalization[
            "out_of_order_frame_count"
        ],
        "pcap_sha256": normalization[
            "ordered_pcap_sha256"
        ],
        "raw_pcap_file": normalization["raw_pcap"],
        "ordered_pcap_file": normalization[
            "ordered_pcap"
        ],
        "pcap_normalization": {
            "tool": normalization[
                "normalization_tool"
            ],
            "status": normalization[
                "normalization_status"
            ],
        },
    })
    save_json(session_path, session)

    report = load_json(report_path)
    report["pcap_normalization"] = normalization

    summary = dict(report.get("summary") or {})
    summary.update({
        "raw_pcap_sha256": normalization[
            "raw_pcap_sha256"
        ],
        "ordered_pcap_sha256": normalization[
            "ordered_pcap_sha256"
        ],
        "raw_strict_time_order": normalization[
            "raw_strict_time_order"
        ],
        "ordered_strict_time_order": normalization[
            "ordered_strict_time_order"
        ],
        "out_of_order_frame_count": normalization[
            "out_of_order_frame_count"
        ],
    })
    report["summary"] = summary
    save_json(report_path, report)


def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Run an experiment, preserve the raw PCAP, "
            "normalize packet timestamp order, enrich metadata, "
            "validate the sample, and rebuild indexes."
        )
    )

    parser.add_argument("--config", required=True)
    parser.add_argument("--dataset-root", required=True)
    parser.add_argument("--dry-run", action="store_true")

    args = parser.parse_args()

    config_path = resolve_config(args.config)
    dataset_root = Path(
        args.dataset_root
    ).expanduser().resolve()
    dataset_root.mkdir(parents=True, exist_ok=True)

    for executable in ("reordercap", "tshark"):
        if shutil.which(executable) is None:
            raise RuntimeError(
                f"Required executable not found: {executable}"
            )

    before = existing_samples(dataset_root)

    run_command = [
        sys.executable,
        str(RUN_EXPERIMENT),
        "--config",
        str(config_path),
        "--dataset-root",
        str(dataset_root),
        "--no-index",
    ]

    if args.dry_run:
        run_command.append("--dry-run")

    command_output = run(
        run_command,
        capture_output=True,
    )

    sample_dir = locate_sample(
        dataset_root,
        before,
        command_output,
    )

    normalization = normalize_pcap(sample_dir)

    run([
        sys.executable,
        str(ENRICH_SAMPLE),
        "--dataset-root",
        str(dataset_root),
        "--experiment-config",
        str(config_path),
        "--sample-dir",
        str(sample_dir),
    ])

    persist_normalization(
        sample_dir,
        normalization,
    )

    validator_command = [
        sys.executable,
        str(VALIDATOR),
        str(dataset_root),
    ]

    if args.dry_run:
        validator_command.append("--allow-empty-pcap")

    run(validator_command)

    run([
        sys.executable,
        str(BUILD_INDEX),
        str(dataset_root),
    ])

    run([
        sys.executable,
        str(BUILD_ENRICHED_INDEX),
        str(dataset_root),
    ])

    print(sample_dir)
    print(
        "raw_pcap_sha256="
        + normalization["raw_pcap_sha256"]
    )
    print(
        "ordered_pcap_sha256="
        + normalization["ordered_pcap_sha256"]
    )
    print(
        "raw_strict_time_order="
        + str(normalization["raw_strict_time_order"])
    )
    print(
        "ordered_strict_time_order="
        + str(
            normalization["ordered_strict_time_order"]
        )
    )
    print(
        "out_of_order_frame_count="
        + str(
            normalization["out_of_order_frame_count"]
        )
    )
    print("PCAP_NORMALIZATION_PASSED")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())

