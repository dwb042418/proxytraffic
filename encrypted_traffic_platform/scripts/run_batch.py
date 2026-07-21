#!/usr/bin/env python3
"""Run reproducible, resumable batches of ETIP collection scenarios."""

from __future__ import annotations

import argparse
import copy
import datetime as dt
import hashlib
import json
import os
import platform
import random
import shutil
import subprocess
import sys
import tempfile
import math
from pathlib import Path
from typing import Any, Iterable

import yaml


PLATFORM_ROOT = Path(__file__).resolve().parents[1]
PROJECT_ROOT = PLATFORM_ROOT.parent
STATE_DIR_NAME = ".batch"


def atomic_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(
        "w", encoding="utf-8", dir=path.parent, delete=False
    ) as handle:
        json.dump(value, handle, ensure_ascii=False, indent=2, sort_keys=True)
        handle.write("\n")
        temporary = Path(handle.name)
    os.replace(temporary, path)


def load_yaml(path: Path) -> dict[str, Any]:
    value = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"configuration must be a mapping: {path}")
    return value


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def config_hash(config: dict[str, Any]) -> str:
    canonical = json.dumps(
        config, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    return sha256_bytes(canonical)


def derived_seed(batch_seed: int, category: str, ordinal: int) -> int:
    material = f"{batch_seed}:{category}:{ordinal}".encode("utf-8")
    return int.from_bytes(hashlib.sha256(material).digest()[:4], "big")


def choose_randomized(randomization: dict[str, Any], rng: random.Random) -> dict[str, Any]:
    selected: dict[str, Any] = {}
    for key, specification in randomization.items():
        if key == "action_order":
            selected[key] = specification
        elif isinstance(specification, list):
            if not specification:
                raise ValueError(f"randomization.{key} cannot be empty")
            selected[key] = rng.choice(specification)
        elif isinstance(specification, dict) and {"min", "max"} <= specification.keys():
            selected[key] = rng.randint(int(specification["min"]), int(specification["max"]))
        else:
            selected[key] = copy.deepcopy(specification)
    return selected


def deep_merge(base: dict[str, Any], overlay: dict[str, Any]) -> dict[str, Any]:
    result = copy.deepcopy(base)
    for key, value in overlay.items():
        if isinstance(value, dict) and isinstance(result.get(key), dict):
            result[key] = deep_merge(result[key], value)
        else:
            result[key] = copy.deepcopy(value)
    return result


def category_entries(config: dict[str, Any]) -> list[tuple[str, int, dict[str, Any]]]:
    raw = config.get("categories") or config.get("sessions")
    if not isinstance(raw, dict) or not raw:
        raise ValueError("config requires a non-empty 'categories' mapping")
    entries = []
    for name, value in raw.items():
        if isinstance(value, int):
            count, overrides = value, {}
        elif isinstance(value, dict):
            count = value.get("sessions", value.get("count"))
            overrides = {k: v for k, v in value.items() if k not in {"sessions", "count"}}
        else:
            raise ValueError(f"categories.{name} must be an integer or mapping")
        if not isinstance(count, int) or count < 0:
            raise ValueError(f"categories.{name}.sessions must be a non-negative integer")
        entries.append((str(name), count, overrides))
    return entries


def iter_sample_dirs(dataset_root: Path) -> Iterable[Path]:
    if not dataset_root.exists():
        return []
    return sorted(
        path.parent
        for path in dataset_root.rglob("session.json")
        if STATE_DIR_NAME not in path.parts
    )


def command_version(command: list[str]) -> str:
    executable = shutil.which(command[0])
    if not executable:
        return "unavailable"
    try:
        result = subprocess.run(
            [executable, *command[1:]], capture_output=True, text=True, timeout=10, check=False
        )
        line = (result.stdout or result.stderr).splitlines()
        return line[0].strip() if line else "unknown"
    except (OSError, subprocess.SubprocessError):
        return "unknown"


def software_versions(config: dict[str, Any]) -> dict[str, str]:
    declared = config.get("software_versions", {})
    versions = {
        "collector": str(declared.get("collector", "0.1.0")),
        "curl": command_version(["curl", "--version"]),
        "tcpdump": command_version(["tcpdump", "--version"]),
        "python": platform.python_version(),
        "platform": platform.platform(),
    }
    versions.update({str(k): str(v) for k, v in declared.items()})
    return versions


def session_key(category: str, ordinal: int) -> str:
    return f"{category}:{ordinal:06d}"


def prepare_session_config(
    batch: dict[str, Any], category: str, ordinal: int, overrides: dict[str, Any], seed: int
) -> tuple[dict[str, Any], dict[str, Any]]:
    base: dict[str, Any] = {}
    base_path = overrides.get("scenario_config") or batch.get("scenario_config")
    if base_path:
        candidate = Path(str(base_path)).expanduser()
        if not candidate.is_absolute():
            candidate = (Path(str(batch["_config_dir"])) / candidate).resolve()
        base = load_yaml(candidate)

    excluded = {"scenario_config", "randomization", "scenario_overrides"}
    base = deep_merge(base, batch.get("scenario_overrides", {}))
    base = deep_merge(base, overrides.get("scenario_overrides", {}))
    direct_overrides = {key: value for key, value in overrides.items() if key not in excluded}
    base = deep_merge(base, direct_overrides)

    rng = random.Random(seed)
    randomization = deep_merge(
        batch.get("randomization", {}), overrides.get("randomization", {})
    )
    parameters = choose_randomized(randomization, rng)
    actions = base.get("actions")
    if parameters.get("action_order") == "shuffle" and isinstance(actions, list):
        rng.shuffle(actions)
    base["scenario_parameters"] = parameters
    base["random_seed"] = seed
    base.setdefault("label", category)

    if category == "benign" and {"file_size_mb", "rate_limit_mbps", "idle_seconds", "request_count", "tls_version"} <= parameters.keys():
        size = int(parameters["file_size_mb"])
        rate = float(parameters["rate_limit_mbps"])
        idle = float(parameters["idle_seconds"])
        requests = int(parameters["request_count"])
        tls_version = str(parameters["tls_version"])
        rate_bytes = max(1, int(rate * 1_000_000 / 8))
        url_root = str(batch.get("benign_url_root", "https://etip-server.lab:18443"))
        ca_path = Path(str(batch.get("ca_certificate", "config/certs/etip-ca.crt"))).expanduser()
        if not ca_path.is_absolute():
            ca_path = (PLATFORM_ROOT / ca_path).resolve()
        tls_args = ["--tlsv1.2", "--tls-max", "1.2"] if tls_version == "TLSv1.2" else ["--tlsv1.3"]
        actions: list[dict[str, Any]] = []
        for request_number in range(1, requests + 1):
            target = f"{url_root}/files/file_{size}m.bin" if request_number == 1 else f"{url_root}/"
            actions.append({
                "type": "command",
                "name": "https_file_download" if request_number == 1 else f"https_page_{request_number}",
                "command": [
                    "curl", "--fail", "--silent", "--show-error", "--noproxy", "*",
                    "--cacert", str(ca_path), *tls_args,
                    "--limit-rate", str(rate_bytes),
                    target, "--output", "/dev/null",
                ],
                # The lab link is substantially slower than the nominal rate limit;
                # reserve enough wall-clock time for retransmits and VM jitter.
                "timeout": max(120, math.ceil((size * 8 / rate * 20 + 120) if request_number == 1 else 120)),
            })
            if request_number != requests:
                actions.append({"type": "sleep", "name": f"idle_{request_number}", "seconds": idle})
        if parameters.get("action_order") == "shuffle":
            request_actions = actions[::2]
            rng.shuffle(request_actions)
            actions[::2] = request_actions
        expected_seconds = size * 8 / rate + max(0, requests - 1) * idle + max(0, requests - 1) * 2
        base["duration"] = max(int(base.get("duration", 0)), math.ceil(expected_seconds * 20 + 180))
        base["scenario_definition"] = {
            "name": f"benign_https_{seed}",
            "label": "benign", "category": "benign", "protocol": "https",
            "duration": base["duration"], "actions": actions,
        }

    metadata = {
        "random_seed": seed,
        "scenario_version": str(overrides.get("scenario_version", batch.get("scenario_version", f"{category}_v1"))),
        "collection_batch": str(batch.get("collection_batch", "batch_001")),
        "collection_date": str(batch.get("collection_date", dt.date.today().isoformat())),
        "data_origin": str(batch.get("data_origin", "live_lab")),
        "scenario_parameters": parameters,
    }
    metadata["scenario_config_hash"] = config_hash(base)
    base.update(metadata)
    return base, metadata


def update_session_metadata(sample_dir: Path, metadata: dict[str, Any], versions: dict[str, str]) -> None:
    path = sample_dir / "session.json"
    session = json.loads(path.read_text(encoding="utf-8"))
    session.update(metadata)
    session["software_versions"] = versions
    atomic_json(path, session)


def find_recoverable_sample(dataset_root: Path, batch_id: str, seed: int) -> Path | None:
    matches = []
    for sample in iter_sample_dirs(dataset_root):
        try:
            session = json.loads((sample / "session.json").read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        actions = session.get("executed_actions", [])
        actions_ok = isinstance(actions, list) and bool(actions) and all(action.get("status") == "completed" for action in actions if isinstance(action, dict))
        if session.get("collection_batch") == batch_id and session.get("random_seed") == seed and session.get("status") == "completed" and actions_ok:
            matches.append(sample)
    return matches[0] if len(matches) == 1 else None


def find_seed_samples(dataset_root: Path, batch_id: str, seed: int) -> list[Path]:
    matches = []
    for sample in iter_sample_dirs(dataset_root):
        try:
            session = json.loads((sample / "session.json").read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        if session.get("collection_batch") == batch_id and session.get("random_seed") == seed:
            matches.append(sample)
    return matches


def run_logged(command: list[str], log_handle: Any, dry_run: bool = False) -> None:
    printable = " ".join(command)
    log_handle.write(f"$ {printable}\n")
    log_handle.flush()
    if dry_run:
        return
    result = subprocess.run(
        command, cwd=PROJECT_ROOT, stdout=log_handle, stderr=subprocess.STDOUT, check=False
    )
    if result.returncode:
        raise subprocess.CalledProcessError(result.returncode, command)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", required=True, type=Path)
    parser.add_argument("--dataset-root", required=True, type=Path)
    parser.add_argument("--seed", type=int, default=None)
    parser.add_argument("--lab-config", type=Path)
    parser.add_argument("--dry-run", action="store_true", help="run the pipeline without packet collection")
    parser.add_argument("--limit", type=int, help="process at most this many sessions")
    parser.add_argument("--retry-failed", action="store_true")
    parser.add_argument("--fail-fast", action="store_true")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    config_path = args.config.expanduser().resolve()
    dataset_root = args.dataset_root.expanduser().resolve()
    batch = load_yaml(config_path)
    batch["_config_dir"] = str(config_path.parent)
    batch_seed = args.seed if args.seed is not None else int(batch.get("seed", 42))
    dataset_root.mkdir(parents=True, exist_ok=True)

    batch_id = str(batch.get("collection_batch", config_path.stem))
    state_dir = dataset_root / STATE_DIR_NAME / batch_id
    generated_dir = state_dir / "configs"
    log_dir = state_dir / "logs"
    state_path = state_dir / "state.json"
    state: dict[str, Any] = {"batch": batch_id, "seed": batch_seed, "sessions": {}}
    if state_path.exists():
        state = json.loads(state_path.read_text(encoding="utf-8"))
        if state.get("seed") != batch_seed:
            raise SystemExit(f"refusing to resume {batch_id} with a different seed")

    versions = software_versions(batch)
    atomic_json(state_dir / "software_versions.json", versions)
    original_hash = sha256_bytes(config_path.read_bytes())
    atomic_json(
        state_dir / "batch_manifest.json",
        {"collection_batch": batch_id, "batch_config": str(config_path), "batch_config_hash": original_hash, "seed": batch_seed},
    )

    runner = PLATFORM_ROOT / "scripts" / "run_enriched_experiment.py"
    validator = PLATFORM_ROOT / "dataset" / "validator.py"
    indexer = PLATFORM_ROOT / "dataset" / "build_index.py"
    enriched_indexer = PLATFORM_ROOT / "dataset" / "build_enriched_index.py"
    enricher = PLATFORM_ROOT / "dataset" / "enrich_sample.py"
    failures = 0
    attempted = 0

    for category, count, overrides in category_entries(batch):
        for ordinal in range(1, count + 1):
            if args.limit is not None and attempted >= args.limit:
                break
            attempted += 1
            key = session_key(category, ordinal)
            previous = state["sessions"].get(key, {})
            seed = derived_seed(batch_seed, category, ordinal)
            previous_sample = Path(previous.get("sample_dir", ""))
            if previous.get("status") == "completed" and (previous_sample / "session.json").exists():
                print(f"SKIP {key}: completed")
                continue
            if previous.get("status") == "running":
                recovered = find_recoverable_sample(dataset_root, batch_id, seed)
                if recovered:
                    _, metadata = prepare_session_config(batch, category, ordinal, overrides, seed)
                    log_path = Path(previous.get("log") or state_dir / "logs" / f"{category}_{ordinal:06d}.log")
                    log_path.parent.mkdir(parents=True, exist_ok=True)
                    try:
                        update_session_metadata(recovered, metadata, versions)
                        with log_path.open("a", encoding="utf-8") as log:
                            run_logged([sys.executable, str(enricher), "--dataset-root", str(dataset_root), "--experiment-config", str(previous["scenario_config"]), "--sample-dir", str(recovered)], log)
                            validator_command = [sys.executable, str(validator), str(dataset_root)]
                            if args.dry_run:
                                validator_command.append("--allow-empty-pcap")
                            run_logged(validator_command, log)
                            run_logged([sys.executable, str(indexer), str(dataset_root)], log)
                            run_logged([sys.executable, str(enriched_indexer), str(dataset_root)], log)
                        state["sessions"][key].update(status="completed", sample_dir=str(recovered), recovered=True, finished_at=dt.datetime.now(dt.timezone.utc).isoformat())
                        atomic_json(state_path, state)
                        print(f"RECOVER {key}: {recovered.name}")
                        continue
                    except Exception as exc:
                        state["sessions"][key].update(status="failed", error=f"recovery failed: {type(exc).__name__}: {exc}")
                        atomic_json(state_path, state)
            if previous.get("status") == "failed" and not args.retry_failed:
                print(f"SKIP {key}: failed previously (use --retry-failed)")
                failures += 1
                continue
            if previous.get("status") == "failed" and args.retry_failed:
                quarantine = state_dir / "incomplete"
                quarantine.mkdir(parents=True, exist_ok=True)
                for stale in find_seed_samples(dataset_root, batch_id, seed):
                    target = quarantine / stale.name
                    if stale.exists() and stale != target:
                        shutil.move(str(stale), str(target))
            scenario, metadata = prepare_session_config(batch, category, ordinal, overrides, seed)
            generated_path = generated_dir / f"{category}_{ordinal:06d}.yaml"
            generated_path.parent.mkdir(parents=True, exist_ok=True)
            scenario_definition = scenario.get("scenario_definition")
            if isinstance(scenario_definition, dict):
                workload_path = generated_dir / f"{category}_{ordinal:06d}_scenario.yaml"
                workload_path.write_text(yaml.safe_dump(scenario_definition, sort_keys=False), encoding="utf-8")
                scenario["scenario"] = str(workload_path)
            generated_path.write_text(yaml.safe_dump(scenario, sort_keys=False), encoding="utf-8")
            log_path = log_dir / f"{category}_{ordinal:06d}.log"
            log_path.parent.mkdir(parents=True, exist_ok=True)
            state["sessions"][key] = {
                "status": "running", "random_seed": seed, "scenario_config": str(generated_path),
                "scenario_config_hash": metadata["scenario_config_hash"], "log": str(log_path),
                "started_at": dt.datetime.now(dt.timezone.utc).isoformat(),
            }
            atomic_json(state_path, state)
            before = {str(path) for path in iter_sample_dirs(dataset_root)}
            try:
                with log_path.open("a", encoding="utf-8") as log:
                    command = [sys.executable, str(runner), "--config", str(generated_path), "--dataset-root", str(dataset_root)]
                    if args.lab_config:
                        command.extend(["--lab-config", str(args.lab_config.expanduser().resolve())])
                    if args.dry_run:
                        command.append("--dry-run")
                    run_logged(command, log)
                    after = {str(path) for path in iter_sample_dirs(dataset_root)}
                    created = sorted(after - before)
                    if len(created) != 1:
                        raise RuntimeError(f"expected exactly one new sample, found {len(created)}")
                    sample_dir = Path(created[0])
                    update_session_metadata(sample_dir, metadata, versions)
                    # Explicit per-round checks keep indexes current even if the runner changes.
                    validator_command = [sys.executable, str(validator), str(dataset_root)]
                    if args.dry_run:
                        validator_command.append("--allow-empty-pcap")
                    run_logged(validator_command, log)
                    run_logged([sys.executable, str(indexer), str(dataset_root)], log)
                    run_logged([sys.executable, str(enriched_indexer), str(dataset_root)], log)
                state["sessions"][key].update(
                    status="completed", sample_dir=str(sample_dir),
                    finished_at=dt.datetime.now(dt.timezone.utc).isoformat(),
                )
                print(f"OK   {key}: {sample_dir.name}")
            except Exception as exc:  # Continue is the batch default.
                failures += 1
                state["sessions"][key].update(
                    status="failed", error=f"{type(exc).__name__}: {exc}",
                    finished_at=dt.datetime.now(dt.timezone.utc).isoformat(),
                )
                with (state_dir / "failures.jsonl").open("a", encoding="utf-8") as handle:
                    handle.write(json.dumps({"session": key, **state["sessions"][key]}, ensure_ascii=False) + "\n")
                print(f"FAIL {key}: {exc}", file=sys.stderr)
                if args.fail_fast:
                    atomic_json(state_path, state)
                    return 1
            finally:
                atomic_json(state_path, state)

    completed = sum(item.get("status") == "completed" for item in state["sessions"].values())
    print(f"Batch {batch_id}: completed={completed}, failures={failures}, state={state_path}")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
