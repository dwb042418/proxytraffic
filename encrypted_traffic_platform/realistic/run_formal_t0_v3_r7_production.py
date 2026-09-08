#!/usr/bin/env python3
"""Formal T0 v3 R7 schedule orchestrator.

This is a thin, fail-closed production layer over the preregistered and
validated v3 capture/retry components.  ``--dry-run`` is strictly read-only
with respect to both Formal roots.  Actual collection requires an explicit
``--run`` or ``--resume`` action and the final frozen Git commit.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import importlib.util
import json
import os
import shlex
import shutil
import stat
import subprocess
import sys
import tempfile
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Iterable


ORCHESTRATOR_VERSION = "formal-t0-v3-r7-production-v1"
DATASET_TRACK = "realistic_t0_v3_r7"
ARTIFACT_CLASS = "FORMAL_PRODUCTION"
FORMAL_CLASSIFICATION = "FORMAL_T0_V3_R7_PRODUCTION"

REPO = Path("/home/etip/Tunnel/proxytraffic")
DOC = REPO / "docs/realistic_v1/formal_t0_v3"
LOCAL_PRODUCTION_ROOT = Path("/home/etip/datasets/staging/realistic_v1/t0_v3_r7")
REMOTE_PRODUCTION_ROOT = Path("/home/dataset-assist-0/duwenbiao/Tunnel/proxydata/realistic_v1/t0_v3_r7")
UPLOAD_HOST = "proxydata-server"
USER_HOST = "realistic-user"

POOL = DOC / "formal_domain_pool_v3_r7.tsv"
SPLIT = DOC / "formal_domain_split_v3_r7.tsv"
MANIFEST = DOC / "formal_t0_v3_plan_manifest_r7.tsv"
REGISTRY = DOC / "FORMAL_T0_V3_PLAN_SHA256SUMS_R7.txt"
SCHEDULE = DOC / "formal_t0_v3_schedule_r7.tsv"
RETRY_POLICY = DOC / "formal_transient_retry_policy_v4.txt"
RETRY_POLICY_FREEZE = DOC / "formal_transient_retry_policy_v4.sha256"
HEALTH_DEFINITION = DOC / "trojan_transport_qualification_v3_definition.txt"
ROOT_AMENDMENT = DOC / "formal_t0_v3_r7_production_root_amendment.txt"
RETIREMENT_RULE = DOC / "domain_contextual_retirement_rule_v2.txt"
CAPACITY_PROVENANCE = DOC / "realistic_v3_redsocks_capacity_deployment_audit_v1.txt"

CAPTURE_RUNNER = REPO / "encrypted_traffic_platform/realistic/run_single_quartet_v3_validation.py"
RETRY_RUNNER = REPO / "encrypted_traffic_platform/realistic/run_single_quartet_v3_validation_retry_v4.py"
FAILURE_CLASSIFIER = REPO / "encrypted_traffic_platform/realistic/formal_failure_classifier_v3.py"
EXECUTOR = REPO / "encrypted_traffic_platform/realistic/realistic_browser_v3.py"
SUPERVISOR = REPO / "encrypted_traffic_platform/scripts/realistic/realistic-executor-supervisor"
AUDITOR = REPO / "encrypted_traffic_platform/realistic/audit_realistic_sample.py"
NOFILE_DROPIN = Path("/etc/systemd/system/redsocks-realistic@.service.d/10-nofile.conf")

FROZEN_SHA256 = {
    POOL: "9139aaa16f04c837272fa966729118f76d4f3693f2a2a1b60c63dadc14d38756",
    SPLIT: "9f6f0663f24e7a05186d739510efa3685c382ffb8b74b4a7d1b2bf1ff03c92a3",
    MANIFEST: "84684f25fec5cd7672bc02737b929a32432a26be119e67a53cb77786d27dc830",
    REGISTRY: "4c5a1e0c6ad264076bbe2cf2faf431ff1036f9925cab276f99eacf89d02d0907",
    SCHEDULE: "5bc38db6a6a2e831a3620f35be4be363e219d8ad96af47fd1831cf20d970f90e",
    RETRY_POLICY: "48fb9290e9192d9068882693384ee24f37cc14c7bc40c9fdfe6e0d4b9f31d32a",
    HEALTH_DEFINITION: "b26988debe3b4fd147a986f31902a8e628209b3825d0f2798a847e0203a09ffb",
    ROOT_AMENDMENT: "3f7e2b5bccadbf781ed3f97961d8df7f120fdef9465e11cb37e7e1905cbf19c0",
    RETIREMENT_RULE: "107ffbe4aafaf6a37d52c7aa194bdde61536a1b6db8aff1e9b08d8071fee334b",
    CAPACITY_PROVENANCE: "b3d656a205298f93334aa566e772a5ab60b1073995c17eeea505d2fb7409baff",
    CAPTURE_RUNNER: "9fa8c0f67228a09282d541071f502ef112eb7b3cd1588ee7ae581a9de3085294",
    RETRY_RUNNER: "7fca6b92c56caa251703aa356dc22ff97e94bcade76ec19c5f92dbb194848a2b",
    FAILURE_CLASSIFIER: "c86b4ea1ce4cf74c486025a57e7aef325a39f0ea8f0c3eafa080488100893e98",
    EXECUTOR: "8e034da6979c463391f78ff95c4f98f76d675d44f72377980ab00e4636cc74a1",
    SUPERVISOR: "9a97f5912310d877f5ec24f09873f005ff6d9c4d0c0e4d4c583e1e423d7ee63c",
    AUDITOR: "bf4237d0ca62cc4a23bc2ee4cdc836e506002bc5da37c8344083c48acf14964a",
    NOFILE_DROPIN: "84d309f8f6fc709d431009c2f1a9eb2af946b9b66276a82fc60e14ad794c1fcf",
}

MODES = ("direct", "vless", "shadowsocks", "trojan")
REDSOCKS_UNITS = {
    "vless": "redsocks-realistic@vless.service",
    "shadowsocks": "redsocks-realistic@shadowsocks.service",
    "trojan": "redsocks-realistic@trojan.service",
}
MAX_ATTEMPTS_PER_SAMPLE = 3

MIN_FREE_BYTES = 20 * 1024**3

LEDGER_FIELDS = (
    "sample_id", "sequence_id", "pair_group_id", "mode", "attempt",
    "failure_class", "event_index", "url", "retry_authorized", "retry_reason",
    "failure_stage", "workload_started", "mode_purity", "bypass_observed",
    "plan_sha", "git_head", "attempt_start_utc", "attempt_end_utc",
    "browser_attempt_consumed", "final_status", "artifact_path",
)
EVICTION_FIELDS = (
    "sample_id", "sequence_id", "remote_path", "remote_sha_pass",
    "remote_complete_pass", "ledger_written_utc", "local_eviction_utc",
)


class PrecheckFail(RuntimeError):
    """A failure that must occur before proxy/capture/browser startup."""


class HardStop(RuntimeError):
    """A production condition that requires immediate human review."""


class RemoteArchivePending(RuntimeError):
    """Local sample is complete but archive connectivity is unavailable."""


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def safe_stamp(value: str | None = None) -> str:
    raw = value or utc_now()
    return "".join(ch for ch in raw if ch.isalnum())[:20]


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def run_command(
    command: list[str], timeout: int = 30, *, check: bool = False,
) -> subprocess.CompletedProcess[str]:
    try:
        completed = subprocess.run(
            command, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            timeout=timeout, check=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError(f"command timeout after {timeout}s: {shlex.join(command)}") from exc
    if check and completed.returncode != 0:
        raise RuntimeError(
            f"command failed rc={completed.returncode}: {shlex.join(command)}: "
            f"{completed.stderr[-2000:]}"
        )
    return completed


def atomic_write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary_path = Path(temporary)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="") as handle:
            handle.write(text)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary_path, path)
        directory_fd = os.open(path.parent, os.O_DIRECTORY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    finally:
        if temporary_path.exists():
            temporary_path.unlink()


def atomic_write_json(path: Path, value: object) -> None:
    atomic_write_text(path, json.dumps(value, indent=2, sort_keys=True) + "\n")


def read_tsv(path: Path) -> list[dict[str, str]]:
    with path.open(newline="", encoding="utf-8") as handle:
        return list(csv.DictReader(handle, delimiter="\t"))


def read_ledger(path: Path) -> list[dict[str, str]]:
    if not path.exists():
        return []
    with path.open(newline="", encoding="utf-8") as handle:
        reader = csv.DictReader(handle, delimiter="\t")
        if tuple(reader.fieldnames or ()) != LEDGER_FIELDS:
            raise HardStop("retry ledger header mismatch")
        return list(reader)


def atomic_write_rows(path: Path, fields: tuple[str, ...], rows: list[dict[str, object]]) -> None:
    output: list[str] = []
    with tempfile.SpooledTemporaryFile(mode="w+", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields, delimiter="\t", lineterminator="\n")
        writer.writeheader()
        for row in rows:
            writer.writerow({field: row.get(field, "") for field in fields})
        handle.seek(0)
        output.append(handle.read())
    atomic_write_text(path, "".join(output))


def append_ledger_atomic(path: Path, rows: list[dict[str, object]]) -> None:
    existing: list[dict[str, object]] = list(read_ledger(path))
    existing.extend(rows)
    atomic_write_rows(path, LEDGER_FIELDS, existing)


def parse_registry() -> dict[Path, str]:
    registry: dict[Path, str] = {}
    for line in REGISTRY.read_text(encoding="utf-8").splitlines():
        digest, filename = line.split(maxsplit=1)
        path = Path(filename)
        if path in registry:
            raise PrecheckFail(f"duplicate plan registry path: {path}")
        registry[path] = digest
    if len(registry) != 300:
        raise PrecheckFail(f"plan registry entries={len(registry)} expected=300")
    return registry


def verify_frozen_sha() -> None:
    mismatches = [
        f"{path}:{sha256(path) if path.is_file() else 'MISSING'}!={expected}"
        for path, expected in FROZEN_SHA256.items()
        if not path.is_file() or sha256(path) != expected
    ]
    if mismatches:
        raise PrecheckFail("frozen SHA mismatch: " + "; ".join(mismatches))


def verify_git(frozen_git_head: str, *, verify_origin: bool) -> dict[str, str]:
    if len(frozen_git_head) != 40 or any(ch not in "0123456789abcdef" for ch in frozen_git_head):
        raise PrecheckFail("frozen Git HEAD must be a lowercase 40-character SHA-1")
    local = run_command(["git", "-C", str(REPO), "rev-parse", "HEAD"], check=True).stdout.strip()
    if local != frozen_git_head:
        raise PrecheckFail(f"Git HEAD mismatch local={local} expected={frozen_git_head}")
    tracked = run_command(
        ["git", "-C", str(REPO), "status", "--porcelain=v1", "--untracked-files=no"], check=True,
    ).stdout.strip()
    if tracked:
        raise PrecheckFail(f"tracked worktree is not clean: {tracked}")
    result = {"local_head": local}
    if verify_origin:
        remote = run_command(
            ["git", "-C", str(REPO), "ls-remote", "origin", "refs/heads/main"],
            timeout=30, check=True,
        ).stdout.split()[0]
        if remote != frozen_git_head:
            raise PrecheckFail(f"origin/main mismatch remote={remote} expected={frozen_git_head}")
        result["actual_origin_main"] = remote
    return result


def verify_orchestrator_at_head() -> None:
    path = Path(__file__).resolve()
    try:
        relative = path.relative_to(REPO).as_posix()
    except ValueError as exc:
        raise PrecheckFail("production orchestrator is outside the frozen repository") from exc
    tracked = run_command([
        "git", "-C", str(REPO), "ls-files", "--error-unmatch", relative,
    ])
    if tracked.returncode != 0:
        raise PrecheckFail("production orchestrator is not tracked at frozen Git HEAD")
    blob = run_command([
        "git", "-C", str(REPO), "show", f"HEAD:{relative}",
    ], check=True).stdout.encode("utf-8")
    if hashlib.sha256(blob).hexdigest() != sha256(path):
        raise PrecheckFail("production orchestrator differs from frozen Git HEAD")


def verify_root_amendment() -> None:
    values: dict[str, str] = {}
    for line in ROOT_AMENDMENT.read_text(encoding="utf-8").splitlines():
        if "=" in line:
            key, value = line.split("=", 1)
            values[key] = value
    expected = {
        "status": "PREREGISTERED_ROOT_AMENDMENT",
        "formal_samples_started": "0",
        "LOCAL_PRODUCTION_ROOT": str(LOCAL_PRODUCTION_ROOT),
        "REMOTE_PRODUCTION_ROOT": str(REMOTE_PRODUCTION_ROOT),
        "scope": "FORMAL_T0_V3_R7_PRODUCTION_ONLY",
        "r2_production_root_reuse": "PROHIBITED",
        "r2_valid_samples_final_dataset_eligible": "NO",
        "r3_production_root_reuse": "PROHIBITED",
        "r3_valid_samples_final_dataset_eligible": "NO",
        "r2_r3_resume_source": "PROHIBITED",
        "r4_resume_source": "PROHIBITED",
        "r5_resume_source": "PROHIBITED",
        "r1_production_root_reuse": "PROHIBITED",
        "r4_production_root_reuse": "PROHIBITED",
        "r5_production_root_reuse": "PROHIBITED",
        "production_root_change_during_production": "PROHIBITED",
    }
    if any(values.get(key) != value for key, value in expected.items()):
        raise PrecheckFail("production root amendment content mismatch")


def audit_schedule_and_plans() -> tuple[list[dict[str, str]], dict[Path, str], dict[str, object]]:
    registry = parse_registry()
    plan_sha_pass = 0
    plan_permissions_0444 = 0
    for path, expected in registry.items():
        if path.is_file() and sha256(path) == expected:
            plan_sha_pass += 1
        if path.is_file() and stat.S_IMODE(path.stat().st_mode) == 0o444:
            plan_permissions_0444 += 1
    if plan_sha_pass != 300 or plan_permissions_0444 != 300:
        raise PrecheckFail(
            f"plan integrity failed sha={plan_sha_pass}/300 permissions={plan_permissions_0444}/300"
        )

    pool = read_tsv(POOL)
    split = read_tsv(SPLIT)
    manifest = read_tsv(MANIFEST)
    schedule = read_tsv(SCHEDULE)
    issues: list[str] = []
    pool_domains = [row["domain"] for row in pool]
    split_domains = [row["domain"] for row in split]
    if len(pool) != 500 or len(set(pool_domains)) != 500:
        issues.append("domain_pool")
    if len(split) != 500 or set(split_domains) != set(pool_domains) or len(set(split_domains)) != 500:
        issues.append("domain_split")
    if Counter(row["split"] for row in split) != Counter({"train": 300, "validation": 50, "test": 150}):
        issues.append("split_counts")
    if len(manifest) != 300:
        issues.append("plan_manifest_count")

    manifest_by_group = {row["pair_group_id"]: row for row in manifest}
    if len(manifest_by_group) != 300:
        issues.append("manifest_pair_groups")
    grouped: dict[str, list[dict[str, str]]] = defaultdict(list)
    sequences: set[int] = set()
    for row in schedule:
        grouped[row["pair_group_id"]].append(row)
        sequences.add(int(row["sequence_id"]))
    if len(schedule) != 1200 or sequences != set(range(1, 1201)):
        issues.append("schedule_sequence")
    if len(grouped) != 300:
        issues.append("schedule_pair_groups")
    if Counter(row["mode_order"] for row in schedule) != Counter({mode: 300 for mode in MODES}):
        issues.append("schedule_mode_counts")
    immutable_fields = (
        ("plan_id", "plan_id"), ("plan_path", "plan_path"),
        ("plan_sha256", "plan_sha256"), ("seed", "seed"),
        ("split", "split"), ("intensity", "intensity"),
    )
    for group_id, rows in grouped.items():
        manifest_row = manifest_by_group.get(group_id)
        if (
            len(rows) != 4
            or {row["mode_order"] for row in rows} != set(MODES)
            or {int(row["mode_position"]) for row in rows} != {1, 2, 3, 4}
            or manifest_row is None
            or any(row[schedule_key] != manifest_row[manifest_key]
                   for row in rows for schedule_key, manifest_key in immutable_fields)
        ):
            issues.append(f"pair_group:{group_id}")
    for row in schedule:
        path = Path(row["plan_path"])
        if registry.get(path) != row["plan_sha256"]:
            issues.append(f"registry_schedule:{row['sequence_id']}")
    if issues:
        raise PrecheckFail("schedule integrity issues: " + ",".join(issues[:20]))
    schedule.sort(key=lambda row: int(row["sequence_id"]))
    audit = {
        "domains": 500,
        "plans": 300,
        "pair_groups": 300,
        "schedule_rows": 1200,
        "mode_counts": {mode: 300 for mode in MODES},
        "plan_sha_pass": "300/300",
        "plan_permissions_0444": "300/300",
        "schedule_integrity": "PASS",
        "integrity_issues": 0,
    }
    return schedule, registry, audit


def verify_retry_policy() -> dict[str, object]:
    expected = FROZEN_SHA256[RETRY_POLICY]
    if sha256(RETRY_POLICY) != expected:
        raise PrecheckFail("retry policy SHA mismatch")
    if RETRY_POLICY_FREEZE.read_text(encoding="utf-8").split() != [expected, RETRY_POLICY.name]:
        raise PrecheckFail("retry policy freeze record mismatch")
    text = RETRY_POLICY.read_text(encoding="utf-8")
    values = dict(line.split("=", 1) for line in text.splitlines() if "=" in line)
    maximum = int(values["MAX_ATTEMPTS_PER_SAMPLE"])
    if maximum != MAX_ATTEMPTS_PER_SAMPLE:
        raise PrecheckFail("production attempt limit differs from frozen retry policy")
    section = text.split("\nRETRYABLE_FAILURE_CLASSES\n", 1)[1].split("\nRETRY_AUTHORIZATION_GATES\n", 1)[0]
    classes = {line.split("=", 1)[0] for line in section.splitlines() if line.strip()}
    return {"max_attempts": maximum, "retryable_classes": classes}


def verify_redsocks_unit_definitions() -> dict[str, dict[str, object]]:
    if sha256(NOFILE_DROPIN) != FROZEN_SHA256[NOFILE_DROPIN]:
        raise PrecheckFail("redsocks NOFILE drop-in SHA mismatch")
    evidence: dict[str, dict[str, object]] = {}
    for mode, unit in REDSOCKS_UNITS.items():
        completed = run_command([
            "systemctl", "show", unit, "-p", "LimitNOFILE", "-p", "LimitNOFILESoft",
            "-p", "FragmentPath", "-p", "DropInPaths",
        ], check=True)
        values = dict(line.split("=", 1) for line in completed.stdout.splitlines() if "=" in line)
        if values.get("LimitNOFILESoft") != "2048" or values.get("LimitNOFILE") != "524288":
            raise PrecheckFail(f"redsocks unit NOFILE mismatch: {unit}")
        if str(NOFILE_DROPIN) not in values.get("DropInPaths", "").split():
            raise PrecheckFail(f"redsocks unit missing template drop-in: {unit}")
        evidence[mode] = {
            "unit": unit,
            "soft_nofile": 2048,
            "hard_nofile": 524288,
            "fragment_path": values.get("FragmentPath"),
            "dropin_paths": values.get("DropInPaths", "").split(),
        }
    return evidence


def free_disk_bytes() -> int:
    return shutil.disk_usage("/").free


def verify_remote_connectivity() -> None:
    completed = run_command([
        "ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=10", UPLOAD_HOST,
        "echo", "PROXYDATA_SERVER_PASS",
    ], timeout=20)
    if completed.returncode != 0 or completed.stdout.strip() != "PROXYDATA_SERVER_PASS":
        raise PrecheckFail(f"remote archive connectivity failed: {completed.stderr[-1000:]}")
    quoted = shlex.quote(str(REMOTE_PRODUCTION_ROOT))
    completed = run_command([
        "ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=10", UPLOAD_HOST,
        f"test -d {quoted}",
    ], timeout=20)
    if completed.returncode != 0:
        raise PrecheckFail("remote production root missing")


def remote_reachable() -> bool:
    return run_command([
        "ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=10", UPLOAD_HOST, "true",
    ], timeout=20).returncode == 0


def configure_execution_components():
    spec = importlib.util.spec_from_file_location("formal_t0_v3_r7_retry_component", RETRY_RUNNER)
    module = importlib.util.module_from_spec(spec)
    if spec.loader is None:
        raise RuntimeError("could not load retry component")
    spec.loader.exec_module(module)
    policy = verify_retry_policy()
    if module.MAX_ATTEMPTS_PER_SAMPLE != policy["max_attempts"] or module.POLICY_SHA256 != FROZEN_SHA256[RETRY_POLICY]:
        raise PrecheckFail("validated retry component policy mismatch")
    module.RETRYABLE = policy["retryable_classes"]
    base = module.base
    base.POOL = POOL
    base.SPLIT = SPLIT
    base.REGISTRY = REGISTRY
    base.SCHEDULE = SCHEDULE
    base.FROZEN_SHA256 = {
        POOL: FROZEN_SHA256[POOL], SPLIT: FROZEN_SHA256[SPLIT],
        REGISTRY: FROZEN_SHA256[REGISTRY], SCHEDULE: FROZEN_SHA256[SCHEDULE],
    }
    return module


def row_identity(row: dict[str, str]) -> dict[str, object]:
    return {
        "sequence_id": int(row["sequence_id"]),
        "sample_id": row["schedule_id"],
        "pair_group_id": row["pair_group_id"],
        "seed": row["seed"],
        "split": row["split"],
        "intensity": row["intensity"],
        "mode": row["mode_order"],
        "plan_path": row["plan_path"],
        "plan_sha256": row["plan_sha256"],
    }


def selection_from_row(row: dict[str, str]) -> dict[str, object]:
    return {
        "quartet_index": int(row["quartet_index"]),
        "seed": row["seed"],
        "seed_assignment_id": row["seed_assignment_id"],
        "split": row["split"],
        "intensity": row["intensity"],
        "pair_group_id": row["pair_group_id"],
        "plan_id": row["plan_id"],
        "plan_path": row["plan_path"],
        "plan_sha256": row["plan_sha256"],
        "mode_order": [row["mode_order"]],
    }


def validate_metadata(metadata: dict[str, object], row: dict[str, str], frozen_git_head: str) -> bool:
    identity = row_identity(row)
    return (
        metadata.get("dataset_track") == DATASET_TRACK
        and metadata.get("artifact_class") == ARTIFACT_CLASS
        and metadata.get("formal_manifest_eligible") is True
        and metadata.get("frozen_git_head") == frozen_git_head
        and all(metadata.get(key) == value for key, value in identity.items())
        and metadata.get("frozen_sha256") == {
            "final500": FROZEN_SHA256[POOL],
            "split": FROZEN_SHA256[SPLIT],
            "plan_registry": FROZEN_SHA256[REGISTRY],
            "schedule": FROZEN_SHA256[SCHEDULE],
            "retry_policy": FROZEN_SHA256[RETRY_POLICY],
            "health_definition": FROZEN_SHA256[HEALTH_DEFINITION],
            "production_root_amendment": FROZEN_SHA256[ROOT_AMENDMENT],
        }
    )


def load_json(path: Path) -> dict[str, object]:
    return json.loads(path.read_text(encoding="utf-8"))


def verify_checksum_manifest(root: Path, manifest_name: str) -> bool:
    manifest = root / manifest_name
    if not manifest.is_file():
        return False
    for line in manifest.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        digest, relative = line.split(maxsplit=1)
        relative = relative.lstrip("* ")
        candidate = (root / relative).resolve()
        try:
            candidate.relative_to(root.resolve())
        except ValueError:
            return False
        if not candidate.is_file() or sha256(candidate) != digest:
            return False
    return True


def local_complete_valid(sample_root: Path, row: dict[str, str], frozen_git_head: str) -> bool:
    required = (
        "SAMPLE_COMPLETE", "sample_metadata.json", "remote_sha_verification.json",
        "SHA256SUMS.txt", "FINAL_METADATA_SHA256SUMS.txt",
    )
    if not all((sample_root / name).is_file() for name in required):
        return False
    try:
        metadata = load_json(sample_root / "sample_metadata.json")
        remote = load_json(sample_root / "remote_sha_verification.json")
    except (OSError, ValueError, TypeError):
        return False
    return (
        validate_metadata(metadata, row, frozen_git_head)
        and remote.get("remote_sha_pass") is True
        and remote.get("remote_completeness_pass") is True
        and verify_checksum_manifest(sample_root, "SHA256SUMS.txt")
        and verify_checksum_manifest(sample_root, "FINAL_METADATA_SHA256SUMS.txt")
    )


def remote_sample_path(sample_id: str) -> str:
    return f"{REMOTE_PRODUCTION_ROOT}/samples/{sample_id}"


def remote_complete_valid(row: dict[str, str], frozen_git_head: str) -> bool:
    remote = remote_sample_path(row["schedule_id"])
    quoted = shlex.quote(remote)
    check = run_command([
        "ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=10", UPLOAD_HOST,
        f"cd {quoted} && test -f SAMPLE_COMPLETE && test -f sample_metadata.json "
        "&& test -f remote_sha_verification.json && test -f SHA256SUMS.txt "
        "&& test -f FINAL_METADATA_SHA256SUMS.txt "
        "&& sha256sum -c SHA256SUMS.txt >/dev/null "
        "&& sha256sum -c FINAL_METADATA_SHA256SUMS.txt >/dev/null",
    ], timeout=1800)
    if check.returncode != 0:
        return False
    metadata_result = run_command([
        "ssh", "-o", "BatchMode=yes", UPLOAD_HOST, f"cat {quoted}/sample_metadata.json",
    ], timeout=30)
    verification_result = run_command([
        "ssh", "-o", "BatchMode=yes", UPLOAD_HOST, f"cat {quoted}/remote_sha_verification.json",
    ], timeout=30)
    if metadata_result.returncode != 0 or verification_result.returncode != 0:
        return False
    try:
        metadata = json.loads(metadata_result.stdout)
        verification = json.loads(verification_result.stdout)
    except json.JSONDecodeError:
        return False
    return (
        validate_metadata(metadata, row, frozen_git_head)
        and verification.get("remote_sha_pass") is True
        and verification.get("remote_completeness_pass") is True
    )


def resume_decision(
    row: dict[str, str], local_root: Path, remote_valid: bool,
    ledger_rows: list[dict[str, str]], frozen_git_head: str,
) -> str:
    sample_id = row["schedule_id"]
    sample_root = local_root / "samples" / sample_id
    in_progress = local_root / "in_progress" / sample_id
    failed_root = local_root / "failed_artifacts" / sample_id
    local_valid = local_complete_valid(sample_root, row, frozen_git_head) if sample_root.exists() else False
    if remote_valid and (local_valid or not sample_root.exists()):
        return "SKIP_VALID_COMPLETE" if local_valid else "SKIP_VALID_COMPLETE_REMOTE_ONLY"
    if sample_root.exists():
        if (sample_root / "REMOTE_ARCHIVE_PENDING").exists() and verify_checksum_manifest(sample_root, "SHA256SUMS.txt"):
            return "RESUME_REMOTE_ARCHIVE_ONLY"
        return "REVIEW_REQUIRED"
    sample_ledger = [item for item in ledger_rows if item.get("sample_id") == sample_id]
    if sample_ledger:
        last = max(sample_ledger, key=lambda item: int(item["attempt"]))
        attempt = int(last["attempt"])
        if last.get("final_status") == "PASS":
            return "REVIEW_REQUIRED_REMOTE_COMPLETE_NOT_VALIDATED"
        if attempt >= MAX_ATTEMPTS_PER_SAMPLE and last.get("final_status") != "PASS":
            return "HARD_STOP_ATTEMPT3_FAILED"
        pending_attempts = in_progress / "attempts"
        if pending_attempts.exists() and any(pending_attempts.iterdir()):
            return "REVIEW_REQUIRED"
        if 1 <= attempt < MAX_ATTEMPTS_PER_SAMPLE and last.get("retry_authorized") == "true" and last.get("final_status") != "PASS":
            return f"RUN_ATTEMPT{attempt + 1}"
        if last.get("final_status") != "PASS":
            return "HARD_STOP_NON_RETRYABLE"
    if in_progress.exists() or failed_root.exists():
        return "REVIEW_REQUIRED"
    return "RUN_ATTEMPT1"


def remote_exists_for_row(row: dict[str, str]) -> bool:
    quoted = shlex.quote(remote_sample_path(row["schedule_id"]))
    return run_command([
        "ssh", "-o", "BatchMode=yes", UPLOAD_HOST, f"test -e {quoted}",
    ], timeout=20).returncode == 0


def scan_resume_state(
    schedule: list[dict[str, str]], local_root: Path, frozen_git_head: str,
    remote_probe: Callable[[dict[str, str], str], bool] | None = None,
) -> dict[str, object]:
    ledger = read_ledger(local_root / "formal_t0_v3_r7_retry_ledger.tsv")
    decisions: list[dict[str, object]] = []
    completed: list[dict[str, str]] = []
    probe = remote_probe or remote_complete_valid
    next_action = "ALL_COMPLETE"
    next_sequence = 1201
    for row in schedule:
        sample_root = local_root / "samples" / row["schedule_id"]
        local_valid = local_complete_valid(sample_root, row, frozen_git_head) if sample_root.exists() else False
        remote_candidate = local_valid or remote_exists_for_row(row) if remote_probe is None else True
        remote_valid = probe(row, frozen_git_head) if remote_candidate else False
        decision = resume_decision(row, local_root, remote_valid, ledger, frozen_git_head)
        decisions.append({"sequence_id": int(row["sequence_id"]), "sample_id": row["schedule_id"], "decision": decision})
        if decision.startswith("SKIP_VALID_COMPLETE"):
            completed.append(row)
            continue
        next_action = decision
        next_sequence = int(row["sequence_id"])
        break
    complete_groups = Counter(row["pair_group_id"] for row in completed)
    return {
        "valid_samples": len(completed),
        "complete_pair_groups": sum(count == 4 for count in complete_groups.values()),
        "next_sequence_id": next_sequence,
        "next_action": next_action,
        "mode_counts": dict(Counter(row["mode_order"] for row in completed)),
        "decisions": decisions,
    }


def verify_no_out_of_order_artifacts(
    schedule: list[dict[str, str]], next_sequence_id: int,
) -> None:
    sequence_by_id = {row["schedule_id"]: int(row["sequence_id"]) for row in schedule}
    future: list[str] = []
    unknown: list[str] = []
    for namespace in ("samples", "in_progress", "failed_artifacts"):
        root = LOCAL_PRODUCTION_ROOT / namespace
        if not root.is_dir():
            continue
        for child in root.iterdir():
            if not child.is_dir():
                continue
            sequence = sequence_by_id.get(child.name)
            if sequence is None:
                unknown.append(f"local:{namespace}/{child.name}")
            elif sequence > next_sequence_id:
                future.append(f"local:{namespace}/{child.name}")
    for namespace in ("samples", ".incoming"):
        remote_namespace = f"{REMOTE_PRODUCTION_ROOT}/{namespace}"
        quoted = shlex.quote(remote_namespace)
        completed = run_command([
            "ssh", "-o", "BatchMode=yes", UPLOAD_HOST,
            f"if test -d {quoted}; then find {quoted} -mindepth 1 -maxdepth 1 -type d -printf '%f\\n'; fi",
        ], timeout=60)
        if completed.returncode != 0:
            raise PrecheckFail(f"could not audit remote {namespace} namespace")
        for sample_id in completed.stdout.splitlines():
            sequence = sequence_by_id.get(sample_id)
            if sequence is None:
                unknown.append(f"remote:{namespace}/{sample_id}")
            elif sequence > next_sequence_id:
                future.append(f"remote:{namespace}/{sample_id}")
    if unknown or future:
        raise HardStop(
            "out-of-order or unknown Formal artifacts: "
            + ",".join((unknown + future)[:20])
        )


def dry_run(frozen_git_head: str) -> dict[str, object]:
    git = verify_git(frozen_git_head, verify_origin=True)
    verify_frozen_sha()
    verify_root_amendment()
    policy = verify_retry_policy()
    configure_execution_components()
    schedule, _, integrity = audit_schedule_and_plans()
    if not LOCAL_PRODUCTION_ROOT.is_dir():
        raise PrecheckFail("local production root missing")
    verify_remote_connectivity()
    redsocks = verify_redsocks_unit_definitions()
    if free_disk_bytes() < MIN_FREE_BYTES:
        raise PrecheckFail("free disk below 20 GiB")
    state = scan_resume_state(schedule, LOCAL_PRODUCTION_ROOT, frozen_git_head)
    if state["next_action"].startswith(("HARD_STOP", "REVIEW_REQUIRED")):
        raise PrecheckFail(f"resume requires review: {state['next_action']}")
    verify_no_out_of_order_artifacts(schedule, int(state["next_sequence_id"]))
    remote_disk = run_command(["ssh", "-o", "BatchMode=yes", UPLOAD_HOST,
        f"df -B1 --output=avail {shlex.quote(str(REMOTE_PRODUCTION_ROOT))}"], check=True)
    remote_free = int(remote_disk.stdout.splitlines()[-1].strip())
    if remote_free < MIN_FREE_BYTES:
        raise PrecheckFail("remote free disk below 20 GiB")
    remote_count = run_command(["ssh", "-o", "BatchMode=yes", UPLOAD_HOST,
        f"find {shlex.quote(str(REMOTE_PRODUCTION_ROOT))} -type f -name SAMPLE_COMPLETE | wc -l"], check=True)
    local_count = sum(1 for _ in LOCAL_PRODUCTION_ROOT.rglob("SAMPLE_COMPLETE"))
    return {
        "status": "PASS",
        "action": "DRY_RUN",
        "formal_sample_started": False,
        "dataset_track": DATASET_TRACK,
        "artifact_class": ARTIFACT_CLASS,
        "orchestrator_version": ORCHESTRATOR_VERSION,
        "orchestrator_sha256": sha256(Path(__file__)),
        "git": git,
        "frozen_sha256": {str(path): value for path, value in FROZEN_SHA256.items()},
        "local_production_root": str(LOCAL_PRODUCTION_ROOT),
        "remote_production_root": str(REMOTE_PRODUCTION_ROOT),
        "free_disk_bytes": free_disk_bytes(),
        "remote_free_disk_bytes": remote_free,
        "local_sample_count": local_count,
        "remote_sample_count": int(remote_count.stdout.strip()),
        "max_attempts_per_sample": policy["max_attempts"],
        "retryable_classes_from_frozen_policy": sorted(policy["retryable_classes"]),
        "attempt3_support": True,
        "redsocks_unit_definitions": redsocks,
        "resume_state": state,
        **integrity,
    }


def create_checksum_manifest(root: Path, name: str, excluded: Iterable[str]) -> None:
    excluded_set = set(excluded) | {name}
    rows = []
    for path in sorted(item for item in root.rglob("*") if item.is_file()):
        relative = path.relative_to(root).as_posix()
        if relative in excluded_set or path.name in excluded_set:
            continue
        rows.append(f"{sha256(path)}  {relative}\n")
    atomic_write_text(root / name, "".join(rows))
    if not verify_checksum_manifest(root, name):
        raise HardStop(f"local SHA verification failed: {name}")


def formalize_attempt(
    attempt_dir: Path, row: dict[str, str], result: dict[str, object],
    attempt: int, attempt_start: str, attempt_end: str, frozen_git_head: str,
) -> None:
    for old, new in (
        ("VALIDATION_ATTEMPT_PASS", "FORMAL_ATTEMPT_PASS"),
        ("VALIDATION_ATTEMPT_FAIL", "FORMAL_ATTEMPT_FAIL"),
    ):
        old_path = attempt_dir / old
        if old_path.exists():
            old_path.replace(attempt_dir / new)
    identity = row_identity(row)
    pairing = {
        "dataset_track": DATASET_TRACK,
        "artifact_class": ARTIFACT_CLASS,
        "formal_manifest_eligible": True,
        "pair_group_id": row["pair_group_id"],
        "plan_id": row["plan_id"],
        "workload_plan_sha256": row["plan_sha256"],
        "seed": row["seed"],
        "split": row["split"],
        "intensity": row["intensity"],
        "mode": row["mode_order"],
        "attempt": attempt,
    }
    atomic_write_json(attempt_dir / "pairing.json", pairing)
    atomic_write_json(attempt_dir / "formal_attempt_provenance.json", {
        **identity,
        "dataset_track": DATASET_TRACK,
        "artifact_class": ARTIFACT_CLASS,
        "formal_manifest_eligible": True,
        "attempt": attempt,
        "attempt_start_utc": attempt_start,
        "attempt_end_utc": attempt_end,
        "frozen_git_head": frozen_git_head,
        "orchestrator_version": ORCHESTRATOR_VERSION,
        "orchestrator_sha256": sha256(Path(__file__)),
        "component_result": result,
    })
    (attempt_dir / FORMAL_CLASSIFICATION).write_text(
        f"dataset_track={DATASET_TRACK}\nartifact_class={ARTIFACT_CLASS}\nformal_manifest_eligible=true\n",
        encoding="utf-8",
    )


def prepare_remote_inputs(retry, row: dict[str, str], remote_exec_root: str) -> None:
    base = retry.base
    input_root = f"{remote_exec_root}/input"
    plan_path = Path(row["plan_path"])
    base.run(["ssh", "-o", "BatchMode=yes", USER_HOST, "mkdir", "-p", input_root], 30, True)
    base.run(["scp", "-q", str(EXECUTOR), str(plan_path), f"{USER_HOST}:{input_root}/"], 120, True)
    hashes = base.run([
        "ssh", "-o", "BatchMode=yes", USER_HOST, "sha256sum",
        f"{input_root}/{EXECUTOR.name}", f"{input_root}/{plan_path.name}",
    ], 30, True).stdout
    expected = {FROZEN_SHA256[EXECUTOR], row["plan_sha256"]}
    if {line.split()[0] for line in hashes.splitlines()} != expected:
        raise PrecheckFail("remote immutable input SHA mismatch")
    base.run([
        "ssh", "-o", "BatchMode=yes", USER_HOST, "cp",
        f"{input_root}/{plan_path.name}", f"{input_root}/workload_plan.json",
    ], 30, True)


def assert_final_attempt(result: dict[str, object], row: dict[str, str]) -> None:
    capture = result.get("capture", {})
    browser = result.get("browser", {})
    expected_conn_max: object = "NOT_APPLICABLE" if row["mode_order"] == "direct" else 256
    failures = {
        "status": result.get("status") == "PASS",
        "pre_health": result.get("pre_health") == "PASS",
        "post_health": result.get("post_health") == "PASS",
        "mode_purity": result.get("mode_purity") == "PASS",
        "actual_conn_max": result.get("redsocks_actual_conn_max") == expected_conn_max,
        "conn_max_hits": int(result.get("redsocks_conn_max_hits", -1)) == 0,
        "capture": isinstance(capture, dict) and capture.get("status") == "PASS",
        "browser_bounded": (
            isinstance(capture, dict) and capture.get("executor_bounded") is True
            and capture.get("executor_watchdog_timeout") is False
        ),
        "browser_workload": (
            isinstance(browser, dict) and browser.get("outcome") == "PASS"
            and int(browser.get("hard_failure_count", -1)) == 0
            and int(browser.get("success_count", -1)) == int(browser.get("event_count", -2))
        ),
        "pcap_stable": isinstance(capture, dict) and capture.get("pcap_stable_size") is True,
        "active_health_probe": isinstance(capture, dict) and int(capture.get("active_health_probe_during_capture", -1)) == 0,
        "oom": isinstance(capture, dict) and int(capture.get("oom", -1)) == 0,
        "unexpected_exit": isinstance(capture, dict) and int(capture.get("unexpected_process_exit", -1)) == 0,
        "residual": int(result.get("residual", -1)) == 0,
        "plan_sha": result.get("plan_sha256") == row["plan_sha256"],
    }
    failed = [name for name, passed in failures.items() if not passed]
    if failed:
        raise HardStop("final attempt gates failed: " + ",".join(failed))


def ledger_row_for_attempt(
    row: dict[str, str], result: dict[str, object], attempt: int,
    allowed: bool, reason: str, start: str, end: str, frozen_git_head: str,
    final_status: str,
) -> dict[str, object]:
    capture = result.get("capture") if isinstance(result.get("capture"), dict) else {}
    browser_consumed = capture.get("status") != "NOT_STARTED"
    return {
        "sample_id": row["schedule_id"],
        "sequence_id": row["sequence_id"],
        "pair_group_id": row["pair_group_id"],
        "mode": row["mode_order"],
        "attempt": attempt,
        "failure_class": result.get("failure_class", ""),
        "event_index": result.get("failure_event_index", ""),
        "failure_stage": result.get("failure_stage", ""),
        "workload_started": str(result.get("workload_started", "UNKNOWN")).lower(),
        "mode_purity": result.get("mode_purity", "NOT_ESTABLISHED"),
        "bypass_observed": str("proxy_public_443_bypass" in result.get("mode_purity_issues", [])).lower(),
        "url": result.get("failure_url", ""),
        "retry_authorized": str(allowed).lower(),
        "retry_reason": reason,
        "plan_sha": row["plan_sha256"],
        "git_head": frozen_git_head,
        "attempt_start_utc": start,
        "attempt_end_utc": end,
        "browser_attempt_consumed": str(browser_consumed).lower(),
        "final_status": final_status,
        "artifact_path": result.get("artifact_dir", ""),
    }


def synthetic_component_failure(
    retry, row: dict[str, str], attempt: int, attempts_root: Path,
    exc: BaseException,
) -> dict[str, object]:
    base = retry.base
    base.cleanup_mode()
    attempt_dir = attempts_root / f"attempt_{attempt}"
    attempt_dir.mkdir(parents=True, exist_ok=True)
    browser_residual = int(base.run([
        "ssh", "-o", "BatchMode=yes", USER_HOST, "bash", "-lc",
        "pgrep -c chrome-headless 2>/dev/null || true",
    ], 20).stdout.strip() or "0")
    local_tcpdump = int(bool(base.run([
        "sudo", "-n", "pgrep", "-f", "^tcpdump .*realistic.*\\.pcap",
    ], 10).stdout.strip()))
    remote_tcpdump = int(bool(base.run([
        "ssh", "-o", "BatchMode=yes", base.SERVER_HOST, "sudo", "-n", "pgrep", "-f",
        "^tcpdump .*proxytraffic-realistic.*\\.pcap",
    ], 20).stdout.strip()))
    residual = browser_residual + local_tcpdump + remote_tcpdump
    error = f"{type(exc).__name__}: {exc}"
    atomic_write_text(attempt_dir / "component_exception.log", error + "\n")
    result: dict[str, object] = {
        "classification": FORMAL_CLASSIFICATION,
        "retry_policy": "FORMAL_T0_V3_TRANSIENT_RETRY_POLICY_V4",
        "mode": row["mode_order"],
        "attempt": attempt,
        "status": "FAIL",
        "artifact_dir": str(attempt_dir),
        "failure_class": "CAPTURE_FINALIZATION_FAIL",
        "failure_event_index": "",
        "failure_url": "",
        "failure_error": error,
        "pre_health": "UNKNOWN",
        "post_health": "UNKNOWN",
        "mode_purity": "NOT_ESTABLISHED",
        "redsocks_actual_conn_max": "UNKNOWN",
        "redsocks_conn_max_hits": -1,
        "infrastructure_health_lost": 1,
        "server_egress_degraded": 1,
        "trojan_public_path_degraded": int(row["mode_order"] == "trojan"),
        "plan_sha256": row["plan_sha256"],
        "capture": {
            "status": "FAIL", "pcap_stable_size": False,
            "active_health_probe_during_capture": -1, "oom": -1,
            "unexpected_process_exit": -1,
        },
        "residual": residual,
        "attempt_finished_utc": utc_now(),
    }
    atomic_write_json(attempt_dir / "formal_component_failure_result.json", result)
    return result


def move_failed_attempt(attempt_dir: Path, row: dict[str, str], result: dict[str, object]) -> Path:
    failure = str(result.get("failure_class") or "UNKNOWN_FAILURE")
    target_root = LOCAL_PRODUCTION_ROOT / "failed_artifacts" / row["schedule_id"]
    target_root.mkdir(parents=True, exist_ok=True)
    target = target_root / f"attempt_{result['attempt']}_{safe_stamp(str(result.get('attempt_finished_utc', '')))}_{failure}"
    if target.exists():
        raise HardStop(f"failed artifact target already exists: {target}")
    os.replace(attempt_dir, target)
    return target


def enforce_failed_attempt_stop(
    attempt: int, sample_id: str, result: dict[str, object], allowed: bool,
) -> None:
    if attempt >= MAX_ATTEMPTS_PER_SAMPLE:
        raise HardStop(f"attempt{attempt} failure: {sample_id}: {result.get('failure_class')}")
    if not allowed:
        raise HardStop(f"non-retryable attempt{attempt}: {sample_id}: {result.get('failure_class')}")


def build_sample_metadata(
    row: dict[str, str], frozen_git_head: str, final_attempt: int,
    result: dict[str, object], attempt_history: list[dict[str, object]],
) -> dict[str, object]:
    return {
        **row_identity(row),
        "dataset_track": DATASET_TRACK,
        "artifact_class": ARTIFACT_CLASS,
        "formal_manifest_eligible": True,
        "model_input": "observed.pcap",
        "original_capture_use": "audit_and_provenance_only",
        "egress_capture_use": "audit_and_provenance_only",
        "frozen_git_head": frozen_git_head,
        "frozen_sha256": {
            "final500": FROZEN_SHA256[POOL],
            "split": FROZEN_SHA256[SPLIT],
            "plan_registry": FROZEN_SHA256[REGISTRY],
            "schedule": FROZEN_SHA256[SCHEDULE],
            "retry_policy": FROZEN_SHA256[RETRY_POLICY],
            "health_definition": FROZEN_SHA256[HEALTH_DEFINITION],
            "production_root_amendment": FROZEN_SHA256[ROOT_AMENDMENT],
        },
        "orchestrator_version": ORCHESTRATOR_VERSION,
        "orchestrator_sha256": sha256(Path(__file__)),
        "capture_runner_sha256": FROZEN_SHA256[CAPTURE_RUNNER],
        "retry_runner_sha256": FROZEN_SHA256[RETRY_RUNNER],
        "failure_classifier_sha256": FROZEN_SHA256[FAILURE_CLASSIFIER],
        "browser_executor_sha256": FROZEN_SHA256[EXECUTOR],
        "executor_supervisor_sha256": FROZEN_SHA256[SUPERVISOR],
        "final_attempt": final_attempt,
        "attempt_count": len(attempt_history),
        "attempt_history": attempt_history,
        "final_result": result,
        "local_finalized_utc": utc_now(),
    }


def remote_file_count(path: str) -> int:
    quoted = shlex.quote(path)
    completed = run_command([
        "ssh", "-o", "BatchMode=yes", UPLOAD_HOST,
        f"find {quoted} -type f ! -name REMOTE_ARCHIVE_PENDING | wc -l",
    ], timeout=60)
    if completed.returncode != 0:
        if not remote_reachable():
            raise RemoteArchivePending("remote disconnected during completeness count")
        raise HardStop(f"remote completeness count failed: {path}: {completed.stderr[-1000:]}")
    return int(completed.stdout.strip())


def archive_sample(sample_root: Path, row: dict[str, str], frozen_git_head: str) -> None:
    sample_id = row["schedule_id"]
    incoming = f"{REMOTE_PRODUCTION_ROOT}/.incoming/{sample_id}"
    final = remote_sample_path(sample_id)
    try:
        verify_remote_connectivity()
    except (PrecheckFail, RuntimeError) as exc:
        raise RemoteArchivePending(str(exc)) from exc
    final_quoted = shlex.quote(final)
    incoming_quoted = shlex.quote(incoming)
    if run_command(["ssh", "-o", "BatchMode=yes", UPLOAD_HOST, f"test -e {final_quoted}"], timeout=20).returncode == 0:
        try:
            final_valid = remote_complete_valid(row, frozen_git_head)
        except RuntimeError as exc:
            raise RemoteArchivePending(str(exc)) from exc
        if final_valid:
            try:
                controls = run_command([
                    "rsync", "-a",
                    f"{UPLOAD_HOST}:{final}/remote_sha_verification.json",
                    f"{UPLOAD_HOST}:{final}/SAMPLE_COMPLETE",
                    f"{UPLOAD_HOST}:{final}/FINAL_METADATA_SHA256SUMS.txt",
                    f"{sample_root}/",
                ], timeout=300)
            except RuntimeError as exc:
                raise RemoteArchivePending(str(exc)) from exc
            if controls.returncode != 0:
                raise RemoteArchivePending(f"remote control recovery failed: {controls.stderr[-1000:]}")
            pending = sample_root / "REMOTE_ARCHIVE_PENDING"
            if pending.exists():
                pending.unlink()
            if not local_complete_valid(sample_root, row, frozen_git_head):
                raise HardStop(f"recovered local sample integrity mismatch: {sample_id}")
            return
        marker = run_command([
            "ssh", "-o", "BatchMode=yes", UPLOAD_HOST, f"test -f {final_quoted}/SAMPLE_COMPLETE",
        ], timeout=20).returncode == 0
        if marker:
            raise HardStop(f"remote completed sample integrity mismatch: {sample_id}")
    mkdir = run_command([
        "ssh", "-o", "BatchMode=yes", UPLOAD_HOST,
        f"mkdir -p {shlex.quote(str(REMOTE_PRODUCTION_ROOT / '.incoming'))} "
        f"{shlex.quote(str(REMOTE_PRODUCTION_ROOT / 'samples'))} {incoming_quoted}",
    ], timeout=30)
    if mkdir.returncode != 0:
        if not remote_reachable():
            raise RemoteArchivePending("remote disconnected while creating incoming archive")
        raise HardStop(f"remote incoming directory creation failed: {mkdir.stderr[-1000:]}")
    try:
        rsync = run_command([
            "rsync", "-aH", "--exclude", "SAMPLE_COMPLETE", "--exclude", "REMOTE_ARCHIVE_PENDING",
            f"{sample_root}/", f"{UPLOAD_HOST}:{incoming}/",
        ], timeout=3600)
    except RuntimeError as exc:
        raise RemoteArchivePending(str(exc)) from exc
    if rsync.returncode != 0:
        raise RemoteArchivePending(f"rsync failed: {rsync.stderr[-1000:]}")
    primary = run_command([
        "ssh", "-o", "BatchMode=yes", UPLOAD_HOST,
        f"cd {incoming_quoted} && sha256sum -c SHA256SUMS.txt >/dev/null",
    ], timeout=1800)
    if primary.returncode != 0:
        if not remote_reachable():
            raise RemoteArchivePending("remote disconnected during SHA verification")
        raise HardStop(f"remote independent SHA mismatch: {sample_id}: {primary.stderr[-1000:]}")
    local_primary_count = sum(
        path.is_file() and path.name not in {"SAMPLE_COMPLETE", "REMOTE_ARCHIVE_PENDING"}
        for path in sample_root.rglob("*")
    )
    if remote_file_count(incoming) != local_primary_count:
        raise HardStop(f"remote primary completeness mismatch: {sample_id}")
    metadata_result = run_command([
        "ssh", "-o", "BatchMode=yes", UPLOAD_HOST, f"cat {incoming_quoted}/sample_metadata.json",
    ], timeout=30)
    if metadata_result.returncode != 0:
        if not remote_reachable():
            raise RemoteArchivePending("remote disconnected during metadata verification")
        raise HardStop(f"remote metadata missing: {sample_id}")
    if not validate_metadata(json.loads(metadata_result.stdout), row, frozen_git_head):
        raise HardStop(f"remote metadata mismatch: {sample_id}")
    promote = run_command([
        "ssh", "-o", "BatchMode=yes", UPLOAD_HOST,
        f"if test -e {final_quoted}; then test -d {final_quoted}; else mv {incoming_quoted} {final_quoted}; fi",
    ], timeout=60)
    if promote.returncode != 0:
        raise RemoteArchivePending(f"remote promotion failed: {promote.stderr[-1000:]}")

    remote_verification = {
        "sample_id": sample_id,
        "remote_path": final,
        "remote_upload_pass": True,
        "remote_sha_pass": True,
        "remote_completeness_pass": True,
        "remote_metadata_pass": True,
        "verified_utc": utc_now(),
    }
    atomic_write_json(sample_root / "remote_sha_verification.json", remote_verification)
    atomic_write_text(sample_root / "SAMPLE_COMPLETE", f"SAMPLE_COMPLETE {utc_now()}\n")
    create_checksum_manifest(
        sample_root, "FINAL_METADATA_SHA256SUMS.txt",
        {"FINAL_METADATA_SHA256SUMS.txt", "REMOTE_ARCHIVE_PENDING"},
    )
    try:
        controls = run_command([
            "rsync", "-a",
            str(sample_root / "remote_sha_verification.json"),
            str(sample_root / "SAMPLE_COMPLETE"),
            str(sample_root / "FINAL_METADATA_SHA256SUMS.txt"),
            f"{UPLOAD_HOST}:{final}/",
        ], timeout=300)
    except RuntimeError as exc:
        raise RemoteArchivePending(str(exc)) from exc
    if controls.returncode != 0:
        raise RemoteArchivePending(f"final control upload failed: {controls.stderr[-1000:]}")
    final_check = run_command([
        "ssh", "-o", "BatchMode=yes", UPLOAD_HOST,
        f"cd {final_quoted} && sha256sum -c SHA256SUMS.txt >/dev/null "
        "&& sha256sum -c FINAL_METADATA_SHA256SUMS.txt >/dev/null && test -f SAMPLE_COMPLETE",
    ], timeout=1800)
    if final_check.returncode != 0:
        if not remote_reachable():
            raise RemoteArchivePending("remote disconnected during final verification")
        raise HardStop(f"remote final integrity mismatch: {sample_id}")
    local_count = sum(path.is_file() and path.name != "REMOTE_ARCHIVE_PENDING" for path in sample_root.rglob("*"))
    if remote_file_count(final) != local_count:
        raise HardStop(f"remote final completeness mismatch: {sample_id}")
    pending = sample_root / "REMOTE_ARCHIVE_PENDING"
    if pending.exists():
        pending.unlink()


def finalize_local_sample(
    working_root: Path, row: dict[str, str], frozen_git_head: str,
    result: dict[str, object], attempt_history: list[dict[str, object]],
) -> Path:
    final_attempt = int(result["attempt"])
    attempt_root = Path(str(result["artifact_dir"]))
    for name in ("observed.pcap", "original.pcap", "egress.pcap"):
        source = attempt_root / name
        if not source.is_file():
            raise HardStop(f"final attempt missing required capture: {source}")
        os.link(source, working_root / name)
    plan_copy = attempt_root / "workload/workload_plan.json"
    if not plan_copy.is_file() or sha256(plan_copy) != row["plan_sha256"]:
        raise HardStop("final attempt workload plan copy mismatch")
    shutil.copy2(plan_copy, working_root / "workload_plan.json")
    final_artifact_path = (
        LOCAL_PRODUCTION_ROOT / "samples" / row["schedule_id"]
        / "attempts" / f"attempt_{final_attempt}"
    )
    result = dict(result)
    result["artifact_dir"] = str(final_artifact_path)
    for item in attempt_history:
        if int(item["attempt"]) == final_attempt:
            item["artifact_path"] = str(final_artifact_path)
    metadata = build_sample_metadata(row, frozen_git_head, final_attempt, result, attempt_history)
    atomic_write_json(working_root / "sample_metadata.json", metadata)
    atomic_write_json(working_root / "attempt_provenance.json", {"attempts": attempt_history})
    atomic_write_json(working_root / "plan_reference.json", {
        "plan_path": row["plan_path"], "plan_sha256": row["plan_sha256"],
    })
    atomic_write_text(working_root / FORMAL_CLASSIFICATION, f"{FORMAL_CLASSIFICATION}\n")
    create_checksum_manifest(
        working_root, "SHA256SUMS.txt",
        {"SHA256SUMS.txt", "FINAL_METADATA_SHA256SUMS.txt", "SAMPLE_COMPLETE",
         "remote_sha_verification.json", "REMOTE_ARCHIVE_PENDING"},
    )
    samples = LOCAL_PRODUCTION_ROOT / "samples"
    samples.mkdir(parents=True, exist_ok=True)
    final_root = samples / row["schedule_id"]
    if final_root.exists():
        raise HardStop(f"sample final root already exists: {final_root}")
    os.replace(working_root, final_root)
    return final_root


def verify_sample_precheck(row: dict[str, str], frozen_git_head: str, registry: dict[Path, str]) -> None:
    verify_git(frozen_git_head, verify_origin=False)
    verify_orchestrator_at_head()
    verify_frozen_sha()
    path = Path(row["plan_path"])
    if registry.get(path) != row["plan_sha256"] or sha256(path) != row["plan_sha256"]:
        raise PrecheckFail(f"sample plan SHA mismatch sequence={row['sequence_id']}")
    if stat.S_IMODE(path.stat().st_mode) != 0o444:
        raise PrecheckFail(f"sample plan permission mismatch sequence={row['sequence_id']}")


def run_formal_sample(
    row: dict[str, str], frozen_git_head: str, registry: dict[Path, str],
    start_attempt: int,
) -> Path:
    if not 1 <= start_attempt <= MAX_ATTEMPTS_PER_SAMPLE:
        raise PrecheckFail("invalid starting attempt; attempt4 prohibited")
    verify_sample_precheck(row, frozen_git_head, registry)
    retry = configure_execution_components()
    sample_id = row["schedule_id"]
    working_root = LOCAL_PRODUCTION_ROOT / "in_progress" / sample_id
    if start_attempt == 1:
        working_root.mkdir(parents=True, exist_ok=False)
    elif not working_root.is_dir():
        working_root.mkdir(parents=True, exist_ok=True)
    atomic_write_json(working_root / "schedule_row.json", row)
    attempts_root = working_root / "attempts"
    attempts_root.mkdir(exist_ok=True)
    remote_exec_root = f"/home/etip/.cache/proxytraffic-realistic-v3-formal-t0-r7/{sample_id}"
    prepare_remote_inputs(retry, row, remote_exec_root)
    selection = selection_from_row(row)
    ledger_path = LOCAL_PRODUCTION_ROOT / "formal_t0_v3_r7_retry_ledger.tsv"
    attempt_history: list[dict[str, object]] = [
        dict(item) for item in read_ledger(ledger_path)
        if item.get("sample_id") == sample_id
    ]
    for attempt in range(start_attempt, MAX_ATTEMPTS_PER_SAMPLE + 1):
        verify_sample_precheck(row, frozen_git_head, registry)
        started = utc_now()
        try:
            result = retry.run_attempt(
                row["mode_order"], attempt, selection, attempts_root, remote_exec_root,
                classification=FORMAL_CLASSIFICATION,
            )
        except BaseException as exc:
            result = synthetic_component_failure(retry, row, attempt, attempts_root, exc)
        ended = utc_now()
        attempt_dir = Path(str(result["artifact_dir"]))
        formalize_attempt(attempt_dir, row, result, attempt, started, ended, frozen_git_head)
        allowed, reason = retry.retry_authorized(result, attempt=attempt)
        final_status = "PASS" if result.get("status") == "PASS" else "FAIL"
        ledger_entry = ledger_row_for_attempt(
            row, result, attempt, allowed, reason, started, ended, frozen_git_head, final_status,
        )
        append_ledger_atomic(ledger_path, [ledger_entry])
        attempt_history.append(ledger_entry)
        if result.get("status") == "PASS":
            assert_final_attempt(result, row)
            sample_root = finalize_local_sample(
                working_root, row, frozen_git_head, result, attempt_history,
            )
            ledger_rows = read_ledger(ledger_path)
            for item in ledger_rows:
                if item.get("sample_id") == sample_id and int(item["attempt"]) == attempt:
                    item["artifact_path"] = str(sample_root / "attempts" / f"attempt_{attempt}")
            atomic_write_rows(ledger_path, LEDGER_FIELDS, list(ledger_rows))
            try:
                archive_sample(sample_root, row, frozen_git_head)
            except RemoteArchivePending as exc:
                atomic_write_text(sample_root / "REMOTE_ARCHIVE_PENDING", f"{utc_now()} {exc}\n")
                raise
            return sample_root
        failed_path = move_failed_attempt(attempt_dir, row, result)
        ledger_rows = read_ledger(ledger_path)
        ledger_entry["artifact_path"] = str(failed_path)
        ledger_rows[-1]["artifact_path"] = str(failed_path)
        atomic_write_rows(ledger_path, LEDGER_FIELDS, list(ledger_rows))
        enforce_failed_attempt_stop(attempt, sample_id, result, allowed)
    raise HardStop(f"attempt budget exhausted: {sample_id}")


def progress_from_schedule(
    schedule: list[dict[str, str]], frozen_git_head: str,
) -> dict[str, object]:
    state = scan_resume_state(schedule, LOCAL_PRODUCTION_ROOT, frozen_git_head)
    ledger = read_ledger(LOCAL_PRODUCTION_ROOT / "formal_t0_v3_r7_retry_ledger.tsv")
    attempts = len(ledger)
    retries = sum(int(row["attempt"]) > 1 for row in ledger)
    return {
        "dataset_track": DATASET_TRACK,
        "artifact_class": ARTIFACT_CLASS,
        "VALID_SAMPLES": state["valid_samples"],
        "COMPLETE_PAIR_GROUPS": state["complete_pair_groups"],
        "NEXT_SEQUENCE_ID": state["next_sequence_id"],
        "mode_counts": state["mode_counts"],
        "TOTAL_ATTEMPTS": attempts,
        "RETRY_COUNT": retries,
        "RETRY_RATE": retries / max(1, int(state["valid_samples"])),
        "REMOTE_SHA_PASS": state["valid_samples"],
        "health_failures": sum(row["failure_class"] == "INFRASTRUCTURE_HEALTH_LOST" for row in ledger),
        "capture_failures": sum(row["failure_class"] == "CAPTURE_FINALIZATION_FAIL" for row in ledger),
        "bypass_failures": sum(row["failure_class"] == "PROXY_BYPASS" or row.get("bypass_observed") == "true" for row in ledger),
        "conn_max_hits": sum(row["failure_class"] == "REDSOCKS_CONN_MAX_HIT" for row in ledger),
        "disk_free_bytes": free_disk_bytes(),
        "residual": 0,
        "updated_utc": utc_now(),
    }


def write_progress(schedule: list[dict[str, str]], frozen_git_head: str) -> dict[str, object]:
    progress = progress_from_schedule(schedule, frozen_git_head)
    atomic_write_json(LOCAL_PRODUCTION_ROOT / "formal_t0_v3_r7_progress.json", progress)
    return progress


def write_progress_incremental(
    valid_samples: int, complete_pair_groups: int, next_sequence_id: int,
    mode_counts: Counter[str],
) -> dict[str, object]:
    ledger = read_ledger(LOCAL_PRODUCTION_ROOT / "formal_t0_v3_r7_retry_ledger.tsv")
    attempts = len(ledger)
    retries = sum(int(row["attempt"]) > 1 for row in ledger)
    progress = {
        "dataset_track": DATASET_TRACK,
        "artifact_class": ARTIFACT_CLASS,
        "VALID_SAMPLES": valid_samples,
        "COMPLETE_PAIR_GROUPS": complete_pair_groups,
        "NEXT_SEQUENCE_ID": next_sequence_id,
        "mode_counts": {mode: mode_counts.get(mode, 0) for mode in MODES},
        "TOTAL_ATTEMPTS": attempts,
        "RETRY_COUNT": retries,
        "RETRY_RATE": retries / max(1, valid_samples),
        "REMOTE_SHA_PASS": valid_samples,
        "health_failures": sum(row["failure_class"] == "INFRASTRUCTURE_HEALTH_LOST" for row in ledger),
        "capture_failures": sum(row["failure_class"] == "CAPTURE_FINALIZATION_FAIL" for row in ledger),
        "bypass_failures": sum(row["failure_class"] == "PROXY_BYPASS" or row.get("bypass_observed") == "true" for row in ledger),
        "conn_max_hits": sum(row["failure_class"] == "REDSOCKS_CONN_MAX_HIT" for row in ledger),
        "disk_free_bytes": free_disk_bytes(),
        "residual": 0,
        "updated_utc": utc_now(),
    }
    atomic_write_json(LOCAL_PRODUCTION_ROOT / "formal_t0_v3_r7_progress.json", progress)
    return progress


def write_hard_stop(reason: str, frozen_git_head: str) -> None:
    atomic_write_json(LOCAL_PRODUCTION_ROOT / "formal_t0_v3_r7_hard_stop.json", {
        "status": "HARD_STOP", "reason": reason, "frozen_git_head": frozen_git_head,
        "timestamp_utc": utc_now(),
    })


def execute_production(frozen_git_head: str, *, resume: bool) -> int:
    dry_run(frozen_git_head)
    verify_orchestrator_at_head()
    schedule, registry, _ = audit_schedule_and_plans()
    root_entries = list(LOCAL_PRODUCTION_ROOT.iterdir())
    if not resume and root_entries:
        raise PrecheckFail("initial --run requires empty local production root")
    if not resume:
        remote_entries = run_command([
            "ssh", "-o", "BatchMode=yes", UPLOAD_HOST,
            f"find {shlex.quote(str(REMOTE_PRODUCTION_ROOT))} -mindepth 1 -print -quit",
        ], timeout=30, check=True).stdout.strip()
        if remote_entries:
            raise PrecheckFail("initial --run requires empty remote production root")
    LOCAL_PRODUCTION_ROOT.mkdir(parents=True, exist_ok=True)
    ledger_path = LOCAL_PRODUCTION_ROOT / "formal_t0_v3_r7_retry_ledger.tsv"
    if not ledger_path.exists():
        atomic_write_rows(ledger_path, LEDGER_FIELDS, [])
    state = scan_resume_state(schedule, LOCAL_PRODUCTION_ROOT, frozen_git_head)
    if state["next_action"] in {
        "REVIEW_REQUIRED", "HARD_STOP_ATTEMPT3_FAILED", "HARD_STOP_NON_RETRYABLE",
    }:
        raise HardStop(f"resume state requires review: {state['next_action']}")
    start_sequence = int(state["next_sequence_id"])
    verify_no_out_of_order_artifacts(schedule, start_sequence)
    next_action = str(state["next_action"])
    valid_samples = int(state["valid_samples"])
    complete_pair_groups = int(state["complete_pair_groups"])
    mode_counts: Counter[str] = Counter(state["mode_counts"])
    for row in schedule:
        sequence = int(row["sequence_id"])
        if sequence < start_sequence:
            continue
        action = next_action if sequence == start_sequence else "RUN_ATTEMPT1"
        if action == "RESUME_REMOTE_ARCHIVE_ONLY":
            sample_root = LOCAL_PRODUCTION_ROOT / "samples" / row["schedule_id"]
            try:
                archive_sample(sample_root, row, frozen_git_head)
            except RemoteArchivePending:
                print(f"REMOTE_ARCHIVE_PENDING sample_id={row['schedule_id']}", flush=True)
                return 75
        elif action in {"RUN_ATTEMPT1", "RUN_ATTEMPT2", "RUN_ATTEMPT3"}:
            if int(row["mode_position"]) == 1 and free_disk_bytes() < MIN_FREE_BYTES:
                raise HardStop("STORAGE_CHECKPOINT_REQUIRED: free space below 20 GiB")
            try:
                run_formal_sample(row, frozen_git_head, registry, int(action.removeprefix("RUN_ATTEMPT")))
            except RemoteArchivePending:
                print(f"REMOTE_ARCHIVE_PENDING sample_id={row['schedule_id']}", flush=True)
                return 75
        elif action.startswith("SKIP_VALID_COMPLETE"):
            print(f"SKIP_VALID_COMPLETE sequence_id={sequence} sample_id={row['schedule_id']}", flush=True)
            continue
        else:
            raise HardStop(f"unsupported resume action: {action}")
        valid_samples += 1
        mode_counts[row["mode_order"]] += 1
        if int(row["mode_position"]) == 4:
            complete_pair_groups += 1
        progress = write_progress_incremental(
            valid_samples, complete_pair_groups, sequence + 1, mode_counts,
        )
        if int(row["mode_position"]) == 4:
            print(json.dumps(progress, sort_keys=True), flush=True)
        if progress["VALID_SAMPLES"] and int(progress["VALID_SAMPLES"]) % 100 == 0:
            verify_frozen_sha()
            audit_schedule_and_plans()
            checkpoint = progress_from_schedule(schedule, frozen_git_head)
            if (
                checkpoint["VALID_SAMPLES"] != valid_samples
                or checkpoint["COMPLETE_PAIR_GROUPS"] != complete_pair_groups
                or checkpoint["NEXT_SEQUENCE_ID"] != sequence + 1
            ):
                raise HardStop("storage/integrity checkpoint progress mismatch")
            if free_disk_bytes() < MIN_FREE_BYTES:
                raise HardStop("STORAGE_CHECKPOINT_REQUIRED: free space below 20 GiB")
    final = write_progress(schedule, frozen_git_head)
    if final["VALID_SAMPLES"] != 1200 or final["COMPLETE_PAIR_GROUPS"] != 300:
        raise HardStop("production ended without 1200 valid samples")
    return 0


def append_eviction_ledger(row: dict[str, str], frozen_git_head: str) -> None:
    path = LOCAL_PRODUCTION_ROOT / "formal_t0_v3_r7_eviction_ledger.tsv"
    rows: list[dict[str, object]] = []
    if path.exists():
        with path.open(newline="", encoding="utf-8") as handle:
            reader = csv.DictReader(handle, delimiter="\t")
            if tuple(reader.fieldnames or ()) != EVICTION_FIELDS:
                raise HardStop("eviction ledger header mismatch")
            rows.extend(reader)
    now = utc_now()
    rows.append({
        "sample_id": row["schedule_id"], "sequence_id": row["sequence_id"],
        "remote_path": remote_sample_path(row["schedule_id"]),
        "remote_sha_pass": "true", "remote_complete_pass": "true",
        "ledger_written_utc": now, "local_eviction_utc": now,
    })
    atomic_write_rows(path, EVICTION_FIELDS, rows)


def evict_complete_through(frozen_git_head: str, sequence_limit: int) -> int:
    dry_run(frozen_git_head)
    verify_orchestrator_at_head()
    schedule, _, _ = audit_schedule_and_plans()
    for row in schedule:
        if int(row["sequence_id"]) > sequence_limit:
            break
        sample_root = LOCAL_PRODUCTION_ROOT / "samples" / row["schedule_id"]
        if not sample_root.exists():
            continue
        if not local_complete_valid(sample_root, row, frozen_git_head):
            raise HardStop(f"local sample is not valid complete: {row['schedule_id']}")
        if not remote_complete_valid(row, frozen_git_head):
            raise HardStop(f"remote sample is not valid complete: {row['schedule_id']}")
        append_eviction_ledger(row, frozen_git_head)
        shutil.rmtree(sample_root)
        print(f"EVICTED_VALID_COMPLETE sample_id={row['schedule_id']}", flush=True)
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument("--dry-run", action="store_true")
    action.add_argument("--run", action="store_true")
    action.add_argument("--resume", action="store_true")
    action.add_argument("--evict-complete-through", type=int, metavar="SEQUENCE_ID")
    parser.add_argument("--frozen-git-head", required=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if args.dry_run:
            print(json.dumps(dry_run(args.frozen_git_head), indent=2, sort_keys=True))
            print("FORMAL_T0_V3_R7_PRODUCTION_DRY_RUN_PASS")
            return 0
        if args.evict_complete_through is not None:
            return evict_complete_through(args.frozen_git_head, args.evict_complete_through)
        return execute_production(args.frozen_git_head, resume=args.resume)
    except RemoteArchivePending as exc:
        print(f"REMOTE_ARCHIVE_PENDING: {exc}", file=sys.stderr)
        return 75
    except (PrecheckFail, HardStop, RuntimeError, OSError, ValueError) as exc:
        if not args.dry_run:
            try:
                retry = configure_execution_components()
                retry.base.cleanup_mode()
            except Exception:
                pass
            try:
                write_hard_stop(f"{type(exc).__name__}: {exc}", args.frozen_git_head)
            except Exception:
                pass
        print(f"FORMAL_T0_V3_R7_HARD_STOP: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
