#!/usr/bin/env python3
"""Immutable executor input staging. Also executed on executor via python -c.

Only unique temporary files receive transfers. link(2) publishes a verified,
0444 inode atomically without replacing an existing immutable destination.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys
import tempfile


class InputIntegrityError(RuntimeError):
    pass


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def namespace_path(cache_root: Path, revision: str, run_class: str, run_id: str,
                   sample_id: str, attempt: int) -> Path:
    for value in (revision, sample_id):
        if not re.fullmatch(r"[A-Za-z0-9_-]+", value):
            raise InputIntegrityError("invalid namespace identity")
    if not 1 <= attempt <= 3:
        raise InputIntegrityError("attempt outside frozen limit")
    if run_class == "FORMAL_PRODUCTION":
        if run_id:
            raise InputIntegrityError("Formal namespace cannot use validation run id")
        parent = cache_root / "formal" / revision
    elif run_class == "NON_FORMAL_VALIDATION":
        if not re.fullmatch(r"[A-Za-z0-9_-]+", run_id):
            raise InputIntegrityError("validation requires unique run id")
        parent = cache_root / "non_formal" / revision / "operational_quartet" / run_id
    else:
        raise InputIntegrityError("unrecognized run class")
    return parent / sample_id / f"attempt_{attempt}"


def verify_immutable(path: Path, expected: str) -> bool:
    if not path.exists() and not path.is_symlink():
        return False
    if (path.is_symlink() or not path.is_file() or digest(path) != expected
            or stat.S_IMODE(path.stat().st_mode) != 0o444):
        raise InputIntegrityError(f"EXECUTOR_INPUT_INTEGRITY_MISMATCH: {path}")
    return True


def sync_directory(path: Path) -> None:
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def promote(temp: Path, destination: Path, expected: str) -> str:
    if verify_immutable(destination, expected):
        return "REUSE_VERIFIED_IMMUTABLE_INPUT"
    if temp.is_symlink() or not temp.is_file() or digest(temp) != expected:
        raise InputIntegrityError("EXECUTOR_INPUT_INTEGRITY_MISMATCH: transferred temporary SHA")
    # This chmod applies only to the new temporary inode, never an existing final.
    temp.chmod(0o444)
    with temp.open("rb") as handle:
        os.fsync(handle.fileno())
    try:
        os.link(temp, destination)
    except FileExistsError:
        verify_immutable(destination, expected)
        return "REUSE_VERIFIED_IMMUTABLE_INPUT"
    sync_directory(destination.parent)
    temp.unlink()
    sync_directory(temp.parent)
    verify_immutable(destination, expected)
    return "ATOMIC_IMMUTABLE_INPUT_PROMOTED"


def handle(request: dict[str, object]) -> dict[str, object]:
    base = Path(str(request["cache_root"]))
    root = namespace_path(base, str(request["revision"]), str(request["run_class"]),
                          str(request["run_id"]), str(request["sample_id"]), int(request["attempt"]))
    for parent in (root, *root.parents):
        if parent.is_symlink():
            raise InputIntegrityError("executor namespace symlink prohibited")
    folder = root / "input"
    if folder.is_symlink():
        raise InputIntegrityError("executor input symlink prohibited")
    identity = {k: request[k] for k in ("revision", "run_class", "run_id", "sample_id", "attempt")}
    identity_bytes = (json.dumps(identity, sort_keys=True) + "\n").encode()
    identity_sha = hashlib.sha256(identity_bytes).hexdigest()
    marker = folder / "namespace.json"
    action = request["action"]
    if action not in {"inspect", "prepare", "promote"}:
        raise InputIntegrityError("unsupported staging action")
    if not verify_immutable(marker, identity_sha):
        if folder.exists() and any(not p.name.startswith(".staging-") for p in folder.iterdir()):
            raise InputIntegrityError("EXECUTOR_INPUT_CACHE_NAMESPACE_COLLISION: missing namespace identity")
        if action == "inspect":
            return {"status": "INPUT_NOT_STAGED", "root": str(root), "inputs": {}}
        folder.mkdir(parents=True, exist_ok=True)
        fd, name = tempfile.mkstemp(prefix=".staging-identity-", dir=folder)
        with os.fdopen(fd, "wb") as out:
            out.write(identity_bytes)
        promote(Path(name), marker, identity_sha)
    inputs = request["inputs"]
    results = {}
    for name, expected in inputs.items():
        if name not in {"workload_plan.json", "realistic_browser_v3.py"} or not re.fullmatch(r"[a-f0-9]{64}", expected):
            raise InputIntegrityError("invalid immutable input specification")
        destination = folder / name
        if verify_immutable(destination, expected):
            results[name] = {"status": "REUSE_VERIFIED_IMMUTABLE_INPUT", "path": str(destination), "sha256": expected, "permission": "0444"}
        elif action == "inspect":
            results[name] = {"status": "INPUT_NOT_STAGED", "path": str(destination)}
        elif action == "prepare":
            fd, temp_name = tempfile.mkstemp(prefix=".staging-" + name + "-", dir=folder)
            os.close(fd)
            results[name] = {"status": "TRANSFER_REQUIRED", "temporary_path": temp_name, "path": str(destination)}
        else:
            temp = Path(request["temporary_paths"][name])
            if temp.parent != folder or not temp.name.startswith(".staging-" + name + "-"):
                raise InputIntegrityError("temporary input outside namespace")
            state = promote(temp, destination, expected)
            results[name] = {"status": state, "path": str(destination), "sha256": expected, "permission": "0444"}
    complete = all(x["status"] in {"REUSE_VERIFIED_IMMUTABLE_INPUT", "ATOMIC_IMMUTABLE_INPUT_PROMOTED"} for x in results.values())
    return {"status": "EXECUTOR_INPUT_PREP_PASS" if complete else "INPUT_NOT_STAGED", "root": str(root), "inputs": results}


if __name__ == "__main__":
    try:
        print(json.dumps(handle(json.loads(sys.argv[1])), sort_keys=True))
    except (InputIntegrityError, OSError, ValueError, KeyError) as exc:
        print(f"EXECUTOR_INPUT_PREPARATION: {exc}", file=sys.stderr)
        raise SystemExit(1)
