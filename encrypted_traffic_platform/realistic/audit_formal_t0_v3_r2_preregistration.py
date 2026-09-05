#!/usr/bin/env python3
"""Independent fail-closed preregistration audit for Formal T0 v3 R2."""

from __future__ import annotations

import csv
import hashlib
import json
import stat
from collections import Counter, defaultdict
from pathlib import Path


REPO = Path("/home/etip/Tunnel/proxytraffic")
DOC = REPO / "docs/realistic_v1/formal_t0_v3"
POOL = DOC / "formal_domain_pool_v3_r2.tsv"
SPLIT = DOC / "formal_domain_split_v3_r2.tsv"
MANIFEST = DOC / "formal_t0_v3_plan_manifest_r2.tsv"
REGISTRY = DOC / "FORMAL_T0_V3_PLAN_SHA256SUMS_R2.txt"
SCHEDULE = DOC / "formal_t0_v3_schedule_r2.tsv"
RETRY = DOC / "formal_transient_retry_policy_v1.txt"
HEALTH = DOC / "trojan_transport_qualification_v3_definition.txt"
CAPACITY = DOC / "realistic_v3_redsocks_capacity_deployment_audit_v1.txt"
OUTPUT_JSON = DOC / "formal_t0_v3_r2_preregistration_integrity_audit.json"
OUTPUT_TEXT = DOC / "formal_t0_v3_r2_preregistration_integrity_audit.txt"
EXPECTED_SHA = {
    POOL: "ead6f94c28ec666880ac1a16154b8faebef78e44e76d40001092b10f4040c14a",
    SPLIT: "8d1be7a6fa51eed941fe62a4b7e79d57435bdb87af081b791662763480dabe38",
    MANIFEST: "7ce1293a967526ba1ad257bf95b7c3e73e36c6c6add605558098484004886998",
    REGISTRY: "27e608fcf55cbea1bbedc4660c85715d0dab196049e72209e7a7704ebcaf029c",
    SCHEDULE: "50bd40d4386c606fef70abf013d119b926c3508a0bccaa879550691c28ae3076",
    RETRY: "f84522b948804b218893b5638937f0632f9339495b75502ba5a4cc79808e4227",
    HEALTH: "b26988debe3b4fd147a986f31902a8e628209b3825d0f2798a847e0203a09ffb",
    CAPACITY: "b3d656a205298f93334aa566e772a5ab60b1073995c17eeea505d2fb7409baff",
}
MODES = {"direct", "vless", "shadowsocks", "trojan"}


def sha(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def tsv(path: Path) -> list[dict[str, str]]:
    with path.open(newline="", encoding="utf-8") as handle:
        return list(csv.DictReader(handle, delimiter="\t"))


def main() -> int:
    if OUTPUT_JSON.exists() or OUTPUT_TEXT.exists():
        raise RuntimeError("refusing to overwrite preregistration audit")
    issues: list[str] = []
    for path, expected in EXPECTED_SHA.items():
        if sha(path) != expected:
            issues.append(f"frozen_sha_mismatch:{path.name}")

    pool, split, manifest, schedule = tsv(POOL), tsv(SPLIT), tsv(MANIFEST), tsv(SCHEDULE)
    pool_domains = {row["domain"] for row in pool}
    split_domains = {row["domain"] for row in split}
    duplicate_domain = len(pool) - len(pool_domains)
    missing_domain = len(pool_domains ^ split_domains)
    split_sets = [{row["domain"] for row in split if row["split"] == name} for name in ("train", "validation", "test")]
    split_overlap = sum(len(split_sets[i] & split_sets[j]) for i in range(3) for j in range(i + 1, 3))

    registry: list[tuple[str, Path]] = []
    for line in REGISTRY.read_text(encoding="utf-8").splitlines():
        digest, filename = line.split(maxsplit=1)
        registry.append((digest, Path(filename)))
    missing_plan = sum(not path.is_file() for _, path in registry)
    plan_sha_mismatch = sum(path.is_file() and sha(path) != digest for digest, path in registry)
    all_plans_read_only = all(
        path.is_file() and stat.S_IMODE(path.stat().st_mode) == 0o444 for _, path in registry
    )

    manifest_by_group = {row["pair_group_id"]: row for row in manifest}
    groups: dict[str, list[dict[str, str]]] = defaultdict(list)
    for row in schedule:
        groups[row["pair_group_id"]].append(row)
    pair_group_mode_missing = 0
    schedule_mismatch = 0
    for group_id, rows in groups.items():
        expected = manifest_by_group.get(group_id)
        if len(rows) != 4 or {row["mode_order"] for row in rows} != MODES:
            pair_group_mode_missing += 1
        if expected is None or any(
            row["plan_id"] != expected["plan_id"]
            or row["plan_path"] != expected["plan_path"]
            or row["plan_sha256"] != expected["plan_sha256"]
            or row["seed"] != expected["seed"]
            or row["split"] != expected["split"]
            or row["intensity"] != expected["intensity"]
            for row in rows
        ):
            schedule_mismatch += 1

    checks = {
        "domains": len(pool),
        "plans": len(manifest),
        "pair_groups": len(groups),
        "schedule_rows": len(schedule),
        "direct": Counter(row["mode_order"] for row in schedule)["direct"],
        "vless": Counter(row["mode_order"] for row in schedule)["vless"],
        "shadowsocks": Counter(row["mode_order"] for row in schedule)["shadowsocks"],
        "trojan": Counter(row["mode_order"] for row in schedule)["trojan"],
        "duplicate_domain": duplicate_domain,
        "split_overlap": split_overlap,
        "missing_domain": missing_domain,
        "missing_plan": missing_plan,
        "plan_sha_mismatch": plan_sha_mismatch,
        "schedule_mismatch": schedule_mismatch,
        "pair_group_mode_missing": pair_group_mode_missing,
        "all_plans_read_only": all_plans_read_only,
    }
    expected_values = {
        "domains": 500, "plans": 300, "pair_groups": 300, "schedule_rows": 1200,
        "direct": 300, "vless": 300, "shadowsocks": 300, "trojan": 300,
        "duplicate_domain": 0, "split_overlap": 0, "missing_domain": 0,
        "missing_plan": 0, "plan_sha_mismatch": 0, "schedule_mismatch": 0,
        "pair_group_mode_missing": 0, "all_plans_read_only": True,
    }
    issues.extend(key for key, expected in expected_values.items() if checks[key] != expected)
    report = {
        "status": "PASS" if not issues else "FAIL",
        **checks,
        "integrity_issues": len(issues),
        "issues": issues,
        "frozen_sha256": {path.name: sha(path) for path in EXPECTED_SHA},
    }
    OUTPUT_JSON.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    lines = ["FORMAL_T0_V3_R2_PREREGISTRATION_INTEGRITY_" + report["status"]]
    lines += [f"{key}={value}" for key, value in report.items() if key not in {"issues", "frozen_sha256"}]
    lines += [f"{name}_sha256={digest}" for name, digest in report["frozen_sha256"].items()]
    OUTPUT_TEXT.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(OUTPUT_TEXT.read_text(encoding="utf-8"), end="")
    return 0 if not issues else 1


if __name__ == "__main__":
    raise SystemExit(main())
