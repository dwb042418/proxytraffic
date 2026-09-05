#!/usr/bin/env python3
"""Independent integrity audit for the frozen Formal T0 v3 R2 inputs."""

from __future__ import annotations

import csv
import hashlib
import json
from collections import Counter, defaultdict
from pathlib import Path


REPO = Path("/home/etip/Tunnel/proxytraffic")
DOC = REPO / "docs/realistic_v1/formal_t0_v3"
POOL = DOC / "formal_domain_pool_v3_r2.tsv"
SPLIT = DOC / "formal_domain_split_v3_r2.tsv"
MANIFEST = DOC / "formal_t0_v3_plan_manifest_r2.tsv"
REGISTRY = DOC / "FORMAL_T0_V3_PLAN_SHA256SUMS_R2.txt"
SCHEDULE = DOC / "formal_t0_v3_schedule_r2.tsv"
JSON_OUT = DOC / "formal_t0_v3_r2_integrity_audit.json"
TEXT_OUT = DOC / "formal_t0_v3_r2_integrity_audit.txt"
EXPECTED_SHA = {
    POOL: "ead6f94c28ec666880ac1a16154b8faebef78e44e76d40001092b10f4040c14a",
    SPLIT: "8d1be7a6fa51eed941fe62a4b7e79d57435bdb87af081b791662763480dabe38",
    MANIFEST: "7ce1293a967526ba1ad257bf95b7c3e73e36c6c6add605558098484004886998",
    REGISTRY: "27e608fcf55cbea1bbedc4660c85715d0dab196049e72209e7a7704ebcaf029c",
    SCHEDULE: "50bd40d4386c606fef70abf013d119b926c3508a0bccaa879550691c28ae3076",
}


def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def rows(path: Path) -> list[dict[str, str]]:
    with path.open(newline="", encoding="utf-8") as handle:
        return list(csv.DictReader(handle, delimiter="\t"))


def main() -> int:
    if JSON_OUT.exists() or TEXT_OUT.exists():
        raise RuntimeError("refusing to overwrite R2 integrity audit")
    issues: list[str] = []
    for path, expected in EXPECTED_SHA.items():
        if sha(path) != expected:
            issues.append(f"frozen_sha_mismatch:{path.name}")
    pool, split, manifest, schedule = rows(POOL), rows(SPLIT), rows(MANIFEST), rows(SCHEDULE)
    registry = []
    for line in REGISTRY.read_text(encoding="utf-8").splitlines():
        digest, path = line.split(maxsplit=1)
        registry.append((digest, Path(path)))
    pool_domains = {r["domain"] for r in pool}
    split_domains = {r["domain"] for r in split}
    if len(pool) != 500: issues.append("domains_not_500")
    if len(pool_domains) != 500: issues.append("duplicate_domain")
    if pool_domains != split_domains: issues.append("missing_domain")
    if Counter(r["rank_bucket"] for r in pool) != Counter({"top_1_1000": 350, "rank_1001_100000": 100, "rank_100001_1000000": 50}):
        issues.append("bucket_counts")
    split_sets = [{r["domain"] for r in split if r["split"] == name} for name in ("train", "validation", "test")]
    split_overlap = sum(len(split_sets[i] & split_sets[j]) for i in range(3) for j in range(i + 1, 3))
    if Counter(r["split"] for r in split) != Counter({"train": 300, "validation": 50, "test": 150}): issues.append("split_counts")
    if split_overlap: issues.append("split_overlap")
    if len(manifest) != 300 or len({r["pair_group_id"] for r in manifest}) != 300: issues.append("plans_or_pair_groups")
    if len(registry) != 300: issues.append("registry_count")
    plan_sha_mismatch = 0
    for digest, path in registry:
        if not path.is_file() or sha(path) != digest:
            plan_sha_mismatch += 1
    if plan_sha_mismatch: issues.append("plan_sha_mismatch")
    groups: dict[str, list[dict[str, str]]] = defaultdict(list)
    for row in schedule:
        groups[row["pair_group_id"]].append(row)
    pair_group_mode_missing = sum(
        len(group) != 4
        or {r["mode_order"] for r in group} != {"direct", "vless", "shadowsocks", "trojan"}
        or len({r["plan_sha256"] for r in group}) != 1
        for group in groups.values()
    )
    if len(schedule) != 1200: issues.append("schedule_rows")
    if Counter(r["mode_order"] for r in schedule) != Counter({m: 300 for m in ("direct", "vless", "shadowsocks", "trojan")}): issues.append("mode_counts")
    if len(groups) != 300 or pair_group_mode_missing: issues.append("pair_group_mode_missing")
    report = {
        "status": "PASS" if not issues else "FAIL",
        "domains": len(pool), "plans": len(manifest), "pair_groups": len(groups), "schedule_rows": len(schedule),
        "direct": Counter(r["mode_order"] for r in schedule)["direct"],
        "vless": Counter(r["mode_order"] for r in schedule)["vless"],
        "shadowsocks": Counter(r["mode_order"] for r in schedule)["shadowsocks"],
        "trojan": Counter(r["mode_order"] for r in schedule)["trojan"],
        "duplicate": len(pool) - len(pool_domains), "missing": len(pool_domains ^ split_domains),
        "split_overlap": split_overlap, "plan_sha_mismatch": plan_sha_mismatch,
        "pair_group_mode_missing": pair_group_mode_missing, "integrity_issues": len(issues), "issues": issues,
        "sha256": {path.name: sha(path) for path in EXPECTED_SHA},
    }
    JSON_OUT.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    lines = ["REALISTIC_V3_R2_INTEGRITY_AUDIT_" + report["status"]]
    lines += [f"{key}={value}" for key, value in report.items() if key not in {"issues", "sha256"}]
    lines += [f"{name}_sha256={digest}" for name, digest in report["sha256"].items()]
    TEXT_OUT.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(TEXT_OUT.read_text(encoding="utf-8"), end="")
    return 0 if not issues else 1


if __name__ == "__main__":
    raise SystemExit(main())
