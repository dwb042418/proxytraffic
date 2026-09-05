#!/usr/bin/env python3
"""Build only the approved Formal T0 v3 split, plans, registry, and schedule."""

from __future__ import annotations

import csv
import hashlib
import json
import os
import random
import shutil
import stat
import subprocess
import tempfile
from collections import Counter, defaultdict
from pathlib import Path


REPO = Path("/home/etip/Tunnel/proxytraffic")
DOC = REPO / "docs/realistic_v1/formal_t0_v3"
POOL = DOC / "formal_domain_pool_v3.tsv"
PLANS = Path("/home/etip/datasets/plans/realistic_v1/t0_v3")

FINAL_POOL_SHA256 = "ded7fd1277a32295fb1e5fef3b6df0967f10a578cb2d204b04409b55b6878071"
SOURCE_ID = "46W9X"
SOURCE_SHA256 = "264830dfe5bbf84daeb23d482123d0a7eab1f6ee6830f08984c563be18d998aa"
BROWSER_VERSION = "151.0.7922.34"
PLAYWRIGHT_VERSION = "1.62.0"
SPLIT_SEED = "proxytraffic-realistic-v1-formal-t0-domain-split-v3"
PLAN_SEED_NAMESPACE = "proxytraffic-realistic-v1-formal-t0-v3-plan"

BUCKETS = ("top_1_1000", "rank_1001_100000", "rank_100001_1000000")
BUCKET_LABEL = {
    "top_1_1000": "A",
    "rank_1001_100000": "B",
    "rank_100001_1000000": "C",
}
POOL_BUCKET_COUNTS = {"top_1_1000": 350, "rank_1001_100000": 100, "rank_100001_1000000": 50}
POOL_MEMBERSHIP_COUNTS = {"original_stable": 476, "replacement_stable": 24}
SPLIT_NEEDS = {
    "top_1_1000": {"train": 210, "validation": 35, "test": 105},
    "rank_1001_100000": {"train": 60, "validation": 10, "test": 30},
    "rank_100001_1000000": {"train": 30, "validation": 5, "test": 15},
}
SPLIT_TOTALS = {"train": 300, "validation": 50, "test": 150}
INTENSITY_CONFIG = {
    "light": (2, 1, (900, 1600), (1, 2)),
    "medium": (4, 2, (500, 1100), (2, 3)),
    "heavy": (6, 4, (250, 700), (3, 5)),
}
MODES = ("direct", "vless", "shadowsocks", "trojan")

SPLIT_PATH = DOC / "formal_domain_split_v3.tsv"
MANIFEST_PATH = DOC / "formal_t0_v3_plan_manifest.tsv"
REGISTRY_PATH = DOC / "FORMAL_T0_V3_PLAN_SHA256SUMS.txt"
SCHEDULE_PATH = DOC / "formal_t0_v3_schedule.tsv"
SUMMARY_PATH = DOC / "formal_t0_v3_split_plan_summary.txt"
OUTPUT_PATHS = (SPLIT_PATH, MANIFEST_PATH, REGISTRY_PATH, SCHEDULE_PATH, SUMMARY_PATH)


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def read_tsv(path: Path) -> list[dict[str, str]]:
    with path.open(newline="", encoding="utf-8") as handle:
        return list(csv.DictReader(handle, delimiter="\t"))


def write_tsv(path: Path, fields: list[str], rows: list[dict[str, object]]) -> None:
    with path.open("x", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=fields,
            delimiter="\t",
            lineterminator="\n",
            extrasaction="ignore",
        )
        writer.writeheader()
        writer.writerows(rows)


def truth(value: str) -> bool:
    return value.strip().lower() in {"true", "1", "yes"}


def require(condition: bool, message: str) -> None:
    if not condition:
        raise RuntimeError(message)


def seed_identity(number: int) -> tuple[str, str, str]:
    if number <= 60:
        return f"seed{number:03d}", f"train{number:03d}", "train"
    if number <= 70:
        return f"seed{number:03d}", f"val{number:03d}", "validation"
    return f"seed{number:03d}", f"test{number:03d}", "test"


def verify_pool() -> list[dict[str, str]]:
    require(POOL.is_file(), f"missing final pool: {POOL}")
    require(sha256_file(POOL) == FINAL_POOL_SHA256, "immutable final pool SHA256 mismatch")
    rows = read_tsv(POOL)
    require(len(rows) == 500, f"DOMAIN_TOTAL expected 500, got {len(rows)}")
    require(len({row["domain"] for row in rows}) == 500, "duplicate domain in final pool")
    require(len({row["rank"] for row in rows}) == 500, "duplicate rank in final pool")
    require(len({row["domain_id"] for row in rows}) == 500, "duplicate domain_id in final pool")
    counts = Counter(row["rank_bucket"] for row in rows)
    require(dict(counts) == POOL_BUCKET_COUNTS, f"final pool bucket mismatch: {dict(counts)}")
    for row in rows:
        require(row["source_list_id"] == SOURCE_ID, f"source id mismatch: {row['domain']}")
        require(row["source_sha256"] == SOURCE_SHA256, f"source SHA mismatch: {row['domain']}")
        require(truth(row["syntax_eligible"]), f"syntax-ineligible pool row: {row['domain']}")
        require(row["actionability_status"] == "ACTIONABILITY_STABLE", f"unstable pool row: {row['domain']}")
        require(
            all(row[field] == "3" for field in ("navigation_pass_count", "evaluate_pass_count", "action_pass_count")),
            f"incomplete 3/3 evidence: {row['domain']}",
        )
        reference = row["actionability_evidence_reference"].split("#", 1)[0]
        require(bool(reference) and (REPO / reference).is_file(), f"missing evidence reference: {row['domain']}")
        require(row["pool_membership"] in {"original_stable", "replacement_stable"}, f"invalid membership: {row['domain']}")
    require(Counter(row["pool_membership"] for row in rows) == POOL_MEMBERSHIP_COUNTS, "pool membership mismatch")
    return rows


def build_split(pool_rows: list[dict[str, str]]) -> list[dict[str, str]]:
    split_rows: list[dict[str, str]] = []
    for bucket in BUCKETS:
        keyed: list[tuple[str, dict[str, str]]] = []
        for row in pool_rows:
            if row["rank_bucket"] != bucket:
                continue
            split_key = sha256_bytes(
                SPLIT_SEED.encode() + b"\0" + SOURCE_SHA256.encode() + b"\0" + row["domain_id"].encode()
            )
            keyed.append((split_key, row))
        keyed.sort(key=lambda item: item[0])
        offset = 0
        for split in ("train", "validation", "test"):
            count = SPLIT_NEEDS[bucket][split]
            for split_key, row in keyed[offset : offset + count]:
                split_rows.append(
                    {
                        "domain_id": row["domain_id"],
                        "rank": row["rank"],
                        "domain": row["domain"],
                        "https_url": f"https://{row['domain']}/",
                        "rank_bucket": bucket,
                        "split": split,
                        "split_key_sha256": split_key,
                        "split_seed": SPLIT_SEED,
                        "source_list_id": SOURCE_ID,
                        "source_sha256": SOURCE_SHA256,
                        "final_pool_sha256": FINAL_POOL_SHA256,
                    }
                )
            offset += count
        require(offset == len(keyed), f"unassigned rows in bucket {bucket}")
    split_order = {"train": 0, "validation": 1, "test": 2}
    split_rows.sort(key=lambda row: (split_order[row["split"]], row["split_key_sha256"]))
    return split_rows


def validate_split(rows: list[dict[str, str]]) -> None:
    require(len(rows) == 500, "split row total mismatch")
    require(len({row["domain"] for row in rows}) == 500, "duplicate_domain != 0")
    require(len({row["rank"] for row in rows}) == 500, "rank_overlap != 0")
    require(len({row["domain_id"] for row in rows}) == 500, "duplicate domain_id in split")
    split_counts = Counter(row["split"] for row in rows)
    require(dict(split_counts) == SPLIT_TOTALS, f"split totals mismatch: {dict(split_counts)}")
    for bucket in BUCKETS:
        actual = Counter(row["split"] for row in rows if row["rank_bucket"] == bucket)
        require(dict(actual) == SPLIT_NEEDS[bucket], f"bucket split mismatch {bucket}: {dict(actual)}")


def build_plans(
    split_rows: list[dict[str, str]],
    stage_plans: Path,
    generator_git_head: str,
) -> tuple[list[dict[str, object]], list[dict[str, object]], list[tuple[str, Path]]]:
    by_split = {
        split: [row for row in split_rows if row["split"] == split]
        for split in ("train", "validation", "test")
    }
    manifest: list[dict[str, object]] = []
    schedule: list[dict[str, object]] = []
    registry: list[tuple[str, Path]] = []
    quartet_index = 0
    sequence_id = 1

    for seed_number in range(1, 101):
        seed_id, assignment_id, split = seed_identity(seed_number)
        for intensity in ("light", "medium", "heavy"):
            event_count, tab_count, idle_range, scroll_range = INTENSITY_CONFIG[intensity]
            pair_group_id = f"{seed_id}_{intensity}"
            plan_id = f"formal_t0_v3_{pair_group_id}"
            material = (
                PLAN_SEED_NAMESPACE.encode()
                + b"\0"
                + seed_id.encode()
                + b"\0"
                + intensity.encode()
                + b"\0"
                + split.encode()
                + b"\0"
                + FINAL_POOL_SHA256.encode()
            )
            rng_seed = int.from_bytes(hashlib.sha256(material).digest()[:8], "big")
            rng = random.Random(rng_seed)
            domains = rng.sample(by_split[split], event_count)
            events = []
            for event_index, domain in enumerate(domains):
                scrolls = [
                    {
                        "distance_px": rng.choice([320, 480, 640, 800, 960]),
                        "idle_ms": rng.randint(*idle_range),
                    }
                    for _ in range(rng.randint(*scroll_range))
                ]
                events.append(
                    {
                        "domain_id": domain["domain_id"],
                        "event_index": event_index,
                        "navigation_timeout_ms": 30000,
                        "post_navigation_idle_ms": rng.randint(*idle_range),
                        "pre_navigation_idle_ms": rng.randint(*idle_range),
                        "scrolls": scrolls,
                        "tab_index": rng.randrange(tab_count),
                        "url": domain["https_url"],
                    }
                )
            plan = {
                "browser_args": ["--disable-quic", "--disable-background-networking"],
                "deterministic_rng_seed": rng_seed,
                "domain_ids": [row["domain_id"] for row in domains],
                "domain_split": split,
                "events": events,
                "formal_plan_version": 3,
                "intensity": intensity,
                "navigation_semantics": {
                    "acceptable_main_http_status_max": 399,
                    "acceptable_main_http_status_min": 200,
                    "domcontentloaded_observation_ms": 10000,
                    "domcontentloaded_timeout_is_warning": True,
                    "main_timeout_ms": 30000,
                    "main_wait_until": "commit",
                    "subresource_failure_is_warning": True,
                },
                "pair_group_id": pair_group_id,
                "plan_id": plan_id,
                "schema_version": 1,
                "seed": seed_number,
                "seed_assignment_id": assignment_id,
                "seed_id": seed_id,
                "split": split,
                "tab_count": tab_count,
                "tab_sequence": [event["tab_index"] for event in events],
                "url_sequence": [event["url"] for event in events],
            }
            final_plan_path = PLANS / f"{pair_group_id}_workload_plan.json"
            stage_plan_path = stage_plans / final_plan_path.name
            plan_bytes = (json.dumps(plan, indent=2, sort_keys=True) + "\n").encode()
            stage_plan_path.write_bytes(plan_bytes)
            plan_sha = sha256_bytes(plan_bytes)
            registry.append((plan_sha, final_plan_path))
            manifest.append(
                {
                    "plan_id": plan_id,
                    "seed": seed_id,
                    "seed_assignment_id": assignment_id,
                    "split": split,
                    "intensity": intensity,
                    "pair_group_id": pair_group_id,
                    "plan_path": str(final_plan_path),
                    "plan_sha256": plan_sha,
                    "domain_ids": ",".join(row["domain_id"] for row in domains),
                    "domain_split": split,
                    "browser_version": BROWSER_VERSION,
                    "playwright_version": PLAYWRIGHT_VERSION,
                    "generator_git_head": generator_git_head,
                    "final_pool_sha256": FINAL_POOL_SHA256,
                }
            )
            rotation = quartet_index % len(MODES)
            order = MODES[rotation:] + MODES[:rotation]
            for mode_position, mode in enumerate(order, 1):
                schedule.append(
                    {
                        "schedule_id": f"formal_t0_v3_sample{sequence_id:04d}",
                        "sequence_id": sequence_id,
                        "quartet_index": quartet_index,
                        "mode_position": mode_position,
                        "seed": seed_id,
                        "seed_assignment_id": assignment_id,
                        "split": split,
                        "intensity": intensity,
                        "pair_group_id": pair_group_id,
                        "plan_id": plan_id,
                        "mode_order": mode,
                        "plan_path": str(final_plan_path),
                        "plan_sha256": plan_sha,
                    }
                )
                sequence_id += 1
            quartet_index += 1
    return manifest, schedule, registry


def validate_plans(
    split_rows: list[dict[str, str]],
    manifest: list[dict[str, object]],
    schedule: list[dict[str, object]],
    registry: list[tuple[str, Path]],
    stage_plans: Path,
) -> None:
    require(len(manifest) == 300, "PLANS != 300")
    require(len(registry) == 300, "plan registry count != 300")
    require(len(schedule) == 1200, "SCHEDULE_ROWS != 1200")
    require(len({row["plan_id"] for row in manifest}) == 300, "duplicate_plan_id != 0")
    require(len({row["pair_group_id"] for row in manifest}) == 300, "PAIR_GROUPS != 300")
    require(len({row["schedule_id"] for row in schedule}) == 1200, "duplicate_schedule_id != 0")
    require(len({row["sequence_id"] for row in schedule}) == 1200, "duplicate sequence_id")
    require(Counter(row["mode_order"] for row in schedule) == Counter({mode: 300 for mode in MODES}), "mode counts mismatch")
    require(Counter(row["intensity"] for row in manifest) == Counter({name: 100 for name in INTENSITY_CONFIG}), "intensity counts mismatch")
    require(Counter(row["split"] for row in manifest) == Counter({"train": 180, "validation": 30, "test": 90}), "plan split counts mismatch")

    split_domain_ids = defaultdict(set)
    for row in split_rows:
        split_domain_ids[row["split"]].add(row["domain_id"])
    manifest_by_pair = {str(row["pair_group_id"]): row for row in manifest}
    schedule_by_pair: dict[str, list[dict[str, object]]] = defaultdict(list)
    for row in schedule:
        schedule_by_pair[str(row["pair_group_id"])].append(row)
    require(set(schedule_by_pair) == set(manifest_by_pair), "schedule/manifest pair group mismatch")
    for pair_group_id, rows in schedule_by_pair.items():
        require(len(rows) == 4, f"pair_group_mode_missing: {pair_group_id}")
        require({row["mode_order"] for row in rows} == set(MODES), f"pair_group mode set mismatch: {pair_group_id}")
        require(len({row["plan_sha256"] for row in rows}) == 1, f"mode-specific plan SHA: {pair_group_id}")
        require(len({row["plan_path"] for row in rows}) == 1, f"mode-specific plan path: {pair_group_id}")
        expected = manifest_by_pair[pair_group_id]
        require(rows[0]["plan_sha256"] == expected["plan_sha256"], f"schedule plan SHA mismatch: {pair_group_id}")

    for row in manifest:
        domain_ids = str(row["domain_ids"]).split(",")
        require(set(domain_ids) <= split_domain_ids[str(row["split"])], f"cross-split domain reference: {row['plan_id']}")
        expected_count = INTENSITY_CONFIG[str(row["intensity"])][0]
        require(len(domain_ids) == expected_count and len(set(domain_ids)) == expected_count, f"invalid workload domain count: {row['plan_id']}")
        stage_path = stage_plans / Path(str(row["plan_path"])).name
        require(stage_path.is_file(), f"plan_sha_missing: {row['plan_id']}")
        require(sha256_file(stage_path) == row["plan_sha256"], f"plan_sha_mismatch: {row['plan_id']}")
        plan = json.loads(stage_path.read_text(encoding="utf-8"))
        require(plan["pair_group_id"] == row["pair_group_id"], f"plan pair mismatch: {row['plan_id']}")
        require(plan["domain_ids"] == domain_ids, f"plan domain mismatch: {row['plan_id']}")
        require(plan["split"] == row["split"] == plan["domain_split"], f"plan split mismatch: {row['plan_id']}")
        require(plan["intensity"] == row["intensity"], f"plan intensity mismatch: {row['plan_id']}")

    v2_registry = DOC / "FORMAL_T0_V2_PLAN_SHA256SUMS.txt"
    if v2_registry.is_file():
        v2_hashes = {line.split()[0] for line in v2_registry.read_text(encoding="utf-8").splitlines() if line.strip()}
        require(not ({sha for sha, _ in registry} & v2_hashes), "v2 individual plan SHA reused in v3")


def main() -> int:
    for path in OUTPUT_PATHS:
        require(not path.exists(), f"refusing to overwrite existing artifact: {path}")
    require(not PLANS.exists(), f"refusing to overwrite existing plan directory: {PLANS}")

    pool_rows = verify_pool()
    split_rows = build_split(pool_rows)
    validate_split(split_rows)
    generator_git_head = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=REPO, text=True).strip()

    plan_parent = PLANS.parent
    plan_parent.mkdir(parents=True, exist_ok=True)
    stage_plans = Path(tempfile.mkdtemp(prefix=".t0_v3.tmp-", dir=plan_parent))
    stage_docs = Path(tempfile.mkdtemp(prefix=".formal_t0_v3_split_plan.tmp-", dir=DOC))
    promoted = False
    try:
        manifest, schedule, registry = build_plans(split_rows, stage_plans, generator_git_head)
        validate_plans(split_rows, manifest, schedule, registry, stage_plans)

        split_fields = [
            "domain_id", "rank", "domain", "https_url", "rank_bucket", "split",
            "split_key_sha256", "split_seed", "source_list_id", "source_sha256", "final_pool_sha256",
        ]
        manifest_fields = [
            "plan_id", "seed", "seed_assignment_id", "split", "intensity", "pair_group_id",
            "plan_path", "plan_sha256", "domain_ids", "domain_split", "browser_version",
            "playwright_version", "generator_git_head", "final_pool_sha256",
        ]
        schedule_fields = [
            "schedule_id", "sequence_id", "quartet_index", "mode_position", "seed",
            "seed_assignment_id", "split", "intensity", "pair_group_id", "plan_id",
            "mode_order", "plan_path", "plan_sha256",
        ]
        staged_split = stage_docs / SPLIT_PATH.name
        staged_manifest = stage_docs / MANIFEST_PATH.name
        staged_registry = stage_docs / REGISTRY_PATH.name
        staged_schedule = stage_docs / SCHEDULE_PATH.name
        staged_summary = stage_docs / SUMMARY_PATH.name
        write_tsv(staged_split, split_fields, split_rows)
        write_tsv(staged_manifest, manifest_fields, manifest)
        write_tsv(staged_schedule, schedule_fields, schedule)
        with staged_registry.open("x", encoding="utf-8") as handle:
            for plan_sha, plan_path in registry:
                handle.write(f"{plan_sha}  {plan_path}\n")

        split_sha = sha256_file(staged_split)
        manifest_sha = sha256_file(staged_manifest)
        registry_sha = sha256_file(staged_registry)
        schedule_sha = sha256_file(staged_schedule)
        require(sha256_file(POOL) == FINAL_POOL_SHA256, "final pool changed during generation")

        summary_lines = [
            "REALISTIC_V3_SPLIT_PLAN_GENERATION_PASS",
            f"FINAL_POOL_SHA256={FINAL_POOL_SHA256}",
            f"SPLIT_SHA256={split_sha}",
            f"PLAN_REGISTRY_SHA256={registry_sha}",
            f"SCHEDULE_SHA256={schedule_sha}",
            f"PLAN_MANIFEST_SHA256={manifest_sha}",
            "DOMAIN_TOTAL=500",
            "TRAIN=300",
            "VALIDATION=50",
            "TEST=150",
            "TRAIN_A=210",
            "TRAIN_B=60",
            "TRAIN_C=30",
            "VALIDATION_A=35",
            "VALIDATION_B=10",
            "VALIDATION_C=5",
            "TEST_A=105",
            "TEST_B=30",
            "TEST_C=15",
            "SEEDS=100",
            "SEED_MAPPING=train001-train060,val061-val070,test071-test100",
            "PLANS=300",
            "PAIR_GROUPS=300",
            "SCHEDULE_ROWS=1200",
            "DIRECT=300",
            "VLESS=300",
            "SHADOWSOCKS=300",
            "TROJAN=300",
            "DUPLICATE_DOMAIN=0",
            "RANK_OVERLAP=0",
            "SPLIT_OVERLAP=0",
            "MISSING_DOMAIN=0",
            "DUPLICATE_PLAN_ID=0",
            "DUPLICATE_SCHEDULE_ID=0",
            "PAIR_GROUP_MODE_MISSING=0",
            "PLAN_SHA_MISSING=0",
            "PLAN_SHA_MISMATCH=0",
            "V2_PLAN_SHA_REUSE=0",
            "INDIVIDUAL_PLAN_SHA256_COUNT=300",
            "PLAN_FILE_MODE=0444",
            "INTEGRITY_ISSUES=0",
            f"SPLIT_SEED={SPLIT_SEED}",
            f"SOURCE_LIST_ID={SOURCE_ID}",
            f"SOURCE_SHA256={SOURCE_SHA256}",
            f"GENERATOR_GIT_HEAD={generator_git_head}",
            f"SPLIT_PATH={SPLIT_PATH}",
            f"PLAN_DIRECTORY={PLANS}",
            f"PLAN_MANIFEST_PATH={MANIFEST_PATH}",
            f"PLAN_REGISTRY_PATH={REGISTRY_PATH}",
            f"SCHEDULE_PATH={SCHEDULE_PATH}",
            "FORMAL_COLLECTION_STARTED=NO",
            "NEXT_ACTION=WAIT_FOR_HUMAN_REVIEW",
        ]
        staged_summary.write_text("\n".join(summary_lines) + "\n", encoding="utf-8")

        for path in stage_plans.iterdir():
            path.chmod(stat.S_IRUSR | stat.S_IRGRP | stat.S_IROTH)
        require(all(stat.S_IMODE(path.stat().st_mode) == 0o444 for path in stage_plans.iterdir()), "plan readonly mode failure")
        os.replace(stage_plans, PLANS)
        for staged, final in (
            (staged_split, SPLIT_PATH),
            (staged_manifest, MANIFEST_PATH),
            (staged_registry, REGISTRY_PATH),
            (staged_schedule, SCHEDULE_PATH),
            (staged_summary, SUMMARY_PATH),
        ):
            os.replace(staged, final)
        promoted = True
    finally:
        if stage_docs.exists():
            shutil.rmtree(stage_docs)
        if not promoted and stage_plans.exists():
            shutil.rmtree(stage_plans)

    require(sha256_file(POOL) == FINAL_POOL_SHA256, "immutable final pool post-generation SHA mismatch")
    print(SUMMARY_PATH.read_text(encoding="utf-8"), end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
