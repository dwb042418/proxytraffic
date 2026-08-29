#!/usr/bin/env python3
"""Build deterministic Formal T0 v2 domain artifacts, plans, and schedule."""

from __future__ import annotations

import csv
import hashlib
import json
import os
import random
import stat
from pathlib import Path

REPO = Path("/home/etip/Tunnel/proxytraffic")
DOC = REPO / "docs/realistic_v1/formal_t0_v2"
PLANS = Path("/home/etip/datasets/plans/realistic_v1/t0_v2")
SOURCE_SHA = "264830dfe5bbf84daeb23d482123d0a7eab1f6ee6830f08984c563be18d998aa"
SOURCE_ID = "46W9X"
GENERATOR_HEAD = "57f71d9fe8a267505d038dd1cb6bc3081bee010f"
BROWSER = "151.0.7922.34"
PLAYWRIGHT = "1.62.0"
BUCKET_NEEDS = {"top_1_1000": 350, "rank_1001_100000": 100, "rank_100001_1000000": 50}
REPLACEMENT_NEEDS = {"top_1_1000": 10, "rank_1001_100000": 3, "rank_100001_1000000": 1}
SPLIT_NEEDS = {
    "top_1_1000": {"train": 210, "validation": 35, "test": 105},
    "rank_1001_100000": {"train": 60, "validation": 10, "test": 30},
    "rank_100001_1000000": {"train": 30, "validation": 5, "test": 15},
}


def read_tsv(path: Path) -> list[dict[str, str]]:
    with path.open(newline="") as handle:
        return list(csv.DictReader(handle, delimiter="\t"))


def write_tsv(path: Path, fields: list[str], rows: list[dict[str, object]]) -> None:
    with path.open("w", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields, delimiter="\t", lineterminator="\n", extrasaction="ignore")
        writer.writeheader(); writer.writerows(rows)


def truth(value: str) -> bool:
    return value.strip().lower() in {"true", "1", "yes"}


def digest_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def main() -> int:
    base = read_tsv(DOC / "formal_domain_replay_stability_base500.tsv")
    reserve = read_tsv(DOC / "formal_domain_replacement_audit_batch2.tsv")
    unstable = [row for row in base if not truth(row["replay_stable"])]
    if len(unstable) != 14:
        raise SystemExit(f"expected 14 unstable base domains, got {len(unstable)}")
    selected_replacements = []
    for bucket, needed in REPLACEMENT_NEEDS.items():
        choices = sorted(
            (row for row in reserve if row["rank_bucket"] == bucket and truth(row["all_gates_pass"])),
            key=lambda row: int(row["rank"]),
        )
        if len(choices) < needed:
            raise SystemExit(f"insufficient replacements bucket={bucket}")
        selected_replacements.extend(choices[:needed])
    final = [row for row in base if truth(row["replay_stable"])] + selected_replacements
    final.sort(key=lambda row: int(row["rank"]))
    if len(final) != 500 or len({row["domain"] for row in final}) != 500:
        raise SystemExit("final pool count/duplicate failure")
    for index, row in enumerate(final, 1):
        row["domain_id"] = f"domain{index:04d}"
        row["source_list_id"] = SOURCE_ID
        row["source_sha256"] = SOURCE_SHA
        row["syntax_eligible"] = "true"
        row["reachability_eligible"] = "true"
        if "single_status" in row:
            row["main_http_status"] = row["single_status"]
            row["main_commit_success"] = row["single_commit_success"]
            row["main_commit_latency_ms"] = row["single_commit_latency_ms"]
    counts = {bucket: sum(row["rank_bucket"] == bucket for row in final) for bucket in BUCKET_NEEDS}
    if counts != BUCKET_NEEDS or any(not truth(row["replay_stable"]) or int(row["rate_limit_429_count"]) for row in final):
        raise SystemExit(f"formal eligibility failure counts={counts}")

    replay_fields = [
        "domain_id", "rank", "domain", "rank_bucket", "source_list_id", "source_sha256",
        *[field for i in range(1, 5) for field in (
            f"attempt{i}_status", f"attempt{i}_commit_success", f"attempt{i}_commit_latency_ms",
            f"attempt{i}_warning_count", f"attempt{i}_error",
        )],
        "rate_limit_429_count", "hard_failure_count", "warning_count", "replay_stable", "audit_timestamp",
    ]
    write_tsv(DOC / "formal_domain_replay_stability_audit.tsv", replay_fields, final)
    pool_fields = [
        "domain_id", "rank", "domain", "rank_bucket", "source_list_id", "source_sha256",
        "syntax_eligible", "reachability_eligible", "main_http_status", "main_commit_success",
        "main_commit_latency_ms", "warning_count", "audit_timestamp", "replay_stable", "rate_limit_429_count",
    ]
    write_tsv(DOC / "formal_domain_pool.tsv", pool_fields, final)

    split_seed = "proxytraffic-realistic-v1-formal-t0-domain-split-v2"
    split_rows = []
    for bucket, allocation in SPLIT_NEEDS.items():
        bucket_rows = [row for row in final if row["rank_bucket"] == bucket]
        for row in bucket_rows:
            row["split_key_sha256"] = digest_bytes(
                split_seed.encode() + b"\0" + SOURCE_SHA.encode() + b"\0" + row["domain_id"].encode()
            )
        bucket_rows.sort(key=lambda row: row["split_key_sha256"])
        offset = 0
        for split in ("train", "validation", "test"):
            for row in bucket_rows[offset:offset + allocation[split]]:
                split_rows.append({
                    **row, "https_url": f"https://{row['domain']}/", "split": split, "split_seed": split_seed,
                })
            offset += allocation[split]
    split_rows.sort(key=lambda row: ("train validation test".split().index(row["split"]), row["split_key_sha256"]))
    split_fields = ["domain_id", "rank", "domain", "https_url", "rank_bucket", "split", "split_key_sha256", "split_seed"]
    write_tsv(DOC / "formal_domain_split.tsv", split_fields, split_rows)

    by_split = {}
    for split in ("train", "validation", "test"):
        by_split[split] = [row for row in split_rows if row["split"] == split]
    if {key: len(value) for key, value in by_split.items()} != {"train": 300, "validation": 50, "test": 150}:
        raise SystemExit("split count failure")

    config = {
        "light": (2, 1, (900, 1600), (1, 2)),
        "medium": (4, 2, (500, 1100), (2, 3)),
        "heavy": (6, 4, (250, 700), (3, 5)),
    }
    manifest = []
    schedule = []
    sha_registry = []
    modes = ["direct", "vless", "shadowsocks", "trojan"]
    quartet_index = 0
    sequence_id = 1
    for seed in range(1, 101):
        split = "train" if seed <= 60 else "validation" if seed <= 70 else "test"
        for intensity in ("light", "medium", "heavy"):
            count, tabs, idle_range, scroll_range = config[intensity]
            seed_id = f"seed{seed:03d}"
            pair = f"{seed_id}_{intensity}"
            material = f"proxytraffic-realistic-v1-formal-t0-v2-plan\0{seed_id}\0{intensity}\0{split}\0{SOURCE_SHA}".encode()
            rng_seed = int.from_bytes(hashlib.sha256(material).digest()[:8], "big")
            rng = random.Random(rng_seed)
            domains = rng.sample(by_split[split], count)
            events = []
            for event_index, domain in enumerate(domains):
                scrolls = [
                    {"distance_px": rng.choice([320, 480, 640, 800, 960]), "idle_ms": rng.randint(*idle_range)}
                    for _ in range(rng.randint(*scroll_range))
                ]
                events.append({
                    "domain_id": domain["domain_id"], "event_index": event_index,
                    "navigation_timeout_ms": 30000, "post_navigation_idle_ms": rng.randint(*idle_range),
                    "pre_navigation_idle_ms": rng.randint(*idle_range), "scrolls": scrolls,
                    "tab_index": rng.randrange(tabs), "url": domain["https_url"],
                })
            plan = {
                "browser_args": ["--disable-quic", "--disable-background-networking"],
                "deterministic_rng_seed": rng_seed, "domain_ids": [row["domain_id"] for row in domains],
                "domain_split": split, "events": events, "formal_plan_version": 2, "intensity": intensity,
                "navigation_semantics": {
                    "acceptable_main_http_status_max": 399, "acceptable_main_http_status_min": 200,
                    "domcontentloaded_observation_ms": 10000, "domcontentloaded_timeout_is_warning": True,
                    "main_timeout_ms": 30000, "main_wait_until": "commit", "subresource_failure_is_warning": True,
                },
                "pair_group_id": pair, "schema_version": 1, "seed": seed, "seed_id": seed_id,
                "split": split, "tab_count": tabs, "tab_sequence": [event["tab_index"] for event in events],
                "url_sequence": [event["url"] for event in events],
            }
            plan_path = PLANS / f"{pair}_workload_plan.json"
            data = (json.dumps(plan, indent=2, sort_keys=True) + "\n").encode()
            plan_path.write_bytes(data)
            plan_sha = digest_bytes(data)
            sha_registry.append((plan_sha, plan_path))
            manifest.append({
                "seed": seed_id, "split": split, "intensity": intensity, "pair_group_id": pair,
                "plan_path": str(plan_path), "plan_sha256": plan_sha,
                "domain_ids": ",".join(row["domain_id"] for row in domains), "domain_split": split,
                "browser_version": BROWSER, "playwright_version": PLAYWRIGHT, "generator_git_head": GENERATOR_HEAD,
            })
            order = modes[quartet_index % 4:] + modes[:quartet_index % 4]
            for position, mode in enumerate(order, 1):
                schedule.append({
                    "sequence_id": sequence_id, "quartet_index": quartet_index, "mode_position": position,
                    "seed": seed_id, "split": split, "intensity": intensity, "pair_group_id": pair,
                    "mode_order": mode, "plan_sha256": plan_sha,
                })
                sequence_id += 1
            quartet_index += 1
    for _, path in sha_registry:
        path.chmod(stat.S_IRUSR | stat.S_IRGRP | stat.S_IROTH)
    write_tsv(DOC / "formal_t0_v2_plan_manifest.tsv", list(manifest[0]), manifest)
    write_tsv(DOC / "formal_t0_v2_collection_schedule.tsv", list(schedule[0]), schedule)
    with (DOC / "FORMAL_T0_V2_PLAN_SHA256SUMS.txt").open("w") as handle:
        for plan_sha, path in sha_registry:
            handle.write(f"{plan_sha}  {path}\n")
    print("V2_BUILD_PASS domains=500 plans=300 schedule=1200 replacements=14")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
