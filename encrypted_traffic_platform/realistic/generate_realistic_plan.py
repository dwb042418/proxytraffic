#!/usr/bin/env python3
"""Generate an immutable, deterministic Realistic browser workload plan."""

from __future__ import annotations

import argparse
import hashlib
import json
import random
from pathlib import Path


PROFILES = {
    "light": {"urls": 2, "tabs": 1, "scrolls": (1, 2), "idle": (900, 1600)},
    "medium": {"urls": 4, "tabs": 2, "scrolls": (2, 3), "idle": (500, 1100)},
    "heavy": {"urls": 6, "tabs": 4, "scrolls": (3, 5), "idle": (250, 700)},
}


def canonical_bytes(value: object) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True) + "\n").encode()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--seed", type=int, required=True)
    parser.add_argument("--intensity", choices=sorted(PROFILES), required=True)
    parser.add_argument("--domain-pool", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    if args.output.exists():
        raise SystemExit(f"refusing to overwrite immutable plan: {args.output}")
    urls = [line.strip() for line in args.domain_pool.read_text().splitlines()
            if line.strip() and not line.lstrip().startswith("#")]
    profile = PROFILES[args.intensity]
    if len(urls) < profile["urls"]:
        raise SystemExit("domain pool is smaller than requested workload")

    rng = random.Random(args.seed)
    selected = rng.sample(urls, profile["urls"])
    tab_sequence = [rng.randrange(profile["tabs"]) for _ in selected]
    events = []
    for index, (url, tab_index) in enumerate(zip(selected, tab_sequence)):
        scrolls = []
        for _ in range(rng.randint(*profile["scrolls"])):
            scrolls.append({
                "distance_px": rng.choice([320, 480, 640, 800, 960]),
                "idle_ms": rng.randint(*profile["idle"]),
            })
        events.append({
            "event_index": index,
            "tab_index": tab_index,
            "url": url,
            "pre_navigation_idle_ms": rng.randint(*profile["idle"]),
            "navigation_timeout_ms": 30000,
            "post_navigation_idle_ms": rng.randint(*profile["idle"]),
            "scrolls": scrolls,
        })

    plan = {
        "schema_version": 1,
        "seed": args.seed,
        "intensity": args.intensity,
        "tab_count": profile["tabs"],
        "url_sequence": selected,
        "tab_sequence": tab_sequence,
        "browser_args": ["--disable-quic", "--disable-background-networking"],
        "events": events,
    }
    payload = canonical_bytes(plan)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_bytes(payload)
    print(f"PLAN_SHA256={hashlib.sha256(payload).hexdigest()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
