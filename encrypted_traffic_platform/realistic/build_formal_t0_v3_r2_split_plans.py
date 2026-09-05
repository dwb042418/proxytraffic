#!/usr/bin/env python3
"""Run the unchanged Formal T0 v3 generator against the approved R2 pool."""

from __future__ import annotations

import importlib.util
from pathlib import Path


REPO = Path("/home/etip/Tunnel/proxytraffic")
SOURCE_RUNNER = REPO / "encrypted_traffic_platform/realistic/build_formal_t0_v3_split_plans.py"


def load_generator():
    spec = importlib.util.spec_from_file_location("formal_t0_v3_generator", SOURCE_RUNNER)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


generator = load_generator()
generator.POOL = generator.DOC / "formal_domain_pool_v3_r2.tsv"
generator.PLANS = Path("/home/etip/datasets/plans/realistic_v1/t0_v3_r2")
generator.FINAL_POOL_SHA256 = "ead6f94c28ec666880ac1a16154b8faebef78e44e76d40001092b10f4040c14a"
generator.POOL_MEMBERSHIP_COUNTS = {"original_stable": 474, "replacement_stable": 26}
generator.SPLIT_PATH = generator.DOC / "formal_domain_split_v3_r2.tsv"
generator.MANIFEST_PATH = generator.DOC / "formal_t0_v3_plan_manifest_r2.tsv"
generator.REGISTRY_PATH = generator.DOC / "FORMAL_T0_V3_PLAN_SHA256SUMS_R2.txt"
generator.SCHEDULE_PATH = generator.DOC / "formal_t0_v3_schedule_r2.tsv"
generator.SUMMARY_PATH = generator.DOC / "formal_t0_v3_split_plan_summary_r2.txt"
generator.OUTPUT_PATHS = (
    generator.SPLIT_PATH,
    generator.MANIFEST_PATH,
    generator.REGISTRY_PATH,
    generator.SCHEDULE_PATH,
    generator.SUMMARY_PATH,
)


if __name__ == "__main__":
    raise SystemExit(generator.main())
