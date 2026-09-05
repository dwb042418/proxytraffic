#!/usr/bin/env python3
"""Run the deterministic 24-sample smoke against frozen Formal T0 v3 R2 inputs."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path


REPO = Path("/home/etip/Tunnel/proxytraffic")
DOC = REPO / "docs/realistic_v1/formal_t0_v3"
RUNNER = REPO / "encrypted_traffic_platform/realistic/run_24_sample_smoke_v3.py"
R2_INPUTS = {
    DOC / "formal_domain_pool_v3_r2.tsv": "ead6f94c28ec666880ac1a16154b8faebef78e44e76d40001092b10f4040c14a",
    DOC / "formal_domain_split_v3_r2.tsv": "8d1be7a6fa51eed941fe62a4b7e79d57435bdb87af081b791662763480dabe38",
    DOC / "formal_t0_v3_plan_manifest_r2.tsv": "7ce1293a967526ba1ad257bf95b7c3e73e36c6c6add605558098484004886998",
    DOC / "FORMAL_T0_V3_PLAN_SHA256SUMS_R2.txt": "27e608fcf55cbea1bbedc4660c85715d0dab196049e72209e7a7704ebcaf029c",
    DOC / "formal_t0_v3_schedule_r2.tsv": "50bd40d4386c606fef70abf013d119b926c3508a0bccaa879550691c28ae3076",
}


def load_runner():
    spec = importlib.util.spec_from_file_location("r2_smoke", RUNNER)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


runner = load_runner()
runner.base.POOL = DOC / "formal_domain_pool_v3_r2.tsv"
runner.base.SPLIT = DOC / "formal_domain_split_v3_r2.tsv"
runner.base.REGISTRY = DOC / "FORMAL_T0_V3_PLAN_SHA256SUMS_R2.txt"
runner.base.SCHEDULE = DOC / "formal_t0_v3_schedule_r2.tsv"
runner.base.FROZEN_SHA256 = R2_INPUTS
runner.PASS_MARKER = "REALISTIC_V3_R2_24_SAMPLE_SMOKE_PASS"
runner.FAIL_MARKER = "REALISTIC_V3_R2_24_SAMPLE_SMOKE_FAIL"


if __name__ == "__main__":
    sys.argv = [
        sys.argv[0],
        "--local-parent", "/home/etip/datasets/staging/realistic_v1/r2_non_formal_smoke_v3",
        "--remote-parent", "/home/dataset-assist-0/duwenbiao/Tunnel/proxydata/realistic_v1/r2_non_formal_smoke_v3",
    ]
    raise SystemExit(runner.main())
