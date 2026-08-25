#!/usr/bin/env python3
"""Quality gate for one Realistic three-sided paired sample."""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
from pathlib import Path


TUNNEL_PORTS = (21001, 21002, 21003)
EXPECTED_PORT = {"direct": None, "vless": 21001, "shadowsocks": 21002, "trojan": 21003}


def tshark_count(pcap: Path, display_filter: str | None = None) -> int:
    command = ["tshark", "-r", str(pcap)]
    if display_filter:
        command += ["-Y", display_filter]
    command += ["-T", "fields", "-e", "frame.number"]
    result = subprocess.run(command, check=True, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    return sum(bool(line.strip()) for line in result.stdout.splitlines())


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--sample-dir", type=Path, required=True)
    parser.add_argument("--mode", choices=tuple(EXPECTED_PORT), required=True)
    args = parser.parse_args()

    root = args.sample_dir
    pcaps = {name: root / f"{name}.pcap" for name in ("original", "observed", "egress")}
    packet_counts = {name: tshark_count(path) for name, path in pcaps.items()}
    syn = "tcp.flags.syn==1 && tcp.flags.ack==0"
    tunnel_counts = {
        str(port): tshark_count(pcaps["observed"], f"{syn} && tcp.dstport=={port}")
        for port in TUNNEL_PORTS
    }
    original_tunnel_count = sum(
        tshark_count(pcaps["original"], f"tcp.port=={port}") for port in TUNNEL_PORTS
    )
    public_443 = tshark_count(
        pcaps["observed"],
        f"{syn} && tcp.dstport==443 && ip.dst!=192.168.220.20",
    )
    report_path = root / "workload" / "workload_report.json"
    workload = json.loads(report_path.read_text())
    plan_path = root / "workload" / "workload_plan.json"
    plan_hash = digest(plan_path)

    issues: list[str] = []
    for name, count in packet_counts.items():
        if count <= 0:
            issues.append(f"{name}_pcap_empty")
    if workload.get("hard_failure_count") is None:
        issues.append("workload_hard_failure_count_missing")
    elif workload["hard_failure_count"] != 0:
        issues.append("workload_hard_failure")
    if workload.get("workload_plan_sha256") != plan_hash:
        issues.append("workload_plan_hash_mismatch")
    if original_tunnel_count:
        issues.append("original_contains_tunnel_port")

    expected = EXPECTED_PORT[args.mode]
    for port in TUNNEL_PORTS:
        count = tunnel_counts[str(port)]
        if port == expected and count <= 0:
            issues.append(f"expected_tunnel_{port}_missing")
        if port != expected and count:
            issues.append(f"unexpected_tunnel_{port}")
    if args.mode == "direct" and public_443 <= 0:
        issues.append("direct_public_443_missing")
    if args.mode != "direct" and public_443:
        issues.append("proxy_public_443_bypass")

    report = {
        "schema_version": 1,
        "status": "PASS" if not issues else "FAIL",
        "mode": args.mode,
        "packet_counts": packet_counts,
        "observed_tunnel_syn_counts": tunnel_counts,
        "observed_direct_public_443_syn_count": public_443,
        "original_tunnel_packet_count": original_tunnel_count,
        "workload_plan_sha256": plan_hash,
        "egress_applicable": True,
        "issues": issues,
    }
    (root / "quality_report.json").write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    print(json.dumps(report, sort_keys=True))
    return 0 if not issues else 1


if __name__ == "__main__":
    raise SystemExit(main())
