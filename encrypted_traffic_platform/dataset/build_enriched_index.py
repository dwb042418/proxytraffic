#!/usr/bin/env python3
"""Build index_enriched.csv from sample metadata and PCAP reports."""

from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path
from typing import Any


FIELDS = ("sample_id", "label", "category", "protocol", "src_ip", "dst_ip", "duration", "requested_duration", "capture_mode", "packet_count", "byte_count", "flow_count", "tcp_stream_count", "udp_stream_count", "tls_stream_count", "tls_client_hello_count", "tls_server_hello_count", "plaintext_http_request_count", "max_frame_len", "interface", "client_implementation", "client_version", "client_os", "environment_id", "pcap_sha256", "random_seed", "scenario_version", "scenario_config_hash", "collection_batch", "collection_date", "data_origin", "scenario_parameters", "software_versions", "sample_path", "report_path")


def load(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
        return value if isinstance(value, dict) else {}
    except (OSError, json.JSONDecodeError):
        return {}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("dataset_root", type=Path)
    args = parser.parse_args(argv)
    root = args.dataset_root.expanduser().resolve()
    rows = []
    for session_path in sorted(root.rglob("session.json")):
        if ".batch" in session_path.parts:
            continue
        sample = session_path.parent
        session, label, report = load(session_path), load(sample / "label.json"), load(sample / "experiment_report.json")
        row = {field: report.get(field, session.get(field, label.get(field, ""))) for field in FIELDS}
        for field in ("scenario_parameters", "software_versions"):
            if isinstance(row[field], (dict, list)):
                row[field] = json.dumps(row[field], ensure_ascii=False, sort_keys=True)
        row["sample_id"] = row["sample_id"] or sample.name
        row["sample_path"] = str(sample.relative_to(root))
        row["report_path"] = str((sample / "experiment_report.json").relative_to(root))
        rows.append(row)
    output = root / "index_enriched.csv"
    with output.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=FIELDS)
        writer.writeheader(); writer.writerows(rows)
    print(output); print(f"rows={len(rows)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
