#!/usr/bin/env python3

from pathlib import Path
from collections import Counter
import csv
import json
import sys

MANIFEST = Path(sys.argv[1])
OUT = Path(sys.argv[2])

EXPECTED_PROTOCOL = {
    "vless": "vless_tcp_tls",
    "shadowsocks": "shadowsocks_aes_256_gcm",
    "trojan": "trojan_tcp_tls",
}

rows = []
issues = []

with MANIFEST.open(
    newline="",
    encoding="utf-8-sig",
) as f:
    rows = list(
        csv.DictReader(
            f,
            delimiter="\t",
        )
    )

stats = []
class_counts = Counter()
profile_counts = Counter()

for row in rows:

    sample_id = row["sample_id"]
    label = row["class_label"]
    profile = row["profile"]

    session_path = Path(
        row["remote_session_path"]
    )

    pcap_path = Path(
        row["remote_pcap_path"]
    )

    class_counts[label] += 1
    profile_counts[(label, profile)] += 1

    if not session_path.is_file():

        issues.append([
            sample_id,
            "missing_session_json",
            str(session_path),
        ])

        continue

    if (
        not pcap_path.is_file()
        or pcap_path.stat().st_size <= 0
    ):

        issues.append([
            sample_id,
            "missing_or_empty_pcap",
            str(pcap_path),
        ])

        continue

    try:
        session = json.loads(
            session_path.read_text()
        )
    except Exception as exc:

        issues.append([
            sample_id,
            "invalid_session_json",
            str(exc),
        ])

        continue

    env = session.get(
        "environment_metadata",
        {},
    )

    protocol = session.get(
        "protocol",
        "",
    )

    expected_protocol = EXPECTED_PROTOCOL[
        label
    ]

    if protocol != expected_protocol:

        issues.append([
            sample_id,
            "protocol_mismatch",
            f"{protocol} != {expected_protocol}",
        ])

    ordered = session.get(
        "ordered_strict_time_order"
    )

    if ordered is not True:

        issues.append([
            sample_id,
            "ordered_pcap_not_strict",
            str(ordered),
        ])

    flow_count = session.get(
        "flow_count"
    )

    tcp_stream_count = session.get(
        "tcp_stream_count"
    )

    if flow_count is None:

        issues.append([
            sample_id,
            "missing_flow_count",
            "",
        ])

    if tcp_stream_count is None:

        issues.append([
            sample_id,
            "missing_tcp_stream_count",
            "",
        ])

    tls_applicable = session.get(
        "tls_metadata_applicable",
        env.get(
            "tls_metadata_applicable"
        ),
    )

    if label == "vless":

        if tls_applicable is None:

            legacy_tls_valid = (
                protocol == "vless_tcp_tls"
                and int(
                    session.get(
                        "tls_stream_count",
                        0
                    ) or 0
                ) > 0
                and int(
                    session.get(
                        "tls_client_hello_count",
                        0
                    ) or 0
                ) > 0
                and int(
                    session.get(
                        "tls_server_hello_count",
                        0
                    ) or 0
                ) > 0
                and session.get(
                    "tls_handshake_complete"
                ) is True
            )

            if legacy_tls_valid:
                tls_applicable = True
            else:
                issues.append([
                    sample_id,
                    "legacy_vless_tls_evidence_incomplete",
                    "",
                ])

        elif tls_applicable is not True:

            issues.append([
                sample_id,
                "tls_applicability_mismatch",
                str(tls_applicable),
            ])

    elif label == "trojan":

        if tls_applicable is not True:

            issues.append([
                sample_id,
                "tls_applicability_mismatch",
                str(tls_applicable),
            ])

    elif label == "shadowsocks":

        if tls_applicable is not False:

            issues.append([
                sample_id,
                "tls_applicability_mismatch",
                str(tls_applicable),
            ])

    stats.append({
        "sample_id":
            sample_id,

        "class_label":
            label,

        "profile":
            profile,

        "replicate_index":
            row["replicate_index"],

        "primary_split":
            row["primary_split"],

        "robustness_split":
            row["robustness_split"],

        "protocol":
            protocol,

        "packet_count":
            session.get(
                "packet_count",
                "",
            ),

        "byte_count":
            session.get(
                "byte_count",
                "",
            ),

        "flow_count":
            flow_count,

        "tcp_stream_count":
            tcp_stream_count,

        "duration":
            session.get(
                "duration",
                "",
            ),

        "actual_capture_duration":
            session.get(
                "actual_capture_duration",
                "",
            ),

        "max_frame_len":
            session.get(
                "max_frame_len",
                "",
            ),

        "tls_metadata_applicable":
            tls_applicable,

        "tls_stream_count":
            session.get(
                "tls_stream_count",
                "",
            ),

        "tls_client_hello_count":
            session.get(
                "tls_client_hello_count",
                "",
            ),

        "tls_server_hello_count":
            session.get(
                "tls_server_hello_count",
                "",
            ),

        "tls_handshake_complete":
            session.get(
                "tls_handshake_complete",
                "",
            ),

        "ordered_strict_time_order":
            ordered,

        "pcap_size_bytes":
            pcap_path.stat().st_size,

        "session_pcap_sha256":
            session.get(
                "pcap_sha256",
                "",
            ),

        "remote_session_path":
            str(session_path),

        "remote_pcap_path":
            str(pcap_path),
    })


OUT.mkdir(
    parents=True,
    exist_ok=True,
)

fields = [
    "sample_id",
    "class_label",
    "profile",
    "replicate_index",
    "primary_split",
    "robustness_split",
    "protocol",
    "packet_count",
    "byte_count",
    "flow_count",
    "tcp_stream_count",
    "duration",
    "actual_capture_duration",
    "max_frame_len",
    "tls_metadata_applicable",
    "tls_stream_count",
    "tls_client_hello_count",
    "tls_server_hello_count",
    "tls_handshake_complete",
    "ordered_strict_time_order",
    "pcap_size_bytes",
    "session_pcap_sha256",
    "remote_session_path",
    "remote_pcap_path",
]

with (
    OUT / "observed_stats.tsv"
).open(
    "w",
    newline="",
) as f:

    writer = csv.DictWriter(
        f,
        delimiter="\t",
        fieldnames=fields,
    )

    writer.writeheader()
    writer.writerows(stats)


with (
    OUT / "remote_integrity_issues.tsv"
).open(
    "w",
    newline="",
) as f:

    writer = csv.writer(
        f,
        delimiter="\t",
    )

    writer.writerow([
        "sample_id",
        "issue",
        "detail",
    ])

    writer.writerows(issues)


status = (
    "PASS"
    if len(rows) == 420
    and len(stats) == 420
    and len(issues) == 0
    else "FAIL"
)


summary = [
    "benchmark=proxytraffic_controlled_v1",
    f"manifest_samples={len(rows)}",
    f"audited_samples={len(stats)}",
    f"vless_samples={class_counts['vless']}",
    f"shadowsocks_samples={class_counts['shadowsocks']}",
    f"trojan_samples={class_counts['trojan']}",
    f"remote_integrity_issue_count={len(issues)}",
    f"status={status}",
]

(
    OUT / "remote_audit_summary.txt"
).write_text(
    "\n".join(summary)
    + "\n"
)


print(
    f"MANIFEST_SAMPLES={len(rows)}"
)

print(
    f"AUDITED_SAMPLES={len(stats)}"
)

print(
    f"REMOTE_ISSUES={len(issues)}"
)

print(
    f"REMOTE_AUDIT_STATUS={status}"
)

if status != "PASS":
    raise SystemExit(1)
