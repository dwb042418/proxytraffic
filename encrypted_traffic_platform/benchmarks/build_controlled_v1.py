#!/usr/bin/env python3

from pathlib import Path
from collections import Counter, defaultdict
import csv
import hashlib
import re
import sys
import yaml

ROOT = Path(__file__).resolve().parents[2]

OUT = ROOT / "docs/benchmarks/proxytraffic_controlled_v1"
SPLIT = OUT / "splits"

OUT.mkdir(parents=True, exist_ok=True)
SPLIT.mkdir(parents=True, exist_ok=True)

PROFILES = [
    "standard",
    "low_rate",
    "high_concurrency",
    "bursty",
    "long_session",
    "perturbed_uplink",
    "perturbed_fullpath",
]

CLASS_ORDER = [
    "vless",
    "shadowsocks",
    "trojan",
]

PROFILE_ORDER = {
    p: i
    for i, p in enumerate(PROFILES)
}

SOURCES = {
    "vless": {
        "freeze": ROOT / "docs/dataset_freeze_records/"
        "v2ray_vless_tcp_tls_freeze_20260816T200211+0800",
        "manifest": "v2ray_dataset_manifest.tsv",
        "protocol": "vless_tcp_tls",
        "implementation": "xray",
        "remote_root":
        "/home/dataset-assist-0/duwenbiao/Tunnel/"
        "proxydata/v2ray/vless_tcp_tls",
        "freeze_tag": "v2ray-vless-tcp-tls-data-freeze-v1",
    },

    "shadowsocks": {
        "freeze": ROOT / "docs/dataset_freeze_records/"
        "shadowsocks_aes_256_gcm_freeze_20260821T132655+0800",
        "manifest": "shadowsocks_dataset_manifest.tsv",
        "protocol": "shadowsocks_aes_256_gcm",
        "implementation": "shadowsocks-rust",
        "remote_root":
        "/home/dataset-assist-0/duwenbiao/Tunnel/"
        "proxydata/shadowsocks/aes_256_gcm/formal_v1",
        "freeze_tag": "shadowsocks-aes-256-gcm-data-freeze-v1",
    },

    "trojan": {
        "freeze": ROOT / "docs/dataset_freeze_records/"
        "trojan_tcp_tls_freeze_20260822T094754Z",
        "manifest": "trojan_dataset_manifest.tsv",
        "protocol": "trojan_tcp_tls",
        "implementation": "xray",
        "remote_root":
        "/home/dataset-assist-0/duwenbiao/Tunnel/"
        "proxydata/trojan/tcp_tls/formal_v1",
        "freeze_tag": "trojan-tcp-tls-data-freeze-v1",
    },
}


def read_tsv(path):
    with path.open(
        newline="",
        encoding="utf-8-sig",
    ) as f:
        return list(
            csv.DictReader(
                f,
                delimiter="\t",
            )
        )


def sha256(path):
    h = hashlib.sha256()

    with path.open("rb") as f:
        for chunk in iter(
            lambda: f.read(1024 * 1024),
            b"",
        ):
            h.update(chunk)

    return h.hexdigest()


def git_tag_commit(tag):
    import subprocess

    result = subprocess.run(
        [
            "git",
            "-C",
            str(ROOT),
            "rev-list",
            "-n",
            "1",
            tag,
        ],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
    )

    return result.stdout.strip()


samples = []
issues = []

for label in CLASS_ORDER:

    src = SOURCES[label]

    freeze = src["freeze"]
    manifest_path = freeze / src["manifest"]

    if not manifest_path.is_file():
        raise SystemExit(
            f"MISSING_MANIFEST={manifest_path}"
        )

    rows = read_tsv(manifest_path)

    if label == "vless":

        rows = [
            r
            for r in rows
            if r.get("dataset", "").strip()
            == "formal_v1"
        ]

        for r in rows:

            profile = r.get(
                "profile",
                "",
            ).strip()

            rel = r.get(
                "relative_path",
                "",
            ).strip()

            samples.append({
                "class_label": label,
                "protocol": src["protocol"],
                "implementation": src["implementation"],
                "profile": profile,
                "source_order":
                r.get("run_id", "").strip()
                or rel,
                "source_relative_session": rel,
                "source_pcap_sha256": "",
                "packet_count": "",
                "byte_count": "",
                "flow_count": "",
                "tcp_stream_count": "",
                "ordered_strict_time_order": "",
                "source_freeze":
                freeze.name,
            })

    elif label == "shadowsocks":

        rows = [
            r
            for r in rows
            if r.get("stage", "").strip()
            == "formal_v1"
        ]

        for r in rows:

            rel = r.get(
                "sample_path",
                "",
            ).strip()

            samples.append({
                "class_label": label,
                "protocol": src["protocol"],
                "implementation": src["implementation"],
                "profile":
                r.get("profile", "").strip(),
                "source_order":
                r.get("batch_id", "").strip()
                or rel,
                "source_relative_session":
                rel + "/session.json",
                "source_pcap_sha256":
                r.get("pcap_sha256", "").strip(),
                "packet_count":
                r.get("packet_count", "").strip(),
                "byte_count":
                r.get("byte_count", "").strip(),
                "flow_count":
                r.get("flow_count", "").strip(),
                "tcp_stream_count":
                r.get("tcp_stream_count", "").strip(),
                "ordered_strict_time_order":
                r.get(
                    "ordered_strict_time_order",
                    "",
                ).strip(),
                "source_freeze":
                freeze.name,
            })

    elif label == "trojan":

        for r in rows:

            rel = r.get(
                "sample_path",
                "",
            ).strip()

            samples.append({
                "class_label": label,
                "protocol": src["protocol"],
                "implementation": src["implementation"],
                "profile":
                r.get("profile", "").strip(),
                "source_order":
                r.get("replicate", "").strip()
                or rel,
                "source_relative_session":
                rel + "/session.json",
                "source_pcap_sha256":
                r.get("pcap_sha256", "").strip(),
                "packet_count":
                r.get("packet_count", "").strip(),
                "byte_count":
                r.get("byte_count", "").strip(),
                "flow_count":
                r.get("flow_count", "").strip(),
                "tcp_stream_count":
                r.get("tcp_stream_count", "").strip(),
                "ordered_strict_time_order":
                r.get(
                    "ordered_strict_time_order",
                    "",
                ).strip(),
                "source_freeze":
                freeze.name,
            })


groups = defaultdict(list)

for s in samples:

    if s["profile"] not in PROFILES:
        issues.append(
            [
                s["class_label"],
                s["profile"],
                "unexpected_profile",
            ]
        )

    groups[
        (
            s["class_label"],
            s["profile"],
        )
    ].append(s)


for key, group in groups.items():

    group.sort(
        key=lambda x: x["source_order"]
    )

    for i, s in enumerate(
        group,
        start=1,
    ):
        s["replicate_index"] = i

        s["sample_id"] = (
            f"{s['class_label']}_"
            f"{s['profile']}_"
            f"r{i:02d}"
        )

        src = SOURCES[
            s["class_label"]
        ]

        remote_session = (
            Path(src["remote_root"])
            / s["source_relative_session"]
        )

        s["remote_session_path"] = str(
            remote_session
        )

        s["remote_pcap_path"] = str(
            remote_session.parent
            / "traffic.pcap"
        )

        if i <= 12:
            primary = "train"
        elif i <= 16:
            primary = "validation"
        else:
            primary = "test"

        s["primary_split"] = primary

        if s["profile"] in {
            "perturbed_uplink",
            "perturbed_fullpath",
        }:
            robust = "test"
        elif i <= 16:
            robust = "train"
        else:
            robust = "validation"

        s["robustness_split"] = robust


expected_groups = {
    (c, p)
    for c in CLASS_ORDER
    for p in PROFILES
}

for key in expected_groups:

    count = len(
        groups.get(
            key,
            [],
        )
    )

    if count != 20:
        issues.append(
            [
                key[0],
                key[1],
                f"sample_count={count}",
            ]
        )


class_counts = Counter(
    s["class_label"]
    for s in samples
)

profile_counts = Counter(
    (
        s["class_label"],
        s["profile"],
    )
    for s in samples
)

primary_counts = Counter(
    s["primary_split"]
    for s in samples
)

robust_counts = Counter(
    s["robustness_split"]
    for s in samples
)


if len(samples) != 420:
    issues.append(
        [
            "global",
            "all",
            f"total_samples={len(samples)}",
        ]
    )


for label in CLASS_ORDER:
    if class_counts[label] != 140:
        issues.append(
            [
                label,
                "all",
                f"class_count={class_counts[label]}",
            ]
        )


samples.sort(
    key=lambda s: (
        CLASS_ORDER.index(
            s["class_label"]
        ),
        PROFILE_ORDER[
            s["profile"]
        ],
        s["replicate_index"],
    )
)


manifest_fields = [
    "sample_id",
    "class_label",
    "protocol",
    "implementation",
    "profile",
    "replicate_index",
    "primary_split",
    "robustness_split",
    "remote_session_path",
    "remote_pcap_path",
    "source_relative_session",
    "source_pcap_sha256",
    "packet_count",
    "byte_count",
    "flow_count",
    "tcp_stream_count",
    "ordered_strict_time_order",
    "source_freeze",
]


with (
    OUT / "controlled_manifest.tsv"
).open(
    "w",
    newline="",
) as f:

    w = csv.DictWriter(
        f,
        delimiter="\t",
        fieldnames=manifest_fields,
    )

    w.writeheader()

    for s in samples:
        w.writerow({
            k: s.get(k, "")
            for k in manifest_fields
        })


with (
    SPLIT / "primary_split.tsv"
).open(
    "w",
    newline="",
) as f:

    w = csv.writer(
        f,
        delimiter="\t",
    )

    w.writerow([
        "sample_id",
        "class_label",
        "profile",
        "replicate_index",
        "split",
    ])

    for s in samples:
        w.writerow([
            s["sample_id"],
            s["class_label"],
            s["profile"],
            s["replicate_index"],
            s["primary_split"],
        ])


with (
    SPLIT / "perturbation_holdout.tsv"
).open(
    "w",
    newline="",
) as f:

    w = csv.writer(
        f,
        delimiter="\t",
    )

    w.writerow([
        "sample_id",
        "class_label",
        "profile",
        "replicate_index",
        "split",
    ])

    for s in samples:
        w.writerow([
            s["sample_id"],
            s["class_label"],
            s["profile"],
            s["replicate_index"],
            s["robustness_split"],
        ])


with (
    OUT / "source_freezes.tsv"
).open(
    "w",
    newline="",
) as f:

    w = csv.writer(
        f,
        delimiter="\t",
    )

    w.writerow([
        "class_label",
        "protocol",
        "freeze_record",
        "freeze_tag",
        "freeze_tag_commit",
        "remote_root",
        "included_samples",
    ])

    for label in CLASS_ORDER:

        src = SOURCES[label]

        w.writerow([
            label,
            src["protocol"],
            src["freeze"].name,
            src["freeze_tag"],
            git_tag_commit(
                src["freeze_tag"]
            ),
            src["remote_root"],
            class_counts[label],
        ])


with (
    OUT / "integrity_issues.tsv"
).open(
    "w",
    newline="",
) as f:

    w = csv.writer(
        f,
        delimiter="\t",
    )

    w.writerow([
        "scope",
        "profile",
        "issue",
    ])

    w.writerows(issues)


policy = {
    "benchmark":
        "proxytraffic_controlled_v1",

    "model_observation_space": {
        "allowed": [
            "packet_length",
            "packet_direction",
            "inter_arrival_time",
            "relative_timestamp",
            "flow_boundary",
            "packet_order",
            "cross_flow_structure",
        ],

        "forbidden": [
            "source_ip",
            "destination_ip",
            "source_port",
            "destination_port",
            "dns",
            "sni",
            "certificate_identity",
            "tls_cipher",
            "tls_version",
            "protocol_fields",
            "proxy_protocol_metadata",
            "security_metadata",
            "profile_name",
            "sample_path",
            "directory_name",
            "filename",
        ],

        "construction_only": [
            "five_tuple",
            "server_port",
            "local_socks_port",
            "source_freeze",
            "pcap_path",
        ],
    },
}


with (
    OUT / "feature_policy.yaml"
).open("w") as f:
    yaml.safe_dump(
        policy,
        f,
        sort_keys=False,
    )


shortcut_rows = [
    (
        "packet_length",
        "allowed",
        "model_input",
    ),
    (
        "packet_direction",
        "allowed",
        "model_input",
    ),
    (
        "inter_arrival_time",
        "allowed",
        "model_input",
    ),
    (
        "flow_boundary",
        "allowed",
        "model_input",
    ),
    (
        "ip_address",
        "forbidden",
        "construction_only",
    ),
    (
        "port_number",
        "forbidden",
        "construction_only",
    ),
    (
        "sni",
        "forbidden",
        "never_model_input",
    ),
    (
        "certificate",
        "forbidden",
        "never_model_input",
    ),
    (
        "protocol_metadata",
        "forbidden",
        "never_model_input",
    ),
    (
        "profile",
        "forbidden",
        "split_and_audit_only",
    ),
    (
        "sample_path",
        "forbidden",
        "data_loading_only",
    ),
]


with (
    OUT / "shortcut_audit.tsv"
).open(
    "w",
    newline="",
) as f:

    w = csv.writer(
        f,
        delimiter="\t",
    )

    w.writerow([
        "field",
        "policy",
        "usage",
    ])

    w.writerows(shortcut_rows)


status = (
    "PASS"
    if not issues
    and primary_counts
    == {
        "train": 252,
        "validation": 84,
        "test": 84,
    }
    and robust_counts
    == {
        "train": 240,
        "validation": 60,
        "test": 120,
    }
    else "FAIL"
)


summary = [
    "benchmark=proxytraffic_controlled_v1",
    f"total_samples={len(samples)}",
    f"vless_samples={class_counts['vless']}",
    f"shadowsocks_samples={class_counts['shadowsocks']}",
    f"trojan_samples={class_counts['trojan']}",
    "profile_count=7",
    "samples_per_class_profile=20",
    f"primary_train={primary_counts['train']}",
    f"primary_validation={primary_counts['validation']}",
    f"primary_test={primary_counts['test']}",
    f"robustness_train={robust_counts['train']}",
    f"robustness_validation={robust_counts['validation']}",
    f"robustness_test={robust_counts['test']}",
    f"integrity_issue_count={len(issues)}",
    "mist_samples_included=0",
    "older_shadowsocks_freeze_included=0",
    f"status={status}",
]


(
    OUT / "benchmark_summary.txt"
).write_text(
    "\n".join(summary)
    + "\n"
)


hash_files = [
    "benchmark_summary.txt",
    "source_freezes.tsv",
    "controlled_manifest.tsv",
    "integrity_issues.tsv",
    "shortcut_audit.tsv",
    "feature_policy.yaml",
    "splits/primary_split.tsv",
    "splits/perturbation_holdout.tsv",
]


with (
    OUT / "CONTROLLED_V1_SHA256SUMS.txt"
).open("w") as f:

    for name in hash_files:

        path = OUT / name

        f.write(
            f"{sha256(path)}  {name}\n"
        )


print(
    f"TOTAL_SAMPLES={len(samples)}"
)

print(
    "CLASS_COUNTS="
    + ",".join(
        f"{k}:{class_counts[k]}"
        for k in CLASS_ORDER
    )
)

print(
    "PRIMARY="
    + ",".join(
        f"{k}:{primary_counts[k]}"
        for k in [
            "train",
            "validation",
            "test",
        ]
    )
)

print(
    "ROBUSTNESS="
    + ",".join(
        f"{k}:{robust_counts[k]}"
        for k in [
            "train",
            "validation",
            "test",
        ]
    )
)

print(
    f"INTEGRITY_ISSUES={len(issues)}"
)

print(
    f"CONTROLLED_V1_STATUS={status}"
)

if status != "PASS":
    raise SystemExit(1)
