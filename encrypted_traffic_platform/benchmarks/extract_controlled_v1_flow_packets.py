#!/usr/bin/env python3

from pathlib import Path
from collections import defaultdict
import argparse
import csv
import hashlib
import math
import socket
import struct

import numpy as np


CLASS_TO_ID = {
    "vless": 0,
    "shadowsocks": 1,
    "trojan": 2,
}

VARIANTS = {
    "prefix256": 0,
    "skip5_prefix256": 5,
    "skip10_prefix256": 10,
}


def sha256(path):
    h = hashlib.sha256()

    with path.open("rb") as f:
        for chunk in iter(
            lambda: f.read(1024 * 1024),
            b"",
        ):
            h.update(chunk)

    return h.hexdigest()


def parse_pcap(
    path,
    collector_ip,
    server_ip,
    keep_per_flow,
):

    collector = socket.inet_aton(
        collector_ip
    )

    server = socket.inet_aton(
        server_ip
    )

    flows = defaultdict(list)

    with path.open("rb") as f:

        gh = f.read(24)

        if len(gh) != 24:
            raise RuntimeError(
                "short pcap global header"
            )

        magic = gh[:4]

        if magic == b"\xd4\xc3\xb2\xa1":
            endian = "<"
            scale = 1_000_000

        elif magic == b"\x4d\x3c\xb2\xa1":
            endian = "<"
            scale = 1_000_000_000

        elif magic == b"\xa1\xb2\xc3\xd4":
            endian = ">"
            scale = 1_000_000

        elif magic == b"\xa1\xb2\x3c\x4d":
            endian = ">"
            scale = 1_000_000_000

        else:
            raise RuntimeError(
                f"unsupported pcap magic {magic.hex()}"
            )

        network = struct.unpack(
            endian + "I",
            gh[20:24],
        )[0]

        if network != 1:
            raise RuntimeError(
                f"unsupported linktype {network}"
            )

        while True:

            rh = f.read(16)

            if not rh:
                break

            if len(rh) != 16:
                raise RuntimeError(
                    "truncated packet header"
                )

            (
                ts_sec,
                ts_frac,
                incl_len,
                orig_len,
            ) = struct.unpack(
                endian + "IIII",
                rh,
            )

            frame = f.read(
                incl_len
            )

            if len(frame) != incl_len:
                raise RuntimeError(
                    "truncated packet"
                )

            if len(frame) < 14:
                continue

            ethertype = struct.unpack(
                "!H",
                frame[12:14],
            )[0]

            offset = 14

            while ethertype in {
                0x8100,
                0x88A8,
            }:

                if len(frame) < offset + 4:
                    break

                ethertype = struct.unpack(
                    "!H",
                    frame[offset + 2:offset + 4],
                )[0]

                offset += 4

            if ethertype != 0x0800:
                continue

            if len(frame) < offset + 20:
                continue

            version_ihl = frame[offset]

            if version_ihl >> 4 != 4:
                continue

            ihl = (
                version_ihl & 0x0F
            ) * 4

            if ihl < 20:
                continue

            if len(frame) < offset + ihl:
                continue

            total_len = struct.unpack(
                "!H",
                frame[offset + 2:offset + 4],
            )[0]

            protocol = frame[
                offset + 9
            ]

            if protocol != 6:
                continue

            src_ip = frame[
                offset + 12:offset + 16
            ]

            dst_ip = frame[
                offset + 16:offset + 20
            ]

            if (
                src_ip == collector
                and dst_ip == server
            ):
                direction = 1.0

            elif (
                src_ip == server
                and dst_ip == collector
            ):
                direction = -1.0

            else:
                continue

            tcp_offset = offset + ihl

            if len(frame) < tcp_offset + 20:
                continue

            src_port, dst_port = (
                struct.unpack(
                    "!HH",
                    frame[
                        tcp_offset:
                        tcp_offset + 4
                    ],
                )
            )

            tcp_hlen = (
                frame[tcp_offset + 12]
                >> 4
            ) * 4

            if tcp_hlen < 20:
                continue

            payload_len = (
                total_len
                - ihl
                - tcp_hlen
            )

            if payload_len <= 0:
                continue

            a = (
                src_ip,
                src_port,
            )

            b = (
                dst_ip,
                dst_port,
            )

            key = tuple(
                sorted(
                    (a, b)
                )
            )

            if len(
                flows[key]
            ) >= keep_per_flow:
                continue

            timestamp = (
                ts_sec
                + ts_frac / scale
            )

            flows[key].append(
                (
                    timestamp,
                    direction,
                    total_len,
                )
            )

    ordered = sorted(
        flows.items(),
        key=lambda item:
        item[1][0][0]
        if item[1]
        else float("inf"),
    )

    return [
        packets
        for _, packets in ordered
        if packets
    ]


def make_sequence(
    packets,
    skip,
    budget,
):

    selected = packets[
        skip:
        skip + budget
    ]

    x = np.zeros(
        (budget, 2),
        dtype=np.float32,
    )

    mask = np.zeros(
        budget,
        dtype=np.uint8,
    )

    previous = None

    for i, (
        ts,
        direction,
        ip_len,
    ) in enumerate(selected):

        signed_len = (
            direction
            * float(ip_len)
        )

        if previous is None:
            log_iat = 0.0
        else:
            delta_ms = max(
                0.0,
                (ts - previous) * 1000.0,
            )

            log_iat = math.log1p(
                delta_ms
            )

        x[i, 0] = signed_len
        x[i, 1] = log_iat
        mask[i] = 1

        previous = ts

    return x, mask


def main():

    parser = argparse.ArgumentParser()

    parser.add_argument(
        "--manifest",
        required=True,
    )

    parser.add_argument(
        "--output",
        required=True,
    )

    parser.add_argument(
        "--budget",
        type=int,
        default=256,
    )

    parser.add_argument(
        "--collector-ip",
        default="192.168.100.10",
    )

    parser.add_argument(
        "--server-ip",
        default="192.168.100.20",
    )

    parser.add_argument(
        "--limit-per-class",
        type=int,
        default=0,
    )

    args = parser.parse_args()

    manifest = Path(
        args.manifest
    )

    output = Path(
        args.output
    )

    output.mkdir(
        parents=True,
        exist_ok=True,
    )

    with manifest.open(
        newline="",
        encoding="utf-8-sig",
    ) as f:

        rows = list(
            csv.DictReader(
                f,
                delimiter="\t",
            )
        )

    if args.limit_per_class:

        selected = []
        counts = defaultdict(int)

        for row in rows:

            label = row[
                "class_label"
            ]

            if (
                counts[label]
                >= args.limit_per_class
            ):
                continue

            selected.append(row)

            counts[label] += 1

        rows = selected

    max_skip = max(
        VARIANTS.values()
    )

    keep_per_flow = (
        args.budget
        + max_skip
    )

    arrays = {
        name: {
            "x": [],
            "mask": [],
        }
        for name in VARIANTS
    }

    metadata = []

    audit_rows = []

    for sample_index, row in enumerate(
        rows,
        start=1,
    ):

        sample_id = row[
            "sample_id"
        ]

        label = row[
            "class_label"
        ]

        pcap = Path(
            row[
                "remote_pcap_path"
            ]
        )

        flows = parse_pcap(
            pcap,
            args.collector_ip,
            args.server_ip,
            keep_per_flow,
        )

        if not flows:
            raise RuntimeError(
                f"no data flows {sample_id}"
            )

        flow_count = len(
            flows
        )

        print(
            f"[{sample_index}/{len(rows)}]",
            sample_id,
            "flows=",
            flow_count,
        )

        for flow_index, packets in enumerate(
            flows,
            start=1,
        ):

            metadata.append({
                "sample_id":
                    sample_id,

                "flow_index":
                    flow_index,

                "flows_in_sample":
                    flow_count,

                "class_label":
                    label,

                "class_id":
                    CLASS_TO_ID[label],

                "profile":
                    row["profile"],

                "primary_split":
                    row["primary_split"],

                "robustness_split":
                    row["robustness_split"],

                "sample_weight":
                    1.0 / flow_count,
            })

            audit = [
                sample_id,
                flow_index,
                flow_count,
                len(packets),
            ]

            for name, skip in VARIANTS.items():

                x, mask = make_sequence(
                    packets,
                    skip,
                    args.budget,
                )

                arrays[name][
                    "x"
                ].append(x)

                arrays[name][
                    "mask"
                ].append(mask)

                audit.append(
                    int(mask.sum())
                )

            audit_rows.append(
                audit
            )

    y = np.asarray(
        [
            m["class_id"]
            for m in metadata
        ],
        dtype=np.int64,
    )

    sample_id = np.asarray(
        [
            m["sample_id"]
            for m in metadata
        ]
    )

    flow_index = np.asarray(
        [
            m["flow_index"]
            for m in metadata
        ],
        dtype=np.int16,
    )

    flows_in_sample = np.asarray(
        [
            m["flows_in_sample"]
            for m in metadata
        ],
        dtype=np.int16,
    )

    sample_weight = np.asarray(
        [
            m["sample_weight"]
            for m in metadata
        ],
        dtype=np.float32,
    )

    class_label = np.asarray(
        [
            m["class_label"]
            for m in metadata
        ]
    )

    profile = np.asarray(
        [
            m["profile"]
            for m in metadata
        ]
    )

    primary_split = np.asarray(
        [
            m["primary_split"]
            for m in metadata
        ]
    )

    robustness_split = np.asarray(
        [
            m["robustness_split"]
            for m in metadata
        ]
    )

    for name in VARIANTS:

        x = np.stack(
            arrays[name]["x"]
        )

        mask = np.stack(
            arrays[name]["mask"]
        )

        np.savez_compressed(
            output / f"{name}.npz",
            x=x,
            mask=mask,
            y=y,
            sample_id=sample_id,
            flow_index=flow_index,
            flows_in_sample=
                flows_in_sample,
            sample_weight=
                sample_weight,
            class_label=
                class_label,
            profile=profile,
            primary_split=
                primary_split,
            robustness_split=
                robustness_split,
            feature_names=np.asarray([
                "signed_ipv4_total_length",
                "log1p_iat_ms",
            ]),
            class_names=np.asarray([
                "vless",
                "shadowsocks",
                "trojan",
            ]),
        )

        print(
            name,
            "shape=",
            x.shape,
            "valid_packets=",
            int(mask.sum()),
        )

    with (
        output / "extractor_audit.tsv"
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
            "flow_index",
            "flows_in_sample",
            "captured_data_packets",
            "prefix256_valid",
            "skip5_prefix256_valid",
            "skip10_prefix256_valid",
        ])

        writer.writerows(
            audit_rows
        )

    class_flow_counts = defaultdict(
        int
    )

    for m in metadata:
        class_flow_counts[
            m["class_label"]
        ] += 1

    summary = [
        "extractor=controlled_v1_flow_packets",
        f"manifest_samples={len(rows)}",
        f"flow_records={len(metadata)}",
        f"budget={args.budget}",
        "features=signed_ipv4_total_length,log1p_iat_ms",
        "ip_values_written_to_features=false",
        "port_values_written_to_features=false",
    ]

    for label in [
        "vless",
        "shadowsocks",
        "trojan",
    ]:
        summary.append(
            f"{label}_flow_records="
            f"{class_flow_counts[label]}"
        )

    (
        output / "extractor_summary.txt"
    ).write_text(
        "\n".join(summary)
        + "\n"
    )

    hash_targets = [
        "prefix256.npz",
        "skip5_prefix256.npz",
        "skip10_prefix256.npz",
        "extractor_audit.tsv",
        "extractor_summary.txt",
    ]

    with (
        output / "FEATURE_SHA256SUMS.txt"
    ).open("w") as f:

        for name in hash_targets:

            path = output / name

            f.write(
                f"{sha256(path)}  {name}\n"
            )

    print(
        "FLOW_EXTRACTION_COMPLETE"
    )


if __name__ == "__main__":
    main()
