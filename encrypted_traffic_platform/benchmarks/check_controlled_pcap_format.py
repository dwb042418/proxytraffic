#!/usr/bin/env python3

from pathlib import Path
import csv
import struct
import sys

manifest = Path(sys.argv[1])

MAGIC = {
    b"\xd4\xc3\xb2\xa1": ("little", "microsecond"),
    b"\xa1\xb2\xc3\xd4": ("big", "microsecond"),
    b"\x4d\x3c\xb2\xa1": ("little", "nanosecond"),
    b"\xa1\xb2\x3c\x4d": ("big", "nanosecond"),
}

selected = {}

with manifest.open(
    newline="",
    encoding="utf-8-sig",
) as f:

    for row in csv.DictReader(
        f,
        delimiter="\t",
    ):

        label = row["class_label"]

        if label not in selected:
            selected[label] = row["remote_pcap_path"]


for label in [
    "vless",
    "shadowsocks",
    "trojan",
]:

    path = Path(
        selected[label]
    )

    print()
    print(
        "===== CLASS",
        label,
        "====="
    )

    print(
        "PCAP",
        path
    )

    print(
        "SIZE",
        path.stat().st_size
    )

    with path.open("rb") as f:

        header = f.read(24)

        if len(header) != 24:
            print(
                "ERROR short_global_header"
            )
            continue

        magic = header[:4]

        if magic not in MAGIC:
            print(
                "ERROR unsupported_magic",
                magic.hex()
            )
            continue

        endian_name, precision = MAGIC[
            magic
        ]

        endian = (
            "<"
            if endian_name == "little"
            else ">"
        )

        (
            _magic,
            major,
            minor,
            thiszone,
            sigfigs,
            snaplen,
            network,
        ) = struct.unpack(
            endian + "IHHiiii",
            header,
        )

        print(
            "FORMAT classic_pcap"
        )

        print(
            "ENDIAN",
            endian_name
        )

        print(
            "TIMESTAMP_PRECISION",
            precision
        )

        print(
            "VERSION",
            major,
            minor
        )

        print(
            "SNAPLEN",
            snaplen
        )

        print(
            "LINKTYPE",
            network
        )

        record = f.read(16)

        if len(record) != 16:
            print(
                "ERROR no_packet_record"
            )
            continue

        ts_sec, ts_frac, incl_len, orig_len = (
            struct.unpack(
                endian + "IIII",
                record,
            )
        )

        packet = f.read(
            incl_len
        )

        print(
            "FIRST_PACKET_CAPTURED_LEN",
            incl_len
        )

        print(
            "FIRST_PACKET_ORIGINAL_LEN",
            orig_len
        )

        if network == 1 \
           and len(packet) >= 14:

            ethertype = struct.unpack(
                "!H",
                packet[12:14],
            )[0]

            print(
                "FIRST_ETHERTYPE",
                hex(ethertype)
            )

        print(
            "FORMAT_CHECK_PASS"
        )
