#!/usr/bin/env python3

from __future__ import annotations

import argparse
import json
import subprocess
from pathlib import Path


SERVER_PORT = 20003
BACKEND_PORT = 18443
LOCAL_SOCKS_PORT = 11082


def tshark_count(
    pcap: Path,
    display_filter: str,
) -> int:

    result = subprocess.run(
        [
            'tshark',
            '-r',
            str(pcap),
            '-Y',
            display_filter,
            '-T',
            'fields',
            '-e',
            'frame.number',
        ],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )

    if result.returncode != 0:
        raise RuntimeError(
            result.stderr.strip()
        )

    return sum(
        1
        for line in result.stdout.splitlines()
        if line.strip()
    )


def stream_set(
    pcap: Path,
    display_filter: str,
    tls: bool = False,
) -> set[str]:

    command = [
        'tshark',
        '-r',
        str(pcap),
    ]

    if tls:
        command.extend(
            [
                '-d',
                f'tcp.port=={SERVER_PORT},tls',
            ]
        )

    command.extend(
        [
            '-Y',
            display_filter,
            '-T',
            'fields',
            '-e',
            'tcp.stream',
        ]
    )

    result = subprocess.run(
        command,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )

    if result.returncode != 0:
        raise RuntimeError(
            result.stderr.strip()
        )

    return {
        line.strip()
        for line in result.stdout.splitlines()
        if line.strip()
    }


def main() -> int:

    parser = argparse.ArgumentParser()

    parser.add_argument(
        'sample_dir',
        type=Path,
    )

    args = parser.parse_args()

    sample = args.sample_dir

    session_path = sample / 'session.json'
    label_path = sample / 'label.json'
    pcap = sample / 'traffic.pcap'

    issues: list[str] = []

    for path in [
        session_path,
        label_path,
        pcap,
    ]:
        if not path.is_file():
            print(
                'MISSING',
                path.name
            )
            return 2

    session = json.loads(
        session_path.read_text()
    )

    label = json.loads(
        label_path.read_text()
    )

    env = session.get(
        'environment_metadata',
        {}
    )

    total_packets = tshark_count(
        pcap,
        'frame.number',
    )

    outer_packets = tshark_count(
        pcap,
        f'tcp.port == {SERVER_PORT}',
    )

    direct_packets = tshark_count(
        pcap,
        f'tcp.port == {BACKEND_PORT}',
    )

    raw_streams = stream_set(
        pcap,
        f'tcp.port == {SERVER_PORT}',
    )

    effective_streams = stream_set(
        pcap,
        (
            f'tcp.port == {SERVER_PORT} '
            '&& tcp.len > 0'
        ),
    )

    tls_client_streams = stream_set(
        pcap,
        (
            f'tcp.port == {SERVER_PORT} '
            '&& tls.handshake.type == 1'
        ),
        tls=True,
    )

    tls_server_streams = stream_set(
        pcap,
        (
            f'tcp.port == {SERVER_PORT} '
            '&& tls.handshake.type == 2'
        ),
        tls=True,
    )

    print(
        'TOTAL_PACKETS',
        total_packets
    )

    print(
        'TROJAN_20003_PACKETS',
        outer_packets
    )

    print(
        'DIRECT_18443_PACKETS',
        direct_packets
    )

    print(
        'RAW_TCP_STREAM_COUNT',
        len(raw_streams)
    )

    print(
        'EFFECTIVE_TCP_STREAM_COUNT',
        len(effective_streams)
    )

    print(
        'PCAP_TLS_CLIENT_HELLO_STREAMS',
        len(tls_client_streams)
    )

    print(
        'PCAP_TLS_SERVER_HELLO_STREAMS',
        len(tls_server_streams)
    )

    print(
        'SESSION_FLOW_COUNT',
        session.get('flow_count')
    )

    print(
        'SESSION_TCP_STREAM_COUNT',
        session.get('tcp_stream_count')
    )

    print(
        'SESSION_TLS_STREAM_COUNT',
        session.get('tls_stream_count')
    )

    print(
        'SESSION_TLS_CLIENT_HELLO_COUNT',
        session.get('tls_client_hello_count')
    )

    print(
        'SESSION_TLS_SERVER_HELLO_COUNT',
        session.get('tls_server_hello_count')
    )

    print(
        'TLS_METADATA_SOURCE',
        session.get('tls_metadata_source')
    )

    print(
        'TLS_HANDSHAKE_COMPLETE',
        session.get('tls_handshake_complete')
    )

    print(
        'ORDERED_STRICT_TIME_ORDER',
        session.get('ordered_strict_time_order')
    )

    if session.get(
        'protocol'
    ) != 'trojan_tcp_tls':

        issues.append(
            'protocol_mismatch'
        )

    if label.get(
        'category'
    ) != 'proxy':

        issues.append(
            'category_mismatch'
        )

    if label.get(
        'label'
    ) != 'trojan':

        issues.append(
            'label_mismatch'
        )

    if env.get(
        'proxy_protocol'
    ) != 'trojan':

        issues.append(
            'proxy_protocol_mismatch'
        )

    if env.get(
        'transport'
    ) != 'tcp':

        issues.append(
            'transport_mismatch'
        )

    if env.get(
        'security'
    ) != 'tls':

        issues.append(
            'security_mismatch'
        )

    if env.get(
        'server_port'
    ) != SERVER_PORT:

        issues.append(
            'server_port_mismatch'
        )

    if env.get(
        'local_socks_port'
    ) != LOCAL_SOCKS_PORT:

        issues.append(
            'local_socks_port_mismatch'
        )

    tls_applicable = session.get(
        'tls_metadata_applicable',
        env.get(
            'tls_metadata_applicable'
        )
    )

    if tls_applicable is not True:

        issues.append(
            'tls_metadata_not_applicable'
        )

    if total_packets <= 0:

        issues.append(
            'empty_capture'
        )

    if outer_packets <= 0:

        issues.append(
            'missing_outer_20003'
        )

    if direct_packets != 0:

        issues.append(
            'direct_backend_bypass'
        )

    expected_min = int(
        env.get(
            'expected_connection_min',
            1
        )
    )

    expected_max = int(
        env.get(
            'expected_connection_max',
            expected_min
        )
    )

    if not (
        expected_min
        <= len(effective_streams)
        <= expected_max
    ):

        issues.append(
            'effective_stream_count_out_of_range'
        )

    if int(
        session.get(
            'tls_stream_count',
            0
        )
    ) < 1:

        issues.append(
            'tls_stream_count_zero'
        )

    if int(
        session.get(
            'tls_client_hello_count',
            0
        )
    ) < 1:

        issues.append(
            'tls_client_hello_zero'
        )

    if int(
        session.get(
            'tls_server_hello_count',
            0
        )
    ) < 1:

        issues.append(
            'tls_server_hello_zero'
        )

    if session.get(
        'tls_handshake_complete'
    ) is not True:

        issues.append(
            'tls_handshake_incomplete'
        )

    if not tls_client_streams:

        issues.append(
            'pcap_client_hello_missing'
        )

    if not tls_server_streams:

        issues.append(
            'pcap_server_hello_missing'
        )

    if (
        tls_client_streams
        != tls_server_streams
    ):

        issues.append(
            'tls_handshake_stream_mismatch'
        )

    if session.get(
        'ordered_strict_time_order'
    ) is not True:

        issues.append(
            'ordered_pcap_not_strict'
        )

    for issue in issues:

        print(
            'ISSUE',
            issue
        )

    print(
        'ISSUE_COUNT',
        len(issues)
    )

    if issues:

        print(
            'TROJAN_SAMPLE_VALIDATION_FAIL'
        )

        return 1

    print(
        'TROJAN_SAMPLE_VALIDATION_PASS'
    )

    return 0


if __name__ == '__main__':
    raise SystemExit(
        main()
    )
