#!/usr/bin/env python3

from __future__ import annotations

import argparse
import json
import subprocess
from pathlib import Path


def load_json(path: Path) -> dict:
    return json.loads(
        path.read_text(
            encoding='utf-8'
        )
    )


def packet_count(
    pcap: Path,
    display_filter: str | None = None,
) -> int:
    command = [
        'tshark',
        '-r',
        str(pcap),
    ]

    if display_filter:
        command.extend([
            '-Y',
            display_filter,
        ])

    command.extend([
        '-T',
        'fields',
        '-e',
        'frame.number',
    ])

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

    return sum(
        1
        for line in result.stdout.splitlines()
        if line.strip()
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument('sample_dir')
    args = parser.parse_args()

    sample = Path(
        args.sample_dir
    ).expanduser().resolve()

    label = load_json(
        sample / 'label.json'
    )

    session = load_json(
        sample / 'session.json'
    )

    pcap = sample / 'traffic.pcap'

    issues: list[str] = []

    def require(
        condition: bool,
        message: str,
    ) -> None:
        if not condition:
            issues.append(message)

    require(
        label.get('category') == 'proxy',
        'category_not_proxy',
    )

    require(
        label.get('label') == 'shadowsocks',
        'label_not_shadowsocks',
    )

    require(
        label.get('protocol')
        == 'shadowsocks_aes_256_gcm',
        'label_protocol_mismatch',
    )

    require(
        session.get('protocol')
        == 'shadowsocks_aes_256_gcm',
        'session_protocol_mismatch',
    )

    require(
        session.get(
            'ordered_strict_time_order'
        ) is True,
        'ordered_pcap_not_strict',
    )

    require(
        session.get('max_frame_len', 99999)
        <= 1518,
        'max_frame_len_invalid',
    )

    require(
        session.get('tls_stream_count') == 0,
        'unexpected_outer_tls_stream',
    )

    require(
        session.get(
            'tls_client_hello_count'
        ) == 0,
        'unexpected_outer_client_hello',
    )

    require(
        session.get(
            'tls_server_hello_count'
        ) == 0,
        'unexpected_outer_server_hello',
    )

    require(
        session.get(
            'tls_handshake_complete'
        ) is False,
        'unexpected_outer_tls_handshake',
    )

    raw_hash = session.get(
        'raw_pcap_sha256'
    )

    ordered_hash = session.get(
        'ordered_pcap_sha256'
    )

    pcap_hash = session.get(
        'pcap_sha256'
    )

    require(
        bool(raw_hash),
        'missing_raw_hash',
    )

    require(
        bool(ordered_hash),
        'missing_ordered_hash',
    )

    require(
        bool(pcap_hash),
        'missing_pcap_hash',
    )

    require(
        ordered_hash == pcap_hash,
        'ordered_and_pcap_hash_mismatch',
    )

    env = session.get(
        'environment_metadata'
    ) or {}

    expected_env = {
        'client_implementation':
            'shadowsocks-rust',
        'client_version':
            '1.24.0',
        'proxy_protocol':
            'shadowsocks',
        'cipher':
            'aes-256-gcm',
        'transport':
            'tcp',
        'security':
            'aead',
        'server_port':
            20002,
        'backend_port':
            18443,
        'local_socks_port':
            11081,
    }

    for key, expected in expected_env.items():
        actual = env.get(key)

        require(
            actual == expected,
            '%s_expected_%r_got_%r'
            % (
                key,
                expected,
                actual,
            ),
        )

    tcp_streams = session.get(
        'tcp_stream_count'
    )

    stream_result = subprocess.run(
        [
            'tshark',
            '-r',
            str(pcap),
            '-Y',
            'tcp.len > 0',
            '-T',
            'fields',
            '-e',
            'tcp.stream',
        ],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )

    if stream_result.returncode != 0:
        raise RuntimeError(
            stream_result.stderr.strip()
        )

    effective_streams = {
        item.strip()
        for item in stream_result.stdout.splitlines()
        if item.strip()
    }

    effective_tcp_stream_count = len(
        effective_streams
    )

    minimum = env.get(
        'expected_connection_min'
    )

    maximum = env.get(
        'expected_connection_max'
    )

    if minimum is not None:
        require(
            effective_tcp_stream_count
            >= int(minimum),
            'effective_tcp_stream_count_below_min',
        )

    if maximum is not None:
        require(
            effective_tcp_stream_count
            <= int(maximum),
            'effective_tcp_stream_count_above_max',
        )

    total = packet_count(
        pcap
    )

    shadowsocks_packets = packet_count(
        pcap,
        'tcp.port == 20002',
    )

    direct_packets = packet_count(
        pcap,
        'tcp.port == 18443',
    )

    print(
        'TOTAL_PACKETS=%d'
        % total
    )

    print(
        'SHADOWSOCKS_20002_PACKETS=%d'
        % shadowsocks_packets
    )

    print(
        'DIRECT_18443_PACKETS=%d'
        % direct_packets
    )

    print(
        'TCP_STREAM_COUNT=%s'
        % tcp_streams
    )

    print(
        'EFFECTIVE_TCP_STREAM_COUNT=%s'
        % effective_tcp_stream_count
    )

    require(
        shadowsocks_packets > 0,
        'no_shadowsocks_traffic',
    )

    require(
        direct_packets == 0,
        'direct_backend_leakage',
    )

    require(
        total == shadowsocks_packets,
        'capture_contains_unexpected_packets',
    )

    if issues:
        for issue in issues:
            print(
                'ISSUE=%s'
                % issue
            )

        print(
            'SHADOWSOCKS_SAMPLE_VALIDATION_FAIL'
        )

        return 1

    print(
        'SHADOWSOCKS_SAMPLE_VALIDATION_PASS'
    )

    return 0


if __name__ == '__main__':
    raise SystemExit(
        main()
    )
