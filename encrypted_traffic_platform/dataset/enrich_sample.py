#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import time
from pathlib import Path
from typing import Any

import yaml


def run_checked(command: list[str]) -> str:
    result = subprocess.run(
        command,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )

    if result.returncode != 0:
        raise RuntimeError(
            'Command failed:\n'
            + ' '.join(command)
            + '\n'
            + result.stderr
        )

    return result.stdout


def load_json(path: Path) -> dict[str, Any]:
    with path.open(encoding='utf-8') as handle:
        return json.load(handle)


def save_json(path: Path, data: dict[str, Any]) -> None:
    temporary = Path(str(path) + '.tmp')

    with temporary.open('w', encoding='utf-8') as handle:
        json.dump(
            data,
            handle,
            ensure_ascii=False,
            indent=2,
            sort_keys=True,
        )
        handle.write('\n')

    temporary.replace(path)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()

    with path.open('rb') as handle:
        for chunk in iter(
            lambda: handle.read(1024 * 1024),
            b'',
        ):
            digest.update(chunk)

    return digest.hexdigest()


def latest_sample(dataset_root: Path) -> Path:
    samples = [
        path.parent
        for path in dataset_root.rglob('session.json')
    ]

    if not samples:
        raise FileNotFoundError(
            f'No session.json under {dataset_root}'
        )

    return max(
        samples,
        key=lambda path: path.stat().st_mtime,
    )


def parse_tls_streams(
    pcap: Path,
    server_port: int,
    handshake_type: int,
    attempts: int = 3,
) -> set[str]:
    last_error = ''

    for attempt in range(1, attempts + 1):
        result = subprocess.run(
            [
                'tshark',
                '-r',
                str(pcap),
                '-d',
                f'tcp.port=={server_port},tls',
                '-Y',
                f'tls.handshake.type == {handshake_type}',
                '-T',
                'fields',
                '-e',
                'tcp.stream',
            ],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

        if result.returncode == 0:
            streams = {
                item.strip()
                for item in result.stdout.splitlines()
                if item.strip()
            }

            if streams:
                return streams

            last_error = (
                f'empty TLS handshake result '
                f'on attempt {attempt}'
            )
        else:
            last_error = (
                f'tshark exit={result.returncode} '
                f'on attempt {attempt}: '
                f'{result.stderr.strip()}'
            )

        if attempt < attempts:
            time.sleep(1)

    return set()


def analyse_tls(
    ordered_pcap: Path,
    raw_pcap: Path,
    server_port: int,
) -> dict[str, Any]:
    ordered_client = parse_tls_streams(
        ordered_pcap,
        server_port,
        1,
    )
    ordered_server = parse_tls_streams(
        ordered_pcap,
        server_port,
        2,
    )

    selected_client = ordered_client
    selected_server = ordered_server
    source = ordered_pcap.name

    needs_fallback = (
        not ordered_client
        or (
            ordered_client
            and not ordered_server
        )
    )

    if needs_fallback and raw_pcap.is_file():
        raw_client = parse_tls_streams(
            raw_pcap,
            server_port,
            1,
        )
        raw_server = parse_tls_streams(
            raw_pcap,
            server_port,
            2,
        )

        if (
            len(raw_client) + len(raw_server)
            > len(selected_client) + len(selected_server)
        ):
            selected_client = raw_client
            selected_server = raw_server
            source = raw_pcap.name

    return {
        'tls_stream_count': len(
            selected_client | selected_server
        ),
        'tls_client_hello_count': len(
            selected_client
        ),
        'tls_server_hello_count': len(
            selected_server
        ),
        'tls_metadata_source': source,
        'tls_handshake_complete': (
            bool(selected_client)
            and selected_client == selected_server
        ),
    }


def analyse_pcap(
    pcap: Path,
    raw_pcap: Path,
    server_port: int,
    tls_metadata_applicable: bool,
) -> dict[str, Any]:
    if not pcap.exists() or pcap.stat().st_size == 0:
        return {
            'packet_count': 0,
            'byte_count': 0,
            'flow_count': 0,
            'tcp_stream_count': 0,
            'udp_stream_count': 0,
            'duration': 0.0,
            'max_frame_len': 0,
            'pcap_sha256': None,
            'tls_stream_count': 0,
            'tls_client_hello_count': 0,
            'tls_server_hello_count': 0,
            'tls_metadata_source': None,
            'tls_handshake_complete': False,
        }

    fields = run_checked([
        'tshark',
        '-r',
        str(pcap),
        '-T',
        'fields',
        '-E',
        'separator=|',
        '-E',
        'occurrence=f',
        '-e',
        'frame.time_epoch',
        '-e',
        'frame.len',
        '-e',
        'tcp.stream',
        '-e',
        'udp.stream',
    ])

    packet_count = 0
    byte_count = 0
    max_frame_len = 0
    timestamps: list[float] = []
    tcp_streams: set[str] = set()
    udp_streams: set[str] = set()

    for line in fields.splitlines():
        columns = line.split('|')
        columns.extend([''] * (4 - len(columns)))
        timestamp, frame_len, tcp_stream, udp_stream = (
            columns[:4]
        )

        packet_count += 1

        if timestamp:
            timestamps.append(float(timestamp))

        if frame_len:
            length = int(frame_len)
            byte_count += length
            max_frame_len = max(
                max_frame_len,
                length,
            )

        if tcp_stream:
            tcp_streams.add(tcp_stream)

        if udp_stream:
            udp_streams.add(udp_stream)

    duration = (
        max(timestamps) - min(timestamps)
        if len(timestamps) >= 2
        else 0.0
    )

    if tls_metadata_applicable:
        tls = analyse_tls(
            pcap,
            raw_pcap,
            server_port,
        )
        tls['tls_metadata_applicable'] = True
    else:
        tls = {
            'tls_stream_count': 0,
            'tls_client_hello_count': 0,
            'tls_server_hello_count': 0,
            'tls_metadata_source': 'not_applicable',
            'tls_handshake_complete': False,
            'tls_metadata_applicable': False,
        }

    return {
        'packet_count': packet_count,
        'byte_count': byte_count,
        'flow_count': (
            len(tcp_streams)
            + len(udp_streams)
        ),
        'tcp_stream_count': len(
            tcp_streams
        ),
        'udp_stream_count': len(
            udp_streams
        ),
        'duration': round(duration, 6),
        'max_frame_len': max_frame_len,
        'pcap_sha256': sha256_file(pcap),
        **tls,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        '--dataset-root',
        required=True,
    )
    parser.add_argument(
        '--experiment-config',
        required=True,
    )
    parser.add_argument(
        '--sample-dir',
    )
    args = parser.parse_args()

    dataset_root = Path(
        args.dataset_root
    ).expanduser().resolve()

    config_path = Path(
        args.experiment_config
    ).expanduser().resolve()

    sample_dir = (
        Path(args.sample_dir).expanduser().resolve()
        if args.sample_dir
        else latest_sample(dataset_root)
    )

    config = yaml.safe_load(
        config_path.read_text(encoding='utf-8')
    ) or {}

    environment = dict(
        config.get('environment_metadata') or {}
    )

    source_ip = (
        environment.get('collector_address')
        or '192.168.100.10'
    )
    destination_ip = (
        environment.get('server_address')
        or '192.168.100.20'
    )
    server_port = int(
        environment.get('server_port')
        or 20001
    )
    protocol = str(
        config.get('protocol')
        or 'vless_tcp_tls'
    )

    label_path = sample_dir / 'label.json'
    session_path = sample_dir / 'session.json'
    report_path = (
        sample_dir / 'experiment_report.json'
    )
    pcap_path = sample_dir / 'traffic.pcap'
    raw_pcap_path = (
        sample_dir / 'traffic_raw.pcap'
    )

    if not pcap_path.is_file():
        raise FileNotFoundError(pcap_path)

    label = load_json(label_path)
    session = load_json(session_path)
    report = load_json(report_path)

    merged_environment = dict(
        session.get('environment_metadata') or {}
    )
    merged_environment.update(environment)
    merged_environment.update({
        'collector_address': source_ip,
        'server_address': destination_ip,
        'server_port': server_port,
        'client_implementation': (
            merged_environment.get(
                'client_implementation',
                'xray',
            )
        ),
        'client_version': (
            merged_environment.get(
                'client_version',
                '26.6.1',
            )
        ),
        'proxy_protocol': (
            merged_environment.get(
                'proxy_protocol',
                'vless',
            )
        ),
        'transport': (
            merged_environment.get(
                'transport',
                'tcp_tls',
            )
        ),
        'local_socks_port': int(
            merged_environment.get(
                'local_socks_port',
                11080,
            )
        ),
        'capture_mode': (
            merged_environment.get(
                'capture_mode',
                'scenario_bound',
            )
        ),
    })

    explicit_tls_applicability = (
        merged_environment.get(
            'tls_metadata_applicable'
        )
    )

    if explicit_tls_applicability is None:
        security_value = str(
            merged_environment.get(
                'security',
                '',
            )
        ).strip().lower()

        transport_value = str(
            merged_environment.get(
                'transport',
                '',
            )
        ).strip().lower()

        tls_metadata_applicable = (
            security_value == 'tls'
            and 'quic' not in transport_value
        )
    elif isinstance(
        explicit_tls_applicability,
        str,
    ):
        tls_metadata_applicable = (
            explicit_tls_applicability
            .strip()
            .lower()
            in {
                '1',
                'true',
                'yes',
                'on',
            }
        )
    else:
        tls_metadata_applicable = bool(
            explicit_tls_applicability
        )

    merged_environment[
        'tls_metadata_applicable'
    ] = tls_metadata_applicable

    stats = analyse_pcap(
        pcap_path,
        raw_pcap_path,
        server_port,
        tls_metadata_applicable,
    )

    label['protocol'] = protocol

    session.update({
        'protocol': protocol,
        'src': source_ip,
        'src_ip': source_ip,
        'dst': destination_ip,
        'dst_ip': destination_ip,
        'flow_count': stats['flow_count'],
        'tcp_stream_count': stats[
            'tcp_stream_count'
        ],
        'udp_stream_count': stats[
            'udp_stream_count'
        ],
        'packet_count': stats[
            'packet_count'
        ],
        'byte_count': stats['byte_count'],
        'duration': stats['duration'],
        'actual_capture_duration': stats[
            'duration'
        ],
        'requested_duration': config.get(
            'duration',
            120,
        ),
        'capture_mode': merged_environment[
            'capture_mode'
        ],
        'duration_semantics': (
            'scenario_bound_actual_elapsed'
        ),
        'max_frame_len': stats[
            'max_frame_len'
        ],
        'pcap_sha256': stats[
            'pcap_sha256'
        ],
        'tls_stream_count': stats[
            'tls_stream_count'
        ],
        'tls_client_hello_count': stats[
            'tls_client_hello_count'
        ],
        'tls_server_hello_count': stats[
            'tls_server_hello_count'
        ],
        'tls_metadata_source': stats[
            'tls_metadata_source'
        ],
        'tls_handshake_complete': stats[
            'tls_handshake_complete'
        ],
        'tls_metadata_applicable': stats[
            'tls_metadata_applicable'
        ],
        'environment_metadata': (
            merged_environment
        ),
    })

    summary = dict(
        report.get('summary') or {}
    )

    for key in [
        'protocol',
        'src_ip',
        'dst_ip',
        'flow_count',
        'tcp_stream_count',
        'udp_stream_count',
        'packet_count',
        'byte_count',
        'duration',
        'capture_mode',
        'max_frame_len',
        'tls_stream_count',
        'tls_client_hello_count',
        'tls_server_hello_count',
        'tls_metadata_source',
        'tls_handshake_complete',
    ]:
        summary[key] = session.get(key)

    report['label'] = label
    report['session'] = session
    report['summary'] = summary
    report['metadata_enrichment'] = {
        'version': 'tls-retry-fallback-1.0',
        'status': 'completed',
        'source': 'tshark',
        'experiment_config': str(
            config_path
        ),
    }

    save_json(label_path, label)
    save_json(session_path, session)
    save_json(report_path, report)

    print(f'sample_dir={sample_dir}')

    for key in [
        'protocol',
        'src_ip',
        'dst_ip',
        'flow_count',
        'tcp_stream_count',
        'packet_count',
        'byte_count',
        'duration',
        'actual_capture_duration',
        'max_frame_len',
        'tls_stream_count',
        'tls_client_hello_count',
        'tls_server_hello_count',
        'tls_metadata_source',
        'tls_handshake_complete',
        'pcap_sha256',
    ]:
        print(
            f'{key}={session.get(key)}'
        )

    return 0


if __name__ == '__main__':
    raise SystemExit(main())
