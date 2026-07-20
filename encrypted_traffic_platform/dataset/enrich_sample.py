#!/usr/bin/env python3

from __future__ import annotations

import argparse
import hashlib
import json
import platform
import subprocess
from pathlib import Path
from typing import Any

import yaml


PROJECT_ROOT = Path(__file__).resolve().parents[2]


def run_command(command: list[str]) -> str:
    result = subprocess.run(
        command,
        check=True,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    return result.stdout


def load_json(path: Path) -> dict[str, Any]:
    with path.open(encoding='utf-8') as handle:
        return json.load(handle)


def dump_json(path: Path, data: dict[str, Any]) -> None:
    temporary = path.with_suffix(path.suffix + '.tmp')

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
        for chunk in iter(lambda: handle.read(1024 * 1024), b''):
            digest.update(chunk)

    return digest.hexdigest()


def resolve_config(path_text: str) -> Path:
    path = Path(path_text).expanduser()

    if not path.is_absolute():
        path = PROJECT_ROOT / path

    return path.resolve()


def find_latest_sample(dataset_root: Path) -> Path:
    candidates = [
        path.parent
        for path in dataset_root.rglob('session.json')
    ]

    if not candidates:
        raise FileNotFoundError(
            f'No sample directory found under {dataset_root}'
        )

    return max(
        candidates,
        key=lambda path: path.stat().st_mtime,
    )


def get_curl_version() -> str:
    try:
        first_line = run_command(
            ['curl', '--version']
        ).splitlines()[0]

        parts = first_line.split()

        if len(parts) >= 2:
            return parts[1]

        return first_line
    except Exception:
        return 'unknown'


def analyse_pcap(pcap_path: Path) -> dict[str, Any]:
    if not pcap_path.exists() or pcap_path.stat().st_size == 0:
        return {
            'packet_count': 0,
            'byte_count': 0,
            'flow_count': 0,
            'tcp_stream_count': 0,
            'udp_stream_count': 0,
            'max_frame_len': 0,
            'actual_capture_duration': 0.0,
            'pcap_sha256': None,
        }

    fields = [
        'frame.time_epoch',
        'frame.len',
        'ip.src',
        'ip.dst',
        'tcp.stream',
        'udp.stream',
        'tcp.srcport',
        'tcp.dstport',
        'udp.srcport',
        'udp.dstport',
    ]

    command = [
        'tshark',
        '-r',
        str(pcap_path),
        '-T',
        'fields',
        '-E',
        'separator=\t',
        '-E',
        'occurrence=f',
    ]

    for field in fields:
        command.extend(['-e', field])

    output = run_command(command)

    packet_count = 0
    byte_count = 0
    max_frame_len = 0
    timestamps: list[float] = []
    tcp_streams: set[str] = set()
    udp_streams: set[str] = set()

    for raw_line in output.splitlines():
        columns = raw_line.split('\t')

        if len(columns) < len(fields):
            columns.extend(
                [''] * (len(fields) - len(columns))
            )

        (
            time_epoch,
            frame_len,
            _src_ip,
            _dst_ip,
            tcp_stream,
            udp_stream,
            _tcp_srcport,
            _tcp_dstport,
            _udp_srcport,
            _udp_dstport,
        ) = columns[:len(fields)]

        packet_count += 1

        if frame_len:
            length = int(frame_len)
            byte_count += length
            max_frame_len = max(max_frame_len, length)

        if time_epoch:
            timestamps.append(float(time_epoch))

        if tcp_stream:
            tcp_streams.add(tcp_stream)

        if udp_stream:
            udp_streams.add(udp_stream)

    if len(timestamps) >= 2:
        duration = max(timestamps) - min(timestamps)
    else:
        duration = 0.0

    return {
        'packet_count': packet_count,
        'byte_count': byte_count,
        'flow_count': len(tcp_streams) + len(udp_streams),
        'tcp_stream_count': len(tcp_streams),
        'udp_stream_count': len(udp_streams),
        'max_frame_len': max_frame_len,
        'actual_capture_duration': round(duration, 6),
        'pcap_sha256': sha256_file(pcap_path),
    }


def analyse_tls(
    pcap_path: Path,
    server_port: int | None,
) -> dict[str, Any]:
    result = {
        'tls_client_hello_count': 0,
        'tls_server_hello_count': 0,
        'tls_stream_count': 0,
    }

    if (
        server_port is None
        or not pcap_path.exists()
        or pcap_path.stat().st_size == 0
    ):
        return result

    decode_rule = f'tcp.port=={server_port},tls'

    client_output = run_command([
        'tshark',
        '-r',
        str(pcap_path),
        '-d',
        decode_rule,
        '-Y',
        'tls.handshake.type == 1',
        '-T',
        'fields',
        '-e',
        'tcp.stream',
    ])

    server_output = run_command([
        'tshark',
        '-r',
        str(pcap_path),
        '-d',
        decode_rule,
        '-Y',
        'tls.handshake.type == 2',
        '-T',
        'fields',
        '-e',
        'tcp.stream',
    ])

    client_streams = {
        line.strip()
        for line in client_output.splitlines()
        if line.strip()
    }

    server_streams = {
        line.strip()
        for line in server_output.splitlines()
        if line.strip()
    }

    result['tls_client_hello_count'] = len(
        client_output.splitlines()
    )

    result['tls_server_hello_count'] = len(
        server_output.splitlines()
    )

    result['tls_stream_count'] = len(
        client_streams | server_streams
    )

    return result


def main() -> int:
    parser = argparse.ArgumentParser(
        description='Enrich one ETIP sample with PCAP-derived metadata'
    )

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

    config_path = resolve_config(
        args.experiment_config
    )

    with config_path.open(encoding='utf-8') as handle:
        experiment_config = yaml.safe_load(handle) or {}

    if args.sample_dir:
        sample_dir = Path(
            args.sample_dir
        ).expanduser().resolve()
    else:
        sample_dir = find_latest_sample(dataset_root)

    label_path = sample_dir / 'label.json'
    session_path = sample_dir / 'session.json'
    report_path = sample_dir / 'experiment_report.json'
    pcap_path = sample_dir / 'traffic.pcap'

    label = load_json(label_path)
    session = load_json(session_path)
    report = load_json(report_path)

    protocol = str(
        experiment_config.get(
            'protocol',
            label.get('protocol', 'unknown'),
        )
    )

    capture_config = (
        experiment_config.get('capture') or {}
    )

    environment = dict(
        experiment_config.get('environment_metadata') or {}
    )

    capture_mode = str(
        capture_config.get(
            'mode',
            environment.get(
                'capture_mode',
                'scenario_bound',
            ),
        )
    )

    environment.setdefault(
        'client_implementation',
        'curl',
    )

    environment.setdefault(
        'client_version',
        get_curl_version(),
    )

    environment.setdefault(
        'client_os',
        'ubuntu22.04',
    )

    environment['client'] = environment[
        'client_implementation'
    ]

    environment['os'] = environment[
        'client_os'
    ]

    environment['capture_mode'] = capture_mode

    source_ip = environment.get(
        'collector_address'
    )

    destination_ip = environment.get(
        'server_address'
    )

    server_port_value = environment.get(
        'server_port'
    )

    server_port = (
        int(server_port_value)
        if server_port_value is not None
        else None
    )

    pcap_stats = analyse_pcap(pcap_path)
    tls_stats = analyse_tls(
        pcap_path,
        server_port,
    )

    requested_duration = experiment_config.get(
        'duration'
    )

    label['protocol'] = protocol

    session.update({
        'protocol': protocol,
        'src': source_ip,
        'src_ip': source_ip,
        'dst': destination_ip,
        'dst_ip': destination_ip,
        'flow_count': pcap_stats['flow_count'],
        'tcp_stream_count': pcap_stats[
            'tcp_stream_count'
        ],
        'udp_stream_count': pcap_stats[
            'udp_stream_count'
        ],
        'packet_count': pcap_stats[
            'packet_count'
        ],
        'byte_count': pcap_stats[
            'byte_count'
        ],
        'duration': pcap_stats[
            'actual_capture_duration'
        ],
        'actual_capture_duration': pcap_stats[
            'actual_capture_duration'
        ],
        'requested_duration': requested_duration,
        'capture_mode': capture_mode,
        'duration_semantics': (
            'scenario_bound_actual_elapsed'
            if capture_mode == 'scenario_bound'
            else 'fixed_duration_window'
        ),
        'max_frame_len': pcap_stats[
            'max_frame_len'
        ],
        'pcap_sha256': pcap_stats[
            'pcap_sha256'
        ],
        'environment_metadata': environment,
        **tls_stats,
    })

    report['label'] = label
    report['session'] = session

    summary = dict(
        report.get('summary') or {}
    )

    summary.update({
        'protocol': protocol,
        'packet_count': session[
            'packet_count'
        ],
        'byte_count': session[
            'byte_count'
        ],
        'flow_count': session[
            'flow_count'
        ],
        'duration': session[
            'duration'
        ],
        'capture_mode': capture_mode,
        'src_ip': source_ip,
        'dst_ip': destination_ip,
        'max_frame_len': session[
            'max_frame_len'
        ],
        **tls_stats,
    })

    report['summary'] = summary

    report['metadata_enrichment'] = {
        'version': '0.1.0',
        'status': 'completed',
        'platform': platform.platform(),
        'pcap_source': 'tshark',
    }

    dump_json(label_path, label)
    dump_json(session_path, session)
    dump_json(report_path, report)

    print(sample_dir)
    print(f'protocol={protocol}')
    print(f'src_ip={source_ip}')
    print(f'dst_ip={destination_ip}')
    print(f'flow_count={session["flow_count"]}')
    print(f'max_frame_len={session["max_frame_len"]}')
    print(f'capture_mode={capture_mode}')

    return 0


if __name__ == '__main__':
    raise SystemExit(main())
