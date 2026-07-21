#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
from pathlib import Path
from typing import Any

import yaml


def run(command: list[str], allow_failure: bool = False) -> str:
    result = subprocess.run(
        command,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if result.returncode != 0 and not allow_failure:
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
    tmp = Path(str(path) + '.tmp')
    with tmp.open('w', encoding='utf-8') as handle:
        json.dump(data, handle, ensure_ascii=False, indent=2, sort_keys=True)
        handle.write('\n')
    tmp.replace(path)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open('rb') as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b''):
            digest.update(chunk)
    return digest.hexdigest()


def latest_sample(dataset_root: Path) -> Path:
    samples = [p.parent for p in dataset_root.rglob('session.json')]
    if not samples:
        raise FileNotFoundError(f'No session.json under {dataset_root}')
    return max(samples, key=lambda p: p.stat().st_mtime)


def analyse_pcap(pcap: Path, server_port: int) -> dict[str, Any]:
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
        }

    fields = run([
        'tshark', '-r', str(pcap),
        '-T', 'fields',
        '-E', 'separator=|',
        '-E', 'occurrence=f',
        '-e', 'frame.time_epoch',
        '-e', 'frame.len',
        '-e', 'tcp.stream',
        '-e', 'udp.stream',
    ])

    packet_count = 0
    byte_count = 0
    max_frame_len = 0
    timestamps: list[float] = []
    tcp_streams: set[str] = set()
    udp_streams: set[str] = set()

    for line in fields.splitlines():
        cols = line.split('|')
        cols.extend([''] * (4 - len(cols)))
        ts, frame_len, tcp_stream, udp_stream = cols[:4]
        packet_count += 1
        if ts:
            timestamps.append(float(ts))
        if frame_len:
            length = int(frame_len)
            byte_count += length
            max_frame_len = max(max_frame_len, length)
        if tcp_stream:
            tcp_streams.add(tcp_stream)
        if udp_stream:
            udp_streams.add(udp_stream)

    duration = max(timestamps) - min(timestamps) if len(timestamps) >= 2 else 0.0

    def hello_streams(handshake_type: int) -> set[str]:
        output = run([
            'tshark', '-r', str(pcap),
            '-d', f'tcp.port=={server_port},tls',
            '-Y', f'tls.handshake.type == {handshake_type}',
            '-T', 'fields',
            '-e', 'tcp.stream',
        ], allow_failure=True)
        return {x.strip() for x in output.splitlines() if x.strip()}

    client_hellos = hello_streams(1)
    server_hellos = hello_streams(2)

    return {
        'packet_count': packet_count,
        'byte_count': byte_count,
        'flow_count': len(tcp_streams) + len(udp_streams),
        'tcp_stream_count': len(tcp_streams),
        'udp_stream_count': len(udp_streams),
        'duration': round(duration, 6),
        'max_frame_len': max_frame_len,
        'pcap_sha256': sha256_file(pcap),
        'tls_stream_count': len(client_hellos | server_hellos),
        'tls_client_hello_count': len(client_hellos),
        'tls_server_hello_count': len(server_hellos),
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument('--dataset-root', required=True)
    parser.add_argument('--experiment-config', required=True)
    parser.add_argument('--sample-dir')
    args = parser.parse_args()

    dataset_root = Path(args.dataset_root).expanduser().resolve()
    config_path = Path(args.experiment_config).expanduser().resolve()
    sample_dir = (
        Path(args.sample_dir).expanduser().resolve()
        if args.sample_dir else latest_sample(dataset_root)
    )

    config = yaml.safe_load(config_path.read_text(encoding='utf-8')) or {}
    environment = dict(config.get('environment_metadata') or {})

    source_ip = environment.get('collector_address') or '192.168.100.10'
    destination_ip = environment.get('server_address') or '192.168.100.20'
    server_port = int(environment.get('server_port') or 20001)
    protocol = str(config.get('protocol') or 'vless_tcp_tls')

    label_path = sample_dir / 'label.json'
    session_path = sample_dir / 'session.json'
    report_path = sample_dir / 'experiment_report.json'
    pcap_path = sample_dir / 'traffic.pcap'

    if not pcap_path.is_file():
        raise FileNotFoundError(pcap_path)

    label = load_json(label_path)
    session = load_json(session_path)
    report = load_json(report_path)

    merged_environment = dict(session.get('environment_metadata') or {})
    merged_environment.update(environment)
    merged_environment.update({
        'collector_address': source_ip,
        'server_address': destination_ip,
        'server_port': server_port,
        'client_implementation': merged_environment.get('client_implementation', 'xray'),
        'client_version': merged_environment.get('client_version', '26.6.1'),
        'proxy_protocol': merged_environment.get('proxy_protocol', 'vless'),
        'transport': merged_environment.get('transport', 'tcp_tls'),
        'local_socks_port': int(merged_environment.get('local_socks_port', 11080)),
        'capture_mode': merged_environment.get('capture_mode', 'scenario_bound'),
    })

    stats = analyse_pcap(pcap_path, server_port)

    label['protocol'] = protocol
    session.update({
        'protocol': protocol,
        'src': source_ip,
        'src_ip': source_ip,
        'dst': destination_ip,
        'dst_ip': destination_ip,
        'flow_count': stats['flow_count'],
        'tcp_stream_count': stats['tcp_stream_count'],
        'udp_stream_count': stats['udp_stream_count'],
        'packet_count': stats['packet_count'],
        'byte_count': stats['byte_count'],
        'duration': stats['duration'],
        'actual_capture_duration': stats['duration'],
        'requested_duration': config.get('duration', 120),
        'capture_mode': merged_environment['capture_mode'],
        'duration_semantics': 'scenario_bound_actual_elapsed',
        'max_frame_len': stats['max_frame_len'],
        'pcap_sha256': stats['pcap_sha256'],
        'tls_stream_count': stats['tls_stream_count'],
        'tls_client_hello_count': stats['tls_client_hello_count'],
        'tls_server_hello_count': stats['tls_server_hello_count'],
        'environment_metadata': merged_environment,
    })

    summary = dict(report.get('summary') or {})
    for key in [
        'protocol', 'src_ip', 'dst_ip', 'flow_count', 'tcp_stream_count',
        'udp_stream_count', 'packet_count', 'byte_count', 'duration',
        'capture_mode', 'max_frame_len', 'tls_stream_count',
        'tls_client_hello_count', 'tls_server_hello_count',
    ]:
        summary[key] = session.get(key)

    report['label'] = label
    report['session'] = session
    report['summary'] = summary
    report['metadata_enrichment'] = {
        'version': 'repair-1.0',
        'status': 'completed',
        'source': 'tshark',
        'experiment_config': str(config_path),
    }

    save_json(label_path, label)
    save_json(session_path, session)
    save_json(report_path, report)

    print(f'sample_dir={sample_dir}')
    for key in [
        'protocol', 'src_ip', 'dst_ip', 'flow_count', 'tcp_stream_count',
        'packet_count', 'byte_count', 'duration', 'actual_capture_duration',
        'max_frame_len', 'tls_stream_count', 'tls_client_hello_count',
        'tls_server_hello_count', 'pcap_sha256',
    ]:
        print(f'{key}={session.get(key)}')

    for key in [
        'client_implementation', 'client_version', 'proxy_protocol',
        'transport', 'server_port', 'local_socks_port',
    ]:
        print(f'{key}={merged_environment.get(key)}')

    return 0


if __name__ == '__main__':
    raise SystemExit(main())
