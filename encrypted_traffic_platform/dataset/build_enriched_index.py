#!/usr/bin/env python3

from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path
from typing import Any


FIELDS = [
    'sample_id',
    'label',
    'category',
    'protocol',
    'src_ip',
    'dst_ip',
    'duration',
    'requested_duration',
    'capture_mode',
    'packet_count',
    'byte_count',
    'flow_count',
    'tcp_stream_count',
    'udp_stream_count',
    'tls_stream_count',
    'tls_client_hello_count',
    'tls_server_hello_count',
    'max_frame_len',
    'interface',
    'client_implementation',
    'client_version',
    'client_os',
    'environment_id',
    'pcap_sha256',
    'sample_path',
    'report_path',
]


def load_json(path: Path) -> dict[str, Any]:
    with path.open(encoding='utf-8') as handle:
        return json.load(handle)


def main() -> int:
    parser = argparse.ArgumentParser()

    parser.add_argument(
        'dataset_root',
    )

    args = parser.parse_args()

    dataset_root = Path(
        args.dataset_root
    ).expanduser().resolve()

    rows: list[dict[str, Any]] = []

    for session_path in sorted(
        dataset_root.rglob('session.json')
    ):
        sample_dir = session_path.parent
        label_path = sample_dir / 'label.json'
        report_path = (
            sample_dir / 'experiment_report.json'
        )

        if not label_path.exists():
            continue

        session = load_json(session_path)
        label = load_json(label_path)

        environment = (
            session.get('environment_metadata') or {}
        )

        rows.append({
            'sample_id': session.get(
                'sample_id',
                label.get('sample_id'),
            ),
            'label': label.get('label'),
            'category': label.get('category'),
            'protocol': label.get(
                'protocol',
                session.get('protocol'),
            ),
            'src_ip': session.get('src_ip'),
            'dst_ip': session.get('dst_ip'),
            'duration': session.get('duration'),
            'requested_duration': session.get(
                'requested_duration'
            ),
            'capture_mode': session.get(
                'capture_mode'
            ),
            'packet_count': session.get(
                'packet_count'
            ),
            'byte_count': session.get(
                'byte_count'
            ),
            'flow_count': session.get(
                'flow_count'
            ),
            'tcp_stream_count': session.get(
                'tcp_stream_count'
            ),
            'udp_stream_count': session.get(
                'udp_stream_count'
            ),
            'tls_stream_count': session.get(
                'tls_stream_count'
            ),
            'tls_client_hello_count': session.get(
                'tls_client_hello_count'
            ),
            'tls_server_hello_count': session.get(
                'tls_server_hello_count'
            ),
            'max_frame_len': session.get(
                'max_frame_len'
            ),
            'interface': session.get('interface'),
            'client_implementation': environment.get(
                'client_implementation'
            ),
            'client_version': environment.get(
                'client_version'
            ),
            'client_os': environment.get(
                'client_os'
            ),
            'environment_id': environment.get(
                'environment_id'
            ),
            'pcap_sha256': session.get(
                'pcap_sha256'
            ),
            'sample_path': str(
                sample_dir.relative_to(dataset_root)
            ),
            'report_path': (
                str(report_path.relative_to(dataset_root))
                if report_path.exists()
                else None
            ),
        })

    output_path = dataset_root / 'index_enriched.csv'

    with output_path.open(
        'w',
        encoding='utf-8',
        newline='',
    ) as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=FIELDS,
        )
        writer.writeheader()
        writer.writerows(rows)

    print(output_path)
    print(f'rows={len(rows)}')

    return 0


if __name__ == '__main__':
    raise SystemExit(main())
