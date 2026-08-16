#!/usr/bin/env python3
from __future__ import annotations
import argparse
import csv
import hashlib
import json
import subprocess
from decimal import Decimal
from pathlib import Path
from typing import Any


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open('rb') as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b''):
            digest.update(chunk)
    return digest.hexdigest()


def run_tshark(pcap: Path, display_filter: str, fields: list[str], decode_as: list[str] | None = None) -> list[list[str]]:
    command = ['tshark', '-r', str(pcap)]
    for rule in decode_as or []:
        command.extend(['-d', rule])
    command.extend(['-Y', display_filter, '-T', 'fields', '-E', 'separator=\t', '-E', 'occurrence=f'])
    for field in fields:
        command.extend(['-e', field])
    result = subprocess.run(command, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if result.returncode != 0:
        raise RuntimeError('tshark failed:\n' + ' '.join(command) + '\n' + result.stderr)
    rows: list[list[str]] = []
    for raw_line in result.stdout.splitlines():
        values = raw_line.split('\t')
        values += [''] * (len(fields) - len(values))
        rows.append(values[:len(fields)])
    return rows


def unique_tcp_streams(pcap: Path, port: int) -> list[int]:
    rows = run_tshark(pcap, f'tcp.port == {port}', ['tcp.stream'])
    return sorted({int(row[0]) for row in rows if row and row[0].isdigit()})


def tls_client_hellos(pcap: Path, port: int, client_to_server: bool, decode_socks: bool = False) -> list[dict[str, Any]]:
    direction = f'tcp.dstport == {port}' if client_to_server else f'tcp.port == {port}'
    decode = [f'tcp.port=={port},socks'] if decode_socks else []
    rows = run_tshark(
        pcap,
        f'{direction} && tls.handshake.type == 1',
        ['frame.number', 'frame.time_epoch', 'tcp.stream', 'ip.src', 'tcp.srcport', 'ip.dst', 'tcp.dstport', 'tls.handshake.extensions_server_name'],
        decode,
    )
    events: list[dict[str, Any]] = []
    for row in rows:
        if not row[1] or not row[2].isdigit():
            continue
        events.append({
            'frame_number': int(row[0]) if row[0].isdigit() else None,
            'time_epoch': row[1],
            'tcp_stream': int(row[2]),
            'src_ip': row[3],
            'src_port': int(row[4]) if row[4].isdigit() else None,
            'dst_ip': row[5],
            'dst_port': int(row[6]) if row[6].isdigit() else None,
            'sni': row[7] or None,
            'event_source': 'tls_dissector',
        })
    deduplicated: dict[int, dict[str, Any]] = {}
    for event in sorted(events, key=lambda item: Decimal(item['time_epoch'])):
        deduplicated.setdefault(event['tcp_stream'], event)
    return list(deduplicated.values())



def payload_rows(
    pcap: Path,
    port: int,
) -> list[dict[str, Any]]:
    rows = run_tshark(
        pcap,
        f'tcp.port == {port} && tcp.len > 0',
        [
            'frame.number',
            'frame.time_epoch',
            'tcp.stream',
            'ip.src',
            'tcp.srcport',
            'ip.dst',
            'tcp.dstport',
            'tcp.len',
        ],
    )

    result: list[dict[str, Any]] = []

    for row in rows:
        if not row[1] or not row[2].isdigit():
            continue

        result.append({
            'frame_number': (
                int(row[0])
                if row[0].isdigit()
                else None
            ),
            'time_epoch': row[1],
            'tcp_stream': int(row[2]),
            'src_ip': row[3],
            'src_port': (
                int(row[4])
                if row[4].isdigit()
                else None
            ),
            'dst_ip': row[5],
            'dst_port': (
                int(row[6])
                if row[6].isdigit()
                else None
            ),
            'tcp_len': (
                int(row[7])
                if row[7].isdigit()
                else 0
            ),
        })

    return sorted(
        result,
        key=lambda item: (
            Decimal(item['time_epoch']),
            item['frame_number'] or 0,
        ),
    )


def socks_tls_start_fallback(
    pcap: Path,
    port: int,
) -> list[dict[str, Any]]:
    grouped: dict[int, list[dict[str, Any]]] = {}

    for row in payload_rows(pcap, port):
        grouped.setdefault(
            row['tcp_stream'],
            [],
        ).append(row)

    events: list[dict[str, Any]] = []

    for stream_id, rows in grouped.items():
        state = 0
        event = None

        for row in rows:
            client_to_proxy = row['dst_port'] == port
            proxy_to_client = row['src_port'] == port

            if state == 0:
                if client_to_proxy:
                    state = 1
                continue

            if state == 1:
                if proxy_to_client:
                    state = 2
                continue

            if state == 2:
                if (
                    client_to_proxy
                    and row['tcp_len'] >= 7
                ):
                    state = 3
                continue

            if state == 3:
                if proxy_to_client:
                    state = 4
                continue

            if state == 4:
                if (
                    client_to_proxy
                    and row['tcp_len'] >= 5
                ):
                    event = {
                        **row,
                        'sni': None,
                        'event_source':
                            'socks_state_fallback',
                    }
                    break

        if event is not None:
            events.append(event)

    return sorted(
        events,
        key=lambda item: Decimal(
            item['time_epoch']
        ),
    )


def first_client_payload_fallback(
    pcap: Path,
    port: int,
) -> list[dict[str, Any]]:
    events: dict[int, dict[str, Any]] = {}

    for row in payload_rows(pcap, port):
        if row['dst_port'] != port:
            continue

        stream_id = row['tcp_stream']

        if stream_id in events:
            continue

        events[stream_id] = {
            **row,
            'sni': None,
            'event_source':
                'first_client_payload_fallback',
        }

    return sorted(
        events.values(),
        key=lambda item: Decimal(
            item['time_epoch']
        ),
    )


def merge_events(
    primary: list[dict[str, Any]],
    fallback: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    merged = {
        event['tcp_stream']: event
        for event in primary
    }

    for event in fallback:
        merged.setdefault(
            event['tcp_stream'],
            event,
        )

    return sorted(
        merged.values(),
        key=lambda item: Decimal(
            item['time_epoch']
        ),
    )


def deduplicate_events_by_stream(
    events: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    priority = {
        'tls_dissector': 0,
        'socks_state_fallback': 1,
        'first_client_payload_fallback': 2,
    }

    selected: dict[int, dict[str, Any]] = {}

    def event_time(event: dict[str, Any]) -> float:
        try:
            return float(event.get('time_epoch', 0))
        except (TypeError, ValueError):
            return 0.0

    def event_priority(event: dict[str, Any]) -> int:
        source = event.get(
            'event_source',
            'tls_dissector',
        )
        return priority.get(str(source), 3)

    for event in sorted(events, key=event_time):
        stream = event.get('tcp_stream')

        if stream is None:
            continue

        stream = int(stream)
        current = selected.get(stream)

        if current is None:
            selected[stream] = event
            continue

        if event_priority(event) < event_priority(current):
            selected[stream] = event

    return sorted(
        selected.values(),
        key=event_time,
    )


def canonicalize_events_to_observed_streams(
    events: list[dict[str, Any]],
    observed_streams: list[int],
) -> list[dict[str, Any]]:
    valid_streams = {
        int(stream)
        for stream in observed_streams
    }

    source_priority = {
        'tls_dissector': 0,
        'socks_state_fallback': 1,
        'first_client_payload_fallback': 2,
    }

    selected: dict[int, dict[str, Any]] = {}
    selected_keys: dict[int, tuple[Any, ...]] = {}

    for event in events:
        try:
            stream = int(event.get('tcp_stream'))
        except (TypeError, ValueError):
            continue

        if stream not in valid_streams:
            continue

        source = str(
            event.get(
                'event_source',
                'tls_dissector',
            )
        )

        try:
            event_time = Decimal(
                str(event.get('time_epoch', '0'))
            )
        except Exception:
            event_time = Decimal(0)

        try:
            frame_number = int(
                event.get('frame_number') or 0
            )
        except (TypeError, ValueError):
            frame_number = 0

        candidate_key = (
            source_priority.get(source, 3),
            event_time,
            frame_number,
        )

        if (
            stream not in selected
            or candidate_key < selected_keys[stream]
        ):
            selected[stream] = event
            selected_keys[stream] = candidate_key

    return sorted(
        selected.values(),
        key=lambda event: (
            Decimal(
                str(event.get('time_epoch', '0'))
            ),
            int(event.get('tcp_stream')),
        ),
    )

def first_client_application_data(pcap: Path, port: int, decode_socks: bool) -> dict[int, str]:
    decode = [f'tcp.port=={port},socks'] if decode_socks else []
    rows = run_tshark(
        pcap,
        f'tcp.dstport == {port} && tls.record.content_type == 23',
        ['frame.time_epoch', 'tcp.stream'],
        decode,
    )
    result: dict[int, str] = {}
    for row in rows:
        if row[0] and row[1].isdigit():
            result.setdefault(int(row[1]), row[0])
    return result


def read_workload_events(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    with path.open(encoding='utf-8', newline='') as handle:
        rows = list(csv.DictReader(handle, delimiter='\t'))
    return [
        {'action_id': row.get('action_id'), 'launch_epoch_ns': int(row['launch_epoch_ns']), 'url': row.get('url')}
        for row in rows
    ]


def epoch_to_ns(value: str) -> int:
    return int(Decimal(value) * Decimal(1_000_000_000))


def save_json(path: Path, value: dict[str, Any]) -> None:
    temporary = Path(str(path) + '.tmp')
    with temporary.open('w', encoding='utf-8') as handle:
        json.dump(value, handle, ensure_ascii=False, indent=2, sort_keys=True)
        handle.write('\n')
    temporary.replace(path)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument('--sample-dir', type=Path, required=True)
    parser.add_argument('--run-id', required=True)
    parser.add_argument('--profile', required=True)
    parser.add_argument('--mux-level', type=int, required=True)
    parser.add_argument('--expected-inner-sessions', type=int, required=True)
    parser.add_argument('--workload-start-ns', type=int, required=True)
    parser.add_argument('--workload-end-ns', type=int, required=True)
    args = parser.parse_args()

    sample_dir = args.sample_dir
    inner = sample_dir / 'inner_client.pcap'
    outer = sample_dir / 'outer_tunnel.pcap'
    server = sample_dir / 'server_egress.pcap'
    for path in [inner, outer, server]:
        if not path.is_file() or path.stat().st_size == 0:
            raise RuntimeError(f'Missing or empty PCAP: {path}')

    inner_tls_dissector_events = tls_client_hellos(
        inner,
        11080,
        True,
        True,
    )
    inner_events = merge_events(
        inner_tls_dissector_events,
        socks_tls_start_fallback(
            inner,
            11080,
        ),
    )
    inner_decode_mode = 'socks_with_state_fallback'

    server_tls_dissector_events = tls_client_hellos(
        server,
        18443,
        True,
        False,
    )
    server_events = merge_events(
        server_tls_dissector_events,
        first_client_payload_fallback(
            server,
            18443,
        ),
    )

    outer_tls_dissector_events = tls_client_hellos(
        outer,
        20001,
        True,
        False,
    )
    outer_events = merge_events(
        outer_tls_dissector_events,
        first_client_payload_fallback(
            outer,
            20001,
        ),
    )
    inner_events = deduplicate_events_by_stream(
        inner_events
    )
    server_events = deduplicate_events_by_stream(
        server_events
    )
    outer_events = deduplicate_events_by_stream(
        outer_events
    )

    inner_streams = unique_tcp_streams(inner, 11080)
    outer_streams = unique_tcp_streams(outer, 20001)
    server_streams = unique_tcp_streams(server, 18443)
    inner_events = canonicalize_events_to_observed_streams(
        inner_events,
        inner_streams,
    )
    outer_events = canonicalize_events_to_observed_streams(
        outer_events,
        outer_streams,
    )
    server_events = canonicalize_events_to_observed_streams(
        server_events,
        server_streams,
    )

    application_data = first_client_application_data(inner, 11080, inner_decode_mode.startswith('socks'))
    workload_events = sorted(read_workload_events(sample_dir / 'workload_events.tsv'), key=lambda item: item['launch_epoch_ns'])
    inner_events = sorted(inner_events, key=lambda item: Decimal(item['time_epoch']))
    outer_events = sorted(outer_events, key=lambda item: Decimal(item['time_epoch']))

    event_records = []
    for index, event in enumerate(inner_events, start=1):
        stream_id = event['tcp_stream']
        start_ns = epoch_to_ns(event['time_epoch'])
        end_epoch = application_data.get(stream_id)
        end_ns = epoch_to_ns(end_epoch) if end_epoch else None
        action = workload_events[index - 1] if index - 1 < len(workload_events) else {}
        if args.mux_level > 0 and outer_events:
            outer_id = f'outer_tcp_stream_{outer_events[0]["tcp_stream"]}'
            mapping_basis = 'shared_mux_outer_connection'
        elif index - 1 < len(outer_events):
            outer_id = f'outer_tcp_stream_{outer_events[index - 1]["tcp_stream"]}'
            mapping_basis = 'temporal_order_non_mux'
        else:
            outer_id = None
            mapping_basis = 'unresolved'
        event_records.append({
            'inner_session_id': f'inner_{index:03d}',
            'action_id': action.get('action_id'),
            'inner_tcp_stream': stream_id,
            'outer_connection_id': outer_id,
            'mapping_basis': mapping_basis,
            'tls_start_epoch_ns': start_ns,
            'tls_end_epoch_ns': end_ns,
            'tls_start_offset_from_workload_ns': start_ns - args.workload_start_ns,
            'launch_epoch_ns': action.get('launch_epoch_ns'),
            'target_sni': event.get('sni'),
            'event_label_source': event.get(
                'event_source',
                'tls_dissector',
            ),
        })

    checks = {
        'inner_tls_client_hello_count_matches': len(inner_events) == args.expected_inner_sessions,
        'server_tls_client_hello_count_matches': len(server_events) == args.expected_inner_sessions,
        'inner_tcp_stream_count_matches': len(inner_streams) == args.expected_inner_sessions,
        'outer_tls_client_hello_present': len(outer_events) >= 1,
    }
    if args.mux_level > 0:
        checks['outer_connection_count_matches_mux'] = len(outer_streams) == 1
    else:
        checks['outer_connection_count_matches_non_mux'] = len(outer_streams) == args.expected_inner_sessions
    status = 'PASS' if all(checks.values()) else 'FAIL'

    stream_map = {
        'run_id': args.run_id,
        'mapping_version': 'mist_pilot_v1',
        'mux_enabled': args.mux_level > 0,
        'mux_level': args.mux_level,
        'expected_inner_sessions': args.expected_inner_sessions,
        'inner_tls_decode_mode': inner_decode_mode,
        'outer_connections': [
            {
                'outer_connection_id': f'outer_tcp_stream_{stream}',
                'inner_session_ids': [item['inner_session_id'] for item in event_records if item['outer_connection_id'] == f'outer_tcp_stream_{stream}'],
            }
            for stream in outer_streams
        ],
        'inner_sessions': event_records,
    }

    pcap_names = [
        'inner_client_raw.pcap', 'inner_client.pcap',
        'outer_tunnel_raw.pcap', 'outer_tunnel.pcap',
        'server_egress_raw.pcap', 'server_egress.pcap',
    ]
    pcap_files = {name: sample_dir / name for name in pcap_names}
    session = {
        'run_id': args.run_id,
        'dataset_generation': 'mist_pilot_v1',
        'dataset_role': 'cross_layer_event_alignment',
        'category': 'proxy',
        'label': 'v2ray',
        'client_implementation': 'xray',
        'client_version': '26.6.1',
        'proxy_protocol': 'vless',
        'transport': 'tcp_tls',
        'security': 'tls',
        'scenario_profile': args.profile,
        'capture_views': ['inner_client', 'outer_tunnel', 'server_egress'],
        'mux_enabled': args.mux_level > 0,
        'mux_level': args.mux_level,
        'expected_inner_session_count': args.expected_inner_sessions,
        'observed_inner_tcp_stream_count': len(inner_streams),
        'observed_inner_tls_handshake_count': len(inner_events),
        'observed_outer_tcp_stream_count': len(outer_streams),
        'observed_outer_tls_handshake_count': len(outer_events),
        'observed_server_tcp_stream_count': len(server_streams),
        'observed_server_tls_handshake_count': len(server_events),
        'workload_start_epoch_ns': args.workload_start_ns,
        'workload_end_epoch_ns': args.workload_end_ns,
        'event_labels_available': bool(inner_events),
        'inner_tls_decode_mode': inner_decode_mode,
        'validation_checks': checks,
        'validation_status': status,
        'pcap_files': {name: {'size_bytes': path.stat().st_size, 'sha256': sha256_file(path)} for name, path in pcap_files.items()},
    }
    label = {
        'category': 'proxy', 'label': 'v2ray', 'protocol': 'vless_tcp_tls',
        'mux_enabled': args.mux_level > 0, 'mux_level': args.mux_level,
        'inner_session_count': args.expected_inner_sessions, 'scenario_profile': args.profile,
    }
    report = {
        'run_id': args.run_id,
        'validation_status': status,
        'checks': checks,
        'counts': {
            'inner_tcp_streams': len(inner_streams),
            'inner_tls_client_hellos': len(inner_events),
            'outer_tcp_streams': len(outer_streams),
            'outer_tls_client_hellos': len(outer_events),
            'server_tcp_streams': len(server_streams),
            'server_tls_client_hellos': len(server_events),
        },
    }
    save_json(sample_dir / 'stream_map.json', stream_map)
    save_json(sample_dir / 'session.json', session)
    save_json(sample_dir / 'label.json', label)
    save_json(sample_dir / 'experiment_report.json', report)
    print(json.dumps(report, ensure_ascii=False, indent=2))
    if status != 'PASS':
        raise SystemExit(2)


if __name__ == '__main__':
    main()
