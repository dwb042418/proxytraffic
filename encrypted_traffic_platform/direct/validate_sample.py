#!/usr/bin/env python3

from pathlib import Path
import argparse
import json
import subprocess


DIRECT_PORT = 18443
PROXY_PORTS = [20001, 20002, 20003]


def tshark(pcap, display_filter, field, decode_tls=False):
    cmd = ["tshark", "-r", str(pcap)]
    if decode_tls:
        cmd += ["-d", "tcp.port==18443,tls"]
    cmd += ["-Y", display_filter, "-T", "fields", "-e", field]
    result = subprocess.run(
        cmd, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE
    )
    if result.returncode != 0:
        raise RuntimeError(result.stderr.strip())
    return [line.strip() for line in result.stdout.splitlines() if line.strip()]


def stream_set(pcap, display_filter, decode_tls=False):
    return set(tshark(pcap, display_filter, "tcp.stream", decode_tls))


def packet_count(pcap, display_filter):
    return len(tshark(pcap, display_filter, "frame.number"))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("sample_dir", type=Path)
    args = parser.parse_args()
    sample = args.sample_dir
    session_path = sample / "session.json"
    label_path = sample / "label.json"
    pcap = sample / "traffic.pcap"

    for path in [session_path, label_path, pcap]:
        if not path.is_file():
            print("MISSING", path.name)
            return 2

    session = json.loads(session_path.read_text())
    label = json.loads(label_path.read_text())
    env = session.get("environment_metadata", {})
    issues = []

    direct_packets = packet_count(pcap, "tcp.port == 18443")
    proxy_packets = sum(
        packet_count(pcap, f"tcp.port == {port}") for port in PROXY_PORTS
    )
    raw_streams = stream_set(pcap, "tcp.port == 18443")
    effective_streams = stream_set(pcap, "tcp.port == 18443 && tcp.len > 0")
    tls_client = stream_set(
        pcap, "tcp.port == 18443 && tls.handshake.type == 1", True
    )
    tls_server = stream_set(
        pcap, "tcp.port == 18443 && tls.handshake.type == 2", True
    )

    print("DIRECT_18443_PACKETS", direct_packets)
    print("PROXY_PORT_PACKETS", proxy_packets)
    print("RAW_TCP_STREAM_COUNT", len(raw_streams))
    print("EFFECTIVE_TCP_STREAM_COUNT", len(effective_streams))
    print("PCAP_TLS_CLIENT_HELLO_STREAMS", len(tls_client))
    print("PCAP_TLS_SERVER_HELLO_STREAMS", len(tls_server))
    print("SESSION_FLOW_COUNT", session.get("flow_count"))
    print("SESSION_TCP_STREAM_COUNT", session.get("tcp_stream_count"))
    print("SESSION_TLS_STREAM_COUNT", session.get("tls_stream_count"))

    checks = [
        (session.get("protocol") == "direct_https_tls", "protocol_mismatch"),
        (label.get("category") == "benign", "category_mismatch"),
        (label.get("label") == "benign", "label_mismatch"),
        (env.get("traffic_mode") == "direct", "traffic_mode_mismatch"),
        (env.get("is_proxy") is False, "is_proxy_mismatch"),
        (env.get("server_port") == DIRECT_PORT, "server_port_mismatch"),
        (env.get("transport") == "tcp", "transport_mismatch"),
        (env.get("security") == "tls", "security_mismatch"),
        (
            session.get(
                "tls_metadata_applicable", env.get("tls_metadata_applicable")
            )
            is True,
            "tls_metadata_not_applicable",
        ),
        (direct_packets > 0, "missing_direct_18443"),
        (proxy_packets == 0, "proxy_port_traffic_present"),
        (bool(tls_client), "tls_client_hello_missing"),
        (bool(tls_server), "tls_server_hello_missing"),
        (tls_client == tls_server, "tls_handshake_stream_mismatch"),
        (session.get("tls_handshake_complete") is True, "tls_handshake_incomplete"),
        (
            session.get("ordered_strict_time_order") is True,
            "ordered_pcap_not_strict",
        ),
    ]
    issues.extend(issue for passed, issue in checks if not passed)

    minimum = int(env.get("expected_connection_min", 1))
    maximum = int(env.get("expected_connection_max", minimum))
    if not minimum <= len(effective_streams) <= maximum:
        issues.append("effective_stream_count_out_of_range")

    for issue in issues:
        print("ISSUE", issue)
    print("ISSUE_COUNT", len(issues))
    if issues:
        print("DIRECT_SAMPLE_VALIDATION_FAIL")
        return 1
    print("DIRECT_SAMPLE_VALIDATION_PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
