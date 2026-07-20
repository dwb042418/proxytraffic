#!/usr/bin/env python3
"""Capture a labeled PCAP sample with tcpdump."""

from __future__ import annotations

import argparse
import shutil
import signal
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

if __package__ in {None, ""}:  # Allow direct script execution.
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from encrypted_traffic_platform.common import infer_category
from encrypted_traffic_platform.common import utc_now_iso
from encrypted_traffic_platform.dataset import DatasetManager, SampleRecord


@dataclass(frozen=True)
class CaptureOptions:
    interface: str
    duration: int
    label: str
    dataset_root: Path
    category: str | None = None
    protocol: str = "unknown"
    tool: str | None = None
    environment: str = "lab"
    capture_filter: str | None = None
    dry_run: bool = False
    tcpdump_path: str = "tcpdump"
    interface_candidates: tuple[str, ...] = ("eth0", "ens33", "enp0s3", "docker0", "lo")


class CaptureSession:
    """Manage one tcpdump process and its dataset metadata."""

    def __init__(self, options: CaptureOptions):
        self.options = options
        self.manager = DatasetManager(options.dataset_root)
        self.record: SampleRecord | None = None
        self.process: subprocess.Popen[bytes] | None = None
        self.started_at: float | None = None

    def __enter__(self) -> "CaptureSession":
        self.start()
        return self

    def __exit__(self, exc_type: object, exc: object, tb: object) -> None:
        self.stop()

    def start(self) -> SampleRecord:
        category = self.options.category or infer_category(self.options.label)
        selected_interface = resolve_interface(self.options.interface, self.options.interface_candidates)
        self.record = self.manager.create_sample(
            label=self.options.label,
            category=category,
            protocol=self.options.protocol,
            tool=self.options.tool,
            environment=self.options.environment,
            session={
                "interface": selected_interface,
                "requested_interface": self.options.interface,
                "requested_duration": self.options.duration,
                "capture_filter": self.options.capture_filter,
                "collector": "tcpdump",
                "collector_path": self.options.tcpdump_path,
                "generator": "capture.py",
                "dry_run": self.options.dry_run,
            },
        )
        self.started_at = time.time()

        if self.options.dry_run:
            self.record.pcap_path.touch()
            return self.record

        tcpdump_bin = shutil.which(self.options.tcpdump_path)
        if tcpdump_bin is None:
            raise FileNotFoundError(f"tcpdump not found: {self.options.tcpdump_path}")

        command = [
            tcpdump_bin,
            "-i",
            selected_interface,
            "-w",
            str(self.record.pcap_path),
        ]
        if self.options.capture_filter:
            command.extend(self.options.capture_filter.split())

        self.process = subprocess.Popen(
            command,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
        )
        return self.record

    def wait(self) -> SampleRecord:
        if self.record is None:
            raise RuntimeError("Capture has not been started")
        if not self.options.dry_run:
            time.sleep(max(0, self.options.duration))
        self.stop()
        return self.record

    def stop(self) -> None:
        if self.record is None:
            return

        if self.process and self.process.poll() is None:
            self.process.send_signal(signal.SIGINT)
            try:
                self.process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                self.process.terminate()
                self.process.wait(timeout=5)

        elapsed = time.time() - self.started_at if self.started_at else None
        self.manager.update_session(
            self.record,
            {
                "duration": round(elapsed, 3) if elapsed is not None else None,
                "end_time": utc_now_iso(),
                **pcap_stats(self.record.pcap_path),
            },
        )


def pcap_stats(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {"packet_count": 0, "byte_count": 0}

    byte_count = path.stat().st_size
    packet_count: int | None = None
    try:
        from scapy.all import RawPcapReader

        packet_count = sum(1 for _pkt, _meta in RawPcapReader(str(path)))
    except Exception:
        packet_count = None

    return {"packet_count": packet_count, "byte_count": byte_count}


def list_interfaces() -> list[str]:
    net_dir = Path("/sys/class/net")
    if net_dir.exists():
        return sorted(path.name for path in net_dir.iterdir())
    try:
        import socket

        return [name for _idx, name in socket.if_nameindex()]
    except Exception:
        return []


def resolve_interface(interface: str, candidates: tuple[str, ...]) -> str:
    if interface != "auto":
        return interface

    available = set(list_interfaces())
    for candidate in candidates:
        if candidate in available:
            return candidate

    if available:
        return sorted(available)[0]
    raise RuntimeError("No network interfaces found for auto capture")


def capture_once(options: CaptureOptions) -> SampleRecord:
    with CaptureSession(options) as session:
        return session.wait()


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Capture one labeled PCAP sample")
    parser.add_argument("--interface", required=True, help="Network interface, e.g. eth0, or auto")
    parser.add_argument("--duration", type=int, required=True, help="Capture duration in seconds")
    parser.add_argument("--label", required=True, help="Traffic label")
    parser.add_argument("--category", default=None, help="Override inferred category")
    parser.add_argument("--protocol", default="unknown", help="Protocol name for label.json")
    parser.add_argument("--tool", default=None, help="Tool name for label.json")
    parser.add_argument("--environment", default="lab", help="Environment name")
    parser.add_argument("--dataset-root", default="dataset", help="Dataset output root")
    parser.add_argument("--filter", dest="capture_filter", default=None, help="tcpdump capture filter")
    parser.add_argument("--tcpdump-path", default="tcpdump", help="tcpdump executable path")
    parser.add_argument(
        "--interface-candidates",
        default="eth0,ens33,enp0s3,docker0,lo",
        help="Comma-separated candidates used when --interface auto",
    )
    parser.add_argument("--dry-run", action="store_true", help="Create metadata without running tcpdump")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    options = CaptureOptions(
        interface=args.interface,
        duration=args.duration,
        label=args.label,
        category=args.category,
        protocol=args.protocol,
        tool=args.tool,
        environment=args.environment,
        dataset_root=Path(args.dataset_root),
        capture_filter=args.capture_filter,
        tcpdump_path=args.tcpdump_path,
        dry_run=args.dry_run,
        interface_candidates=tuple(item.strip() for item in args.interface_candidates.split(",") if item.strip()),
    )
    record = capture_once(options)
    print(record.sample_dir)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
