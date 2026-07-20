"""PCAP dataset layout and metadata management."""

from __future__ import annotations

import json
import shutil
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from encrypted_traffic_platform import __version__
from encrypted_traffic_platform.common import infer_category


@dataclass(frozen=True)
class SampleRecord:
    """Paths for a single captured dataset sample."""

    sample_id: str
    sample_dir: Path
    pcap_path: Path
    label_path: Path
    session_path: Path
    report_path: Path


class DatasetManager:
    """Create and update labeled traffic samples.

    Layout:

    dataset/
      cobaltstrike/
        sample_YYYYmmddTHHMMSSZ_ab12cd34/
          traffic.pcap
          label.json
          session.json
          experiment_report.json
    """

    def __init__(self, root: str | Path):
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)

    def create_sample(
        self,
        *,
        label: str,
        category: str | None = None,
        protocol: str = "unknown",
        tool: str | None = None,
        environment: str = "lab",
        pcap_source: str | Path | None = None,
        label_extra: dict[str, Any] | None = None,
        session: dict[str, Any] | None = None,
    ) -> SampleRecord:
        normalized_label = label.lower()
        category = category or infer_category(normalized_label)
        timestamp = datetime.now(timezone.utc)
        sample_id = f"sample_{timestamp.strftime('%Y%m%dT%H%M%SZ')}_{uuid.uuid4().hex[:8]}"

        sample_dir = self.root / normalized_label / sample_id
        sample_dir.mkdir(parents=True, exist_ok=False)

        record = SampleRecord(
            sample_id=sample_id,
            sample_dir=sample_dir,
            pcap_path=sample_dir / "traffic.pcap",
            label_path=sample_dir / "label.json",
            session_path=sample_dir / "session.json",
            report_path=sample_dir / "experiment_report.json",
        )

        if pcap_source is not None:
            shutil.copy2(Path(pcap_source), record.pcap_path)

        label_doc: dict[str, Any] = {
            "sample_id": sample_id,
            "label": normalized_label,
            "category": category,
            "protocol": protocol,
            "tool": tool or normalized_label,
            "environment": environment,
            "timestamp": timestamp.isoformat(),
            "pcap": "traffic.pcap",
        }
        if label_extra:
            label_doc.update(label_extra)

        session_doc: dict[str, Any] = {
            "sample_id": sample_id,
            "label": normalized_label,
            "category": category,
            "protocol": protocol,
            "tool": tool or normalized_label,
            "src": None,
            "dst": None,
            "src_ip": None,
            "dst_ip": None,
            "start_time": timestamp.isoformat(),
            "end_time": None,
            "duration": None,
            "packet_count": None,
            "byte_count": None,
            "flow_count": None,
            "generator_version": __version__,
            "generator": None,
        }
        if session:
            session_doc.update(session)

        self.write_json(record.label_path, label_doc)
        self.write_json(record.session_path, session_doc)
        self.write_report(
            record,
            {
                "sample_id": sample_id,
                "label": normalized_label,
                "category": category,
                "status": "created",
                "summary": {},
                "actions": [],
            },
        )
        return record

    def update_session(self, record: SampleRecord, updates: dict[str, Any]) -> None:
        current = self.read_json(record.session_path)
        current.update(updates)
        self.write_json(record.session_path, current)

    def write_report(self, record: SampleRecord, payload: dict[str, Any]) -> None:
        self.write_json(record.report_path, payload)

    @staticmethod
    def read_json(path: str | Path) -> dict[str, Any]:
        json_path = Path(path)
        if not json_path.exists():
            return {}
        return json.loads(json_path.read_text(encoding="utf-8"))

    @staticmethod
    def write_json(path: str | Path, payload: dict[str, Any]) -> None:
        Path(path).write_text(
            json.dumps(payload, indent=2, ensure_ascii=False, sort_keys=True) + "\n",
            encoding="utf-8",
        )
