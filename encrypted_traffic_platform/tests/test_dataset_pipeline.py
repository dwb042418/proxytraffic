from pathlib import Path

from encrypted_traffic_platform.capture.capture import CaptureOptions, capture_once
from encrypted_traffic_platform.benign_generator import generate_benign
from encrypted_traffic_platform.c2_generator import generate_traffic
from encrypted_traffic_platform.dataset import DatasetManager, build_index
from encrypted_traffic_platform.dataset.validator import validate_dataset
from encrypted_traffic_platform.proxy_generator import generate_proxy
from encrypted_traffic_platform.run_experiment import run_experiment


def test_dataset_manager_creates_standard_sample(tmp_path: Path) -> None:
    manager = DatasetManager(tmp_path)
    record = manager.create_sample(
        label="cobaltstrike",
        category="c2",
        protocol="https",
        session={"duration": 120},
    )

    assert record.pcap_path.name == "traffic.pcap"
    assert record.label_path.exists()
    assert record.session_path.exists()
    assert "cobaltstrike" in str(record.sample_dir)


def test_capture_dry_run_creates_metadata_and_empty_pcap(tmp_path: Path) -> None:
    record = capture_once(
        CaptureOptions(
            interface="lo",
            duration=0,
            label="v2ray",
            category="proxy",
            protocol="vless_vmess_tls",
            dataset_root=tmp_path,
            dry_run=True,
        )
    )

    assert record.pcap_path.exists()
    assert record.label_path.exists()
    assert record.session_path.exists()


def test_c2_generator_dry_run(tmp_path: Path) -> None:
    record = generate_traffic(
        attack_type="behinder",
        duration=0,
        dataset_root=tmp_path,
        dry_run=True,
    )

    assert record.sample_dir.exists()
    assert record.pcap_path.exists()


def test_proxy_generator_dry_run(tmp_path: Path) -> None:
    record = generate_proxy(
        proxy_type="shadowsocks",
        duration=0,
        dataset_root=tmp_path,
        dry_run=True,
    )

    assert record.sample_dir.exists()
    assert record.pcap_path.exists()


def test_benign_generator_dry_run(tmp_path: Path) -> None:
    record = generate_benign(duration=10, dataset_root=tmp_path, dry_run=True)

    assert record.sample_dir.exists()
    assert record.pcap_path.exists()


def test_build_index_and_validator_for_dry_run(tmp_path: Path) -> None:
    generate_benign(duration=0, dataset_root=tmp_path, dry_run=True)
    index_path = build_index(tmp_path)
    samples, issues, counts = validate_dataset(tmp_path, allow_empty_pcap=True)

    assert index_path.exists()
    assert len(samples) == 1
    assert not issues
    assert counts["benign"] == 1


def test_run_experiment_dry_run(tmp_path: Path) -> None:
    record = run_experiment(
        "encrypted_traffic_platform/experiments/benign.yaml",
        dataset_root=tmp_path,
        dry_run=True,
    )

    assert record.sample_dir.exists()
    assert (tmp_path / "index.csv").exists()
