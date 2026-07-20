# Encrypted Traffic Intelligence Platform

First-stage dataset generation infrastructure for encrypted C2 and proxy traffic research.

This module focuses on reproducibility:

- automated sample directories
- `traffic.pcap`, `label.json`, and `session.json` per sample
- unified capture CLI
- unified C2 and proxy generator APIs
- Docker/Ansible deployment skeletons

High-risk C2 tools are treated as externally managed lab adapters. Configure your own authorized, isolated lab scripts in `config/lab.yaml`; the repository does not bundle payload deployment or C2 control logic.

## Layout

```text
encrypted_traffic_platform/
├── capture/
├── c2_generator/
├── proxy_generator/
├── dataset/
├── deployment/
├── config/
├── scripts/
└── tests/
```

## Capture One Sample

Dry-run metadata only:

```bash
python encrypted_traffic_platform/capture/capture.py \
  --interface eth0 \
  --duration 1 \
  --label cobaltstrike \
  --protocol https \
  --dataset-root /tmp/etip_dataset \
  --dry-run
```

Live capture requires `tcpdump` and capture privileges:

```bash
python encrypted_traffic_platform/capture/capture.py \
  --interface eth0 \
  --duration 300 \
  --label v2ray \
  --category proxy \
  --protocol vless_vmess_tls
```

## C2 Generator Interface

```python
from encrypted_traffic_platform.c2_generator import generate_traffic

generate_traffic(
    attack_type="cobaltstrike",
    duration=300,
    config_path="encrypted_traffic_platform/config/lab.yaml",
)
```

Supported labels:

- `cobaltstrike`
- `behinder`
- `antsword`
- `godzilla`

Configure each external lab command under `c2_generators.<label>.command`.
You can also pass a scenario file:

```bash
python encrypted_traffic_platform/c2_generator/generate.py \
  --attack-type cobaltstrike \
  --scenario encrypted_traffic_platform/c2_generator/cobaltstrike/scenario.yaml \
  --duration 300 \
  --dry-run
```

## Proxy Generator Interface

```python
from encrypted_traffic_platform.proxy_generator import generate_proxy

generate_proxy(
    proxy_type="v2ray",
    duration=300,
    config_path="encrypted_traffic_platform/config/lab.yaml",
)
```

Supported labels:

- `v2ray`
- `shadowsocks`
- `clash`

Configure each workload command under `proxy_generators.<label>.command`.

## Benign Generator

```bash
python encrypted_traffic_platform/benign_generator/generate.py \
  --duration 300 \
  --actions browser,download,cloud
```

Dry-run:

```bash
python encrypted_traffic_platform/benign_generator/generate.py \
  --duration 300 \
  --dataset-root /tmp/etip_dataset \
  --dry-run
```

## Experiment YAML

Run a complete experiment configuration:

```bash
python encrypted_traffic_platform/run_experiment.py \
  --config encrypted_traffic_platform/experiments/benign.yaml \
  --dry-run
```

Live capture requires `tcpdump` on the collector host and packet-capture privileges:

```bash
python encrypted_traffic_platform/run_experiment.py \
  --config encrypted_traffic_platform/experiments/benign.yaml \
  --dataset-root encrypted_traffic_platform/dataset/output
```

Each experiment sample contains:

```text
traffic.pcap
label.json
session.json
experiment_report.json
```

Experiment files live under `experiments/` for all 8 labels:

- `benign`
- `cobaltstrike`
- `behinder`
- `antsword`
- `godzilla`
- `v2ray`
- `shadowsocks`
- `clash`

## Dataset Format

```text
dataset/
└── cobaltstrike/
    └── sample_YYYYmmddTHHMMSSZ_ab12cd34/
        ├── traffic.pcap
        ├── label.json
        └── session.json
```

`label.json` stores stable label metadata. `session.json` stores runtime details such as interface, duration, packet count, byte count, generator status, and external command result.

Build an index:

```bash
python encrypted_traffic_platform/dataset/build_index.py encrypted_traffic_platform/dataset/output
```

Validate a dataset:

```bash
python encrypted_traffic_platform/dataset/validator.py encrypted_traffic_platform/dataset/output
```

For dry-run datasets:

```bash
python encrypted_traffic_platform/dataset/validator.py encrypted_traffic_platform/dataset/output --allow-empty-pcap
```

## Deployment

```bash
bash encrypted_traffic_platform/scripts/setup.sh --dry-run
bash encrypted_traffic_platform/scripts/setup.sh --compose-up
```

The deployment files are a lab scaffold. Review IP ranges, interfaces, and external tool commands before running outside a throwaway isolated network.
