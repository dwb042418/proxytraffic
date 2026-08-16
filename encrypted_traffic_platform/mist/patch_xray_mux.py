#!/usr/bin/env python3
from __future__ import annotations
import argparse
import json
from pathlib import Path
from typing import Any


def load_json(path: Path) -> dict[str, Any]:
    with path.open(encoding='utf-8') as handle:
        value = json.load(handle)
    if not isinstance(value, dict):
        raise RuntimeError('Xray configuration must be a JSON object')
    return value


def save_json(path: Path, value: dict[str, Any]) -> None:
    temporary = Path(str(path) + '.tmp')
    with temporary.open('w', encoding='utf-8') as handle:
        json.dump(value, handle, ensure_ascii=False, indent=2)
        handle.write('\n')
    temporary.replace(path)


def nonempty_flow(value: Any) -> bool:
    if isinstance(value, dict):
        for key, child in value.items():
            if key == 'flow' and isinstance(child, str) and child.strip():
                return True
            if nonempty_flow(child):
                return True
    elif isinstance(value, list):
        return any(nonempty_flow(child) for child in value)
    return False


def patch(path: Path, concurrency: int) -> None:
    config = load_json(path)
    outbounds = config.get('outbounds')
    if not isinstance(outbounds, list):
        raise RuntimeError('Xray configuration has no outbounds list')

    candidates = [
        outbound for outbound in outbounds
        if isinstance(outbound, dict)
        and str(outbound.get('protocol', '')).lower() == 'vless'
    ]
    if len(candidates) != 1:
        raise RuntimeError(f'Expected exactly one VLESS outbound, found {len(candidates)}')

    outbound = candidates[0]
    if nonempty_flow(outbound.get('settings')):
        raise RuntimeError('The VLESS outbound uses a non-empty flow field; Mux is not enabled automatically')

    outbound['mux'] = {
        'enabled': concurrency > 0,
        'concurrency': concurrency if concurrency > 0 else -1,
        'xudpConcurrency': -1,
        'xudpProxyUDP443': 'reject',
    }
    save_json(path, config)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument('config', type=Path)
    parser.add_argument('concurrency', type=int)
    args = parser.parse_args()
    if args.concurrency not in {0, 2, 4, 8}:
        raise SystemExit('concurrency must be one of 0, 2, 4, or 8')
    patch(args.config, args.concurrency)


if __name__ == '__main__':
    main()
