#!/usr/bin/env python3
"""Summarize one or all persisted batch runs."""

from __future__ import annotations

import argparse
import json
from collections import Counter
from pathlib import Path


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("dataset_root", type=Path)
    parser.add_argument("--batch")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)
    state_root = args.dataset_root.expanduser().resolve() / ".batch"
    paths = [state_root / args.batch / "state.json"] if args.batch else sorted(state_root.glob("*/state.json"))
    summaries = []
    for path in paths:
        if not path.exists():
            continue
        state = json.loads(path.read_text(encoding="utf-8"))
        sessions = state.get("sessions", {})
        statuses = Counter(item.get("status", "unknown") for item in sessions.values())
        categories = Counter(key.split(":", 1)[0] for key in sessions)
        summaries.append({"batch": state.get("batch", path.parent.name), "seed": state.get("seed"), "total": len(sessions), "statuses": dict(statuses), "categories": dict(categories)})
    if args.json:
        print(json.dumps(summaries, ensure_ascii=False, indent=2, sort_keys=True))
    else:
        for item in summaries:
            print(f"{item['batch']}: total={item['total']} statuses={item['statuses']} categories={item['categories']}")
    return 0 if summaries else 1


if __name__ == "__main__":
    raise SystemExit(main())
