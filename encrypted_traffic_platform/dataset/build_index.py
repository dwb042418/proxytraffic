#!/usr/bin/env python3
"""CLI wrapper for building the dataset CSV index."""

from __future__ import annotations

import sys
from pathlib import Path

if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from encrypted_traffic_platform.dataset.index import main


if __name__ == "__main__":
    raise SystemExit(main())
