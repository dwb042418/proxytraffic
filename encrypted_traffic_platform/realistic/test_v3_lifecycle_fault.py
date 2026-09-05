#!/usr/bin/env python3
"""Synthetic lifecycle timeout fixture; never executes a browser workload."""
import argparse
import json
import os
import signal
import time
from pathlib import Path

parser = argparse.ArgumentParser()
parser.add_argument("--phase-log", type=Path, required=True)
args = parser.parse_args()
args.phase_log.parent.mkdir(parents=True, exist_ok=True)

def phase(name: str) -> None:
    with args.phase_log.open("a") as handle:
        handle.write(json.dumps({"timestamp_ns": time.time_ns(), "phase": name}) + "\n")
        handle.flush()
        os.fsync(handle.fileno())

phase("EXECUTOR_START")
phase("BROWSER_READY")
phase("WORKLOAD_COMPLETE")
phase("CONTEXT_CLOSE_START")
signal.signal(signal.SIGINT, signal.SIG_IGN)
while True:
    time.sleep(60)
