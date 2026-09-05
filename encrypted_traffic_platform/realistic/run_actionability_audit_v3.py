#!/usr/bin/env python3
"""Run frozen v3 actionability replays under the user-side supervisor."""

from __future__ import annotations

import argparse
import csv
import json
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

DELAYS = (10.251, 11.255, 13.266)


def run_one(row: dict[str, str], replay: int, root: Path, trial_script: Path,
            supervisor: Path, python: Path) -> dict:
    label = f"rank{int(row['rank']):07d}_{row['domain'].replace('.', '_')}_r{replay}"
    evidence = root / label
    command = [
        str(supervisor), "--label", label, "--evidence", str(evidence),
        "--timeout", "75", "--int-grace", "2", "--term-grace", "2",
        "--kill-grace", "2", "run", "--", str(python), str(trial_script),
        "--rank", row["rank"], "--domain", row["domain"],
        "--bucket", row["rank_bucket"], "--replay", str(replay),
        "--delay", str(DELAYS[replay - 1]), "--result", str(evidence / "trial.json"),
    ]
    completed = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    supervisor_result = {}
    trial = {}
    try:
        supervisor_result = json.loads((evidence / "result.json").read_text())
    except Exception as exc:
        supervisor_result = {"status": "MISSING", "residual_count": -1,
                             "timed_out": True, "error": str(exc)}
    try:
        trial = json.loads((evidence / "trial.json").read_text())
    except Exception as exc:
        trial = {
            "rank": int(row["rank"]), "domain": row["domain"],
            "bucket": row["rank_bucket"], "replay": replay,
            "post_commit_delay_seconds": DELAYS[replay - 1],
            "navigation_status": "FAIL", "main_http_status": 0,
            "evaluate_status": "NOT_RUN", "action_status": "NOT_RUN",
            "http429": 0, "renderer_unresponsive": 1,
            "error": f"trial result missing: {exc}", "exit_code": -1,
        }
    trial.update({
        "supervisor_status": supervisor_result.get("status", "UNKNOWN"),
        "supervisor_timed_out": int(bool(supervisor_result.get("timed_out", True))),
        "executor_residual": supervisor_result.get("residual_count", -1),
        "browser_residual": supervisor_result.get("residual_count", -1),
        "supervisor_exit_code": completed.returncode,
    })
    return trial


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--evidence-root", type=Path, required=True)
    parser.add_argument("--trial-script", type=Path, required=True)
    parser.add_argument("--supervisor", type=Path, required=True)
    parser.add_argument("--python", type=Path, required=True)
    parser.add_argument("--trial-output", type=Path, required=True)
    parser.add_argument("--workers", type=int, default=8)
    args = parser.parse_args()
    rows = list(csv.DictReader(args.input.open(newline=""), delimiter="\t"))
    if not rows or len({row["domain"] for row in rows}) != len(rows):
        raise SystemExit("empty input or duplicate domain")
    args.evidence_root.mkdir(parents=True, exist_ok=False)
    jobs = [(row, replay) for row in rows for replay in (1, 2, 3)]
    results = []
    with ThreadPoolExecutor(max_workers=args.workers) as executor:
        futures = {
            executor.submit(run_one, row, replay, args.evidence_root,
                            args.trial_script, args.supervisor, args.python): (row, replay)
            for row, replay in jobs
        }
        for count, future in enumerate(as_completed(futures), 1):
            result = future.result()
            results.append(result)
            print(f"ACTIONABILITY_PROGRESS completed={count} total={len(jobs)} "
                  f"domain={result['domain']} replay={result['replay']}", flush=True)
    results.sort(key=lambda row: (int(row["rank"]), int(row["replay"])))
    fields = sorted({key for row in results for key in row})
    args.trial_output.parent.mkdir(parents=True, exist_ok=True)
    with args.trial_output.open("w", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields, delimiter="\t", lineterminator="\n")
        writer.writeheader()
        writer.writerows(results)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
