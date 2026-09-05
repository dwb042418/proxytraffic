#!/usr/bin/env python3
"""Aggregate three frozen actionability replays into a domain eligibility audit."""

import argparse
import csv
from collections import defaultdict
from pathlib import Path


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--trials", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    trials = list(csv.DictReader(args.trials.open(newline=""), delimiter="\t"))
    grouped = defaultdict(list)
    for trial in trials:
        grouped[(int(trial["rank"]), trial["domain"], trial["bucket"])].append(trial)
    rows = []
    for (rank, domain, bucket), group in sorted(grouped.items()):
        nav_pass = sum(row["navigation_status"] == "PASS" for row in group)
        eval_pass = sum(row["evaluate_status"] == "PASS" for row in group)
        eval_timeout = sum(row["evaluate_status"] == "TIMEOUT" for row in group)
        action_pass = sum(row["action_status"] == "PASS" for row in group)
        action_timeout = sum(row["action_status"] == "TIMEOUT" for row in group)
        http429 = sum(int(row.get("http429", 0)) for row in group)
        renderer = sum(int(row.get("renderer_unresponsive", 0)) for row in group)
        residual = sum(int(row.get("executor_residual", -1)) != 0 or
                       int(row.get("browser_residual", -1)) != 0 for row in group)
        stable = (len(group) == 3 and nav_pass == eval_pass == action_pass == 3 and
                  eval_timeout == action_timeout == http429 == renderer == residual == 0)
        reasons = []
        if len(group) != 3: reasons.append(f"replay_count={len(group)}")
        if nav_pass != 3: reasons.append(f"navigation_pass={nav_pass}/3")
        if eval_pass != 3: reasons.append(f"evaluate_pass={eval_pass}/3")
        if action_pass != 3: reasons.append(f"action_pass={action_pass}/3")
        if eval_timeout: reasons.append(f"evaluate_timeout={eval_timeout}")
        if action_timeout: reasons.append(f"action_timeout={action_timeout}")
        if http429: reasons.append(f"http429={http429}")
        if renderer: reasons.append(f"renderer_unresponsive={renderer}")
        if residual: reasons.append(f"residual_replays={residual}")
        rows.append({
            "rank": rank, "domain": domain, "bucket": bucket,
            "navigation_pass_count": nav_pass,
            "navigation_fail_count": len(group) - nav_pass,
            "evaluate_pass_count": eval_pass, "evaluate_timeout_count": eval_timeout,
            "action_pass_count": action_pass, "action_timeout_count": action_timeout,
            "http429_count": http429, "renderer_unresponsive_count": renderer,
            "final_actionability_status": "ACTIONABILITY_STABLE" if stable else "ACTIONABILITY_UNSTABLE",
            "failure_reason": ";".join(reasons),
        })
    fields = list(rows[0])
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("w", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields, delimiter="\t", lineterminator="\n")
        writer.writeheader(); writer.writerows(rows)
    stable = sum(row["final_actionability_status"] == "ACTIONABILITY_STABLE" for row in rows)
    print(f"CURRENT_POOL_TOTAL={len(rows)}")
    print(f"ACTIONABILITY_STABLE={stable}")
    print(f"ACTIONABILITY_UNSTABLE={len(rows)-stable}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
