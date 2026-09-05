#!/usr/bin/env python3
"""Qualify deterministic v3 replacement candidates with two fail-closed workers."""

from __future__ import annotations

import argparse
import csv
import json
import os
import signal
import subprocess
import time
from collections import deque
from datetime import datetime, timezone
from pathlib import Path


DELAYS = (10.251, 11.255, 13.266)
STOP_REQUESTED = False


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def atomic_json(path: Path, value: dict) -> None:
    temporary = path.with_suffix(path.suffix + ".tmp")
    with temporary.open("w") as handle:
        json.dump(value, handle, indent=2, sort_keys=True)
        handle.write("\n")
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(temporary, path)


def request_stop(signum, _frame) -> None:
    global STOP_REQUESTED
    STOP_REQUESTED = True
    print(f"REPLACEMENT_STOP_REQUESTED signal={signal.Signals(signum).name}", flush=True)


def signal_group(pgid: int, sig: int) -> None:
    try:
        os.killpg(pgid, sig)
    except ProcessLookupError:
        pass


def wait_group_gone(pgid: int, seconds: float) -> bool:
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        try:
            os.killpg(pgid, 0)
        except ProcessLookupError:
            return True
        time.sleep(0.05)
    return False


def stop_process(process: subprocess.Popen, evidence: Path) -> None:
    try:
        state = json.loads((evidence / "state.json").read_text())
        pgid = int(state["executor_pgid"])
    except Exception:
        pgid = 0
    if pgid > 1:
        for sig in (signal.SIGINT, signal.SIGTERM, signal.SIGKILL):
            signal_group(pgid, sig)
            if wait_group_gone(pgid, 2.0):
                break
    if process.poll() is None:
        process.terminate()
        try:
            process.wait(timeout=2)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=2)


def stop_active(active: list[dict]) -> None:
    for qualification in active:
        process = qualification.get("process")
        evidence = qualification.get("trial_evidence")
        if process is not None and evidence is not None:
            stop_process(process, evidence)


def fallback_trial(qualification: dict, replay: int, error: str) -> dict:
    candidate = qualification["candidate"]
    return {
        "rank": int(candidate["candidate_rank"]),
        "domain": candidate["candidate_domain"],
        "bucket": candidate["candidate_bucket"],
        "replay": replay,
        "post_commit_delay_seconds": DELAYS[replay - 1],
        "navigation_status": "FAIL",
        "main_http_status": 0,
        "evaluate_status": "NOT_RUN",
        "action_status": "NOT_RUN",
        "http429": 0,
        "renderer_unresponsive": 1,
        "error": error[:1000],
        "exit_code": -1,
    }


def collect(qualification: dict) -> dict:
    process = qualification["process"]
    evidence = qualification["trial_evidence"]
    replay = qualification["replay"]
    try:
        supervisor = json.loads((evidence / "result.json").read_text())
    except Exception as exc:
        supervisor = {
            "status": "MISSING",
            "residual_count": -1,
            "timed_out": True,
            "error": str(exc),
        }
    try:
        trial = json.loads((evidence / "trial.json").read_text())
    except Exception as exc:
        trial = fallback_trial(qualification, replay, f"trial result missing: {exc}")
    trial.update({
        "trial_start_utc": supervisor.get("start_utc", ""),
        "trial_end_utc": supervisor.get("end_utc", ""),
        "supervisor_status": supervisor.get("status", "UNKNOWN"),
        "supervisor_timed_out": int(bool(supervisor.get("timed_out", True))),
        "executor_residual": supervisor.get("residual_count", -1),
        "browser_residual": supervisor.get("residual_count", -1),
        "supervisor_exit_code": process.returncode,
        "old_rank": int(qualification["slot"]["old_rank"]),
        "old_domain": qualification["slot"]["old_domain"],
        "candidate_attempt_order": qualification["attempt_order"],
        "trial_evidence": str(evidence),
    })
    return trial


def infrastructure_failure(trial: dict) -> str:
    if int(trial.get("supervisor_timed_out", 1)) != 0:
        return "SUPERVISOR_TIMEOUT"
    if int(trial.get("executor_residual", -1)) != 0:
        return "EXECUTOR_RESIDUAL"
    if int(trial.get("browser_residual", -1)) != 0:
        return "BROWSER_RESIDUAL"
    if trial.get("supervisor_status") not in {"PASS", "FAIL"}:
        return "UNCLASSIFIED_SUPERVISOR_OUTCOME"
    if trial.get("navigation_status") not in {"PASS", "FAIL"}:
        return "UNCLASSIFIED_NAVIGATION_OUTCOME"
    if trial.get("evaluate_status") not in {"PASS", "TIMEOUT", "NOT_RUN"}:
        return "UNCLASSIFIED_RENDERER_OUTCOME"
    if trial.get("action_status") not in {"PASS", "TIMEOUT", "NOT_RUN"}:
        return "UNCLASSIFIED_ACTION_OUTCOME"
    return ""


def summarize(qualification: dict) -> dict:
    trials = qualification["trials"]
    nav = sum(row.get("navigation_status") == "PASS" for row in trials)
    evaluate = sum(row.get("evaluate_status") == "PASS" for row in trials)
    action = sum(row.get("action_status") == "PASS" for row in trials)
    eval_timeout = sum(row.get("evaluate_status") == "TIMEOUT" for row in trials)
    action_timeout = sum(row.get("action_status") == "TIMEOUT" for row in trials)
    renderer = sum(int(row.get("renderer_unresponsive", 0)) for row in trials)
    http429 = sum(int(row.get("http429", 0)) for row in trials)
    residual = sum(
        int(row.get("executor_residual", -1)) != 0
        or int(row.get("browser_residual", -1)) != 0
        for row in trials
    )
    supervisor_pass = sum(row.get("supervisor_status") == "PASS" for row in trials)
    stable = (
        len(trials) == 3
        and nav == evaluate == action == supervisor_pass == 3
        and eval_timeout == action_timeout == renderer == http429 == residual == 0
    )
    reasons = []
    if len(trials) != 3:
        reasons.append(f"replay_count={len(trials)}")
    if nav != 3:
        reasons.append(f"navigation_pass={nav}/3")
    if evaluate != 3:
        reasons.append(f"evaluate_pass={evaluate}/3")
    if action != 3:
        reasons.append(f"action_pass={action}/3")
    if eval_timeout:
        reasons.append(f"evaluate_timeout={eval_timeout}")
    if action_timeout:
        reasons.append(f"action_timeout={action_timeout}")
    if renderer:
        reasons.append(f"renderer_unresponsive={renderer}")
    if http429:
        reasons.append(f"http429={http429}")
    if residual:
        reasons.append(f"residual_replays={residual}")
    if supervisor_pass != 3:
        reasons.append(f"supervisor_pass={supervisor_pass}/3")
    slot = qualification["slot"]
    candidate = qualification["candidate"]
    return {
        **slot,
        **candidate,
        "candidate_attempt_order": qualification["attempt_order"],
        "navigation_pass_count": nav,
        "evaluate_pass_count": evaluate,
        "action_pass_count": action,
        "evaluate_timeout_count": eval_timeout,
        "action_timeout_count": action_timeout,
        "renderer_unresponsive_count": renderer,
        "http429_count": http429,
        "supervisor_pass_count": supervisor_pass,
        "qualification_status": (
            "REPLACEMENT_CANDIDATE_QUALIFIED"
            if stable else "REPLACEMENT_CANDIDATE_REJECTED"
        ),
        "qualification_failure_reason": ";".join(reasons),
        "final_selected": stable,
        "qualification_completed_utc": utc_now(),
        "trials": trials,
    }


def launch(qualification: dict, args, root: Path) -> None:
    replay = qualification["replay"]
    slot = qualification["slot"]
    candidate = qualification["candidate"]
    label = (
        f"old{int(slot['old_rank']):07d}_"
        f"cand{int(candidate['candidate_rank']):07d}_"
        f"{candidate['candidate_domain'].replace('.', '_')}_r{replay}"
    )
    evidence = root / "trials" / label
    command = [
        str(args.supervisor), "--label", label, "--evidence", str(evidence),
        "--timeout", "75", "--int-grace", "2", "--term-grace", "2",
        "--kill-grace", "2", "run", "--", str(args.python), str(args.trial_script),
        "--rank", candidate["candidate_rank"],
        "--domain", candidate["candidate_domain"],
        "--bucket", candidate["candidate_bucket"],
        "--replay", str(replay), "--delay", str(DELAYS[replay - 1]),
        "--result", str(evidence / "trial.json"),
    ]
    qualification["trial_evidence"] = evidence
    qualification["process"] = subprocess.Popen(
        command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
    )


def main() -> int:
    global STOP_REQUESTED
    parser = argparse.ArgumentParser()
    parser.add_argument("--slots", type=Path, required=True)
    parser.add_argument("--candidates", type=Path, required=True)
    parser.add_argument("--evidence-root", type=Path, required=True)
    parser.add_argument("--trial-script", type=Path, required=True)
    parser.add_argument("--supervisor", type=Path, required=True)
    parser.add_argument("--python", type=Path, required=True)
    parser.add_argument("--workers", type=int, required=True)
    parser.add_argument("--start-barrier", type=Path, required=True)
    args = parser.parse_args()
    if args.workers != 2:
        raise SystemExit("frozen workers requirement violated: workers must equal 2")
    slots = list(csv.DictReader(args.slots.open(newline=""), delimiter="\t"))
    candidates = list(csv.DictReader(args.candidates.open(newline=""), delimiter="\t"))
    if len(slots) != 24 or len({row["old_domain"] for row in slots}) != 24:
        raise SystemExit("replacement slot count/uniqueness failure")
    if len({row["candidate_domain"] for row in candidates}) != len(candidates):
        raise SystemExit("duplicate replacement candidate")
    candidate_queues = {
        bucket: deque(row for row in candidates if row["candidate_bucket"] == bucket)
        for bucket in ("top_1_1000", "rank_1001_100000", "rank_100001_1000000")
    }
    root = args.evidence_root
    root.mkdir(parents=True, exist_ok=False)
    (root / "trials").mkdir()
    signal.signal(signal.SIGINT, request_stop)
    signal.signal(signal.SIGTERM, request_stop)
    manifest = {
        "status": "WAITING_FOR_HEALTH_GUARD",
        "created_utc": utc_now(),
        "workers": 2,
        "replacement_slots": 24,
        "candidate_counts": {key: len(value) for key, value in candidate_queues.items()},
        "delays_seconds": DELAYS,
        "same_domain_replays_concurrent": False,
    }
    atomic_json(root / "manifest.json", manifest)
    (root / "CONTROLLER_READY").write_text(utc_now() + "\n")
    while not args.start_barrier.exists() and not STOP_REQUESTED:
        time.sleep(0.1)
    if STOP_REQUESTED:
        atomic_json(root / "controller_result.json", {
            "status": "INVALID_INFRASTRUCTURE_FAILURE",
            "hard_failure": "EXTERNAL_STOP_BEFORE_FIRST_TRIAL",
            "end_utc": utc_now(),
        })
        return 3

    pending = deque(slots)
    attempts = {row["old_domain"]: 0 for row in slots}
    active: list[dict] = []
    selected: list[dict] = []
    tested = 0
    rejected = 0
    completed_trials = 0
    hard_failure = ""
    raw_ledger = (root / "replacement_ledger.jsonl").open("a", buffering=1)
    raw_trials = (root / "trials.jsonl").open("a", buffering=1)

    def start_candidate(slot: dict) -> dict:
        bucket = slot["old_bucket"]
        if not candidate_queues[bucket]:
            raise RuntimeError(f"CANDIDATE_QUEUE_EXHAUSTED bucket={bucket}")
        attempts[slot["old_domain"]] += 1
        qualification = {
            "slot": slot,
            "candidate": candidate_queues[bucket].popleft(),
            "attempt_order": attempts[slot["old_domain"]],
            "replay": 1,
            "trials": [],
        }
        launch(qualification, args, root)
        return qualification

    try:
        while pending or active:
            while not STOP_REQUESTED and pending and len(active) < args.workers:
                active.append(start_candidate(pending.popleft()))
            if STOP_REQUESTED:
                stop_active(active)
                break
            progressed = False
            for qualification in list(active):
                process = qualification["process"]
                if process.poll() is None:
                    continue
                progressed = True
                trial = collect(qualification)
                completed_trials += 1
                qualification["trials"].append(trial)
                raw_trials.write(json.dumps(trial, sort_keys=True) + "\n")
                raw_trials.flush()
                os.fsync(raw_trials.fileno())
                hard_failure = infrastructure_failure(trial)
                if hard_failure:
                    STOP_REQUESTED = True
                    stop_active([item for item in active if item is not qualification])
                    break
                if qualification["replay"] < 3:
                    qualification["replay"] += 1
                    launch(qualification, args, root)
                    continue
                record = summarize(qualification)
                tested += 1
                raw_ledger.write(json.dumps(record, sort_keys=True) + "\n")
                raw_ledger.flush()
                os.fsync(raw_ledger.fileno())
                active.remove(qualification)
                if record["final_selected"]:
                    selected.append(record)
                else:
                    rejected += 1
                    active.append(start_candidate(qualification["slot"]))
                print(
                    f"REPLACEMENT_PROGRESS selected={len(selected)}/24 "
                    f"tested={tested} rejected={rejected} trials={completed_trials} "
                    f"old_domain={record['old_domain']} "
                    f"candidate={record['candidate_domain']} "
                    f"status={record['qualification_status']}",
                    flush=True,
                )
                atomic_json(root / "progress.json", {
                    "timestamp": utc_now(),
                    "selected": len(selected),
                    "tested": tested,
                    "rejected": rejected,
                    "completed_trials": completed_trials,
                    "active": len(active),
                    "pending": len(pending),
                    "hard_failure": hard_failure,
                })
            if not progressed:
                time.sleep(0.05)
    except BaseException as exc:
        hard_failure = hard_failure or f"{type(exc).__name__}: {exc}"
        STOP_REQUESTED = True
        stop_active(active)
    finally:
        raw_ledger.close()
        raw_trials.close()

    if STOP_REQUESTED:
        atomic_json(root / "controller_result.json", {
            "status": "INVALID_INFRASTRUCTURE_FAILURE",
            "end_utc": utc_now(),
            "selected": len(selected),
            "tested": tested,
            "rejected": rejected,
            "completed_trials": completed_trials,
            "hard_failure": hard_failure or "EXTERNAL_STOP_REQUEST",
        })
        return 3
    if len(selected) != 24:
        raise SystemExit(f"selected replacement count mismatch: {len(selected)}")
    atomic_json(root / "controller_result.json", {
        "status": "COMPLETE",
        "end_utc": utc_now(),
        "selected": 24,
        "tested": tested,
        "rejected": rejected,
        "completed_trials": completed_trials,
    })
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
