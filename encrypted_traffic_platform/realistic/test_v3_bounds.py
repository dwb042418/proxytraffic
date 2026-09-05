#!/usr/bin/env python3
"""Calculate candidate v3 whole-executor bounds for immutable plans."""
import argparse, json, math
from pathlib import Path

PROGRAMMATIC_SCROLL_TIMEOUT_S=5
STARTUP_BUDGET_S=45
TEARDOWN_BUDGET_S=30
REPORT_BUDGET_S=10
SUPERVISOR_MARGIN_S=30

def calculate(path):
    plan=json.loads(path.read_text()); observation=plan["navigation_semantics"]["domcontentloaded_observation_ms"]
    base_ms=0; scroll_actions=0
    for event in plan["events"]:
        base_ms += event["navigation_timeout_ms"]+observation
        base_ms += event["pre_navigation_idle_ms"]+event["post_navigation_idle_ms"]
        base_ms += sum(x["idle_ms"] for x in event.get("scrolls",[]))
        scroll_actions += len(event.get("scrolls",[]))
    base=base_ms/1000
    scroll_budget=scroll_actions*PROGRAMMATIC_SCROLL_TIMEOUT_S
    bound=base+scroll_budget+STARTUP_BUDGET_S+TEARDOWN_BUDGET_S+REPORT_BUDGET_S
    watchdog=math.ceil(bound+SUPERVISOR_MARGIN_S)
    return plan,base,scroll_actions,scroll_budget,bound,watchdog

parser=argparse.ArgumentParser(); parser.add_argument("plan_root",type=Path); args=parser.parse_args()
results=[]
for path in sorted(args.plan_root.glob("*_workload_plan.json")):
    plan,base,scroll_actions,sb,bound,watchdog=calculate(path); results.append((path,plan,base,scroll_actions,sb,bound,watchdog))
assert len(results)==300
print(f"PLAN_COUNT={len(results)}")
print(f"SCROLL_ACTIONS_MIN={min(x[3] for x in results)}")
print(f"SCROLL_ACTIONS_MAX={max(x[3] for x in results)}")
print(f"SCROLL_ACTIONS_TOTAL={sum(x[3] for x in results)}")
for path,plan,base,scroll_actions,sb,bound,watchdog in results:
    if plan["seed_id"]=="seed004" and plan["intensity"]=="heavy":
        print(f"PLAN={path}")
        print(f"PLAN_BASE_BOUND={base:.3f}")
        print(f"NUMBER_OF_SCROLL_ACTIONS={scroll_actions}")
        print(f"PROGRAMMATIC_SCROLL_TIMEOUT_S={PROGRAMMATIC_SCROLL_TIMEOUT_S}")
        print(f"SCROLL_ACTION_BUDGET={sb:.3f}")
        print(f"STARTUP_BUDGET={STARTUP_BUDGET_S:.3f}")
        print(f"TEARDOWN_BUDGET={TEARDOWN_BUDGET_S:.3f}")
        print(f"REPORT_BUDGET={REPORT_BUDGET_S:.3f}")
        print(f"EXECUTOR_THEORETICAL_BOUND={bound:.3f}")
        print(f"REMOTE_SUPERVISOR_WATCHDOG={watchdog}")
        assert watchdog>bound
