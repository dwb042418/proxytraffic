#!/usr/bin/env python3
"""Async v3 candidate executor for bounded Realistic workload replay."""
from __future__ import annotations

import argparse, asyncio, contextlib, csv, hashlib, importlib.metadata, json, os, shutil, tempfile, time
from pathlib import Path
from urllib.parse import urlsplit
from playwright.async_api import async_playwright

MAIN_NAVIGATION_TIMEOUT_MS = 30000
DOMCONTENTLOADED_OBSERVATION_MS = 10000
ACCEPTABLE_MAIN_STATUS_MIN = 200
ACCEPTABLE_MAIN_STATUS_MAX = 399
PROGRAMMATIC_SCROLL_TIMEOUT_S = 5
CONTEXT_CLOSE_TIMEOUT_S = 15
PLAYWRIGHT_STOP_TIMEOUT_S = 15
REPORT_WRITE_TIMEOUT_S = 10

class ProgrammaticScrollTimeout(RuntimeError): pass
class LifecycleTimeout(RuntimeError): pass

class PhaseLog:
    def __init__(self, path: Path):
        self.path = path; path.parent.mkdir(parents=True, exist_ok=True)
    def emit(self, phase: str, **details):
        record = {"timestamp_ns": time.time_ns(), "phase": phase, **details}
        with self.path.open("a") as handle:
            handle.write(json.dumps(record, sort_keys=True) + "\n"); handle.flush(); os.fsync(handle.fileno())

def sha256(path): return hashlib.sha256(path.read_bytes()).hexdigest()

def classify_resource(resource_type, domain):
    if any(token in domain for token in ("analytics", "doubleclick", "googletagmanager")): return "analytics"
    if resource_type in {"script", "stylesheet", "image", "font"}: return resource_type
    return "other"

def write_report(output_dir, rows, report):
    with (output_dir / "workload_events.tsv").open("w", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=rows[0].keys(), delimiter="\t")
        writer.writeheader(); writer.writerows(rows); handle.flush(); os.fsync(handle.fileno())
    with (output_dir / "workload_report.json").open("w") as handle:
        handle.write(json.dumps(report, indent=2, sort_keys=True) + "\n"); handle.flush(); os.fsync(handle.fileno())

async def perform_scroll(page, event, scroll_index, scroll, log):
    action_started=time.monotonic(); ei=event["event_index"]; distance=scroll["distance_px"]
    log.emit(f"SCROLL_{scroll_index}_START",event_index=ei,url=event["url"],scroll_index=scroll_index,
             primitive="DETERMINISTIC_BOUNDED_VIEWPORT_SCROLL",requested_delta_y=distance)
    try:
        result=await asyncio.wait_for(page.evaluate("""requestedDeltaY => {
          const beforeX=window.scrollX, beforeY=window.scrollY;
          window.scrollBy({top:requestedDeltaY,left:0,behavior:'instant'});
          return {beforeX,beforeY,afterX:window.scrollX,afterY:window.scrollY,
            requestedDeltaY,scrollHeight:document.documentElement.scrollHeight,
            innerHeight:window.innerHeight};
        }""",distance),timeout=PROGRAMMATIC_SCROLL_TIMEOUT_S)
    except asyncio.TimeoutError as exc:
        elapsed=time.monotonic()-action_started
        log.emit(f"SCROLL_{scroll_index}_TIMEOUT",event_index=ei,url=event["url"],scroll_index=scroll_index,
                 requested_delta_y=distance,elapsed_seconds=round(elapsed,6),failure="PROGRAMMATIC_SCROLL_TIMEOUT")
        raise ProgrammaticScrollTimeout(f"PROGRAMMATIC_SCROLL_TIMEOUT event_index={ei} url={event['url']} scroll_index={scroll_index} requested_delta_y={distance} elapsed={elapsed:.6f}") from exc
    structured={"before_x":result["beforeX"],"before_y":result["beforeY"],"after_x":result["afterX"],
                "after_y":result["afterY"],"requested_delta_y":result["requestedDeltaY"],
                "document_scroll_height":result["scrollHeight"],"viewport_height":result["innerHeight"]}
    structured["scroll_delta"]=structured["after_y"]-structured["before_y"]
    log.emit(f"SCROLL_{scroll_index}_END",event_index=ei,url=event["url"],scroll_index=scroll_index,
             elapsed_seconds=round(time.monotonic()-action_started,6),**structured)
    return structured

async def execute(args, log):
    plan = json.loads(args.plan.read_text())
    if plan.get("schema_version") != 1 or not plan.get("events"): raise SystemExit("unsupported or empty workload plan")
    args.output_dir.mkdir(parents=True, exist_ok=False)
    plan_copy = args.output_dir / "workload_plan.json"; shutil.copyfile(args.plan, plan_copy)
    plan_hash = sha256(plan_copy); rows=[]; hard_failures=[]; subresource_failures=[]; scroll_results=[]; started=time.time()
    playwright=None; context=None; browser_version="unknown"; primary_error=None
    try:
        log.emit("BROWSER_START")
        playwright = await async_playwright().start()
        profile_dir = tempfile.mkdtemp(prefix="realistic-browser-profile-")
        with contextlib.nullcontext(profile_dir):
            context = await playwright.chromium.launch_persistent_context(
                profile_dir, headless=True, args=plan["browser_args"], service_workers="block",
                viewport={"width":1365,"height":768})
            browser_version = context.browser.version if context.browser else "unknown"
            request_failures=[]
            def record_request_failure(request):
                domain=urlsplit(request.url).hostname or ""
                request_failures.append({"request_failed":True,"resource_type":classify_resource(request.resource_type,domain),
                    "browser_resource_type":request.resource_type or "other","url":request.url,"domain":domain,
                    "failure_reason":request.failure or "unknown"})
            context.on("requestfailed", record_request_failure)
            pages=list(context.pages)
            while len(pages)<plan["tab_count"]: pages.append(await context.new_page())
            log.emit("BROWSER_READY",browser_version=browser_version,tab_count=len(pages))
            for event in plan["events"]:
                ei=event["event_index"]; page=pages[event["tab_index"]]
                log.emit(f"EVENT_{ei}_START",event_index=ei,url=event["url"])
                await page.bring_to_front(); await page.wait_for_timeout(event["pre_navigation_idle_ms"])
                event_started=time.monotonic(); failure_start=len(request_failures)
                main_commit_success=False; main_http_status=0; main_commit_latency_ms=0
                domcontentloaded=False; domcontentloaded_timeout=False; domcontentloaded_latency_ms=0
                navigation_hard_failure=False; navigation_warning=""; error=""
                log.emit("NAV_START",event_index=ei,url=event["url"])
                try:
                    response=await page.goto(event["url"],wait_until="commit",timeout=MAIN_NAVIGATION_TIMEOUT_MS)
                    main_commit_latency_ms=int((time.monotonic()-event_started)*1000)
                    if response is None: raise RuntimeError("main response missing after navigation commit")
                    main_http_status=response.status
                    if not (ACCEPTABLE_MAIN_STATUS_MIN<=main_http_status<=ACCEPTABLE_MAIN_STATUS_MAX):
                        raise RuntimeError(f"unacceptable main HTTP status: {main_http_status}")
                    main_commit_success=True; observation_started=time.monotonic()
                    try:
                        await page.wait_for_load_state("domcontentloaded",timeout=DOMCONTENTLOADED_OBSERVATION_MS)
                        domcontentloaded=True; domcontentloaded_latency_ms=int((time.monotonic()-event_started)*1000)
                    except Exception as exc:
                        if type(exc).__name__!="TimeoutError": raise
                        domcontentloaded_timeout=True; navigation_warning="domcontentloaded_timeout"
                    elapsed=int((time.monotonic()-observation_started)*1000)
                    if elapsed<DOMCONTENTLOADED_OBSERVATION_MS: await page.wait_for_timeout(DOMCONTENTLOADED_OBSERVATION_MS-elapsed)
                except Exception as exc:
                    navigation_hard_failure=True; error=f"{type(exc).__name__}: {exc}"[:500]
                    hard_failures.append({"event_index":ei,"url":event["url"],"error":error})
                log.emit("NAV_END",event_index=ei,url=event["url"],main_commit_success=main_commit_success,
                         navigation_hard_failure=navigation_hard_failure)
                if main_commit_success:
                    await page.wait_for_timeout(event["post_navigation_idle_ms"])
                    for wi,scroll in enumerate(event["scrolls"]):
                        result=await perform_scroll(page,event,wi,scroll,log)
                        scroll_results.append({"event_index":ei,"url":event["url"],"scroll_index":wi,**result})
                        await page.wait_for_timeout(scroll["idle_ms"])
                event_subresource_failures=[x for x in request_failures[failure_start:] if x["browser_resource_type"]!="document"]
                subresource_failures.extend(event_subresource_failures)
                if event_subresource_failures and not navigation_warning: navigation_warning="subresource_request_failed"
                rows.append({"event_index":ei,"tab_index":event["tab_index"],"url":event["url"],
                    "main_commit_success":main_commit_success,"main_http_status":main_http_status,
                    "main_commit_latency_ms":main_commit_latency_ms,"domcontentloaded":domcontentloaded,
                    "domcontentloaded_timeout":domcontentloaded_timeout,"domcontentloaded_latency_ms":domcontentloaded_latency_ms,
                    "subresource_failed_count":len(event_subresource_failures),"navigation_hard_failure":navigation_hard_failure,
                    "navigation_warning":navigation_warning,"elapsed_ms":int((time.monotonic()-event_started)*1000),"error":error})
                log.emit(f"EVENT_{ei}_END",event_index=ei,url=event["url"],navigation_hard_failure=navigation_hard_failure)
            log.emit("WORKLOAD_COMPLETE",event_count=len(rows),hard_failure_count=len(hard_failures))
            report={"schema_version":1,"mode":args.mode,"seed":plan["seed"],"intensity":plan["intensity"],
                "workload_plan_sha256":plan_hash,"browser":"chromium","browser_version":browser_version,
                "playwright_version":importlib.metadata.version("playwright"),"disable_quic":"--disable-quic" in plan["browser_args"],
                "fresh_profile":True,"service_workers_blocked":True,"event_count":len(rows),
                "success_count":sum(not r["navigation_hard_failure"] for r in rows),"failure_count":len(hard_failures),
                "hard_failure_count":len(hard_failures),"warning_count":sum(bool(r["navigation_warning"]) for r in rows),
                "domcontentloaded_timeout_count":sum(r["domcontentloaded_timeout"] for r in rows),
                "subresource_failure_count":len(subresource_failures),"failures":hard_failures,
                "hard_failures":hard_failures,"subresource_failures":subresource_failures,
                "scroll_primitive":"DETERMINISTIC_BOUNDED_VIEWPORT_SCROLL",
                "programmatic_scroll_timeout_seconds":PROGRAMMATIC_SCROLL_TIMEOUT_S,
                "scroll_action_count":len(scroll_results),"scroll_actions":scroll_results,
                "elapsed_ms":int((time.time()-started)*1000)}
            log.emit("REPORT_WRITE_START")
            try: await asyncio.wait_for(asyncio.to_thread(write_report,args.output_dir,rows,report),timeout=REPORT_WRITE_TIMEOUT_S)
            except asyncio.TimeoutError as exc: raise LifecycleTimeout("LIFECYCLE_TIMEOUT phase=REPORT_WRITE") from exc
            log.emit("REPORT_WRITE_END"); print(json.dumps(report,sort_keys=True),flush=True)
            return 0 if not hard_failures else 1
    except BaseException as exc:
        primary_error=exc; raise
    finally:
        cleanup_error=None
        if context is not None:
            log.emit("CONTEXT_CLOSE_START")
            try: await asyncio.wait_for(context.close(),timeout=CONTEXT_CLOSE_TIMEOUT_S); log.emit("CONTEXT_CLOSE_END")
            except BaseException as exc:
                log.emit("CONTEXT_CLOSE_TIMEOUT",error=f"{type(exc).__name__}: {exc}")
                cleanup_error=LifecycleTimeout("LIFECYCLE_TIMEOUT phase=CONTEXT_CLOSE")
        if playwright is not None:
            log.emit("PLAYWRIGHT_STOP_START")
            try: await asyncio.wait_for(playwright.stop(),timeout=PLAYWRIGHT_STOP_TIMEOUT_S); log.emit("PLAYWRIGHT_STOP_END")
            except BaseException as exc:
                log.emit("PLAYWRIGHT_STOP_TIMEOUT",error=f"{type(exc).__name__}: {exc}")
                cleanup_error=cleanup_error or LifecycleTimeout("LIFECYCLE_TIMEOUT phase=PLAYWRIGHT_STOP")
        if 'profile_dir' in locals():
            shutil.rmtree(profile_dir, ignore_errors=True)
        if primary_error is None and cleanup_error is not None: raise cleanup_error

async def main():
    parser=argparse.ArgumentParser(); parser.add_argument("--plan",type=Path,required=True)
    parser.add_argument("--output-dir",type=Path,required=True)
    parser.add_argument("--mode",choices=("direct","vless","shadowsocks","trojan"),required=True)
    parser.add_argument("--phase-log",type=Path,required=True); args=parser.parse_args()
    log=PhaseLog(args.phase_log); log.emit("EXECUTOR_START")
    try: result=await execute(args,log)
    except BaseException as exc: log.emit("EXECUTOR_EXIT",exit_code=1,error=f"{type(exc).__name__}: {exc}"); raise
    log.emit("EXECUTOR_EXIT",exit_code=result); return result

if __name__=="__main__": raise SystemExit(asyncio.run(main()))
