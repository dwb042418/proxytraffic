#!/usr/bin/env python3
"""Offline fail-closed test for the v3 programmatic scroll deadline."""
import argparse, asyncio, json, sys
from pathlib import Path
HERE=Path(__file__).resolve().parent; sys.path.insert(0,str(HERE))
from realistic_browser_v3 import PhaseLog, ProgrammaticScrollTimeout, perform_scroll
class NeverPage:
    calls=0
    async def evaluate(self,*args): self.calls+=1; await asyncio.Future()
async def main(path):
    page=NeverPage(); log=PhaseLog(path); event={"event_index":1,"url":"https://mega.co.nz/"}
    try: await perform_scroll(page,event,0,{"distance_px":960},log)
    except ProgrammaticScrollTimeout:
        phases=[json.loads(x)["phase"] for x in path.read_text().splitlines()]
        assert page.calls==1 and phases==["SCROLL_0_START","SCROLL_0_TIMEOUT"]
        print("V3_PROGRAMMATIC_SCROLL_TIMEOUT_FAIL_CLOSED_PASS",flush=True); return
    raise AssertionError("scroll did not timeout")
parser=argparse.ArgumentParser(); parser.add_argument("--log",type=Path,required=True); args=parser.parse_args()
asyncio.run(main(args.log))
