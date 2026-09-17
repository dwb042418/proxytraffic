#!/usr/bin/env python3
"""Supervise only the explicitly amended Formal campaign; preserve resume state."""
import argparse,json,subprocess,sys,time
from pathlib import Path
import manage_realistic_mission as manager


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--config',required=True,type=Path)
    parser.add_argument('--resume',action='store_true',required=True)
    args=parser.parse_args();config=args.config.resolve()
    info=json.loads(config.read_text())
    assert info['campaign_id']=='t0_v3_r11' and info['kind']=='FORMAL'
    amendment=json.loads((config.parent/'protocol_amendment.json').read_text())
    assert amendment['status']=='FORMAL_PROTOCOL_AMENDED_CONTINUATION'
    carry_forward='1-128' if (config.parent/'capacity2048_protocol_amendment.json').exists() else '1-92' if (config.parent/'netcraze_protocol_amendment.json').exists() else '1-48'
    external_since=None
    while True:
        try:_,local,setup=manager.ensure_roots(config)
        except subprocess.TimeoutExpired:setup=None
        if setup is None or setup.returncode:
            code=78
            manager.status(dict(state='PRESTART_INFRASTRUCTURE_BLOCKER',config=str(config),campaign_id=info['campaign_id']))
        else:
            command=[sys.executable,'-B',str(Path(__file__).with_name('run_formal_r11_amended_continuation.py')),'--config',str(config),'--resume']
            log=manager.EVIDENCE/(info['campaign_id']+'.log')
            log.parent.mkdir(parents=True,exist_ok=True)
            with log.open('a') as output:
                process=subprocess.Popen(command,cwd=manager.REPO,stdout=output,stderr=subprocess.STDOUT)
                manager.status(dict(state='RUNNING',campaign_id=info['campaign_id'],child_pid=process.pid,
                    config=str(config),log=str(log),resume=True,protocol_status=amendment['status'],carry_forward_samples=carry_forward))
                code=process.wait()
        if code==0:
            manager.status(dict(state='COLLECTION_COMPLETE_FINAL_GIT_PUSH_PENDING',config=str(config),campaign_id=info['campaign_id'],protocol_status=amendment['status']))
            return 0
        if code==76:
            external_since=None
            continue
        if code in (75,78):
            external_since=external_since or time.monotonic()
            manager.status(dict(state='REMOTE_AVAILABILITY_RECHECK',config=str(config),campaign_id=info['campaign_id'],unavailable_seconds=time.monotonic()-external_since,MISSION_HARD_STOP=False))
            time.sleep(30 if code==75 else 60)
            continue
        manager.status(dict(state='REVISION_HARD_STOP_INTERNAL_AUTONOMOUS_REVIEW_REQUIRED',config=str(config),campaign_id=info['campaign_id'],exit_code=code))
        return code


if __name__=='__main__':raise SystemExit(main())
