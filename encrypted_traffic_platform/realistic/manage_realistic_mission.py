#!/usr/bin/env python3
"""Run campaign processes, bounded external recovery and automatic Formal entry.

Revision failures return to the autonomous agent for forensic and a new revision.
They are not mission failure or permission requests.
"""
import argparse
import json
import os
from pathlib import Path
import subprocess
import sys
import time

from prepare_realistic_campaign import prepare,freeze,REPO,CODE,MISSION

EVIDENCE=Path('/home/etip/datasets/diagnostics/autonomous_realistic_mission')


def status(value):
    EVIDENCE.mkdir(parents=True,exist_ok=True)
    value.update(manager_pid=os.getpid(),updated_epoch=time.time())
    temporary=EVIDENCE/'status.tmp';temporary.write_text(json.dumps(value,indent=2)+'\n')
    temporary.replace(EVIDENCE/'status.json')


def ensure_roots(config):
    value=json.loads(config.read_text())
    local=Path('/home/etip/datasets/staging/realistic_v1')/value['storage_name']
    remote=Path('/home/dataset-assist-0/duwenbiao/Tunnel/proxydata/realistic_v1')/value['storage_name']
    local.mkdir(parents=True,exist_ok=True)
    result=subprocess.run(['ssh','-o','BatchMode=yes','-o','ConnectTimeout=10','proxydata-server','mkdir','-p',str(remote)],capture_output=True,text=True,timeout=30)
    return value,local,result


def campaign(config):
    resume=False;external_since=None
    while True:
        try:
            value,local,setup=ensure_roots(config)
        except subprocess.TimeoutExpired:
            setup=None
        if setup is None or setup.returncode:
            code=78
            status({'state':'PRESTART_INFRASTRUCTURE_BLOCKER','config':str(config),'detail':'timeout' if setup is None else setup.stderr[-1000:]})
        else:
            # Existing state is only resumed on explicit recovery from this same
            # manager or its recorded ledger. Closed revisions are rejected by runner.
            ledger=local/'retry_ledger.tsv'
            resume=resume or ledger.exists() and len(ledger.read_text().splitlines())>1
            command=[sys.executable,'-B',str(CODE/'run_realistic_campaign.py'),'--config',str(config)]
            if resume:command.append('--resume')
            log=EVIDENCE/(value['campaign_id']+'.log')
            with log.open('a') as output:
                process=subprocess.Popen(command,cwd=REPO,stdout=output,stderr=subprocess.STDOUT)
                status({'state':'RUNNING','campaign_id':value['campaign_id'],'child_pid':process.pid,'config':str(config),'log':str(log),'resume':resume})
                code=process.wait()
        if code==0:
            status({'state':'CAMPAIGN_PASS','config':str(config)})
            return 0
        if code==76:
            resume=True;external_since=None
            status({'state':'SAFE_BOUNDARY_PROCESS_RESTART','config':str(config)})
            continue
        if code in (75,78):
            external_since=external_since or time.monotonic()
            if time.monotonic()-external_since>=1800:
                status({'state':'MISSION_HARD_STOP_REMOTE_UNAVAILABLE','config':str(config),'bounded_recheck_seconds':1800})
                return 78
            time.sleep(30 if code==75 else 60)
            continue
        status({'state':'REVISION_HARD_STOP_INTERNAL_AUTONOMOUS_REVIEW_REQUIRED','config':str(config),'exit_code':code})
        return code


def main():
    parser=argparse.ArgumentParser();parser.add_argument('--config',required=True,type=Path)
    args=parser.parse_args();config=args.config.resolve()
    code=campaign(config)
    if code:return code
    info=json.loads(config.read_text())
    if info['kind']=='STRESS':
        qualification=Path('/home/etip/datasets/staging/realistic_v1')/info['storage_name']
        report=json.loads((qualification/'campaign_result.json').read_text())
        assert report['PASS_MARKER']=='PRODUCTION_READINESS_STRESS_PASS' and report['VALID_SAMPLES']==192
        revision=11
        while (MISSION/f't0_v3_r{revision}').exists():revision+=1
        formal=prepare(f't0_v3_r{revision}','FORMAL',qualification=str(qualification))
        files=[formal/'campaign_config.json',formal/'campaign_manifest.tsv',formal/'methodology.json',formal/'historical_hotspot_evidence.json']
        subprocess.run(['git','-C',str(REPO),'add',*[str(p) for p in files]],check=True)
        subprocess.run(['git','-C',str(REPO),'commit','-m',f'Preregister final Formal r{revision} after complete Stress qualification'],check=True)
        freeze(formal)
        code=campaign(formal/'campaign_config.json')
        if code:return code
        config=formal/'campaign_config.json'
    status({'state':'COLLECTION_COMPLETE_FINAL_GIT_PUSH_PENDING','config':str(config)})
    return 0


if __name__=='__main__':raise SystemExit(main())
