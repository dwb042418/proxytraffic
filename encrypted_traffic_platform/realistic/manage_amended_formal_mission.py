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
    carry_forward='1-360' if (config.parent/'context361_protocol_amendment.json').exists() else '1-128' if (config.parent/'capacity2048_protocol_amendment.json').exists() else '1-92' if (config.parent/'netcraze_protocol_amendment.json').exists() else '1-48'
    external_since=None
    while True:
        # Complete a journaled acquisition transition before starting any runner.
        local=Path('/home/etip/datasets/staging/realistic_v1')/info['storage_name']
        state_path=local/'pair_group_reacquisition_state.json'
        if state_path.exists():
            reference=json.loads(state_path.read_text())['acquisitions'][-1]
            activated=json.loads(Path(reference['path']).read_text())
            carry_forward='1-'+str(activated['carry_forward']['valid_samples'])
        for name in ('context369_protocol_amendment.json','context389_protocol_amendment.json'):
            domain_amendment=config.parent/name
            if domain_amendment.exists():
                domain_boundary=json.loads(domain_amendment.read_text())['carry_forward_boundary']
                carry_forward='1-'+str(max(int(carry_forward.split('-')[1]),domain_boundary))
        pending=(local/'pending_pair_group_reacquisition.json').exists()
        stop=json.loads((local/'revision_hard_stop.json').read_text()) if (local/'revision_hard_stop.json').exists() else {}
        if pending or (stop.get('category')=='SAMPLE_POLICY_HARD_STOP'
                       and (config.parent/'pair_group_reacquisition_amendment.json').exists()):
            manager.status(dict(state='EXHAUSTED_ACQUISITION_AUTONOMOUS_REVIEW',config=str(config),campaign_id=info['campaign_id']))
            review_log=manager.EVIDENCE/(info['campaign_id']+'_reacquisition.log')
            with review_log.open('a') as output:
                review=subprocess.run([sys.executable,'-B',str(Path(__file__).with_name('resolve_pair_group_reacquisition.py')),
                    '--config',str(config)],cwd=manager.REPO,stdout=output,stderr=subprocess.STDOUT)
            if review.returncode==76:
                external_since=None
                continue
            if review.returncode==75:
                manager.status(dict(state='REMOTE_AVAILABILITY_RECHECK',config=str(config),campaign_id=info['campaign_id'],MISSION_HARD_STOP=False))
                time.sleep(30)
                continue
            manager.status(dict(state='PAIR_GROUP_REACQUISITION_ROOT_CAUSE_REVIEW_REQUIRED',config=str(config),
                campaign_id=info['campaign_id'],log=str(review_log),exit_code=review.returncode))
            return review.returncode
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
        stop_path=local/'revision_hard_stop.json'
        if stop_path.exists() and json.loads(stop_path.read_text()).get('category')=='SAMPLE_POLICY_HARD_STOP':
            continue
        manager.status(dict(state='REVISION_HARD_STOP_INTERNAL_AUTONOMOUS_REVIEW_REQUIRED',config=str(config),campaign_id=info['campaign_id'],exit_code=code))
        return code


if __name__=='__main__':raise SystemExit(main())
