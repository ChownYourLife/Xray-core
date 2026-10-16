#!/usr/bin/env python3
"""Supplement-only orchestration; original application and cell implementations unchanged."""
import argparse
import datetime
import hashlib
import os
from pathlib import Path
import subprocess
import remote_runner as rr
import udp_cohort as uc

ROOT=Path(__file__).resolve().parent
rr.CASES=['ss2022-wireguard']
p=argparse.ArgumentParser();p.add_argument('--phase',choices=['smoke','timing'],required=True);p.add_argument('--network',choices=['tcp','udp'],required=True)
a=p.parse_args();out=ROOT/(a.phase+'-'+a.network);out.mkdir(exist_ok=False)
subprocess.run(['ip','link','set','lo','up'],check=True)
rr.save(out/'environment.json',{'cohort':'separately-collected-ss2022-wireguard-supplement','phase':a.phase,'network':a.network,'started_utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),'netns':os.readlink('/proc/self/ns/net'),'pins':{str(f.relative_to(ROOT)):hashlib.sha256(f.read_bytes()).hexdigest() for d in ['binaries','configs'] for f in sorted((ROOT/d).iterdir()) if f.is_file()},'source_pins':{f.name:hashlib.sha256(f.read_bytes()).hexdigest() for f in ROOT.glob('*.py')},'round_orders':rr.ORDERS,'assignments':{'relay':{'cpus':[2,3],'GOMAXPROCS':2},'fixed_support':{'cpus':[0,1],'GOMAXPROCS':2}},'facts':[rr.fact(c) for c in [['uname','-a'],['lscpu'],['ip','-j','addr'],['ip','-j','route'],['ip','-j','-6','route']]],'ipv6_disable':{x:Path('/proc/sys/net/ipv6/conf/'+x+'/disable_ipv6').read_text().strip() for x in ['all','default','lo']}})
echo=rr.launch('echo',ROOT/'binaries/application',None,out);records=[]
try:
    rr.ready(19090,[echo])
    if a.phase=='smoke' and a.network=='udp':uc.driver_controls(out)
    for r in ([0] if a.phase=='smoke' else range(1,8)):
        for v in (rr.VARIANTS if a.phase=='smoke' else rr.ORDERS[r-1]):
            label=f'r{r:02d}-ss2022-wireguard-{a.network}-{v}'
            record=rr.cell(a.phase,r,'ss2022-wireguard','tcp',v,out/label) if a.network=='tcp' else uc.cell(a.phase,r,'ss2022-wireguard',v,out/label)
            records.append(record)
            rr.save(out/'index.json',[{k:x[k] for k in ['round','case','network','variant','status']} for x in records])
            print(datetime.datetime.now(datetime.timezone.utc).isoformat(),label,record['status'],flush=True)
            if record['status']!='passed':raise RuntimeError('Retain failure and stop, no retry: '+label)
finally:
    rr.stop(echo);expected=4 if a.phase=='smoke' else 28
    rr.save(out/'closure.json',{'finished_utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),'completed_cells':len(records),'expected_cells':expected,'all_passed':len(records)==expected and all(x['status']=='passed' for x in records)})
