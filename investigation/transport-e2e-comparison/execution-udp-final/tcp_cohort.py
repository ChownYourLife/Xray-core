#!/usr/bin/env python3
"""One director-authorized TCPv2 cohort; unchanged v2 application and runner helpers."""
import datetime
import hashlib
import os
from pathlib import Path
import subprocess
import remote_runner as rr

ROOT=Path(__file__).resolve().parent
OUT=ROOT/'timing-tcp-v2'
OUT.mkdir(exist_ok=False)
subprocess.run(['ip','link','set','lo','up'],check=True)
environment={'cohort':'TCPv2, seven matched rounds, no tracing, no concurrent server workload',
    'started_utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),'netns':os.readlink('/proc/self/ns/net'),
    'invocation':['unshare','--net','python3',str(Path(__file__).resolve())],
    'pins':{str(p.relative_to(ROOT)):hashlib.sha256(p.read_bytes()).hexdigest() for directory in ['binaries','configs'] for p in sorted((ROOT/directory).iterdir()) if p.is_file()},
    'source_pins':{name:hashlib.sha256((ROOT/name).read_bytes()).hexdigest() for name in ['application.go','remote_runner.py','tcp_cohort.py']},
    'ipv6_disable':{x:Path('/proc/sys/net/ipv6/conf/'+x+'/disable_ipv6').read_text().strip() for x in ['all','default','lo']},
    'facts':[rr.fact(a) for a in [['uname','-a'],['lscpu'],['ip','-j','addr'],['ip','-j','route'],['ip','-j','-6','route']]],
    'round_orders':rr.ORDERS,'assignments':{'candidate_relay':{'cpus':[2,3],'GOMAXPROCS':2},'fixed_support':{'cpus':[0,1],'GOMAXPROCS':2}},
    'limitation':'Same-host private-loopback observed goodput/RTT, not WAN capacity; support endpoints share CPU0,1 and may bottleneck; no retuning.'}
rr.save(OUT/'environment.json',environment)
echo=rr.launch('echo',ROOT/'binaries/application',None,OUT)
records=[]
try:
    rr.ready(19090,[echo])
    for round_id in range(1,8):
        cases=rr.CASES[round_id%len(rr.CASES):]+rr.CASES[:round_id%len(rr.CASES)]
        for case in cases:
            for variant in rr.ORDERS[round_id-1]:
                label=f'r{round_id:02d}-{case}-tcp-{variant}'
                r=rr.cell('timing',round_id,case,'tcp',variant,OUT/label)
                records.append(r)
                rr.save(OUT/'index.json',[{'round':x['round'],'case':x['case'],'network':x['network'],'variant':x['variant'],'status':x['status']} for x in records])
                print(datetime.datetime.now(datetime.timezone.utc).isoformat(),label,r['status'],flush=True)
                if r['status']!='passed':raise RuntimeError('Retain failed TCP cohort and stop; no retry: '+label)
finally:
    rr.stop(echo)
    rr.save(OUT/'closure.json',{'finished_utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),'completed_cells':len(records),'expected_cells':140,
        'all_passed':len(records)==140 and all(r['status']=='passed' for r in records)})
