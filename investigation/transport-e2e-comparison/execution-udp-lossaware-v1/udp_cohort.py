#!/usr/bin/env python3
"""Separate loss-aware UDP cohort; actual Xray processes, no retransmission or loss filtering."""
import argparse
import datetime
import hashlib
import json
import os
from pathlib import Path
import socket
import subprocess
import time
import remote_runner as rr

ROOT=Path(__file__).resolve().parent

def application(offered,samples,timeout=90):
    argv=['taskset','-c','0,1',str(ROOT/'binaries/application'),'-mode','client','-addr','127.0.0.1:19300',
          '-bytes',str(offered),'-samples',str(samples)]
    began=time.monotonic_ns()
    try:
        p=subprocess.run(argv,env=dict(os.environ,GOMAXPROCS='2'),text=True,capture_output=True,timeout=timeout)
        record={'argv':argv,'exit':p.returncode,'stdout':p.stdout,'stderr':p.stderr,'wall_duration_ns':time.monotonic_ns()-began}
        if p.returncode==0:record['sample']=json.loads(p.stdout)
        return record
    except subprocess.TimeoutExpired as e:
        return {'argv':argv,'exit':None,'timeout':timeout,'stdout':str(e.stdout),'stderr':str(e.stderr),'wall_duration_ns':time.monotonic_ns()-began}


def driver_controls(out):
    x=0x98abcdef; payload=bytearray()
    for _ in range(1200):
        x^=(x<<13)&0xffffffff; x^=x>>17; x^=(x<<5)&0xffffffff; payload.append(x&255)
    controls=[]
    with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as data, socket.create_connection(('127.0.0.1',19090),timeout=2) as control:
        data.settimeout(2); data.connect(('127.0.0.1',19090))
        for transfer_id in [101,102,103]:
            data.send(b'B'+transfer_id.to_bytes(8,'big')+(32).to_bytes(4,'big')+b'U')
            ack=data.recv(128)
            if ack!=b'K'+transfer_id.to_bytes(8,'big'):raise RuntimeError('driver begin identity ACK')
            if transfer_id!=103:
                for seq in [1,0,*range(31,19,-1),*range(13,1,-1),0]:
                    data.send(b'P'+transfer_id.to_bytes(8,'big')+seq.to_bytes(4,'big')+payload)
                corrupt=bytearray(payload);corrupt[-1]^=1
                data.send(b'P'+transfer_id.to_bytes(8,'big')+(14).to_bytes(4,'big')+corrupt)
            time.sleep(.1)
            control.sendall(b'Q'+transfer_id.to_bytes(8,'big'))
            report=bytearray()
            while len(report)<40:
                chunk=control.recv(40-len(report))
                if not chunk:raise RuntimeError('driver reliable report EOF')
                report.extend(chunk)
            values=[int.from_bytes(report[i:i+8],'big') for i in range(0,40,8)]
            expected=[32,26,1,1] if transfer_id!=103 else [32,0,0,0]
            passed=values[:4]==expected and values[4]>0
            controls.append({'transfer_id':transfer_id,'same_bound_source':data.getsockname(),
                'offered_datagrams':values[0],'unique_verified':values[1],'duplicates':values[2],'corrupt':values[3],
                'lost_datagrams':values[0]-values[1],'receiver_duration_ns':values[4],
                'expected':expected,'passed':passed,'retransmissions':0})
    rr.save(out/'driver-correctness.json',controls)
    if not all(c['passed'] for c in controls):raise RuntimeError('loss/reorder/duplicate/corruption/reused-source control failed')


def cell(phase,round_id,case,variant,out):
    out.mkdir()
    record={'cohort':'loss-aware-UDP-final','phase':phase,'round':round_id,'case':case,'network':'udp','variant':variant,
        'fixed_binary':'hybrid','candidate_role':'relay','loadavg_before':Path('/proc/loadavg').read_text()}
    processes=[];gateway=None
    try:
        if case.endswith('wireguard'):
            gateway=rr.launch('gateway',ROOT/'binaries/hybrid',ROOT/'configs/gateway.json',out);processes.append(gateway)
        relay=rr.launch('relay',ROOT/'binaries'/variant,ROOT/'configs'/(case+'-relay.json'),out,trace=phase=='smoke' and case.endswith('wireguard'))
        processes.append(relay);rr.ready(19200,processes)
        client=rr.launch('client',ROOT/'binaries/hybrid',ROOT/'configs'/(case+'-client.json'),out)
        processes.append(client);rr.ready(19300,processes)
        for p in processes:p.bench_record['observed_affinity']=sorted(os.sched_getaffinity(p.pid))
        record['processes']=[p.bench_record for p in processes]
        record['application']=application(307200 if phase=='smoke' else 16*1024*1024,16 if phase=='smoke' else 256)
        record['status']='passed' if record['application']['exit']==0 else 'failed'
        if record['status']=='passed':
            if any(t['corrupt_datagrams'] or not t['verified_all_counted_bytes'] for t in record['application']['sample']['transfers']):
                record['status']='failed-integrity'
        if phase=='smoke' and gateway and record['status']=='passed':
            rr.stop(gateway);blocked=application(38400,1,timeout=3)
            record['gateway_removed_negative_control']=blocked;record['gateway_required']=blocked['exit']!=0
            if not record['gateway_required']:record['status']='failed-route-control'
    except Exception as e:record.update(status='runner-error',error=repr(e))
    finally:
        for p in reversed(processes):rr.stop(p)
        record['loadavg_after']=Path('/proc/loadavg').read_text()
        rr.save(out/'sample.json',record)
    return record


def main():
    p=argparse.ArgumentParser();p.add_argument('--phase',choices=['smoke','timing'],required=True);p.add_argument('--output',required=True)
    args=p.parse_args();out=Path(args.output);out.mkdir(exist_ok=False)
    subprocess.run(['ip','link','set','lo','up'],check=True)
    rr.save(out/'environment.json',{'cohort':'loss-aware-UDP-final','started_utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),
        'netns':os.readlink('/proc/self/ns/net'),'phase':args.phase,
        'invocation':['unshare','--net','python3',str(Path(__file__).resolve()),'--phase',args.phase,'--output',args.output],
        'pins':{str(p.relative_to(ROOT)):hashlib.sha256(p.read_bytes()).hexdigest() for directory in ['binaries','configs'] for p in sorted((ROOT/directory).iterdir()) if p.is_file()},
        'source_pins':{name:hashlib.sha256((ROOT/name).read_bytes()).hexdigest() for name in ['application.go','remote_runner.py','udp_cohort.py']},
        'ipv6_disable':{x:Path('/proc/sys/net/ipv6/conf/'+x+'/disable_ipv6').read_text().strip() for x in ['all','default','lo']},
        'facts':[rr.fact(a) for a in [['uname','-a'],['lscpu'],['ip','-j','addr'],['ip','-j','route'],['ip','-j','-6','route']]],
        'round_orders':rr.ORDERS,'assignments':{'relay':{'cpus':[2,3],'GOMAXPROCS':2},'fixed_support':{'cpus':[0,1],'GOMAXPROCS':2}},
        'method':'1200B unique verified payload, fixed32 datagram windows, TCP progress/pull control through same actual Xray chain,100ms final drain, reliable final receiver counters, no DATA retry; receiver goodput includes drain/control overhead; not raw UDP capacity'})
    echo=rr.launch('echo',ROOT/'binaries/application',None,out);records=[]
    try:
        rr.ready(19090,[echo])
        if args.phase=='smoke':driver_controls(out)
        for round_id in ([0] if args.phase=='smoke' else range(1,8)):
            cases=rr.CASES[round_id%len(rr.CASES):]+rr.CASES[:round_id%len(rr.CASES)]
            for case in cases:
                for variant in (rr.VARIANTS if args.phase=='smoke' else rr.ORDERS[round_id-1]):
                    label=f'r{round_id:02d}-{case}-udp-{variant}';r=cell(args.phase,round_id,case,variant,out/label);records.append(r)
                    rr.save(out/'index.json',[{'round':x['round'],'case':x['case'],'network':'udp','variant':x['variant'],'status':x['status']} for x in records])
                    print(datetime.datetime.now(datetime.timezone.utc).isoformat(),label,r['status'],flush=True)
                    if r['status']!='passed' and args.phase=='timing':raise RuntimeError('UDP timed cell failed; preserve and stop, no retry: '+label)
    finally:
        rr.stop(echo);rr.save(out/'closure.json',{'finished_utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),'completed_cells':len(records),
            'expected_cells':20 if args.phase=='smoke' else 140,'all_passed':all(r['status']=='passed' for r in records)})
    if not all(r['status']=='passed' for r in records):raise SystemExit(1)

if __name__=='__main__':main()
