#!/usr/bin/env python3
"""One missing chain, original frozen binaries and drivers, no timing retries."""
import argparse
import hashlib
import json
from pathlib import Path
import shlex
import shutil
import subprocess
import tarfile

ROOT=Path(__file__).resolve().parent;BASE=ROOT.parent
E=Path('/Users/hosi/D/V2ray/Xray-core/investigation/ss2022-wireguard-comparison')
REMOTE='/tmp/xray-ss2022-wireguard-supplement-20261015'
HOST='root@216.195.211.248'
OPTIONS=['-i','/Users/hosi/.ssh/id_ed25519','-o','IdentitiesOnly=yes','-o','StrictHostKeyChecking=yes','-o','BatchMode=yes','-o','ServerAliveInterval=30','-o','ServerAliveCountMax=6']
def run(argv):
    p=subprocess.run(argv,text=True,stdout=subprocess.PIPE,stderr=subprocess.STDOUT);return {'argv':argv,'exit':p.returncode,'output':p.stdout}
def ssh(command):return run(['ssh',*OPTIONS,HOST,command])
def save(path,obj):path.parent.mkdir(parents=True,exist_ok=True);path.write_text(json.dumps(obj,indent=2)+'\n')
def require(r):
    if r['exit']:raise RuntimeError(json.dumps(r))
def prepare():
    cfg=ROOT/'configs';cfg.mkdir(exist_ok=False)
    client=json.loads((BASE/'configs/ss2022-freedom-client.json').read_text());client['inbounds'][0]['settings']['address']='10.77.0.1'
    relay=json.loads((BASE/'configs/ssclassic-wireguard-relay.json').read_text());ss=json.loads((BASE/'configs/ss2022-freedom-relay.json').read_text());relay['inbounds']=ss['inbounds']
    save(cfg/'ss2022-wireguard-client.json',client);save(cfg/'ss2022-wireguard-relay.json',relay);shutil.copyfile(BASE/'configs/gateway.json',cfg/'gateway.json')
    for network,source in [('tcp','tcp-v2'),('udp','udp-final')]:
        dest=ROOT/network;dest.mkdir(exist_ok=False)
        for name in ['remote_runner.py','application.go']+(['udp_cohort.py'] if network=='udp' else []):shutil.copyfile(BASE/source/name,dest/name)
        if network=='tcp':shutil.copyfile(BASE/'udp-final/udp_cohort.py',dest/'udp_cohort.py')
        shutil.copyfile(ROOT/'supplement.py',dest/'supplement.py')
    old=Path('/Users/hosi/D/V2ray/Xray-core/investigation/transport-e2e-comparison')
    save(E/'execution/original-artifacts.json',{n:hashlib.sha256((old/n).read_bytes()).hexdigest() for n in ['report.html','summary-tcp.json','summary-udp.json']})
    records=[ssh('mkdir '+REMOTE)]
    for network,source in [('tcp','/tmp/xray-transport-e2e-comparison-tcp-v2-20261015'),('udp','/tmp/xray-transport-e2e-comparison-udp-final-20261015')]:
        records.append(ssh('mkdir '+REMOTE+'/'+network+' && cp -R '+source+'/binaries '+REMOTE+'/'+network+'/'))
        records.append(run(['scp',*OPTIONS,*[str(x) for x in (ROOT/network).iterdir() if x.is_file()],HOST+':'+REMOTE+'/'+network+'/']))
        records.append(run(['scp','-r',*OPTIONS,str(cfg),HOST+':'+REMOTE+'/'+network+'/']))
    save(E/'execution/deployment.json',records)
    for r in records:require(r)
    for network in ['tcp','udp']:
        dest=E/'execution'/network;dest.mkdir(exist_ok=False)
        for f in (ROOT/network).iterdir():shutil.copyfile(f,dest/f.name)
    shutil.copytree(cfg,E/'execution/configs')
    shutil.copyfile(__file__,E/'execution/run_supplement.py')

def phase(phase,network):
    out=E/(phase+'-'+network);out.mkdir(exist_ok=False)
    snapshot='python3 -c '+shlex.quote("import json,subprocess,pathlib; cmds=[['ip','-j','route'],['ip','-j','-6','route'],['systemctl','list-units','--type=service','--state=running','--no-pager','--plain']]; print(json.dumps({'netns':str(pathlib.Path('/proc/self/ns/net').readlink()),'sysctls':{x:pathlib.Path('/proc/sys/net/ipv6/conf/'+x+'/disable_ipv6').read_text().strip() for x in ['all','default','lo']},'facts':[{'argv':c,'output':subprocess.run(c,text=True,capture_output=True).stdout} for c in cmds]},indent=2))")
    before=ssh(snapshot);save(out/'host-before.json',before);require(before)
    result=ssh('unshare --net python3 '+REMOTE+'/'+network+'/supplement.py --phase '+phase+' --network '+network);save(out/'run.json',result)
    after=ssh(snapshot);save(out/'host-after.json',after)
    collection=ssh('tar -czf '+REMOTE+'/'+phase+'-'+network+'.tar.gz -C '+REMOTE+'/'+network+' '+phase+'-'+network);save(out/'collection.json',collection);require(collection)
    copied=run(['scp',*OPTIONS,HOST+':'+REMOTE+'/'+phase+'-'+network+'.tar.gz',str(out/'raw.tar.gz')]);save(out/'copy.json',copied);require(copied)
    with tarfile.open(out/'raw.tar.gz') as tf:tf.extractall(out,filter='data')
    b,a=json.loads(before['output']),json.loads(after['output'])
    save(out/'preservation.json',{'host_netns_unchanged':b['netns']==a['netns'],'ipv6_sysctls_unchanged':b['sysctls']==a['sysctls'],'v4_routes_unchanged':b['facts'][0]['output']==a['facts'][0]['output'],'v6_routes_unchanged':b['facts'][1]['output']==a['facts'][1]['output'],'running_services_unchanged':b['facts'][2]['output']==a['facts'][2]['output']})
    print(json.dumps({'phase':phase,'network':network,'exit':result['exit'],'output':result['output']}),flush=True);require(result)
if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('action',choices=['prepare','smoke','timing']);a=p.parse_args()
    if a.action=='prepare':prepare()
    else:
        for network in ['tcp','udp']:phase(a.action,network)
