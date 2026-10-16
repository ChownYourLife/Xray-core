#!/usr/bin/env python3
"""Execute the authorized immutable TCPv2 cohort once and collect complete raw evidence."""
import json
from pathlib import Path
import shlex
import subprocess
import tarfile

BASE=Path(__file__).resolve().parent
LOCAL=BASE/'tcp-v2'
OUT=Path('/Users/hosi/D/V2ray/Xray-core/investigation/transport-e2e-comparison/tcp-cohort-v2')
REMOTE='/tmp/xray-transport-e2e-comparison-tcp-v2-20261015'
OLD='/tmp/xray-transport-e2e-comparison-20261015'
HOST='root@216.195.211.248'
OPTIONS=['-i','/Users/hosi/.ssh/id_ed25519','-o','IdentitiesOnly=yes','-o','StrictHostKeyChecking=yes','-o','BatchMode=yes','-o','ServerAliveInterval=30','-o','ServerAliveCountMax=6']


def run(argv):
    p=subprocess.run(argv,text=True,stdout=subprocess.PIPE,stderr=subprocess.STDOUT)
    return {'argv':argv,'exit':p.returncode,'output':p.stdout}

def ssh(command):return run(['ssh',*OPTIONS,HOST,command])
def save(name,value):(OUT/name).write_text(json.dumps(value,indent=2)+'\n')


def main():
    OUT.mkdir(exist_ok=False)
    records=[]
    records.append(ssh('mkdir '+REMOTE+' && cp -R '+OLD+'/binaries '+OLD+'/configs '+REMOTE+'/'))
    records.append(run(['scp',*OPTIONS,str(LOCAL/'application.go'),str(LOCAL/'remote_runner.py'),str(LOCAL/'tcp_cohort.py'),HOST+':'+REMOTE+'/']))
    records.append(run(['scp',*OPTIONS,str(LOCAL/'binaries/application'),HOST+':'+REMOTE+'/binaries/application']))
    save('deployment.json',records)
    if any(r['exit'] for r in records):raise RuntimeError('TCP immutable workspace preparation failed')
    snapshot='python3 -c '+shlex.quote("import json,subprocess,pathlib; cmds=[['ip','-j','route'],['ip','-j','-6','route'],['systemctl','list-units','--type=service','--state=running','--no-pager','--plain']]; print(json.dumps({'netns':str(pathlib.Path('/proc/self/ns/net').readlink()),'sysctls':{x:pathlib.Path('/proc/sys/net/ipv6/conf/'+x+'/disable_ipv6').read_text().strip() for x in ['all','default','lo']},'facts':[{'argv':c,'output':subprocess.run(c,text=True,capture_output=True).stdout} for c in cmds]},indent=2))")
    before=ssh(snapshot);save('host-before.json',before)
    result=ssh('unshare --net python3 '+REMOTE+'/tcp_cohort.py');save('run.json',result)
    after=ssh(snapshot);save('host-after.json',after)
    collection=ssh('tar -czf '+REMOTE+'/timing-tcp-v2.tar.gz -C '+REMOTE+' timing-tcp-v2');save('collection.json',collection)
    copied=run(['scp',*OPTIONS,HOST+':'+REMOTE+'/timing-tcp-v2.tar.gz',str(OUT/'raw.tar.gz')]);save('copy.json',copied)
    if copied['exit']:raise RuntimeError('TCP raw collection failed')
    with tarfile.open(OUT/'raw.tar.gz') as tf:tf.extractall(OUT,filter='data')
    b,a=json.loads(before['output']),json.loads(after['output'])
    save('preservation.json',{'host_netns_unchanged':b['netns']==a['netns'],'ipv6_sysctls_unchanged':b['sysctls']==a['sysctls'],
        'v4_routes_unchanged':b['facts'][0]['output']==a['facts'][0]['output'],'v6_routes_unchanged':b['facts'][1]['output']==a['facts'][1]['output'],
        'running_services_unchanged':b['facts'][2]['output']==a['facts'][2]['output']})
    print(json.dumps({'exit':result['exit'],'output':result['output'],'evidence':str(OUT)},indent=2))
    raise SystemExit(result['exit'])

if __name__=='__main__':main()
