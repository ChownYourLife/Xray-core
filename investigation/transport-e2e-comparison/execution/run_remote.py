#!/usr/bin/env python3
"""Deploy isolated benchmark payload, execute one explicit phase, collect all evidence."""
import argparse
import hashlib
import json
from pathlib import Path
import shlex
import shutil
import subprocess
import tarfile

ROOT = Path(__file__).resolve().parent
EVIDENCE = Path('/Users/hosi/D/V2ray/Xray-core/investigation/transport-e2e-comparison')
REMOTE = '/tmp/xray-transport-e2e-comparison-20261015'
OPTIONS = ['-i', '/Users/hosi/.ssh/id_ed25519', '-o', 'IdentitiesOnly=yes', '-o', 'StrictHostKeyChecking=yes', '-o', 'BatchMode=yes']
HOST = 'root@216.195.211.248'


def run(args):
    p = subprocess.run(args, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    return {'argv': args, 'exit': p.returncode, 'output': p.stdout}


def ssh(command):
    return run(['ssh', *OPTIONS, HOST, command])


def main():
    p = argparse.ArgumentParser()
    p.add_argument('--phase', choices=['smoke','timing'], required=True)
    p.add_argument('--label', required=True)
    p.add_argument('--deploy', action='store_true')
    args = p.parse_args()
    local = EVIDENCE / args.label
    local.mkdir(exist_ok=False)
    records = []
    if args.deploy:
        archive = ROOT / 'payload.tar.gz'
        with tarfile.open(archive, 'w:gz') as tf:
            for item in ['binaries', 'configs', 'remote_runner.py', 'application.go']:
                tf.add(ROOT / item, arcname=item)
        payload_sha = hashlib.sha256(archive.read_bytes()).hexdigest()
        records.append(ssh('mkdir '+shlex.quote(REMOTE)))
        if records[-1]['exit']:
            raise RuntimeError(records[-1])
        records.append(run(['scp', *OPTIONS, str(archive), HOST+':'+REMOTE+'/payload.tar.gz']))
        records.append(ssh('tar -xzf '+REMOTE+'/payload.tar.gz -C '+REMOTE+' && sha256sum '+REMOTE+'/payload.tar.gz'))
        (local/'payload.json').write_text(json.dumps({'sha256':payload_sha,'commands':records}, indent=2)+'\n')
        if any(r['exit'] for r in records):
            raise RuntimeError('Deployment failed; see payload.json')
    snapshot = "python3 -c " + shlex.quote("import json,subprocess,pathlib; cmds=[['ip','-j','route'],['ip','-j','-6','route'],['ip','-j','addr'],['systemctl','list-units','--type=service','--state=running','--no-pager','--plain']]; print(json.dumps({'netns':str(pathlib.Path('/proc/self/ns/net').readlink()),'sysctls':{x:pathlib.Path('/proc/sys/net/ipv6/conf/'+x+'/disable_ipv6').read_text().strip() for x in ['all','default','lo']},'facts':[{'argv':c,'output':subprocess.run(c,text=True,capture_output=True).stdout} for c in cmds]},indent=2))")
    before = ssh(snapshot)
    (local/'host-before.json').write_text(json.dumps(before,indent=2)+'\n')
    remote_out = REMOTE+'/'+args.label
    cmd = 'unshare --net python3 '+REMOTE+'/remote_runner.py --phase '+args.phase+' --output '+remote_out
    result = ssh(cmd)
    (local/'run.json').write_text(json.dumps(result,indent=2)+'\n')
    after = ssh(snapshot)
    (local/'host-after.json').write_text(json.dumps(after,indent=2)+'\n')
    collection = ssh('tar -czf '+REMOTE+'/'+args.label+'.tar.gz -C '+REMOTE+' '+args.label)
    (local/'collection.json').write_text(json.dumps(collection,indent=2)+'\n')
    collected = run(['scp', *OPTIONS, HOST+':'+REMOTE+'/'+args.label+'.tar.gz', str(local/'raw.tar.gz')])
    if collected['exit']:
        raise RuntimeError(collected)
    with tarfile.open(local/'raw.tar.gz') as tf:
        tf.extractall(local, filter='data')
    bp, ap = json.loads(before['output']), json.loads(after['output'])
    preservation = {'same_host_netns':bp['netns']==ap['netns'], 'host_ipv6_sysctls_unchanged':bp['sysctls']==ap['sysctls'],
                    'route_v4_unchanged':bp['facts'][0]['output']==ap['facts'][0]['output'],
                    'route_v6_unchanged':bp['facts'][1]['output']==ap['facts'][1]['output'],
                    'running_services_unchanged':bp['facts'][3]['output']==ap['facts'][3]['output']}
    (local/'preservation.json').write_text(json.dumps(preservation,indent=2)+'\n')
    print(json.dumps({'phase':args.phase,'label':args.label,'exit':result['exit'],'output':result['output'], 'preservation':preservation},indent=2))
    raise SystemExit(result['exit'])

if __name__=='__main__':
    main()
