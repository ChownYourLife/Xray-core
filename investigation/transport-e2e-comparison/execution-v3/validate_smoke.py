#!/usr/bin/env python3
"""Bind complete correctness evidence to exact final driver/config/product bytes."""
import argparse
import hashlib
import json
from pathlib import Path
import re


def main():
    p = argparse.ArgumentParser()
    p.add_argument('evidence_root')
    p.add_argument('label')
    p.add_argument('--harness-pins', default='harness-pins-v2.json')
    args = p.parse_args()
    evidence = Path(args.evidence_root)
    wrapper = evidence/args.label
    root = wrapper/args.label
    files = sorted(root.glob('r*/sample.json'))
    environment = json.loads((root/'environment.json').read_text())
    hp = json.loads((evidence/args.harness_pins).read_text())
    sources = json.loads((evidence/'sources.json').read_text())
    configs = json.loads((evidence/'config-pins.json').read_text())
    checks = {'cells_exactly40':len(files)==40,
              'driver_reorder_duplicate_controls':all(r['passed'] for r in json.loads((root/'driver-correctness.json').read_text())),
              'host_preservation':all(json.loads((wrapper/'preservation.json').read_text()).values()),
              'private_ipv6_enabled':all(x=='0' for x in environment['ipv6_disable'].values()),
              'application_binary_pin':environment['pins']['binaries/application']==hp['files']['binaries/application'],
              'application_source_pin':environment['harness_source_pins']['application.go']==hp['files']['application.go'],
              'runner_source_pin':environment['harness_source_pins']['remote_runner.py']==hp['files']['remote_runner.py'],
              'product_binary_pins':all(environment['pins']['binaries/'+n]==r['binary_sha256'] for n,r in sources['build_results'].items()),
              'config_pins':all(environment['pins']['configs/'+n]==v for n,v in configs['files'].items())}
    cells=[]
    for path in files:
        r=json.loads(path.read_text())
        s=r.get('application',{}).get('sample',{})
        expected=1048576 if r['network']=='tcp' else 307200
        passed=(r['status']=='passed' and r['application']['exit']==0 and len(s.get('established_rtt_ns',[]))==16
                and len(s.get('setup_first_response_ns',[]))==8 and len(s.get('transfers',[]))==2
                and all(t['verified_all_received_bytes'] and t['delivered_bytes']==expected and t['receiver_duration_ns']>0 for t in s.get('transfers',[])))
        cell={'case':r['case'],'network':r['network'],'variant':r['variant'],'status':r['status'],
              'complete_integrity':passed,'sample_sha256':hashlib.sha256(path.read_bytes()).hexdigest()}
        if r['case'].endswith('wireguard'):
            trace=(path.parent/'relay-network.strace').read_text()
            sends=[line for line in trace.splitlines() if 'htons(19100)' in line and
                   any(fn in line for fn in ['sendmsg(','sendmmsg(','sendto(']) and re.search(r'= [1-9][0-9]*$',line)]
            cell['successful_candidate_wg_udp_sends']=len(sends)
            cell['outer_route_verified']=bool(sends)
            if r['network']=='tcp':
                cell['gateway_required_negative_control']=r.get('gateway_required',False)
        cells.append(cell)
    checks['all_cells_complete_verified']=all(r['complete_integrity'] for r in cells)
    checks['all_wg_outer_sends_proven']=all(r['outer_route_verified'] for r in cells if 'outer_route_verified' in r)
    checks['all_wg_gateway_required_controls']=all(r['gateway_required_negative_control'] for r in cells if 'gateway_required_negative_control' in r)
    result={'label':args.label,'all_acceptance_checks_passed':all(checks.values()),'checks':checks,'cells':cells,
            'environment_sha256':hashlib.sha256((root/'environment.json').read_bytes()).hexdigest(),
            'not_timing_data':True}
    (evidence/(args.label+'-acceptance.json')).write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps(result['checks'],indent=2))
    if not result['all_acceptance_checks_passed']:
        raise SystemExit(1)

if __name__=='__main__':
    main()
