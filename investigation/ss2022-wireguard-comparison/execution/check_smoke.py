#!/usr/bin/env python3
"""Offline smoke accounting and frozen pin reconciliation; no server commands."""
import hashlib
import json
from pathlib import Path
E=Path('/Users/hosi/D/V2ray/Xray-core/investigation/ss2022-wireguard-comparison');OLD=E.parent/'transport-e2e-comparison'
records=[]
for network in ['tcp','udp']:
    root=E/('smoke-'+network)/('smoke-'+network);env=json.loads((root/'environment.json').read_text())
    previous=json.loads((OLD/('tcp-cohort-v2/timing-tcp-v2/environment.json' if network=='tcp' else 'udp-cohort-lossaware-v1/udp-cohort-lossaware-v1/environment.json')).read_text())
    for key,value in previous['pins'].items():
        if key.startswith('binaries/') or key=='configs/gateway.json':assert env['pins'][key]==value,(network,key)
    paths=sorted(root.glob('r*/sample.json'));assert len(paths)==4
    for path in paths:
        r=json.loads(path.read_text());assert r['case']=='ss2022-wireguard' and r['status']=='passed' and r['gateway_required']
        s=r['application']['sample'];assert r['application']['exit']==0
        for t in s['transfers']:
            assert t.get('verified_all_received_bytes',t.get('verified_all_counted_bytes',False))
            if network=='udp':assert t['retransmissions']==0 and t['corrupt_datagrams']==0 and t['lost_datagrams']==t['offered_datagrams']-t['unique_verified_datagrams']
        trace=path.parent/'relay-network.strace';text=trace.read_text();matches=[line for line in text.splitlines() if 'htons(19100)' in line and any(op in line for op in ['sendmsg(','sendmmsg(','sendto(','connect('])];assert matches
        records.append({'network':network,'variant':r['variant'],'status':r['status'],'gateway_required':r['gateway_required'],'candidate_outer_wireguard_trace_lines':len(matches),'sample_sha256':hashlib.sha256(path.read_bytes()).hexdigest(),'transfers':s['transfers']})
    if network=='udp':assert all(x['passed'] for x in json.loads((root/'driver-correctness.json').read_text()))
result={'status':'passed','smoke_cells':len(records),'frozen_product_application_gateway_pins_match_original':True,'records':records}
(E/'smoke-reconciliation.json').write_text(json.dumps(result,indent=2)+'\n');print(json.dumps({'status':'passed','smoke_cells':len(records)}))
