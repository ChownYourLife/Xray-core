#!/usr/bin/env python3
"""Exact seven-round absolute summaries for one complete140-cell protocol cohort."""
import argparse
from collections import defaultdict
import hashlib
import json
from pathlib import Path
import statistics


def stats(values):
    q1,_,q3=statistics.quantiles(values,n=4,method='inclusive');median=statistics.median(values)
    return {'n':len(values),'median':median,'q1':q1,'q3':q3,'min':min(values),'max':max(values),
            'mad':statistics.median(abs(x-median) for x in values),'round_values':values}


def main():
    p=argparse.ArgumentParser();p.add_argument('--network',choices=['tcp','udp'],required=True)
    p.add_argument('raw_root');p.add_argument('output');args=p.parse_args()
    root=Path(args.raw_root);files=sorted(root.glob('r*/sample.json'))
    if len(files)!=140:raise ValueError('Need exactly140 raw cells; do not summarize partial or retried corpus')
    groups=defaultdict(list);seen=set();hashes={}
    for path in files:
        r=json.loads(path.read_text());key=(r['round'],r['case'],r['network'],r['variant'])
        if key in seen or r['network']!=args.network or r['status']!='passed' or r['application']['exit']!=0:
            raise ValueError('Failed/duplicate/wrong-cohort cell '+str(key))
        seen.add(key);s=r['application']['sample']
        if len(s['established_rtt_ns'])!=256 or len(s['setup_first_response_ns'])!=8:raise ValueError('Missing latency samples')
        if not all(type(n) is int and n>0 for name in ['established_rtt_ns','setup_first_response_ns'] for n in s[name]):raise ValueError('Noninteger monotonic sample')
        one={'round':r['round'],'source':str(path.relative_to(root)),
             'established_rtt_round_median_ns':statistics.median(s['established_rtt_ns']),
             'setup_first_response_round_median_ns':statistics.median(s['setup_first_response_ns'])}
        directions=set()
        for t in s['transfers']:
            direction=t['direction'];directions.add(direction)
            if not t.get('verified_all_received_bytes',t.get('verified_all_counted_bytes',False)) or t['receiver_duration_ns']<=0:
                raise ValueError('Invalid receiver evidence')
            if args.network=='tcp' and t['delivered_bytes']!=128*1024*1024:raise ValueError('Wrong TCP delivered byte count')
            if args.network=='udp':
                expected=(16*1024*1024//(32*1200))*(32*1200)
                if t['offered_bytes']!=expected or t['delivered_bytes']!=t['unique_verified_datagrams']*1200 or t['corrupt_datagrams']:
                    raise ValueError('Invalid UDP offer/delivery/integrity')
                if t['offered_datagrams']-t['unique_verified_datagrams']!=t['lost_datagrams'] or t['retransmissions']!=0:
                    raise ValueError('Invalid UDP loss/retry accounting')
                for name in ['lost_datagrams','duplicate_datagrams','offered_bytes','delivered_bytes']:
                    one[direction+'_'+name]=t[name]
                one[direction+'_loss_percent']=100*t['lost_datagrams']/t['offered_datagrams']
            one[direction+'_MB_s']=t['delivered_bytes']*1000/t['receiver_duration_ns']
            one[direction+'_Mbit_s']=one[direction+'_MB_s']*8
        if directions!={'upload','download'}:raise ValueError('Missing direction')
        groups[(r['case'],r['variant'])].append(one);hashes[str(path.relative_to(root))]=hashlib.sha256(path.read_bytes()).hexdigest()
    records=[]
    for (case,variant),values in sorted(groups.items()):
        values.sort(key=lambda r:r['round'])
        if [v['round'] for v in values]!=list(range(1,8)):raise ValueError('Missing matched rounds')
        result={'case':case,'network':args.network,'variant':variant,'rounds':values}
        for name in values[0]:
            if name not in ['round','source']:result[name]=stats([v[name] for v in values])
        result['established_rtt_us']=stats([v['established_rtt_round_median_ns']/1000 for v in values])
        result['setup_first_response_us']=stats([v['setup_first_response_round_median_ns']/1000 for v in values])
        records.append(result)
    if len(records)!=20:raise ValueError('Need all20 case/product groups')
    output={'network':args.network,'cells':140,'matched_rounds':7,
        'primary_summary':'Median of seven matched round measurements. Established RTT first reduces256 raw64B echo durations to one median per round, then takes median of seven; not pooled request median. Setup first reduces8 fresh-flow first-response samples per round.',
        'units':'Decimal MB/s (bytes*1000/ns), Mbit/s=MB/s*8, latency us=ns/1000; raw integer durations retained in source files.',
        'dispersion':'Inclusive linear Q1/Q3; median absolute deviation over seven round values.',
        'groups':records,'source_sample_sha256':hashes}
    Path(args.output).write_text(json.dumps(output,indent=2)+'\n')
    for g in records:print(g['case'],g['variant'],f"up={g['upload_MB_s']['median']:.6f}MB/s down={g['download_MB_s']['median']:.6f}MB/s RTT={g['established_rtt_us']['median']:.3f}us setup={g['setup_first_response_us']['median']:.3f}us")

if __name__=='__main__':main()
