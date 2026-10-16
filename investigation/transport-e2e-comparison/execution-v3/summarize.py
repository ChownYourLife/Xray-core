#!/usr/bin/env python3
"""Summarize a complete fixed sequence without exclusions, pooling, or retries."""
import argparse
import hashlib
import json
from pathlib import Path
import statistics
from collections import defaultdict


def distribution(values):
    q1, _, q3 = statistics.quantiles(values, n=4, method='inclusive')
    median = statistics.median(values)
    return {'n': len(values), 'median': median, 'q1': q1, 'q3': q3, 'min': min(values), 'max': max(values),
            'mad': statistics.median(abs(v-median) for v in values), 'round_values': values}


def main():
    p = argparse.ArgumentParser()
    p.add_argument('timing_root')
    p.add_argument('output')
    args = p.parse_args()
    root = Path(args.timing_root)
    groups = defaultdict(list)
    seen = set()
    files = sorted(root.glob('r*/sample.json'))
    if len(files) != 280:
        raise ValueError(f'Need all280 cells, got {len(files)}; no partial medians')
    manifests = {}
    for path in files:
        r = json.loads(path.read_text())
        key = (r['round'], r['case'], r['network'], r['variant'])
        if key in seen or r['status'] != 'passed' or r['application']['exit'] != 0:
            raise ValueError('Duplicate or failed cell: '+str(key))
        seen.add(key)
        s = r['application']['sample']
        if len(s['established_rtt_ns']) != 256 or len(s['setup_first_response_ns']) != 8:
            raise ValueError('Missing latency samples: '+str(key))
        if not all(type(n) is int and n > 0 for name in ['established_rtt_ns','setup_first_response_ns'] for n in s[name]):
            raise ValueError('Nonpositive or noninteger monotonic duration: '+str(key))
        rates = {}
        for transfer in s['transfers']:
            if not transfer['verified_all_received_bytes'] or transfer['delivered_bytes'] <= 0 or transfer['receiver_duration_ns'] <= 0:
                raise ValueError('Invalid receiver evidence: '+str(key))
            expected = 128*1024*1024 if r['network']=='tcp' else (16*1024*1024//(32*1200))*(32*1200)
            if transfer['delivered_bytes'] != expected:
                raise ValueError('Unexpected actual delivered bytes: '+str(key))
            rates[transfer['direction']] = transfer['delivered_bytes']*1000/transfer['receiver_duration_ns']
        if set(rates) != {'upload','download'}:
            raise ValueError('Missing direction: '+str(key))
        groups[key[1:]].append({'round':r['round'], 'source':str(path.relative_to(root)),
            'upload_MB_s':rates['upload'], 'download_MB_s':rates['download'],
            'established_rtt_round_median_ns':statistics.median(s['established_rtt_ns']),
            'setup_first_response_round_median_ns':statistics.median(s['setup_first_response_ns'])})
        manifests[str(path.relative_to(root))] = hashlib.sha256(path.read_bytes()).hexdigest()
    records=[]
    for (case,network,variant),values in sorted(groups.items()):
        values.sort(key=lambda r:r['round'])
        if [r['round'] for r in values] != list(range(1,8)):
            raise ValueError('Missing seven matched rounds')
        record={'case':case,'network':network,'variant':variant,'rounds':values}
        for field in ['upload_MB_s','download_MB_s','established_rtt_round_median_ns','setup_first_response_round_median_ns']:
            record[field]=distribution([r[field] for r in values])
        for direction in ['upload','download']:
            record[direction+'_Mbit_s']={k:([v*8 for v in x] if isinstance(x,list) else x if k=='n' else x*8)
                for k,x in record[direction+'_MB_s'].items()}
        record['established_rtt_us']={k:([v/1000 for v in x] if isinstance(x,list) else x if k=='n' else x/1000)
            for k,x in record['established_rtt_round_median_ns'].items()}
        record['setup_first_response_us']={k:([v/1000 for v in x] if isinstance(x,list) else x if k=='n' else x/1000)
            for k,x in record['setup_first_response_round_median_ns'].items()}
        records.append(record)
    if len(records) != 40:
        raise ValueError('Need all40 case/network/variant summaries')
    result={'definition':'Primary is median of seven matched round measurements. RTT first reduces256 established64B request-response samples to a median per round, then takes median over seven rounds. No pooled-request median is substituted.',
        'dispersion':'Q1/Q3 use inclusive linear quantiles; MAD is median absolute deviation from seven-round median.',
        'units':'Decimal MB/s, Mbit/s; ns raw, us for display. No ns/op microbenchmark is used.',
        'cells':len(files),'rounds':7,'groups':records,'source_sample_sha256':manifests}
    Path(args.output).write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps({'groups':len(records),'cells':len(files),'output':args.output},indent=2))

if __name__=='__main__':
    main()
