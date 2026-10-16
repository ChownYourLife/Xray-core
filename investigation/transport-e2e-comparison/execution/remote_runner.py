#!/usr/bin/env python3
"""Run only in a fresh unshared network namespace. No host networking/tuning changes."""
import argparse
import datetime
import hashlib
import json
import os
from pathlib import Path
import signal
import socket
import subprocess
import time

ROOT = Path(__file__).resolve().parent
VARIANTS = ['official', 'original-gso', 'batching-only', 'hybrid']
CASES = ['ssclassic-freedom', 'ss2022-freedom', 'ssclassic-wireguard', 'vless-wireguard', 'vmess-wireguard']
ORDERS = [
 ['official', 'original-gso', 'batching-only', 'hybrid'],
 ['original-gso', 'batching-only', 'hybrid', 'official'],
 ['batching-only', 'hybrid', 'official', 'original-gso'],
 ['hybrid', 'official', 'original-gso', 'batching-only'],
 ['hybrid', 'batching-only', 'original-gso', 'official'],
 ['official', 'hybrid', 'batching-only', 'original-gso'],
 ['original-gso', 'official', 'hybrid', 'batching-only'],
]
assert len(ORDERS) == 7 and all(sorted(o) == sorted(VARIANTS) for o in ORDERS)


def save(path, value):
    path.write_text(json.dumps(value, indent=2) + '\n')


def fact(argv):
    p = subprocess.run(argv, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    return {'argv': argv, 'exit': p.returncode, 'output': p.stdout}


def launch(role, binary, config, out, trace=False):
    cpus = '2,3' if role == 'relay' else '0,1'
    argv = ['taskset', '-c', cpus, str(binary)]
    if config:
        argv += ['run', '-c', str(config)]
    else:
        argv += ['-mode', 'server', '-addr', '127.0.0.1:19090']
    if trace:
        argv = ['strace', '-f', '-qq', '-s', '32', '-e', 'trace=sendmsg,sendmmsg,sendto,connect',
                '-o', str(out / 'relay-network.strace'), *argv]
    log = (out / (role + '.log')).open('w')
    p = subprocess.Popen(argv, stdout=log, stderr=subprocess.STDOUT,
                         env=dict(os.environ, GOMAXPROCS='2'), start_new_session=True)
    p.bench_record = {'role': role, 'pid': p.pid, 'argv': argv, 'requested_cpus': cpus, 'GOMAXPROCS': 2}
    p.bench_log = log
    return p


def stop(p):
    if p.poll() is None:
        os.killpg(p.pid, signal.SIGTERM)
        try:
            p.wait(timeout=3)
        except subprocess.TimeoutExpired:
            os.killpg(p.pid, signal.SIGKILL)
            p.wait(timeout=3)
    p.bench_log.close()


def ready(port, processes):
    end = time.monotonic() + 5
    while time.monotonic() < end:
        if any(p.poll() is not None for p in processes):
            raise RuntimeError('Xray/application exited before readiness')
        try:
            with socket.create_connection(('127.0.0.1', port), timeout=.1):
                return
        except OSError:
            time.sleep(.02)
    raise RuntimeError('listener readiness deadline')


def app(network, nbytes, samples, timeout=90):
    argv = ['taskset', '-c', '0,1', str(ROOT / 'binaries/application'), '-mode', 'client',
            '-addr', '127.0.0.1:19300', '-network', network, '-bytes', str(nbytes), '-samples', str(samples)]
    started = datetime.datetime.now(datetime.timezone.utc).isoformat()
    began = time.monotonic_ns()
    try:
        p = subprocess.run(argv, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                           env=dict(os.environ, GOMAXPROCS='2'), timeout=timeout)
        r = {'argv': argv, 'started_utc': started, 'wall_duration_ns': time.monotonic_ns()-began,
             'exit': p.returncode, 'stderr': p.stderr, 'stdout': p.stdout}
        if p.returncode == 0:
            r['sample'] = json.loads(p.stdout)
        return r
    except subprocess.TimeoutExpired as e:
        return {'argv': argv, 'started_utc': started, 'wall_duration_ns': time.monotonic_ns()-began,
                'exit': None, 'timeout': timeout, 'stdout': str(e.stdout), 'stderr': str(e.stderr)}


def cell(phase, round_id, case, network, variant, out):
    out.mkdir(parents=True)
    procs = []
    record = {'phase': phase, 'round': round_id, 'case': case, 'network': network, 'variant': variant,
              'loadavg_before': Path('/proc/loadavg').read_text(), 'fixed_binary': 'hybrid', 'candidate_role': 'relay'}
    try:
        gateway = None
        if case.endswith('wireguard'):
            gateway = launch('gateway', ROOT / 'binaries/hybrid', ROOT / 'configs/gateway.json', out)
            procs.append(gateway)
        relay = launch('relay', ROOT / 'binaries' / variant, ROOT / 'configs' / (case+'-relay.json'),
                       out, trace=phase == 'smoke' and case.endswith('wireguard'))
        procs.append(relay)
        ready(19200, procs)
        client = launch('client', ROOT / 'binaries/hybrid', ROOT / 'configs' / (case+'-client.json'), out)
        procs.append(client)
        ready(19300, procs)
        for p in procs:
            p.bench_record['proc_status'] = Path('/proc') .joinpath(str(p.pid), 'status').read_text()
            p.bench_record['observed_affinity'] = sorted(os.sched_getaffinity(p.pid))
        record['processes'] = [p.bench_record for p in procs]
        nbytes = (1024*1024 if phase=='smoke' else 128*1024*1024) if network=='tcp' else (32*1200*8 if phase=='smoke' else 16*1024*1024)
        record['application'] = app(network, nbytes, 16 if phase=='smoke' else 256)
        record['status'] = 'passed' if record['application']['exit'] == 0 else 'failed'
        if phase=='smoke' and gateway and network=='tcp' and record['status']=='passed':
            stop(gateway)
            blocked = app(network, 65536, 1, timeout=3)
            record['gateway_removed_negative_control'] = blocked
            record['gateway_required'] = blocked['exit'] != 0
            if not record['gateway_required']:
                record['status'] = 'failed-route-control'
    except Exception as e:
        record['status'] = 'runner-error'
        record['error'] = repr(e)
    finally:
        for p in reversed(procs):
            stop(p)
        record['loadavg_after'] = Path('/proc/loadavg').read_text()
        trace = out / 'relay-network.strace'
        if trace.exists():
            text = trace.read_text()
            lines = [s for s in text.splitlines() if 'htons(19100)' in s and ('sendmsg(' in s or 'sendmmsg(' in s or 'sendto(' in s or 'connect(' in s)]
            record['candidate_wireguard_outer_udp_proof'] = {'destination': '127.0.0.1:19100',
                'trace_sha256': hashlib.sha256(trace.read_bytes()).hexdigest(), 'matching_lines': lines[:24],
                'matching_line_count': len(lines)}
        save(out / 'sample.json', record)
    return record


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--phase', required=True, choices=['smoke', 'timing'])
    parser.add_argument('--output', required=True)
    args = parser.parse_args()
    out = Path(args.output)
    out.mkdir(parents=True, exist_ok=False)
    subprocess.run(['ip', 'link', 'set', 'lo', 'up'], check=True)
    environment = {'started_utc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
        'netns': os.readlink('/proc/self/ns/net'),
        'invocation': ['unshare', '--net', 'python3', str(Path(__file__).resolve()), '--phase', args.phase, '--output', args.output],
        'harness_source_pins': {name: hashlib.sha256((ROOT/name).read_bytes()).hexdigest() for name in ['remote_runner.py', 'application.go']},
        'facts': [fact(a) for a in [['uname', '-a'], ['ip', '-j', 'addr'], ['ip', '-j', 'route'],
                                  ['ip', '-j', '-6', 'route'], ['lscpu']]],
        'ipv6_disable': {x: Path('/proc/sys/net/ipv6/conf/'+x+'/disable_ipv6').read_text().strip() for x in ['all','default','lo']},
        'pins': {str(p.relative_to(ROOT)): hashlib.sha256(p.read_bytes()).hexdigest()
                 for directory in ['binaries','configs'] for p in sorted((ROOT/directory).iterdir()) if p.is_file()},
        'assignments': {'relay': {'cpus': [2,3], 'GOMAXPROCS': 2},
                        'client_gateway_echo_measurement': {'cpus': [0,1], 'GOMAXPROCS': 2}},
        'interpretation': 'Private network namespace loopback CPU-isolation comparison, not WAN capacity. Fixed support endpoints share CPU0,1 and may bottleneck; no post-result retuning.'}
    save(out / 'environment.json', environment)
    echo = launch('echo', ROOT / 'binaries/application', None, out)
    ready(19090, [echo])
    all_records = []
    try:
        rounds = [0] if args.phase=='smoke' else list(range(1,8))
        for round_id in rounds:
            cases = CASES[round_id%len(CASES):] + CASES[:round_id%len(CASES)]
            networks = ['tcp','udp'] if round_id%2==0 else ['udp','tcp']
            variants = VARIANTS if args.phase=='smoke' else ORDERS[round_id-1]
            for case in cases:
                for network in networks:
                    for variant in variants:
                        label = f'r{round_id:02d}-{case}-{network}-{variant}'
                        record = cell(args.phase, round_id, case, network, variant, out/label)
                        all_records.append(record)
                        save(out/'index.json', [{'round': r['round'], 'case': r['case'], 'network':r['network'],
                            'variant': r['variant'], 'status': r['status']} for r in all_records])
                        print(label, record['status'], flush=True)
                        if record['status'] != 'passed':
                            raise RuntimeError('Cell failed; retain raw failure and stop sequence without retries: '+label)
    finally:
        stop(echo)
        save(out/'closure.json', {'finished_utc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
            'completed_cells': len(all_records), 'expected_cells': 40 if args.phase=='smoke' else 280,
            'all_completed_passed': all(r['status']=='passed' for r in all_records)})

if __name__=='__main__':
    main()
