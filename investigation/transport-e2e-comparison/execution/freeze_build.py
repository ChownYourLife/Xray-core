#!/usr/bin/env python3
"""Freeze actual whole-product Git snapshots and build actual Xray executables."""
import concurrent.futures
import datetime
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tarfile
import time

ROOT = Path(__file__).resolve().parent
EVIDENCE = Path('/Users/hosi/D/V2ray/Xray-core/investigation/transport-e2e-comparison')
LOCAL = Path('/Users/hosi/D/V2ray/Xray-core')
GO = '/Users/hosi/go/pkg/mod/golang.org/toolchain@v0.0.1-go1.27.0.darwin-arm64/bin/go'
POOL = ROOT / 'objects.git'
COMMANDS = []


def run(args, cwd=None, env=None):
    began = datetime.datetime.now(datetime.timezone.utc).isoformat()
    p = subprocess.run(args, cwd=cwd, env=env, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    COMMANDS.append({'started_utc': began, 'argv': args, 'cwd': str(cwd) if cwd else None,
                     'exit': p.returncode, 'output': p.stdout})
    (EVIDENCE / 'source-commands.json').write_text(json.dumps(COMMANDS, indent=2) + '\n')
    if p.returncode:
        raise RuntimeError(f'{args}: exit {p.returncode}: {p.stdout}')
    return p.stdout.strip()


def git(*args):
    return run(['git', '--git-dir=' + str(POOL), *args])


def main():
    ROOT.mkdir(parents=True, exist_ok=True)
    (ROOT / 'sources').mkdir(exist_ok=True)
    (ROOT / 'binaries').mkdir(exist_ok=True)
    if not POOL.exists():
        run(['git', 'init', '--bare', str(POOL)])
    advertised = {
        'official': run(['git', 'ls-remote', 'chownyourlife:XTLS/Xray-core.git', 'HEAD', 'refs/heads/main']),
        'original-gso': run(['git', 'ls-remote', 'chownyourlife:T3ST3ST3R0N/Xray-core.git', 'refs/heads/wireguard-gso']),
    }
    git('fetch', '--no-tags', 'chownyourlife:XTLS/Xray-core.git', 'refs/heads/main:refs/heads/official')
    git('fetch', '--no-tags', 'chownyourlife:T3ST3ST3R0N/Xray-core.git', 'refs/heads/wireguard-gso:refs/heads/original-gso')
    for name, rev in [('batching-only', '13419e49'), ('hybrid', '1a52c36f')]:
        sha = run(['git', '-C', str(LOCAL), 'rev-parse', rev + '^{commit}'])
        git('fetch', '--no-tags', str(LOCAL), sha + ':refs/heads/' + name)
    manifest = {
        'captured_utc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
        'external_root': str(ROOT), 'advertised': advertised,
        'interpretation': 'Four actual whole-product source snapshots, not sender-swapped microbench fixtures. The 13419 snapshot includes other integrated lifecycle and stream/auth changes; whole-product differences confound attribution to batching alone. Official means fetched advertised main tip, even if equal to historical shared ancestor.',
        'common_client_gateway': 'hybrid',
        'variants': {},
        'build': {'go': GO, 'go_version': run([GO, 'version']),
                  'environment': {'GOTOOLCHAIN': 'local', 'GOOS': 'linux', 'GOARCH': 'amd64', 'GOAMD64': 'v1', 'CGO_ENABLED': '0'},
                  'flags': ['-trimpath', '-buildvcs=false', '-ldflags=-buildid='],
                  'package': './main'},
    }
    for name in ['official', 'original-gso', 'batching-only', 'hybrid']:
        rev = git('rev-parse', 'refs/heads/' + name + '^{commit}')
        tree = git('rev-parse', rev + '^{tree}')
        meta = git('show', '-s', '--format=%H%n%T%n%aI%n%cI%n%s', rev).splitlines()
        archive = ROOT / (name + '.tar')
        run(['git', '--git-dir=' + str(POOL), 'archive', '--format=tar', '--output=' + str(archive), rev])
        dest = ROOT / 'sources' / name
        if dest.exists():
            raise RuntimeError('Source destination already exists; never overwrite a frozen tree: ' + str(dest))
        dest.mkdir()
        with tarfile.open(archive) as tf:
            tf.extractall(dest, filter='data')
        files = {str(p.relative_to(dest)): hashlib.sha256(p.read_bytes()).hexdigest()
                 for p in sorted(dest.rglob('*')) if p.is_file()}
        (EVIDENCE / (name + '-files.json')).write_text(json.dumps(files, indent=2) + '\n')
        manifest['variants'][name] = {
            'commit': rev, 'tree': tree, 'author_date': meta[2], 'commit_date': meta[3], 'subject': meta[4],
            'source_directory': str(dest), 'archive_sha256': hashlib.sha256(archive.read_bytes()).hexdigest(),
            'file_count': len(files), 'file_manifest_sha256': hashlib.sha256((EVIDENCE / (name + '-files.json')).read_bytes()).hexdigest(),
            'go_mod_sha256': files['go.mod'], 'go_sum_sha256': files['go.sum'],
            'go_mod': (dest / 'go.mod').read_text(),
            'core_version_source': (dest / 'core/core.go').read_text(),
            'diff_vs_official': git('diff', '--stat', 'refs/heads/official', rev),
            'diff_names_vs_official': git('diff', '--name-status', 'refs/heads/official', rev),
            'url': 'https://github.com/' + ('T3ST3ST3R0N' if name == 'original-gso' else 'XTLS' if name == 'official' else 'ChownYourLife') + '/Xray-core',
        }
    manifest['official_fork_merge_base'] = git('merge-base', 'official', 'original-gso')
    (EVIDENCE / 'sources.json').write_text(json.dumps(manifest, indent=2) + '\n')
    env = dict(os.environ, **manifest['build']['environment'])
    def build(name):
        dest = ROOT / 'sources' / name
        binary = ROOT / 'binaries' / name
        argv = [GO, 'build', *manifest['build']['flags'], '-o', str(binary), './main']
        began = time.monotonic_ns()
        p = subprocess.run(argv, cwd=dest, env=env, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        record = {'argv': argv, 'cwd': str(dest), 'exit': p.returncode, 'output': p.stdout,
                  'elapsed_ns': time.monotonic_ns() - began}
        if p.returncode == 0:
            record['binary_sha256'] = hashlib.sha256(binary.read_bytes()).hexdigest()
            record['go_version_m'] = subprocess.run([GO, 'version', '-m', str(binary)], text=True, capture_output=True).stdout
        (EVIDENCE / (name + '-build.json')).write_text(json.dumps(record, indent=2) + '\n')
        if p.returncode:
            raise RuntimeError(name + ': ' + p.stdout)
        return name, record
    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as executor:
        builds = dict(executor.map(build, manifest['variants']))
    manifest['build_results'] = builds
    (EVIDENCE / 'sources.json').write_text(json.dumps(manifest, indent=2) + '\n')
    print(json.dumps({'commits': {n: v['commit'] for n, v in manifest['variants'].items()},
                      'binary_sha256': {n: v['binary_sha256'] for n, v in builds.items()}}, indent=2))


if __name__ == '__main__':
    main()
