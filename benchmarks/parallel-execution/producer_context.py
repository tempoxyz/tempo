#!/usr/bin/env python3
"""Prepare one producer diagnostic from bound install and live-node evidence.

This verifier does not install tools, start nodes, submit transactions, claim
measurement exclusivity, or run the producer. Root/workflow owns those actions.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import resource
import shutil
import stat
import time
import tomllib
import urllib.request

import producer_supervisor as sup
import producer_lifecycle as lifecycle_module
from producer_lifecycle import System as CommandSystem, validate_config as validate_lifecycle

TXGEN = sup.TXGEN_COMMIT
PRESET = sup.PRESET_COMMIT
URL = 'https://github.com/tempoxyz/txgen'
INSTALL = ['cargo', 'install', '--git', URL, '--locked', '--rev', TXGEN, '--force', 'txgen-tempo', 'bench-cli']
ENV_KEYS = ('RUSTFLAGS', 'CARGO_ENCODED_RUSTFLAGS', 'RUSTC_WRAPPER', 'RUSTC_WORKSPACE_WRAPPER', 'CARGO_BUILD_TARGET')
UNSUPPORTED_CARGO_SECTIONS = ('build', 'profile', 'target', 'env', 'unstable')
SPEC_FILES = ('contrib/bench/txgen/presets/public-mix.yml', 'contrib/bench/txgen/presets/mpp.yml',
              'contrib/bench/txgen/tip20.abi.json', 'contrib/bench/txgen/tip20-channel-reserve.abi.json')
NODE_FLAGS = {'--execution.threads': '8', '--execution.batch-size': '128', '--execution.capture-window': '128',
              '--engine.prewarming-threads': '16', '--engine.account-worker-count': '32',
              '--engine.storage-worker-count': '32', '--log.file.filter': 'debug',
              '--builder.gaslimit': '1000000000000'}
PRIVATE_FILES = {f'/var/lib/schelk/{r}.json' for r in 'ab'} | {
    f'/reth-bench-{r}/tempo_e2e_100000mb/.bench-meta/{name}.json' for r in 'ab' for name in ('marker', 'genesis')}
READ_HELPER = """import hashlib,json,os,re,sys
p=sys.argv[1]; n=int(sys.argv[2]); mode=sys.argv[3]
assert re.fullmatch(r'/proc/[1-9][0-9]*/(stat|status|cmdline|cgroup|limits|exe)',p) or p in %r
assert '/environ' not in p
if mode in ('exe','hash'):
 assert (mode=='exe' and p.endswith('/exe')) or (mode=='hash' and not p.startswith('/proc/'))
 target=os.readlink(p) if mode=='exe' else p; h=hashlib.sha256(); total=0
 with open(p,'rb') as s:
  while True:
   b=s.read(1048576)
   if not b: break
   total+=len(b); assert total<=(536870912 if mode=='exe' else 16777216); h.update(b)
 print(json.dumps({'path':target,'sha256':h.hexdigest(),'bytes':total}))
else:
 with open(p,'rb') as s: b=s.read(n+1)
 assert len(b)<=n
 sys.stdout.buffer.write(b)
""" % sorted(PRIVATE_FILES)


def require(ok, message):
    if not ok: raise ValueError(message)


def save(path, value):
    raw = (json.dumps(value, indent=2, allow_nan=False) + '\n').encode()
    require(len(raw) <= 16 * 1024**2, 'Evidence JSON cap')
    with Path(path).open('xb') as stream: stream.write(raw)
    return file_binding(path)


def file_binding(path, cap=16 * 1024**2):
    path = Path(path)
    require(path.is_absolute() and path.is_file() and not path.is_symlink(), 'Require absolute regular evidence file')
    require(path.stat().st_size <= cap, 'Evidence file cap')
    return {'path': str(path), 'sha256': sup.digest(path)}


def verified(item, cap=16 * 1024**2):
    actual = file_binding(item['path'], cap)
    require(actual == item, 'Evidence file identity mismatch')
    return Path(item['path'])


def command(system, argv, timeout=15):
    result = system.command(argv, timeout)
    require(result['code'] == 0, 'Command failed: ' + str(argv[:3]))
    return result['stdout']


class System(CommandSystem):
    def bytes(self, path, cap=1024 * 1024):
        path = str(path)
        try:
            with open(path, 'rb') as stream: raw = stream.read(cap + 1)
            require(len(raw) <= cap, 'Machine read cap')
            return raw
        except PermissionError:
            require(re.fullmatch(r'/proc/[1-9][0-9]*/(?:stat|status|cmdline|cgroup|limits)', path)
                    or path in PRIVATE_FILES, 'Privileged read path is not allowlisted')
            return command(self, ['sudo', '-n', 'python3', '-c', READ_HELPER, path, str(cap), 'read'], 10).encode()

    def executable(self, pid):
        path = Path(f'/proc/{pid}/exe')
        try:
            target = str(path.readlink()); size = 0; digest = hashlib.sha256()
            with path.open('rb') as stream:
                while block := stream.read(1024 * 1024):
                    size += len(block); require(size <= 512 * 1024**2, 'Live ELF cap'); digest.update(block)
            return {'path': target, 'sha256': digest.hexdigest(), 'bytes': size}
        except PermissionError:
            return json.loads(command(self, ['sudo', '-n', 'python3', '-c', READ_HELPER, str(path), '0', 'exe'], 30))

    def snapshot_genesis(self, path):
        path = str(path)
        require(path in PRIVATE_FILES and path.endswith('/genesis.json'), 'Snapshot genesis path')
        try:
            item = file_binding(path)
            return {**item, 'bytes': Path(path).stat().st_size}
        except PermissionError:
            return json.loads(command(self, ['sudo', '-n', 'python3', '-c', READ_HELPER, path, '0', 'hash'], 15))

    def rpc(self, url, method, params):
        require(url in ('http://127.0.0.1:8545', 'http://127.0.0.1:8645'), 'Non-local RPC refused')
        request = urllib.request.Request(url, data=json.dumps({'jsonrpc': '2.0', 'id': 1, 'method': method, 'params': params}).encode(),
                                         headers={'Content-Type': 'application/json'})
        with urllib.request.urlopen(request, timeout=10) as response: raw = response.read(2 * 1024**2 + 1)
        require(len(raw) <= 2 * 1024**2, 'RPC response cap')
        value = json.loads(raw)
        require(value.get('jsonrpc') == '2.0' and value.get('id') == 1 and 'error' not in value and value.get('result') is not None,
                'RPC failed or malformed')
        return value['result']


def elf_info(path, system):
    path = Path(path).resolve(); sup.verify_elf(path)
    item = file_binding(path, 512 * 1024**2)
    notes = command(system, ['readelf', '-n', str(path)])
    identifiers = re.findall(r'Build ID: ([0-9a-f]+)', notes)
    require(len(identifiers) == 1, 'Require exactly one ELF build ID')
    return item, identifiers[0]


def installed_packages(metadata, target, rustc):
    require(isinstance(metadata.get('installs'), dict), 'Cargo install metadata schema')
    result = {}
    for package, binary in (('txgen-tempo', 'txgen-tempo'), ('bench-cli', 'bench')):
        matches = [(key, value) for key, value in metadata['installs'].items() if key.startswith(package + ' ')]
        require(len(matches) == 1, 'Ambiguous installed package')
        key, value = matches[0]
        require('git+' + URL + '?rev=' + TXGEN + '#' + TXGEN in key, 'Installed package source changed')
        require(value.get('bins') == [binary] and value.get('profile') == 'release' and value.get('features') == []
                and value.get('all_features') is False and value.get('no_default_features') is False,
                'Installed package build controls changed')
        require(value.get('target') == target and isinstance(value.get('rustc'), str)
                and value['rustc'].strip() == rustc.strip(), 'Installed compiler/target differ')
        result[package] = {'package_id': key, **value}
    return result


def cargo_configuration(evidence, checkout):
    require(evidence.get('schema_version') == 1 and evidence.get('source_checkout') == str(checkout), 'Cargo config evidence schema')
    cwd, home = Path(evidence['cwd']), Path(evidence['cargo_home'])
    require(cwd.is_absolute() and home.is_absolute(), 'Absolute Cargo environment paths required')
    base = {str(home / name) for name in ('config', 'config.toml')}
    for parent in (cwd, *cwd.parents):
        base.update(str(parent / '.cargo' / name) for name in ('config', 'config.toml'))
    expected = set(base)
    for root in (cwd, checkout):
        for parent in (root, *root.parents):
            expected.update(str(parent / '.cargo' / name) for name in ('config', 'config.toml'))
    before = sup.read_json(verified(evidence['before']))
    require(before.get('schema_version') == 1 and before.get('cwd') == str(cwd) and before.get('cargo_home') == str(home),
            'Before-install Cargo config context differs')
    prior = before['searched']
    require(isinstance(prior, list) and len(prior) <= 256 and len({row['path'] for row in prior}) == len(prior)
            and base <= {row['path'] for row in prior}, 'Incomplete/duplicate before-install Cargo config inventory')
    for row in prior:
        path = Path(row['path'])
        require(path.is_absolute() and (str(path) in base or
                (path.parent.name == '.cargo' and path.name in ('config', 'config.toml'))), 'Unexpected prior Cargo config path')
    expected.update(row['path'] for row in prior)
    require(evidence.get('unsupported_environment_names') == [], 'Unsupported compiler environment override')
    rows = evidence['searched']
    require(isinstance(rows, list) and len(rows) <= 256 and len(rows) == len(expected)
            and {row['path'] for row in rows} == expected, 'Incomplete/duplicate applicable Cargo config inventory')
    for row in rows:
        path = Path(row['path'])
        require(type(row.get('exists')) is bool and path.exists() == row['exists'], 'Cargo config presence changed')
        if row['exists']:
            require(set(row) == {'path', 'exists', 'sha256', 'unsupported_sections'} and file_binding(path)['sha256'] == row['sha256'], 'Cargo config bytes changed')
            parsed = tomllib.loads(path.read_text())
            unsupported = [key for key in UNSUPPORTED_CARGO_SECTIONS if parsed.get(key)]
            require(row['unsupported_sections'] == unsupported == [], 'Unsupported Cargo build/profile/target/env override')
        else:
            require(set(row) == {'path', 'exists'}, 'Absent Cargo config schema')
    prior_by_path = {row['path']: row for row in prior}
    for row in rows:
        require(row == prior_by_path[row['path']] if row['path'] in prior_by_path else row['exists'] is False,
                'Cargo configuration changed or was not checked before install')
    return evidence


def pinned_file(checkout, revision, relative, system):
    path = checkout / relative
    expected = command(system, ['git', '-C', str(checkout), 'rev-parse', revision + ':' + relative]).strip()
    actual = command(system, ['git', '-C', str(checkout), 'hash-object', '--no-filters', str(path)]).strip()
    require(re.fullmatch('[0-9a-f]{40}', expected) and expected == actual, 'Pinned source file differs: ' + relative)
    return path


def verify_clean_checkout(checkout, system, observation=None):
    """Permit only Cargo's empty, untracked checkout-completion sentinel.

    Keep bounded Git evidence even on refusal when a caller supplies observation.
    NUL-delimited porcelain avoids filename quoting or whitespace ambiguity.
    """
    evidence = observation if observation is not None else {}
    evidence.update(checkout=str(checkout), status='checking')
    argv = ['git', '-C', str(checkout), 'status', '--porcelain', '-z', '--untracked-files=all']
    result = system.command(argv, 15)
    evidence['git_status'] = {'argv': argv, **result}
    require(result['code'] == 0, 'Producer checkout status failed')
    status = result['stdout']
    require(status in ('', '?? .cargo-ok\0'), 'Producer source is dirty beyond Cargo checkout sentinel')
    sentinel = None
    if status:
        metadata = (Path(checkout) / '.cargo-ok').lstat()
        sentinel = {'path': str(Path(checkout) / '.cargo-ok'), 'mode': metadata.st_mode,
                    'bytes': metadata.st_size}
        evidence['cargo_sentinel'] = sentinel
        require(stat.S_ISREG(metadata.st_mode) and metadata.st_size == 0,
                'Cargo checkout sentinel must be a regular empty file')
    evidence.update(status='verified', cargo_sentinel=sentinel)
    return evidence


def install_record(record, checkout, now):
    require(record.get('schema_version') == 1 and record.get('status') == 'completed' and record.get('exit_code') == 0,
            'Install did not complete successfully')
    require(record.get('argv') == INSTALL and record.get('log_complete') is True, 'Require exact forced pinned install and complete log')
    start, end = record['started_realtime_ns'], record['finished_realtime_ns']
    require(type(start) is int and type(end) is int and 0 < start < end <= now, 'Invalid install clock bracket')
    require(record.get('source_checkout') == str(checkout), 'Install checkout binding differs')
    require(record.get('unsupported_environment_names') == [], 'Unsupported compiler environment override')
    return record


def build(args, system):
    output = args.output.resolve(); require(output.parent.is_dir() and not output.exists(), 'New build manifest required')
    record_path = args.install_record.resolve(); record = sup.read_json(record_path)
    checkout = args.source_checkout.resolve()
    install_record(record, checkout, time.time_ns())
    require(command(system, ['git', '-C', str(checkout), 'rev-parse', 'HEAD']).strip() == TXGEN, 'Wrong producer checkout')
    checkout_status = verify_clean_checkout(checkout, system)
    lock = pinned_file(checkout, TXGEN, 'Cargo.lock', system)
    log = verified(record['log']); require(log.stat().st_size > 0, 'Missing complete install log')
    cargo_path = verified(record['cargo_version']); rustc_path = verified(record['rustc_version'])
    cargo = cargo_path.read_text().strip(); rustc_verbose = rustc_path.read_text().strip()
    require(cargo.startswith('cargo ') and rustc_verbose.startswith('rustc '), 'Compiler version evidence')
    host = re.findall(r'^host: (\S+)$', rustc_verbose, re.M); require(len(host) == 1, 'Missing rustc host')
    env = record['effective_environment']; require(set(env) == set(ENV_KEYS) and all(isinstance(v, str) for v in env.values()), 'Compiler environment schema')
    require(all(env[key] == '' for key in ENV_KEYS if key != 'CARGO_BUILD_TARGET')
            and env['CARGO_BUILD_TARGET'] in ('', host[0]), 'Require unwrapped native default release compiler controls')
    target = env['CARGO_BUILD_TARGET'] or host[0]
    installed = installed_packages(sup.read_json(verified(record['install_metadata'])), target, rustc_verbose)
    config_evidence = verified(record['cargo_config_evidence'])
    cargo_configuration(sup.read_json(config_evidence), checkout)
    producer, build_id = elf_info(args.txgen_bin, system)
    bench, bench_build_id = elf_info(args.bench_bin, system)
    require(Path(producer['path']).name == 'txgen-tempo' and Path(bench['path']).name == 'bench', 'Wrong installed bin names')
    # Input records are workflow build attestations, supplemented by exact local
    # source/lock/package/ELF checks; they are not an independent compiler proof.
    value = {'schema_version': 1, 'status': 'verified', 'source_commit': TXGEN, 'source_clean': True,
        'checkout_status': checkout_status,
        'binary': producer, 'bench_binary': bench, 'cargo_lock': file_binding(lock), 'build_evidence': record['log'],
        'install_record': file_binding(record_path), 'install_metadata': record['install_metadata'], 'installed_packages': installed,
        'build': {'profile': 'release', 'features': 'default', 'cargo': cargo, 'rustc': rustc_verbose,
                  'target': target, 'build_id': build_id, 'bench_build_id': bench_build_id,
                  'rustflags': env['RUSTFLAGS'], 'cargo_encoded_rustflags': env['CARGO_ENCODED_RUSTFLAGS'],
                  'effective_environment': env, 'cargo_config_evidence': file_binding(config_evidence)},
        'scope': 'Verified exact workflow install record, clean pinned source/lock, Cargo package metadata and current ELF bytes; not independent compiler attestation.'}
    save(output, value)
    return value


def option(argv, name):
    values = []
    for i, arg in enumerate(argv):
        if arg == name:
            require(i + 1 < len(argv) and not argv[i+1].startswith('--'), 'Missing option value')
            values.append(argv[i+1])
        elif arg.startswith(name + '='): values.append(arg.split('=', 1)[1])
    require(len(values) == 1, 'Missing/duplicate option: ' + name)
    return values[0]


def cpu_set(value):
    require(isinstance(value, str) and len(value) <= 32768, 'CPU list cap')
    result = set()
    for item in value.strip().split(','):
        match = re.fullmatch(r'([0-9]+)(?:-([0-9]+))?', item); require(match is not None, 'CPU list syntax')
        low, high = int(match[1]), int(match[2] or match[1]); require(0 <= low <= high < 65536, 'CPU list range')
        result.update(range(low, high + 1)); require(len(result) <= 4096, 'CPU inventory cap')
    return result


def unified_cgroup(raw):
    values = [line.split(':', 2)[2] for line in raw.splitlines() if line.startswith('0::')]
    require(len(values) == 1 and values[0].startswith('/') and '..' not in Path(values[0]).parts, 'Require safe cgroup v2 path')
    return values[0]


def process_stat(raw):
    fields = raw.rsplit(') ', 1)[1].split()
    return {'state': fields[0], 'ppid': int(fields[1]), 'pgid': int(fields[2]), 'sid': int(fields[3]), 'start_ticks': int(fields[19])}


def same_process(before, after):
    # Sleeping/running state may change during observation; PID start time and
    # the process/session identity must remain stable.
    return all(before[key] == after[key] for key in ('pgid', 'sid', 'start_ticks'))


def telemetry_argv(argv):
    """Never retain or interpolate the secret-derived endpoint into diagnostics."""
    normalized = list(argv); count = 0; i = 0
    while i < len(normalized):
        arg = normalized[i]
        if arg == '--tracing-otlp':
            require(i + 1 < len(normalized) and normalized[i+1] and not normalized[i+1].startswith('--'), 'Missing tracing endpoint')
            normalized[i+1] = 'sha256:' + hashlib.sha256(normalized[i+1].encode()).hexdigest()
            count += 1; i += 1
        elif arg.startswith('--tracing-otlp='):
            value = arg.split('=', 1)[1]; require(value, 'Missing tracing endpoint')
            normalized[i] = '--tracing-otlp=sha256:' + hashlib.sha256(value.encode()).hexdigest(); count += 1
        i += 1
    require(count == 1, 'Require exactly one tracing endpoint')
    return normalized


def cgroup_constraints(path, system):
    current = Path('/sys/fs/cgroup') / path.lstrip('/'); rows = []
    for _ in range(20):
        values = {}
        for name in ('cpu.max', 'cpuset.cpus.effective', 'cpuset.mems.effective', 'memory.max', 'pids.max'):
            try: values[name] = system.bytes(current / name, 32768).decode().strip()
            except FileNotFoundError: values[name] = None
        rows.append({'path': str(current), 'values': values})
        if current == Path('/sys/fs/cgroup'): return rows
        current = current.parent
    raise ValueError('Cgroup ancestor depth cap')


def governor_observation(system):
    before_monotonic_ns, before_realtime_ns = time.monotonic_ns(), time.time_ns()
    paths = system.glob(lifecycle_module.GOVERNORS)
    require(len(paths) <= lifecycle_module.MAX_GOVERNORS and len(paths) == len(set(paths)),
            'CPU governor inventory bound')
    rows = []
    for path in paths:
        require(re.fullmatch(r'/sys/devices/system/cpu/cpu[0-9]+/cpufreq/scaling_governor', path),
                'Unexpected CPU governor path')
        value = system.bytes(path, 128).decode('utf-8', errors='strict').strip()
        require(re.fullmatch(r'[a-zA-Z0-9_-]+', value), 'Malformed CPU governor value')
        rows.append({'path': path, 'value': value})
    return {'status': 'observed' if rows else 'not_exposed', 'governors': rows,
            'before_monotonic_ns': before_monotonic_ns, 'after_monotonic_ns': time.monotonic_ns(),
            'before_realtime_ns': before_realtime_ns, 'after_realtime_ns': time.time_ns(),
            'scope': 'One context_prepare observation; no atomic, continuous, performance-governor or unchanged-throughout-run claim.'}


def node_identity(role, node, context, lifecycle, system):
    unit = lifecycle['node_units']['ab'.index(role)]
    require(node['scope'] == unit and node['datadir'] == f'/reth-bench-{role}/tempo_e2e_100000mb', 'Node scope/datadir changed')
    require(node['snapshot_state'] == f'/var/lib/schelk/{role}.json' and node['snapshot_marker'] == node['datadir'] + '/.bench-meta/marker.json', 'Snapshot paths changed')
    require(node['cpus'] == {'a': '0-7,16-23', 'b': '8-15,24-31'}[role] and node['memory'] == '60G', 'Node placement controls changed')
    expected_group = '/system.slice/' + unit
    properties = command(system, ['systemctl', 'show', unit, '--property=LoadState,ActiveState,Description,ControlGroup,InvocationID'])
    properties = dict(line.split('=', 1) for line in properties.splitlines() if '=' in line)
    require(properties.get('LoadState') == 'loaded' and properties.get('ActiveState') == 'active'
            and properties.get('Description') == lifecycle['unit_description'] and properties.get('ControlGroup') == expected_group,
            'Live node scope ownership mismatch')
    require(re.fullmatch(r'[0-9a-f]{32}', properties.get('InvocationID', '')), 'Missing node scope invocation')
    pids = system.bytes('/sys/fs/cgroup' + expected_group + '/cgroup.procs', 16384).decode().split()
    require(0 < len(pids) <= 128 and all(re.fullmatch('[1-9][0-9]*', p) for p in pids), 'Node scope process inventory')
    matches = []
    for raw_pid in pids:
        pid = int(raw_pid)
        try: argv = system.bytes(f'/proc/{pid}/cmdline', 65536).decode().rstrip('\0').split('\0')
        except FileNotFoundError: continue
        if len(argv) == 1 + len(node['args']) and argv[1:2] == ['node']:
            normalized = telemetry_argv(argv)
            if normalized[1:] == node['args']: matches.append((pid, normalized))
    require(len(matches) == 1, 'Require one exact live node argv inside its owned scope')
    pid, argv = matches[0]; before = process_stat(system.bytes(f'/proc/{pid}/stat', 16384).decode())
    exe = system.executable(pid)
    require(exe['path'] == context['binary'] and exe['sha256'] == context['binary_sha256'], 'Live node ELF differs')
    group = unified_cgroup(system.bytes(f'/proc/{pid}/cgroup', 16384).decode())
    require(group == expected_group, 'Node escaped declared cgroup')
    status_raw = system.bytes(f'/proc/{pid}/status', 32768).decode()
    status = dict(line.split(':', 1) for line in status_raw.splitlines() if ':' in line)
    selected = {key: status[key].strip() for key in ('Uid', 'Gid', 'Groups', 'Cpus_allowed_list', 'Mems_allowed_list', 'Threads')}
    require(cpu_set(selected['Cpus_allowed_list']) == cpu_set(node['cpus']), 'Live node affinity differs')
    require(node['args'][0] == 'node' and option(node['args'], '--datadir') == node['datadir'], 'Node arguments changed')
    for flag, value in NODE_FLAGS.items(): require(option(node['args'], flag) == value, 'Fixed node flag changed: ' + flag)
    require(re.fullmatch('sha256:[0-9a-f]{64}', option(node['args'], '--tracing-otlp')), 'Unnormalized tracing endpoint')
    chain = Path(option(node['args'], '--chain'))
    chain = chain if chain.is_absolute() else Path(context['repository']) / chain
    require(chain.resolve() == Path(context['genesis']), 'Node chainspec argument differs')
    forbidden = ('--debug.skip-state-root', '--debug.skip-genesis-validation', '--execution.stage-diagnostics',
                 '--execution.capture-diagnostics', '--execution.proof-prefetch', '--execution.state-forwarding')
    require(not any(a.split('=')[0] in forbidden for a in node['args']), 'Unreviewed node diagnostic/bypass')
    limits = system.bytes(f'/proc/{pid}/limits', 32768).decode()
    require(same_process(before, process_stat(system.bytes(f'/proc/{pid}/stat', 16384).decode())), 'Node identity changed while reading')
    constraints = cgroup_constraints(group, system)
    require(constraints[0]['values']['memory.max'] == str(60 * 1024**3), 'Node MemoryMax is not enforced')
    return {'pid': pid, **before, 'argv': argv, 'exe': exe, 'scope': properties,
            'cgroup': group, 'constraints': constraints, 'status': selected, 'limits': limits}


def setup_confirmation(raw, state, spec, build):
    require(state == {'version': 1, 'chain_id': 1337, 'transactions': {}}, 'Public setup state is not empty')
    require(raw['chain_id'] == 1337 and raw['rpc_url'] == sup.RPC and raw['exit_code'] == 0, 'Setup route failed')
    argv = raw['setup_argv']
    require(argv == [build['binary']['path'], 'generate', '-s', str(spec), '-n', 0, '--seed', 99,
                     '--rpc', sup.RPC, '--setup-state-out', raw['setup_state_path']], 'Setup generator argv differs')
    sender = raw['sender_argv']
    require([str(x) for x in sender] == [build['bench_binary']['path'], 'send', '--rpc-url',
            'http://127.0.0.1:8545,http://127.0.0.1:8645', '--tps', '50000', '--max-concurrent', '100',
            '--retries', '0', '--scrape-interval-ms', '200', '--drain-timeout', '0'], 'Setup sender control differs')
    text = re.sub(r'\x1b\[[0-9;]*m', '', raw['stdout'] + '\n' + raw['stderr'])
    require(len(text.encode()) <= 1024 * 1024, 'Setup log cap')
    require(not re.search(r'(?i)\b(error|failed|panic|panicked|warn)\b(?![=])', text), 'Setup diagnostics require review')
    lines = text.splitlines()
    completion = [line for line in lines if 'Bench send completed; starting post-processing' in line]
    require(len(completion) == 1 and completion[0].endswith('Bench send completed; starting post-processing sent=0 success=0 failed=0'),
            'Missing unique empty setup completion')
    sender_start = [line for line in lines if 'bench::send: Starting send ' in line]
    require(len(sender_start) == 1, 'Missing unique setup sender start')
    for key, value in (('skip_setup', 'false'), ('tps', '50000'), ('max_pending', '50000'), ('retries', '"0"')):
        require(re.findall(r'\b' + key + r'=([^\s]+)', sender_start[0]) == [value], 'Setup sender start differs: ' + key)
    require(lines.index(sender_start[0]) < lines.index(completion[0]), 'Setup sender ordering')
    expected = ['starting transaction generation: output=stdout count=Some(0) duration=None signing_workers=2',
                'starting workload generation: count=Some(0) duration=None signing_workers=2']
    for prefix, marker in zip(('starting transaction generation:', 'starting workload generation:'), expected):
        require([line for line in lines if line.startswith(prefix)] == [marker], 'Setup generator marker differs')
    workload_end = [line for line in lines if line.startswith('workload generation completed:')]
    generation_end = [line for line in lines if line.startswith('transaction generation completed:')]
    require(len(workload_end) == len(generation_end) == 1, 'Missing unique generator completion')
    pattern = r'([0-9]+(?:\.[0-9]+)?(?:s|ms|µs|ns))'
    work = re.fullmatch(r'workload generation completed: prepared=0 elapsed=' + pattern, workload_end[0])
    total = re.fullmatch(r'transaction generation completed: elapsed=' + pattern, generation_end[0])
    require(work and total, 'Malformed/nonempty setup completion')
    require(sup.duration_ns(work[1]) <= sup.duration_ns(total[1]), 'Setup duration ordering')
    require(lines.index(expected[0]) < lines.index(expected[1]) < lines.index(workload_end[0]) < lines.index(generation_end[0]), 'Generator ordering')
    require(not any(marker in text for marker in ('gas sample:', 'setup_txs=', 'starting setup generation:',
            'Setup transaction', 'Skipped setup transactions', 'Waiting for setup transactions')), 'Setup/workload boundary differs')
    return {'kind': 'empty_stock_public_mix_setup', 'sender_counts': {'sent': 0, 'success': 0, 'failed': 0},
            'scope': 'Fresh zero-count normal pipeline and empty setup-state; no receipts are fabricated.'}


def exclusivity_attestation(exclusive, context, lifecycle, started, run_id):
    require(exclusive.get('status') == 'workflow_attested' and exclusive.get('workflow_sha') == context['workflow_sha']
            and str(exclusive.get('run_id')) == run_id and exclusive.get('run_token') == lifecycle['run_token']
            and exclusive.get('other_owned_measurement_active') is False, 'Missing explicit workflow exclusivity attestation')
    require(type(exclusive.get('captured_realtime_ns')) is int and 0 < exclusive['captured_realtime_ns'] <= started,
            'Exclusivity attestation clock is unbound')
    return exclusive


def node_build_identity(node_build, context):
    require(node_build['shared_binary'] is False and len(node_build['arms']) == 1, 'Feature-only node build required')
    arm = node_build['arms'][0]
    require(arm['side'] == 'feature' and arm['resolved_ref'] == context['source_ref'] and arm['sha256'] == context['binary_sha256']
            and arm['path'] == context['binary'] and arm['profile'] == 'profiling'
            and arm['features'] == 'jemalloc,asm-keccak,keccak-cache-global,otlp'
            and arm['no_default_features'] is True and arm['requested_ref'] == context['source_ref']
            and arm['rustflags'] == '-C target-cpu=native -C force-frame-pointers=yes', 'Node build identity/control mismatch')
    return arm


def prepare(args, system):
    output = args.output.resolve(); folder = output.parent
    require(folder.is_dir() and not output.exists(), 'New context config required')
    context = sup.read_json(args.context.resolve()); started = time.time_ns()
    require(type(context.get('captured_realtime_ns')) is int and 0 < context['captured_realtime_ns'] <= started,
            'Node context clock is unbound')
    require(context['mode'] == 'producer-isolation' and context['phase'] == 'feature-1' and context['tracing_otlp_enabled'] is True,
            'Wrong node context/mode')
    for key in ('workflow_sha', 'source_ref'): require(re.fullmatch('[0-9a-f]{40}', context[key]), 'Source not pinned')
    repository = Path(command(system, ['git', 'rev-parse', '--show-toplevel']).strip()).resolve()
    context['repository'] = str(repository)
    require(command(system, ['git', '-C', str(repository), 'rev-parse', 'HEAD']).strip() == context['workflow_sha'], 'Workflow checkout differs')
    build_path = Path(context['txgen_build_manifest']); build = sup.read_json(build_path)
    require(build['source_commit'] == TXGEN and build['status'] == 'verified' and build['source_clean'] is True, 'Missing verified stock build')
    verified(build['binary'], 512 * 1024**2); verified(build['bench_binary'], 512 * 1024**2)
    node_build = sup.read_json(Path(context['node_build_manifest']))
    node_build_identity(node_build, context)
    require(file_binding(context['binary'], 512 * 1024**2)['sha256'] == context['binary_sha256'], 'Node binary changed')
    spec = args.spec.resolve(); require(spec == repository / SPEC_FILES[0], 'Require exact static public-mix path')
    spec_files = []
    for relative in SPEC_FILES:
        path = pinned_file(repository, PRESET, relative, system)
        spec_files.append(file_binding(path))
    environment = {key: os.environ[key] for key in sup.ALLOWED_ENV if key in os.environ}
    environment['LC_ALL'] = 'C'
    require(environment.get('TXGEN_ACCOUNTS') == '1000', 'Account environment differs')
    end = (100000 * 1024 * 1024 - 4 * (40 + 64)) // 64 // 4
    require(environment.get('TXGEN_EXISTING_RECIPIENTS_START') == '10000' and
            environment.get('TXGEN_EXISTING_RECIPIENTS_END') == str(end), 'State-bloat recipient range differs')
    require(json.loads(environment['TXGEN_TIP20_TOKENS']) == [f'0x20c000000000000000000000{i:016x}' for i in range(4)], 'Token environment differs')
    bundle = save(folder / 'spec-bundle.json', {'schema_version': 1, 'status': 'verified', 'preset': 'public-mix', 'source_commit': PRESET,
        'gas_weights': sup.CONTROLS['gas_weights'], 'entry': spec_files[0], 'dependencies': spec_files[1:],
        'environment': {k: v for k, v in environment.items() if k.startswith('TXGEN_')}})
    setup_state = args.setup_state.resolve(); raw_setup = sup.read_json(args.setup_evidence.resolve())
    raw_setup['setup_state_path'] = str(setup_state)
    setup_info = setup_confirmation(raw_setup, sup.read_json(setup_state), spec, build)
    receipt = save(folder / 'empty-setup-evidence.json', {**setup_info, 'pipeline_evidence': file_binding(args.setup_evidence.resolve())})
    setup = save(folder / 'confirmed-setup.json', {'schema_version': 1, 'status': 'confirmed', 'chain_id': 1337, 'rpc_url': sup.RPC,
        'spec_bundle_sha256': bundle['sha256'], 'setup_state': file_binding(setup_state), 'receipt_evidence': receipt})
    lifecycle = validate_lifecycle(sup.read_json(Path(context['lifecycle_config'])))
    require(lifecycle['node_units'] == [context[r]['scope'] for r in 'ab'], 'Node lifecycle scopes differ')
    own_group = unified_cgroup(system.bytes('/proc/self/cgroup', 16384).decode())
    require(own_group == '/system.slice/' + lifecycle['control_unit'], 'Context not in declared control scope')
    genesis_path = Path(context['genesis']); genesis = sup.read_json(genesis_path)
    require(genesis['config']['chainId'] == 1337 and genesis['config']['t14Time'] == 0 and
            genesis['config']['generalGasLimit'] == 1500000000 and int(genesis['gasLimit'], 16) == 1000000000000,
            'Synthesized T14 genesis controls differ')
    require(all(value == (0 if int(match[1]) < 14 or key == 't14Time' else 9223372036854775807)
            for key, value in genesis['config'].items() if (match := re.fullmatch(r't([0-9]+)[a-z]?Time', key))),
            'Unexpected Tempo hardfork activation')
    nodes = {}; rpc = {}; snapshots = {}
    for role in 'ab':
        node = context[role]
        require(node['rpc_url'] == ('http://127.0.0.1:8545' if role == 'a' else 'http://127.0.0.1:8645'), 'RPC endpoint differs')
        nodes[role] = node_identity(role, node, context, lifecycle, system)
        state_raw = system.bytes(node['snapshot_state']); marker_raw = system.bytes(node['snapshot_marker'])
        state = json.loads(state_raw); marker = json.loads(marker_raw)
        require(state['mount_point'] == f'/reth-bench-{role}', 'Snapshot mount differs')
        require(marker['bloat_mib'] == 100000 and marker['state_hardfork'] == 'T14'
                and str(marker['gas_limit']) == '1000000000000' and str(marker['general_gas_limit']) == '1500000000',
                'Restored snapshot marker controls differ')
        snapshots[role] = {'state_path': node['snapshot_state'], 'state_sha256': hashlib.sha256(state_raw).hexdigest(), 'state': state,
            'marker_path': node['snapshot_marker'], 'marker_sha256': hashlib.sha256(marker_raw).hexdigest(), 'marker': marker,
            'genesis_file': system.snapshot_genesis(node['datadir'] + '/.bench-meta/genesis.json')}
        url = node['rpc_url']
        require(system.rpc(url, 'eth_chainId', []) == '0x539' and system.rpc(url, 'eth_syncing', []) is False, 'Node not ready on expected chain')
        initial = system.rpc(url, 'eth_getBlockByNumber', ['0x0', False]); latest = system.rpc(url, 'eth_getBlockByNumber', ['latest', False])
        require(int(latest['number'], 16) > 0 and re.fullmatch('0x[0-9a-f]{64}', initial['hash']), 'Missing live genesis/head')
        rpc[role] = {'genesis': initial['hash'], 'head': {k: latest[k] for k in ('number', 'hash', 'parentHash', 'stateRoot')},
                     'observed_realtime_ns': time.time_ns()}
        require(same_process(nodes[role], process_stat(system.bytes(f'/proc/{nodes[role]["pid"]}/stat', 16384).decode())),
                'Node identity changed during health checks')
    require(rpc['a']['genesis'] == rpc['b']['genesis'], 'Peer genesis differs')
    require(snapshots['a']['state']['dm_era_name'] != snapshots['b']['state']['dm_era_name'], 'Snapshot devices are shared')
    node_evidence = save(folder / 'nodes.json', {'nodes': nodes, 'rpc': rpc, 'snapshots': snapshots,
        'node_context': file_binding(args.context.resolve()), 'build_manifest': file_binding(context['node_build_manifest']),
        'genesis_file': file_binding(genesis_path), 'lifecycle': file_binding(context['lifecycle_config']),
        'source_ref': context['source_ref'], 'started_realtime_ns': started, 'finished_realtime_ns': time.time_ns()})
    host = {'phase': 'context_prepare', 'wrapper_resource_operation': 'bash: ulimit -Sn unlimited',
        'uname': list(platform.uname()), 'uid': os.getuid(), 'gid': os.getgid(), 'groups': os.getgroups(),
        'affinity': sorted(os.sched_getaffinity(0)), 'nofile': list(resource.getrlimit(resource.RLIMIT_NOFILE)),
        'self_limits': system.bytes('/proc/self/limits', 32768).decode(), 'cgroup': own_group,
        'constraints': cgroup_constraints(own_group, system), 'boot_id': system.bytes('/proc/sys/kernel/random/boot_id', 128).decode().strip(),
        'cpu_topology': json.loads(command(system, ['lscpu', '--json'])), 'meminfo': system.bytes('/proc/meminfo', 32768).decode(),
        'cpu_governors': governor_observation(system),
        'runner_name': os.environ.get('RUNNER_NAME', ''), 'clock_monotonic_ns': time.monotonic_ns(), 'clock_realtime_ns': time.time_ns(),
        'scope': 'Observed control-process identity, affinity, limits and cgroup ancestry; no unchanged-placement or producer-NOFILE equivalence claim.'}
    host_evidence = save(folder / 'host.json', host)
    exclusivity = context['measurement_exclusivity_evidence']; verified(exclusivity)
    exclusive = sup.read_json(Path(exclusivity['path']))
    exclusivity_attestation(exclusive, context, lifecycle, started, os.environ.get('GITHUB_RUN_ID'))
    attempt = lifecycle['run_token']
    workflow = save(folder / 'workflow-context.json', {'schema_version': 1, 'status': 'verified', 'run_id': os.environ['GITHUB_RUN_ID'],
        'workflow_sha': context['workflow_sha'], 'attempt_id': attempt, 'responsibility': 'workflow_verified_before_launch',
        'host_evidence': host_evidence, 'node_evidence': node_evidence, 'measurement_exclusivity_evidence': exclusivity,
        'source_files': [file_binding(Path(module.__file__).resolve()) for module in (sup, lifecycle_module)] +
                        [file_binding(Path(__file__).resolve())]})
    wc_path = Path(shutil.which('wc') or '').resolve(); wc, _wc_build_id = elf_info(wc_path, system)
    version = command(system, [str(wc_path), '--version']); require(version.startswith('wc (GNU coreutils) '), 'Not GNU wc')
    with (folder / 'wc-version.txt').open('x') as sink: sink.write(version)
    wc_binding = save(folder / 'wc-provenance.json', {'schema_version': 1, 'status': 'verified', 'implementation': 'GNU coreutils wc',
        'binary': wc, 'version_evidence': file_binding(folder / 'wc-version.txt')})
    config = {'schema_version': 1, 'attempt_id': attempt, 'controls': sup.CONTROLS, 'publication': {'e2e_series': False, 'slack': False},
        'rpc_url': sup.RPC, 'bindings': {'txgen_build': file_binding(build_path), 'wc_provenance': wc_binding, 'spec_bundle': bundle,
            'setup_confirmation': setup, 'workflow_context': workflow},
        'producer_argv': [build['binary']['path'], 'generate', '-s', str(spec), '--duration', '60s', '--seed', '99', '--rpc', sup.RPC,
                          '--gas-weighted-mix', '--setup-state-in', str(setup_state)],
        'consumer_argv': [wc['path'], '-l', '-c'], 'environment': environment}
    save(output, config)
    sup.validate_config(output)
    return config


def main():
    parser = argparse.ArgumentParser(description=__doc__); commands = parser.add_subparsers(dest='action', required=True)
    install = commands.add_parser('build')
    for key in ('source-checkout', 'txgen-bin', 'bench-bin', 'install-record', 'output'): install.add_argument('--' + key, type=Path, required=True)
    current = commands.add_parser('prepare')
    for key in ('context', 'spec', 'setup-state', 'setup-evidence', 'output'): current.add_argument('--' + key, type=Path, required=True)
    args = parser.parse_args()
    value = build(args, System()) if args.action == 'build' else prepare(args, System())
    print(json.dumps({'status': value.get('status', 'prepared'), 'output': str(args.output)}))


if __name__ == '__main__': main()
