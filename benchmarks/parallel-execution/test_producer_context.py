"""Fake-input tests only; root runs with the selected supervisor/lifecycle on PYTHONPATH."""
import copy
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import producer_context as c


RUSTC = 'rustc 1.98.1 (example)\nbinary: rustc\nhost: x86_64-unknown-linux-gnu\nrelease: 1.98.1'


def packages():
    return {'installs': {f'{package} 0.1.0 (git+{c.URL}?rev={c.TXGEN}#{c.TXGEN})': {
        'version_req': None, 'bins': [binary], 'features': [], 'all_features': False,
        'no_default_features': False, 'profile': 'release', 'target': 'x86_64-unknown-linux-gnu',
        'rustc': RUSTC + '\n'} for package, binary in [('txgen-tempo', 'txgen-tempo'), ('bench-cli', 'bench')]}}


def setup_fixture():
    build = {'binary': {'path': '/tools/txgen-tempo'}, 'bench_binary': {'path': '/tools/bench'}}
    spec, state_path = Path('/source/contrib/bench/txgen/presets/public-mix.yml'), '/results/report.setup.json'
    raw = {'chain_id': 1337, 'rpc_url': c.sup.RPC, 'exit_code': 0, 'setup_state_path': state_path,
        'setup_argv': ['/tools/txgen-tempo', 'generate', '-s', str(spec), '-n', 0, '--seed', 99,
                       '--rpc', c.sup.RPC, '--setup-state-out', state_path],
        'sender_argv': ['/tools/bench', 'send', '--rpc-url', 'http://127.0.0.1:8545,http://127.0.0.1:8645',
                        '--tps', 50000, '--max-concurrent', 100, '--retries', 0, '--scrape-interval-ms', 200,
                        '--drain-timeout', 0],
        'stdout': '2026-10-06T12:00:00.000000Z INFO bench::send: Starting send input="stdin" rpc_urls=[http://127.0.0.1:8545/, http://127.0.0.1:8645/] tps=50000 max_pending=50000 skip_setup=false collect_latencies=false collect_receipt_metrics=false retries="0"\n'
                  '2026-10-06T12:00:01.000000Z INFO bench::send: Bench send completed; starting post-processing sent=0 success=0 failed=0\n',
        'stderr': 'starting transaction generation: output=stdout count=Some(0) duration=None signing_workers=2\n'
                  'starting nonce prefetch\nnonce prefetch completed: elapsed=10ms\n'
                  'starting workload generation: count=Some(0) duration=None signing_workers=2\n'
                  'workload generation completed: prepared=0 elapsed=1.5µs\n'
                  'transaction generation completed: elapsed=10.1ms\n'}
    return raw, {'version': 1, 'chain_id': 1337, 'transactions': {}}, spec, build


def stat(state='S', start=123):
    # /proc fields after comm: state,ppid,pgrp,session,...,starttime(field22).
    fields = [state, '1', '400', '400'] + ['0'] * 15 + [str(start)] + ['0'] * 4
    return ('400 (tempo node) ' + ' '.join(fields)).encode()


class FakeNode:
    def __init__(self):
        self.token = '1' * 32
        self.unit = f'tempo-producer-{self.token}-a.scope'
        self.group = '/system.slice/' + self.unit
        self.lifecycle = {'node_units': [self.unit, f'tempo-producer-{self.token}-b.scope'],
                          'unit_description': 'tempo-producer:' + self.token}
        args = ['node', '--datadir', '/reth-bench-a/tempo_e2e_100000mb', '--chain', '.localnet/genesis.json']
        for key, value in c.NODE_FLAGS.items(): args.extend([key, value])
        args.extend(['--tracing-otlp', 'sha256:' + hashlib.sha256(b'https://telemetry.invalid/token').hexdigest()])
        self.node = {'scope': self.unit, 'datadir': '/reth-bench-a/tempo_e2e_100000mb',
                     'snapshot_state': '/var/lib/schelk/a.json',
                     'snapshot_marker': '/reth-bench-a/tempo_e2e_100000mb/.bench-meta/marker.json',
                     'cpus': '0-7,16-23', 'memory': '60G', 'args': args}
        self.context = {'binary': '/source/.bench-worktrees/feature/target/profiling/tempo',
                        'binary_sha256': 'a' * 64, 'repository': '/source', 'genesis': '/source/.localnet/genesis.json'}
        self.argv = ['.bench-worktrees/feature/target/profiling/tempo', *args]
        self.argv[-1] = 'https://telemetry.invalid/token'
        self.reads = {
            '/sys/fs/cgroup' + self.group + '/cgroup.procs': b'400\n401\n',
            '/sys/fs/cgroup' + self.group + '/memory.max': str(60*1024**3).encode(),
            '/proc/400/cmdline': ('\0'.join(self.argv) + '\0').encode(),
            '/proc/401/cmdline': b'bash\0-lc\0wrapper\0',
            '/proc/400/cgroup': ('0::' + self.group + '\n').encode(),
            '/proc/400/status': b'Uid:\t0 0 0 0\nGid:\t0 0 0 0\nGroups:\t0\nCpus_allowed_list:\t0-7,16-23\nMems_allowed_list:\t0\nThreads:\t200\n',
            '/proc/400/limits': b'Max open files            1048576              1048576              files\n',
        }
        self.stats = [stat('S'), stat('R')]
        self.exe = {'path': self.context['binary'], 'sha256': 'a' * 64, 'bytes': 100}
        self.properties = {'LoadState': 'loaded', 'ActiveState': 'active', 'Description': self.lifecycle['unit_description'],
                           'ControlGroup': self.group, 'InvocationID': '2' * 32}

    def command(self, argv, timeout):
        if argv[:3] != ['systemctl', 'show', self.unit]: raise AssertionError(argv)
        return {'code': 0, 'stdout': '\n'.join(f'{k}={v}' for k, v in self.properties.items()), 'stderr': ''}

    def bytes(self, path, cap=1024*1024):
        path = str(path)
        if path == '/proc/400/stat': return self.stats.pop(0)
        if path in self.reads: return self.reads[path]
        if path.startswith('/sys/fs/cgroup/'): raise FileNotFoundError(path)
        raise AssertionError(path)

    def executable(self, pid):
        if pid != 400: raise AssertionError(pid)
        return self.exe

    def inspect(self):
        return c.node_identity('a', self.node, self.context, self.lifecycle, self)


class ContextTests(unittest.TestCase):
    def test_governors_record_actual_values_and_observation_bracket(self):
        paths = [f'/sys/devices/system/cpu/cpu{i}/cpufreq/scaling_governor' for i in (0, 8)]
        class Fake:
            def glob(self, pattern):
                if pattern != c.lifecycle_module.GOVERNORS: raise AssertionError(pattern)
                return paths
            def bytes(self, path, cap):
                if cap != 128: raise AssertionError(cap)
                return {paths[0]: b'performance\n', paths[1]: b'powersave\n'}[path]
        with patch.object(c.time, 'monotonic_ns', side_effect=[100, 150]), patch.object(c.time, 'time_ns', side_effect=[1000, 1050]):
            result = c.governor_observation(Fake())
        self.assertEqual(result['status'], 'observed')
        self.assertEqual(result['governors'], [{'path': paths[0], 'value': 'performance'}, {'path': paths[1], 'value': 'powersave'}])
        self.assertEqual([result['before_monotonic_ns'], result['after_monotonic_ns']], [100, 150])
        self.assertEqual([result['before_realtime_ns'], result['after_realtime_ns']], [1000, 1050])

    def test_governors_not_exposed_is_explicit(self):
        class Fake:
            def glob(self, _): return []
            def bytes(self, *_): raise AssertionError('No files to read')
        result = c.governor_observation(Fake())
        self.assertEqual(result['status'], 'not_exposed')
        self.assertEqual(result['governors'], [])

    def test_governor_enumeration_and_read_errors_are_not_absence(self):
        class Fake:
            def glob(self, _): return ['/sys/devices/system/cpu/cpu0/cpufreq/scaling_governor']
            def bytes(self, *_): raise PermissionError('denied')
        with self.assertRaises(PermissionError): c.governor_observation(Fake())
        with patch.object(Fake, 'glob', side_effect=OSError('enumeration failed')):
            with self.assertRaises(OSError): c.governor_observation(Fake())

    def test_governor_inventory_and_value_bounds(self):
        path = '/sys/devices/system/cpu/cpu0/cpufreq/scaling_governor'
        class Fake:
            def glob(self, _): return [path]
            def bytes(self, *_): return b'performance\n'
        for paths in ([path, path], ['/proc/self/environ'], [path] * (c.lifecycle_module.MAX_GOVERNORS + 1)):
            with patch.object(Fake, 'glob', return_value=paths), self.assertRaises(ValueError):
                c.governor_observation(Fake())
        with patch.object(Fake, 'bytes', return_value=b'not a governor\n'), self.assertRaises(ValueError):
            c.governor_observation(Fake())

    def test_install_requires_forced_exact_revision_complete_log_and_clock(self):
        source = Path('/source/txgen')
        item = {'schema_version':1, 'status':'completed', 'argv':list(c.INSTALL), 'exit_code':0,
                'log_complete':True,'started_realtime_ns':10,'finished_realtime_ns':20,'source_checkout':str(source),
                'unsupported_environment_names':[]}
        self.assertEqual(c.install_record(item, source, 30), item)
        changes = [('argv',[x for x in c.INSTALL if x != '--force']), ('exit_code',1), ('log_complete',False),
                   ('started_realtime_ns',20), ('finished_realtime_ns',31), ('source_checkout','/other'),
                   ('unsupported_environment_names',['CARGO_PROFILE_RELEASE_OPT_LEVEL'])]
        for key, value in changes:
            with self.subTest(key=key), self.assertRaises(ValueError): c.install_record({**item,key:value}, source,30)

    def test_real_cargo_metadata_trailing_newline(self):
        result = c.installed_packages(packages(), 'x86_64-unknown-linux-gnu', RUSTC)
        self.assertEqual(result['bench-cli']['bins'], ['bench'])

    def test_installed_metadata_rejects_source_compiler_and_build_variants(self):
        for field, value in [('target', 'aarch64-unknown-linux-gnu'), ('rustc', RUSTC.replace('1.98.1', '1.95.0')),
                             ('profile', 'debug'), ('features', ['unsafe-fast-path']), ('no_default_features', True)]:
            with self.subTest(field=field):
                data = packages(); next(iter(data['installs'].values()))[field] = value
                with self.assertRaises(ValueError): c.installed_packages(data, 'x86_64-unknown-linux-gnu', RUSTC)
        data = packages(); key = next(iter(data['installs'])); data['installs'][key.replace(c.TXGEN, '0'*40)] = data['installs'].pop(key)
        with self.assertRaises(ValueError): c.installed_packages(data, 'x86_64-unknown-linux-gnu', RUSTC)

    def test_cargo_configuration_covers_ancestors_and_detects_change(self):
        with tempfile.TemporaryDirectory() as raw:
            base = Path(raw); checkout = base/'source'; checkout.mkdir(); home = base/'cargo'; home.mkdir()
            cwd = base/'work'; cwd.mkdir()
            actual = home/'config.toml'; actual.write_text('[alias]\nx="check"\n')
            paths = {str(home/name) for name in ('config', 'config.toml')}
            for root in (cwd, checkout):
                for parent in (root, *root.parents):
                    paths.update(str(parent/'.cargo'/name) for name in ('config', 'config.toml'))
            rows = []
            for value in sorted(paths):
                path = Path(value); row = {'path': value, 'exists': path.exists()}
                if path.exists(): row.update(sha256=c.sup.digest(path), unsupported_sections=[])
                rows.append(row)
            evidence = {'schema_version': 1, 'cwd': str(cwd), 'cargo_home': str(home), 'source_checkout': str(checkout), 'searched': rows}
            before = base/'before.json'; before.write_text(json.dumps(evidence))
            evidence.update(before=c.file_binding(before), unsupported_environment_names=[])
            self.assertEqual(c.cargo_configuration(evidence, checkout), evidence)
            missing = copy.deepcopy(evidence); missing['searched'].pop()
            with self.assertRaises(ValueError): c.cargo_configuration(missing, checkout)
            actual.write_text('[build]\njobs=3\n')
            with self.assertRaises(ValueError): c.cargo_configuration(evidence, checkout)
            for row in evidence['searched']:
                if row['path'] == str(actual): row['sha256'] = c.sup.digest(actual)
            # Even an accurately hashed config cannot silently weaken release
            # optimization or introduce a target/compiler/environment override.
            with self.assertRaises(ValueError): c.cargo_configuration(evidence, checkout)

    def test_cargo_config_cannot_appear_after_install_even_if_harmless(self):
        with tempfile.TemporaryDirectory() as raw:
            base = Path(raw); source = base/'source'; source.mkdir(); home = base/'cargo'; home.mkdir()
            paths = {str(home/name) for name in ('config','config.toml')}
            for parent in (source,*source.parents): paths.update(str(parent/'.cargo'/name) for name in ('config','config.toml'))
            rows = [{'path':value,'exists':False} for value in sorted(paths)]
            before = base/'before.json'
            before.write_text(json.dumps({'schema_version':1,'cwd':str(source),'cargo_home':str(home),'searched':rows}))
            actual = home/'config.toml'; actual.write_text('[alias]\nx="check"\n')
            rows = [dict(row,exists=True,sha256=c.sup.digest(actual),unsupported_sections=[]) if row['path']==str(actual) else row for row in rows]
            evidence = {'schema_version':1,'cwd':str(source),'cargo_home':str(home),'source_checkout':str(source),
                        'searched':rows,'before':c.file_binding(before),'unsupported_environment_names':[]}
            with self.assertRaises(ValueError): c.cargo_configuration(evidence,source)

    def test_exact_empty_setup_source_shapes(self):
        raw, state, spec, build = setup_fixture()
        self.assertEqual(c.setup_confirmation(raw, state, spec, build)['sender_counts'], {'sent':0,'success':0,'failed':0})

    def test_otlp_node_feature_identity(self):
        context = {'source_ref':'a'*40,'binary_sha256':'b'*64,'binary':'/tools/tempo'}
        arm = {'side':'feature','resolved_ref':'a'*40,'requested_ref':'a'*40,'sha256':'b'*64,'path':'/tools/tempo',
               'profile':'profiling','features':'jemalloc,asm-keccak,keccak-cache-global,otlp',
               'no_default_features':True,'rustflags':'-C target-cpu=native -C force-frame-pointers=yes'}
        self.assertEqual(c.node_build_identity({'shared_binary':False,'arms':[arm]},context),arm)
        for key,value in [('features','jemalloc,asm-keccak,keccak-cache-global'), ('profile','release'),
                          ('no_default_features',False),('requested_ref','main')]:
            with self.subTest(key=key), self.assertRaises(ValueError):
                c.node_build_identity({'shared_binary':False,'arms':[{**arm,key:value}]},context)

    def test_setup_refuses_nonempty_receipts_or_failure(self):
        raw, state, spec, build = setup_fixture()
        state['transactions']['mint'] = {'hash': '0x'+'0'*64}
        with self.assertRaises(ValueError): c.setup_confirmation(raw, state, spec, build)
        raw, state, spec, build = setup_fixture(); raw['exit_code'] = 1
        with self.assertRaises(ValueError): c.setup_confirmation(raw, state, spec, build)

    def test_setup_refuses_misclassified_and_malformed_records(self):
        replacements = [('count=Some(0)', 'count=None'), ('signing_workers=2', 'signing_workers=4'),
                        ('prepared=0', 'prepared=1'), ('failed=0', 'failed=1'), ('skip_setup=false', 'skip_setup=true'),
                        ('tps=50000', 'tps=50000 tps=1'), ('max_pending=50000', 'max_pending=0'),
                        ('retries="0"', 'retries="forever"')]
        for old, new in replacements:
            with self.subTest(old=old):
                raw, state, spec, build = setup_fixture()
                raw = {**raw, 'stdout':raw['stdout'].replace(old,new), 'stderr':raw['stderr'].replace(old,new)}
                with self.assertRaises(ValueError): c.setup_confirmation(raw, state, spec, build)
        for extra in ('gas sample: item=Template("public_mint") block_gas=1 target_weight=5\n',
                      '2026-10-06 WARN bench::send: unusual\n', 'Waiting for setup transactions setup_txs=1\n',
                      'starting workload generation: count=Some(0) duration=None signing_workers=2\n',
                      '2026-10-06 INFO bench::send: Bench send completed; starting post-processing sent=1 success=1 failed=0\n'):
            with self.subTest(extra=extra):
                raw, state, spec, build = setup_fixture(); raw['stderr'] += extra
                with self.assertRaises(ValueError): c.setup_confirmation(raw, state, spec, build)

    def test_setup_refuses_added_sender_or_generator_overrides(self):
        for key, values in [('setup_argv', ['--defer-signing']), ('sender_argv', ['--skip-setup']), ('sender_argv', ['--max-pending', 0])]:
            raw, state, spec, build = setup_fixture(); raw[key] += values
            with self.assertRaises(ValueError): c.setup_confirmation(raw, state, spec, build)

    def test_node_accepts_relative_argv_and_normal_state_transition(self):
        system = FakeNode(); result = system.inspect()
        self.assertEqual(result['pid'], 400); self.assertEqual(result['argv'], c.telemetry_argv(system.argv))
        self.assertEqual(result['exe']['path'], system.context['binary'])
        self.assertNotIn('https://telemetry.invalid/token', str(result))

    def test_telemetry_redaction_preserves_option_shape_and_rejects_duplicates(self):
        for arguments in (['node','--tracing-otlp','secret'], ['node','--tracing-otlp=secret']):
            result = c.telemetry_argv(arguments)
            self.assertNotIn('secret', str(result))
            self.assertEqual(c.option(result,'--tracing-otlp'), 'sha256:'+hashlib.sha256(b'secret').hexdigest())
        for arguments in (['node'], ['node','--tracing-otlp'], ['node','--tracing-otlp='],
                          ['node','--tracing-otlp=one','--tracing-otlp=two']):
            with self.assertRaises(ValueError): c.telemetry_argv(arguments)

    def test_node_rejects_reused_pid_wrong_executable_scope_and_affinity(self):
        for change in ('pid', 'exe', 'cgroup', 'affinity', 'scope', 'args'):
            with self.subTest(change=change):
                system = FakeNode()
                if change == 'pid': system.stats[-1] = stat('R', 999)
                elif change == 'exe': system.exe['sha256'] = 'b'*64
                elif change == 'cgroup': system.reads['/proc/400/cgroup'] = b'0::/system.slice/other.scope\n'
                elif change == 'affinity': system.reads['/proc/400/status'] = system.reads['/proc/400/status'].replace(b'0-7,16-23', b'0-7')
                elif change == 'scope': system.properties['Description'] = 'unrelated'
                else: system.reads['/proc/400/cmdline'] = system.reads['/proc/400/cmdline'].replace(b'--execution.threads\x008', b'--execution.threads\x000')
                with self.assertRaises(ValueError): system.inspect()

    def test_node_refuses_two_matching_processes(self):
        system = FakeNode(); system.reads['/proc/401/cmdline'] = system.reads['/proc/400/cmdline']
        with self.assertRaises(ValueError): system.inspect()

    def test_privileged_fallback_is_narrow_and_only_permission_triggered(self):
        system = c.System()
        with patch('builtins.open', side_effect=PermissionError), patch.object(system, 'command', return_value={'code':0,'stdout':'400','stderr':''}) as child:
            self.assertEqual(system.bytes('/proc/400/stat'), b'400')
            self.assertEqual(child.call_args.args[0][:3], ['sudo','-n','python3'])
            for forbidden in ('/proc/400/environ', '/proc/self/environ', '/etc/shadow', '/var/lib/schelk/c.json'):
                with self.subTest(forbidden=forbidden), self.assertRaises(ValueError): system.bytes(forbidden)
            self.assertEqual(child.call_count, 1)
        with patch('builtins.open', side_effect=FileNotFoundError), patch.object(system, 'command') as child:
            with self.assertRaises(FileNotFoundError): system.bytes('/proc/400/stat')
            child.assert_not_called()

    def test_exclusivity_requires_exact_workflow_attempt_and_false_overlap(self):
        context = {'workflow_sha':'a'*40}; lifecycle = {'run_token':'b'*32}
        item = {'status':'workflow_attested','workflow_sha':'a'*40,'run_id':'123','run_token':'b'*32,
                'other_owned_measurement_active':False,'captured_realtime_ns':10}
        self.assertEqual(c.exclusivity_attestation(item, context, lifecycle, 20, '123'), item)
        for key, value in [('status','inferred_idle'), ('run_id','122'), ('run_token','c'*32),
                           ('other_owned_measurement_active',True), ('captured_realtime_ns',21)]:
            with self.subTest(key=key), self.assertRaises(ValueError):
                c.exclusivity_attestation({**item,key:value}, context, lifecycle,20,'123')

    def test_file_binding_detects_changed_bytes_and_symlink(self):
        with tempfile.TemporaryDirectory() as raw:
            path = Path(raw)/'record.json'; path.write_text('{}\n'); binding = c.file_binding(path)
            self.assertEqual(c.verified(binding), path)
            path.write_text('{"changed":true}\n')
            with self.assertRaises(ValueError): c.verified(binding)
            link = Path(raw)/'link'; link.symlink_to(path)
            with self.assertRaises(ValueError): c.file_binding(link)


if __name__ == '__main__': unittest.main()
