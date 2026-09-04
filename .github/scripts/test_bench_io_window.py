"""Read-only sampler fixtures; no live processes, devices, waits or network calls."""
import base64
import contextlib
import gzip
import importlib.util
import io
import json
import os
import pathlib
import shutil
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import patch

HERE = pathlib.Path(__file__).parent
spec = importlib.util.spec_from_file_location('sampler', HERE / 'bench_io_window.py')
sampler = importlib.util.module_from_spec(spec)
spec.loader.exec_module(sampler)


class SamplerTests(unittest.TestCase):
    def fixtures(self, path, bound=65536):
        if path.endswith('/cmdline'):
            return 'tempo\0--datadir\0/opt/tempo/schelk/data\0--key\0DO_NOT_EMIT\0'
        if path.endswith('/stat') and path.startswith('/proc/'):
            return '42 (tempo worker) ' + ' '.join(['S'] + ['0'] * 18 + ['123'])
        if path.endswith('/dev'):
            return '259:1'
        if path.endswith('/stat'):
            # Kernel's published whole-device example, including distinct flush fields.
            return '255999 814 12369153 47919 996858 81 36123056 426009 0 301795 580491 0 0 0 0 60605 106562'
        if path.endswith('/io') and '/pressure/' not in path:
            return 'rchar: 100\nwrite_bytes: 8192\ncancelled_write_bytes: 1024\nsecret: DO_NOT_EMIT\n'
        if path == '/proc/meminfo':
            return 'MemAvailable: 10240 kB\nDirty: 8192 kB\nWriteback: 2048 kB\n'
        if path == '/proc/vmstat':
            return 'nr_dirty 2048\nnr_writeback 512\npgmajfault 7\n'
        if '/pressure/' in path:
            return 'some avg10=1.25 avg60=2.50 avg300=0.00 total=1234567\nfull avg10=0.25 avg60=0.50 avg300=0.00 total=54321\n'
        raise AssertionError(path)

    def commands(self, args):
        if args[0] == 'systemctl':
            return '42'
        if args[0] == 'findmnt':
            return json.dumps({'filesystems': [{'source': '/dev/mapper/bench_era', 'fstype': 'ext4', 'maj:min': '253:0'}]})
        if args[0] == 'lsblk':
            leaf = {'kname': '/dev/nvme1n1', 'type': 'disk', 'maj:min': '259:1',
                    'size': 1900000000000, 'model': 'Amazon EC2 NVMe Instance Storage'}
            return json.dumps({'blockdevices': [{'kname': '/dev/dm-0', 'type': 'dm', 'children': [leaf, leaf]}]})
        raise AssertionError(args)

    def test_complete_kernel_counter_layout_and_privacy(self):
        clock = [0.0]
        def sleep(seconds):
            clock[0] += seconds
        with patch.object(sampler, 'read', self.fixtures), patch.object(sampler, 'command', self.commands), \
             patch.object(sampler.time, 'monotonic', lambda: clock[0]), patch.object(sampler.time, 'sleep', sleep):
            result = sampler.sample_window()
        self.assertEqual(result['state'], 'complete')
        self.assertEqual(len(result['devices']), 1)
        self.assertEqual(len(result['samples']), 25)
        self.assertEqual(result['samples'][-1]['elapsed_seconds'], 120)
        row = result['samples'][0]
        disk = dict(zip(result['columns']['disk_stat'], row['disk_stat']['nvme1n1']))
        self.assertEqual(disk['sectors_written_512'], 36123056)
        self.assertEqual(disk['flushes_completed'], 60605)
        self.assertEqual(disk['flush_ms'], 106562)
        self.assertEqual(row['io_pressure'][3], 1234567)
        self.assertEqual(row['io_pressure'][7], 54321)
        envelope = json.loads(sampler.encode(result))
        decoded = gzip.decompress(base64.b64decode(envelope['data']))
        self.assertEqual(json.loads(decoded), json.loads(json.dumps(result)))
        self.assertNotIn(b'DO_NOT_EMIT', decoded)
        self.assertLess(len(json.dumps(envelope)), 18000)

    def test_restart_mid_sample_stops_without_claiming_stability(self):
        with patch.object(sampler, 'identity', side_effect=[(42,123), (42,123), (42,123), (42,124)]), \
             patch.object(sampler, 'read', self.fixtures), patch.object(sampler, 'command', self.commands), \
             patch.object(sampler.time, 'sleep'):
            result = sampler.sample_window()
        self.assertEqual(result['state'], 'process_changed_or_unavailable')
        self.assertEqual(len(result['samples']), 1)
        self.assertFalse(result['samples'][0]['process_stable'])

    def test_missing_and_short_kernel_fields_remain_unavailable(self):
        errors = {}
        with patch.object(sampler, 'read', side_effect=FileNotFoundError):
            self.assertEqual(sampler.pressure('/missing', errors, 'pressure'), [None] * 8)
        self.assertEqual(errors, {'pressure': 'FileNotFoundError'})
        with patch.object(sampler, 'read', side_effect=['259:1', '1 2 3 4 5 6 7 8 9 10 11']):
            self.assertEqual(sampler.disk_stats({'name':'nvme1n1','major_minor':'259:1'}, {}), list(range(1,12)) + [None]*6)

    def test_workflow_rejects_wrong_scope_before_ssm(self):
        text = (HERE.parent / 'workflows/bench-inspect-io-window.yml').read_text()
        code = text.split("          python3 - <<'PY'\n", 1)[1].split('\n          PY', 1)[0]
        code = '\n'.join(line[10:] for line in code.splitlines())
        compile(code, 'workflow', 'exec')
        good_live = {'id':33884822499, 'status':'in_progress', 'path':'.github/workflows/bench-e2e-multi-region.yml', 'run_attempt':1}
        regions = ('us-east-1','us-west-2','eu-central-1','ap-southeast-1','ap-northeast-1')
        manifest = [{'index':i, 'instance_id':f'i-{i:017x}', 'region':regions[i%5]} for i in range(10)]
        cases = [('false', good_live, manifest), ('true', dict(good_live, status='completed'), manifest),
                 ('true', good_live, manifest[:-1]),
                 ('true', good_live, [dict(v, region='wrong') if v['index']==4 else v for v in manifest])]
        for confirmed, live, validators in cases:
            calls = []
            def check_output(args, **kwargs):
                calls.append(args)
                self.assertNotIn('ssm', args)
                return json.dumps(live if args[0]=='gh' else validators)
            with patch.dict(os.environ, {'TARGET_RUN_ID':'33884822499','LOAD_WINDOW_CONFIRMED':confirmed}), \
                 patch('subprocess.check_output', check_output), self.assertRaises(AssertionError):
                exec(code, {})
            self.assertTrue(all('ssm' not in call for call in calls))

    def test_workflow_decodes_exact_outputs_and_rejects_hash_mismatch(self):
        source = (HERE.parent / 'workflows/bench-inspect-io-window.yml').read_text()
        code = source.split("          python3 - <<'PY'\n", 1)[1].split('\n          PY', 1)[0]
        code = '\n'.join(line[10:] for line in code.splitlines())
        regions = ('us-east-1','us-west-2','eu-central-1','ap-southeast-1','ap-northeast-1')
        manifest = [{'index':i, 'instance_id':f'i-{i:017x}', 'region':regions[i%5]} for i in range(10)]
        live = {'id':33884822499, 'status':'in_progress', 'path':'.github/workflows/bench-e2e-multi-region.yml',
                'run_attempt':1, 'head_sha':'0'*40}
        benchmark = 'bench-e2e-multi-region-33884822499-1'
        for corrupt in (False, True):
            envelope = json.loads(sampler.encode({'state':'complete', 'samples':[]}))
            if corrupt:
                envelope['decoded_sha256'] = '0'*64
            invocations = []
            def check_output(args, **kwargs):
                if args[0] == 'gh':
                    return json.dumps(live)
                if args[1:3] == ['s3','cp']:
                    return json.dumps(manifest)
                if args[1:3] == ['s3api','get-object']:
                    pathlib.Path(args[-1]).write_text(json.dumps({'benchmark_id':benchmark,
                        'status':'running_feature','side':'feature','message':'SECRET_MUST_NOT_APPEAR'}))
                    return json.dumps({'LastModified':'2026-09-04T00:00:00Z'})
                self.assertEqual(args[1:3], ['ssm','send-command'])
                invocations.append(args)
                return json.dumps({'Command':{'CommandId':'fixture'}})
            def run(args, **kwargs):
                return SimpleNamespace(returncode=0,stdout=json.dumps({'Status':'Success','ResponseCode':0,
                    'StandardOutputContent':json.dumps(envelope)}),stderr='')
            previous = pathlib.Path.cwd()
            with tempfile.TemporaryDirectory() as directory:
                os.chdir(directory)
                try:
                    pathlib.Path('.github/scripts').mkdir(parents=True)
                    shutil.copyfile(HERE/'bench_io_window.py', '.github/scripts/bench_io_window.py')
                    with patch.dict(os.environ, {'TARGET_RUN_ID':'33884822499','LOAD_WINDOW_CONFIRMED':'true'}), \
                         patch('subprocess.check_output', check_output), patch('subprocess.run', run), \
                         contextlib.redirect_stdout(io.StringIO()):
                        if corrupt:
                            with self.assertRaises(AssertionError):
                                exec(code, {})
                        else:
                            exec(code, {})
                    self.assertEqual(len(invocations), 10)
                    rows = [json.loads(p.read_text()) for p in pathlib.Path('.').glob('inspection-io-node-*.json')]
                    self.assertEqual(len(rows), 10)
                    self.assertTrue(all(row['ssm_status']==('inspection_failed' if corrupt else 'Success') for row in rows))
                    for label in ('before','after'):
                        output = pathlib.Path(f'inspection-io-status-{label}.json').read_text()
                        self.assertNotIn('SECRET_MUST_NOT_APPEAR', output)
                        self.assertTrue(json.loads(output)['available'])
                finally:
                    os.chdir(previous)


if __name__ == '__main__':
    unittest.main()
