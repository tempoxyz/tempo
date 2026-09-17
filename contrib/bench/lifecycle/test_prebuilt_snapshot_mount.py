"""Execute production Nu preflight with command doubles; never mount a filesystem."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[3]
SOURCE = (ROOT / 'bench-e2e.nu').read_text()


def function(name):
    return 'def ' + name + ' ' + SOURCE.split('def ' + name + ' ', 1)[1].split('\ndef ', 1)[0]


@unittest.skipUnless(shutil.which('nu'), 'Nu required')
class ExistingSnapshotMount(unittest.TestCase):
    def run_case(self, mounted=(False, False), actual=(32, 32), *, force=False,
                 init=False, fail='', ready=True, omit=False, wrong_mount=False):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for side, state in zip(('a', 'b'), mounted):
                value = {'mount_point': '/mount-' + side, 'is_mounted': state}
                if omit and side == 'b': value.pop('is_mounted')
                if wrong_mount and side == 'b': value['mount_point'] = '/foreign'
                (root / (side + '.json')).write_text(json.dumps(value))
            mountpoint = root / 'mountpoint'
            mountpoint.write_text('#!/usr/bin/env python3\nimport os,sys,json\nsys.exit(json.loads(os.environ["MOUNT_CODES"])[0 if sys.argv[-1]=="/mount-a" else 1])\n')
            mountpoint.chmod(0o755)
            sudo = root / 'sudo'
            sudo.write_text('''#!/usr/bin/env python3
import os,sys,json
from pathlib import Path
assert Path('.bench-snapshot-dirty').is_file()
assert sys.argv[1:] in [['schelk','--state-path','a.json','mount'], ['schelk','--state-path','b.json','mount']]
with open('calls','a') as stream: stream.write(json.dumps(sys.argv[1:])+'\\n')
print('PRIVATE_MOUNT_OUTPUT')
print('PRIVATE_MOUNT_ERROR',file=sys.stderr)
sys.exit(1 if sys.argv[-2] == os.environ.get('FAIL_SIDE') else 0)
''')
            sudo.chmod(0o755)
            prebuilt = (ROOT / 'contrib/bench/lifecycle/prebuilt.nu').read_text()
            helpers = '\n'.join(function(n) for n in ('prebuilt-mount-existing-snapshots',
                'e2e-snapshot-required-files', 'e2e-snapshot-missing-files',
                'e2e-snapshot-ready', 'e2e-snapshots-ready'))
            if ready:
                for side in ('a', 'b'):
                    for name in ('meta/genesis.json','meta/trusted-peers.txt','meta/marker.json',
                                 'signing.key','signing.share','enode.key','enode.identity','db','static_files'):
                        p = root / ('db-' + side) / name
                        p.parent.mkdir(parents=True, exist_ok=True)
                        p.touch()
            # The exact production callsite, ending before later cleanup/restore.
            admission = SOURCE.split('    if $prebuilt {\n        prebuilt-mount-existing-snapshots', 1)[1].split('\n    if ($env.BENCH_RUN_CLEANUP?', 1)[0]
            script = '''
const E2E_A_STATE_PATH = "a.json"
const E2E_B_STATE_PATH = "b.json"
const E2E_A_MOUNT = "/mount-a"
const E2E_B_MOUNT = "/mount-b"
const BENCH_META_SUBDIR = "meta"
def has-schelk [] { true }
def schelk-state [path: string] { open $path }
let prebuilt = true
let a_db = "db-a"
let b_db = "db-b"
''' + f'let force_bloat = {str(force).lower()}\nlet init_only = {str(init).lower()}\n'
            script += '\n' + prebuilt + '\n' + helpers
            script += '\nif $prebuilt {\n prebuilt-mount-existing-snapshots' + admission + '\nprint "ADMITTED"\n'
            result = subprocess.run(['nu', '--no-config-file', '-c', script], cwd=root,
                env={**os.environ, 'PATH': str(root)+os.pathsep+os.environ['PATH'],
                     'MOUNT_CODES': json.dumps(actual), 'FAIL_SIDE': fail},
                text=True, capture_output=True)
            calls = [json.loads(line) for line in (root/'calls').read_text().splitlines()] if (root/'calls').exists() else []
            return result, calls, (root/'.bench-snapshot-dirty').exists()

    def test_mounts_only_both_existing_unmounted_scratch_volumes(self):
        result, calls, dirty = self.run_case()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual([c[-2] for c in calls], ['a.json', 'b.json'])
        self.assertTrue(dirty)
        self.assertNotIn('PRIVATE_', result.stdout + result.stderr)

    def test_mounted_volumes_are_left_alone_and_mixed_mounts_only_one(self):
        for state, actual, expected in [((True, True), (0, 0), []), ((True, False), (0, 32), ['b.json'])]:
            result, calls, dirty = self.run_case(state, actual)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual([c[-2] for c in calls], expected)
            self.assertEqual(dirty, bool(expected))

    def test_both_sides_validate_before_mutation(self):
        cases = [dict(actual=(32,0)), dict(mounted=(False,True)), dict(actual=(32,1)),
                 dict(mounted=(False,0)), dict(omit=True), dict(wrong_mount=True)]
        for case in cases:
            with self.subTest(case=case):
                result, calls, dirty = self.run_case(**case)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(calls, [])
                self.assertFalse(dirty)

    def test_force_and_init_rejected_before_mount(self):
        for case in [dict(force=True), dict(init=True)]:
            result, calls, dirty = self.run_case(**case)
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(calls, [])
            self.assertFalse(dirty)

    def test_mount_failure_is_closed_and_partial_failure_remains_dirty(self):
        result, calls, dirty = self.run_case(fail='b.json')
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(len(calls), 2)
        self.assertTrue(dirty)
        self.assertIn('Prebuilt existing snapshot mount failed', result.stderr)
        self.assertNotIn('PRIVATE_', result.stdout + result.stderr)

    def test_missing_snapshot_still_rejects_after_mount_before_restore(self):
        result, calls, dirty = self.run_case(ready=False)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(len(calls), 2)
        self.assertTrue(dirty)
        self.assertNotIn('ADMITTED', result.stdout)
        self.assertIn('local generation is forbidden', result.stderr)

    def test_systemd_tmpdir_has_explicit_value(self):
        with tempfile.TemporaryDirectory() as directory:
            stub = Path(directory) / 'systemd-run'; stub.touch(); stub.chmod(0o755)
            result = subprocess.run(['nu','--no-config-file','-c',function('systemd-scope-command') + '\nsystemd-scope-command unit "0-1" "" "true" | to json'],
                env={**os.environ, 'PATH':directory+os.pathsep+os.environ['PATH'], 'TMPDIR':directory,
                     'BENCH_RUN_CLEANUP':'true','TEMPO_TELEMETRY_URL':'https://telemetry.invalid',
                     'OTEL_EXPORTER_OTLP_TRACES_ENDPOINT':''}, text=True,capture_output=True)
            self.assertEqual(result.returncode,0,result.stderr)
            args=json.loads(result.stdout)
            self.assertIn('--setenv=TMPDIR='+directory,args)
            self.assertNotIn('--setenv=TMPDIR',args)
            self.assertIn('--setenv=TEMPO_TELEMETRY_URL',args)
            self.assertIn('--preserve-env=TMPDIR,TEMPO_TELEMETRY_URL',args)


if __name__ == '__main__': unittest.main()
