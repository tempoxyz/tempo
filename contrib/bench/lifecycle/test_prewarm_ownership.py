"""Execute the production pre-load ownership/admission block without validators."""
import io
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import tempfile
import unittest
from unittest.mock import patch
from prewarm import admission

ROOT = Path(__file__).resolve().parents[3]
HEADER = dict(type='header', schema=1, clock='shared_monotonic_relative_ns',
              detail='milestones', prewarm_cpu='leaf_v1')


def admission_block(source):
    return source.split('    if $phase_exit == 0 and not (e2e-wait-for-chain-advance $b_rpc 300) { $phase_exit = 1 }', 1)[1].split('    let tracy_output', 1)[0]


def ownership_helper(source):
    return 'def chown-to-current-user '+source.split('def chown-to-current-user ', 1)[1].split('\ndef rpc-block-number', 1)[0]


@unittest.skipUnless(shutil.which('nu'), 'Nushell required')
class PrewarmOwnership(unittest.TestCase):
    def execute(self, directory, helper, *, phase_exit=0):
        source = (ROOT/'bench-e2e.nu').read_text()
        command = (helper+'\nlet ctx = {lifecycle: true, lifecycle_prewarm_cpu: "compare", lifecycle_process_cpu: "disabled"}; '
                   +'let lifecycle_dir = '+json.dumps(str(directory))+'; '
                   +'let process_cpu_config = {expected: "disabled"}; let prewarm_config = {expected: "leaf_v1"}; '
                   +f'mut phase_exit = {phase_exit}; '+admission_block(source)
                   +'\nprint $"phase_exit=($phase_exit)"')
        return subprocess.run(['nu', '-c', command], cwd=ROOT, text=True, capture_output=True)

    def test_handoff_precedes_actual_admission_and_preserves_failed_readiness(self):
        with tempfile.TemporaryDirectory() as directory:
            paths = [Path(directory)/name for name in ('a.jsonl', 'b.jsonl')]
            # Make the valid header visible only at handoff. A later handoff fails.
            helper = ('def chown-to-current-user [path: string] { '
                      +f'let header = {json.dumps(json.dumps(HEADER)+chr(10))}; '
                      +'$header | save --raw ($path | path join "a.jsonl"); '
                      +'$header | save --raw ($path | path join "b.jsonl") }')
            result = self.execute(directory, helper)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stdout.strip(), 'phase_exit=0')
            source = (ROOT/'bench-e2e.nu').read_text()
            self.assertEqual(source.count('chown-to-current-user $lifecycle_dir'), 1)
            self.assertIn('chown-to-current-user $ctx.results_dir', source)
            for path in paths:
                path.unlink()
            result = self.execute(directory, helper, phase_exit=1)
            self.assertEqual(result.stdout.strip(), 'phase_exit=1')
            self.assertFalse(any(path.exists() for path in paths))

    def test_cli_oserror_uses_only_closed_failure(self):
        # Reading a directory is an OSError even when this test runs as root.
        with tempfile.TemporaryDirectory(prefix='private-sentinel-') as directory:
            result = subprocess.run(['python3', 'contrib/bench/lifecycle/prewarm.py',
                                     '--expected', 'leaf_v1', directory, directory],
                                    cwd=ROOT, text=True, capture_output=True)
            self.assertEqual(result.returncode, 1)
            self.assertEqual(result.stdout, '')
            self.assertEqual(result.stderr, 'prewarm_cpu_admission_failed\n')

    def test_missing_files_retry_but_permission_errors_fail_immediately(self):
        streams = [FileNotFoundError(), *[io.StringIO(json.dumps(HEADER)+'\n') for _ in range(3)]]
        with patch('pathlib.Path.open', side_effect=streams), patch('time.sleep') as sleep:
            self.assertTrue(admission(['a', 'b'], 'leaf_v1', timeout=10))
            sleep.assert_called_once_with(.05)
        with patch('pathlib.Path.open', side_effect=PermissionError('private-sentinel')), patch('time.sleep') as sleep:
            self.assertFalse(admission(['a', 'b'], 'leaf_v1', timeout=10))
            sleep.assert_not_called()

    @unittest.skipUnless(os.environ.get('TEMPO_TEST_ROOT_CAPTURE_OWNERSHIP') == '1',
                         'opt-in owned root-file permission fixture')
    def test_root_0600_capture_handoff_before_first_reader(self):
        if os.geteuid() == 0:
            self.skipTest('requires an unprivileged reader')
        subprocess.run(['sudo', '-n', 'true'], check=True, capture_output=True)
        with tempfile.TemporaryDirectory() as directory:
            paths = [Path(directory)/name for name in ('a.jsonl', 'b.jsonl')]
            script = ('import os,sys; '
                      'fd=os.open(sys.argv[1],os.O_CREAT|os.O_EXCL|os.O_WRONLY,0o600); '
                      'os.write(fd,sys.argv[2].encode()); os.close(fd)')
            for path in paths:
                subprocess.run(['sudo', '-n', '/usr/bin/python3', '-c', script,
                                str(path), json.dumps(HEADER)+'\n'], check=True, capture_output=True)
                self.assertEqual(path.stat().st_uid, 0)
                self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
                with self.assertRaises(PermissionError):
                    path.read_bytes()
            before = subprocess.run(['python3', 'contrib/bench/lifecycle/prewarm.py',
                                     '--expected', 'leaf_v1', *map(str, paths)],
                                    cwd=ROOT, text=True, capture_output=True)
            self.assertEqual(before.returncode, 1)
            self.assertEqual(before.stderr, 'prewarm_cpu_admission_failed\n')
            self.assertEqual(before.stdout, '')
            result = self.execute(directory, ownership_helper((ROOT/'bench-e2e.nu').read_text()))
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stdout.strip(), 'phase_exit=0')
            for path in paths:
                self.assertEqual(path.stat().st_uid, os.getuid())
                self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
                self.assertEqual(json.loads(path.read_text()), HEADER)


if __name__ == '__main__':
    unittest.main()
