"""Execute the final Actions script against owned fixtures and a fake helper."""
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[3]


class CleanupWorkflow(unittest.TestCase):
    def test_startup_refuses_symlinked_snapshot_before_rm(self):
        import yaml
        source = yaml.safe_load((ROOT/'.github/workflows/bench-e2e.yml').read_text())
        job = next(j for j in source['jobs'].values() if 'steps' in j and
                   any(s.get('name') == 'Reset workspace directory' for s in j['steps']))
        step = next(s for s in job['steps'] if s.get('name') == 'Reset workspace directory')
        self.assertEqual(step['env']['CLEANUP_DIRECTORY'], '${{ steps.runner-cleanup.outputs.directory }}')
        prefix = step['run'].split('sudo -u actions-runner mkdir', 1)[0]
        with tempfile.TemporaryDirectory() as d:
            root = Path(d); external = root/'snapshot'; external.mkdir()
            workspace = external/'workspace'; workspace.mkdir()
            (workspace/'baseline').write_text('keep')
            (root/'alias').symlink_to(external, target_is_directory=True)
            helper = root/'helper'; helper.mkdir()
            (helper/'cleanup.py').write_bytes((ROOT/'contrib/bench/lifecycle/runner_cleanup.py').read_bytes())
            binary = root/'bin'; binary.mkdir()
            sudo = binary/'sudo'
            sudo.write_text('#!/bin/sh\nif [ "$1" = "-n" ]; then shift; exec "$@"; fi\nprintf "%s\\n" "$*" >> "$RESET_COMMANDS"\n')
            sudo.chmod(0o700)
            commands = root/'commands'
            env = {**os.environ, 'PATH':str(binary)+os.pathsep+os.environ['PATH'],
                   'CLEANUP_DIRECTORY':str(helper), 'RESET_COMMANDS':str(commands)}
            failed = subprocess.run(['bash','-c',prefix], env={**env,'GITHUB_WORKSPACE':str(root/'alias/workspace')}, capture_output=True)
            self.assertNotEqual(failed.returncode, 0)
            self.assertFalse(commands.exists(), 'rm must not run after a rejected guard')
            self.assertEqual((workspace/'baseline').read_text(), 'keep')
            accepted = subprocess.run(['bash','-c',prefix], env={**env,'GITHUB_WORKSPACE':str(workspace)}, capture_output=True)
            self.assertEqual(accepted.returncode, 0, accepted.stderr)
            self.assertEqual(commands.read_text().splitlines(), ['rm -rf --one-file-system -- '+str(workspace)])

    def script(self):
        source = (ROOT / '.github/workflows/bench-e2e.yml').read_text()
        final = source.split('      - name: Remove runner benchmark artifacts\n', 1)[1]
        self.assertIn("always() && steps.runner-cleanup.outputs.directory != ''", final)
        self.assertGreater(source.index('      - name: Remove runner benchmark artifacts'),
                           source.index('      - name: Upload lifecycle reports'))
        return '\n'.join(line[12:] for line in final.split('          script: |\n', 1)[1].splitlines())

    def run_final(self, status, report):
        with tempfile.TemporaryDirectory() as directory:
            temp = Path(directory).resolve()
            owned = temp / '.bench-cleanup-fixture'
            owned.mkdir()
            (owned / 'cleanup.py').write_text('fixture')
            config = dict(script=self.script(), status=status, report=report, env={
                'RUNNER_TEMP': str(temp), 'CLEANUP_DIRECTORY': str(owned),
                'CLEANUP_TEMP_OWNER': json.dumps(dict(dev=owned.stat().st_dev, ino=owned.stat().st_ino)),
                'GITHUB_WORKSPACE': str(temp / 'workspace'),
                'CLEANUP_OWNER': '', 'CLEANUP_RESERVATION': '.capacity-reservation-abc/receipt.json',
                'CLEANUP_ADMISSION': '',
            })
            driver = r'''
const fs = require('node:fs');
const config = JSON.parse(fs.readFileSync(0, 'utf8'));
const logs = []; let called;
const wrapped = name => name === 'node:child_process' ? {
  spawnSync(command, args, options) {
    called = {command, args, input: JSON.parse(options.input)};
    return {status: config.status, stdout: JSON.stringify(config.report)};
  }
} : require(name);
const AsyncFunction = Object.getPrototypeOf(async function(){}).constructor;
(async () => {
  let error = null;
  try { await new AsyncFunction('require','process','core',config.script)(wrapped,{env:config.env},{info:x=>logs.push(x)}); }
  catch (e) { error = e.message; }
  console.log(JSON.stringify({error,called,logs}));
})();
'''
            run = subprocess.run(['node', '-e', driver], input=json.dumps(config),
                                 text=True, capture_output=True, check=True)
            self.assertFalse(owned.exists(), 'Private helper must be removed even on failure')
            return json.loads(run.stdout)

    def test_success_cleans_private_helper_and_passes_exact_loser_receipt(self):
        result = self.run_final(0, dict(schema=1, status=0, processes_stopped=0,
                                       snapshots_cleaned=0, removed_entries=2))
        self.assertIsNone(result['error'])
        self.assertEqual(result['called']['command'], 'sudo')
        self.assertIsNone(result['called']['input']['owner'])
        self.assertEqual(result['called']['input']['capacity_paths'],
                         ['.capacity-reservation-abc/receipt.json'])

    def test_cleanup_failure_is_not_reported_as_success(self):
        result = self.run_final(1, dict(schema=1, status=1, processes_stopped=0,
                                       snapshots_cleaned=0, removed_entries=0))
        self.assertEqual(result['error'], 'runner_cleanup_failed')
        self.assertEqual(len(result['logs']), 1)

    def test_unexpected_private_fields_are_never_logged(self):
        result = self.run_final(0, dict(schema=1, status=0, native_path='private sentinel'))
        self.assertEqual(result['error'], 'cleanup_report_rejected')
        self.assertEqual(result['logs'], [])


if __name__ == '__main__':
    unittest.main()
