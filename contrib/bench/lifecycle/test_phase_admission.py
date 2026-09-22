"""Run the real phase prefix with host effects replaced by owned fixture stubs."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[3]


@unittest.skipUnless(shutil.which('nu'), 'Nushell required')
class PhaseAdmissionTests(unittest.TestCase):
    def phase(self, failure, caller=False):
        source = (ROOT / 'bench-e2e.nu').read_text()
        prefix = source.split('def run-local-e2e-phase [run: record, ctx: record] {', 1)[1]
        prefix = prefix.split('    start-e2e-local-node a ', 1)[0]
        loop = source.split('    mut e2e_exit = 0\n', 1)[1].split(
            '    if $e2e_exit == 0 and $samply', 1)[0]
        cleanup = source.rsplit('    if $needs_baseline {\n', 1)[1]
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'genesis').touch()
            for node in ('a', 'b'):
                (root / node).mkdir()
                for name in ('signing.key', 'signing.share', 'enode.key'):
                    (root / node / name).touch()
            (root / 'results').mkdir()
            (root / 'localnet').mkdir()
            # The cleanup fixture may touch only these owned worktrees.
            for directory_name in ('owned-baseline', 'owned-feature', 'unrelated'):
                (root / directory_name).mkdir()
            mock_git = root / 'git'
            mock_git.write_text('''#!/bin/sh
[ "$1:$2:$3" = "worktree:remove:--force" ] || exit 2
case "$4" in owned-baseline|owned-feature) rmdir "$4" ;; *) exit 3 ;; esac
printf '%s\\n' "$4" >> removed-worktrees
''')
            mock_git.chmod(0o755)
            mock_df = root / 'df'
            mock_df.write_text('''#!/bin/sh
available=49152
case "$LIFECYCLE_TEST_FAILURE:$2" in
  results:results|root:/) available=49151 ;;
  inspect:results) exit 1 ;;
esac
printf 'Filesystem 1048576-blocks Used Available Capacity Mounted on\n'
printf 'fixture 1000000 1 %s 1%% /fixture\n' "$available"
''')
            mock_df.chmod(0o755)
            stubs = '''
const LOCALNET_DIR = "localnet"
const TRACY_SAMPLING_HZ = 100
def parse-cli-args [value] { [] }
def cleanup-local-e2e-processes [] { "cleanup" | save --append effects }
def bench-restore-at [...args] { "restore" | save --append effects }
def bench-update-pr-status [...args] {}
def e2e-regenesis [...args] {}
def apply-system-tuning [] { "tuned" | save tuning-effect; {tuned:true} }
def build-base-args [...args] { [] }
def build-e2e-consensus-args [...args] { [] }
def log-filter-args [...args] { [] }
def benchmark-otlp-args [...args] { [] }
def dedup-args [...args] { [] }
def mark-schelk-dirty-at [...args] {
    if $env.LIFECYCLE_TEST_FAILURE == "after-admission" {
        error make {msg: "fixture post-admission failure"}
    }
    "dirty" | save --append effects
}
'''
            ctx = dict(genesis='genesis', baseline_args='', feature_args='', baseline_env='',
                       feature_env='', baseline_local_reth_args=[], feature_local_reth_args=[],
                       results_dir='results', tune=True, gas_limit='', general_gas_limit='',
                       samply=False, tracy='off', tracing_otlp=False, loud=False,
                       lifecycle=True, lifecycle_scheduler=False, lifecycle_detail='full', lifecycle_prewarm_cpu='disabled', trusted_peers='',
                       benchmark_id='', reference_epoch=0)
            for node in ('a', 'b'):
                ctx[node] = dict(state_path=node, mount=node, datadir=node, node_dir=node,
                                 consensus_port=0, ip='')
            script = (f'source {json.dumps(str(ROOT / "contrib/bench/lifecycle/disk.nu"))}\n'
                      + f'source {json.dumps(str(ROOT / "contrib/bench/lifecycle/run-plan.nu"))}\n'
                      + stubs + '\ndef run-local-e2e-phase [run: record, ctx: record] {' + prefix
                      + '\nprint admitted\n0\n}\n'
                      + "let ctx = ('" + json.dumps(ctx) + "' | from json)\n")
            if caller:
                script += '''
const E2E_A_STATE_PATH = "a"
const E2E_A_MOUNT = "a"
const E2E_B_STATE_PATH = "b"
const E2E_B_MOUNT = "b"
def fixture-caller [ctx: record] {
let runs = [{phase: "feature-1", side: "feature", ref: "fixture"},
            {phase: "feature-2", side: "feature", ref: "fixture"}]
let num_phases = 2
let needs_baseline = true
let needs_feature = true
let baseline_wt = "owned-baseline"
let feature_wt = "owned-feature"
let a_db = "a"
let b_db = "b"
mut e2e_exit = 0
'''+loop+'\nif $needs_baseline {\n'+cleanup+'\nfixture-caller $ctx\n'
            else:
                script += '''let result = (run-local-e2e-phase
{phase: "feature-1", side: "feature", ref: "fixture"} $ctx)
print $"phase-result=($result)"
'''
            (root / 'fixture.nu').write_text(script)
            result = subprocess.run(['nu', '--no-config-file', 'fixture.nu'], cwd=root,
                                    env=dict(os.environ, PATH=str(root)+os.pathsep+os.environ['PATH'],
                                             LIFECYCLE_TEST_FAILURE=failure,
                                             BENCH_READ_READINESS='false'),
                                    text=True, capture_output=True)
            effects = dict(tuned=(root / 'tuning-effect').exists(),
                           key=any((root / 'localnet').glob('lifecycle-key-*')),
                           removed=(root / 'removed-worktrees').read_text().splitlines()
                           if (root / 'removed-worktrees').exists() else [],
                           unrelated=(root / 'unrelated').is_dir(),
                           host=(root / 'effects').read_text()
                           if (root / 'effects').exists() else '')
            return result, effects

    def test_each_capacity_rejection_precedes_host_tuning(self):
        for failure in ('results', 'root'):
            with self.subTest(failure=failure):
                result, effects = self.phase(failure)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertIn('phase-result=1', result.stdout)
                self.assertIn('Lifecycle phase admission failed: capture disk guard', result.stdout)
                self.assertIn('49151 MiB available; 49152 MiB required', result.stdout)
                self.assertFalse(effects['tuned'], 'rejected phase changed host tuning')
                self.assertFalse(effects['key'])
                self.assertNotIn('dirty', effects['host'])

    def test_rejected_phase_reaches_existing_caller_cleanup_and_stops_next_phase(self):
        for failure in ('results', 'root', 'inspect'):
            with self.subTest(failure=failure):
                result, effects = self.phase(failure, caller=True)
                self.assertEqual(result.returncode, 1, result.stderr)
                self.assertIn('Starting local e2e phase: feature-1', result.stdout)
                self.assertNotIn('Starting local e2e phase: feature-2', result.stdout)
                self.assertFalse(effects['tuned'])
                self.assertFalse(effects['key'])
                self.assertEqual(effects['removed'], ['owned-baseline', 'owned-feature'])
                self.assertTrue(effects['unrelated'])
                self.assertEqual(effects['host'], 'cleanuprestorerestorecleanuprestorerestore')

    def test_successful_admission_still_applies_tuning(self):
        result, effects = self.phase('none')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('admitted', result.stdout)
        self.assertIn('phase-result=0', result.stdout)
        self.assertTrue(effects['tuned'])
        self.assertTrue(effects['key'])
        self.assertEqual(effects['removed'], [])

    def test_non_guard_error_is_not_converted_to_phase_admission_failure(self):
        result, effects = self.phase('after-admission', caller=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('fixture post-admission failure', result.stderr)
        self.assertNotIn('Lifecycle phase admission failed', result.stdout)
        self.assertFalse(effects['tuned'])
        self.assertTrue(effects['key'])
        self.assertEqual(effects['removed'], [])


if __name__ == '__main__':
    unittest.main()
