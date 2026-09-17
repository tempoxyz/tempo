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
    def phase(self, failure):
        source = (ROOT / 'bench-e2e.nu').read_text()
        prefix = source.split('def run-local-e2e-phase [run: record, ctx: record] {', 1)[1]
        prefix = prefix.split('    start-e2e-local-node a ', 1)[0]
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'genesis').touch()
            for node in ('a', 'b'):
                (root / node).mkdir()
                for name in ('signing.key', 'signing.share', 'enode.key'):
                    (root / node / name).touch()
            (root / 'results').mkdir()
            (root / 'localnet').mkdir()
            mock_df = root / 'df'
            mock_df.write_text('''#!/bin/sh
available=49152
case "$LIFECYCLE_TEST_FAILURE:$2" in
  results:results|root:/) available=49151 ;;
esac
printf 'Filesystem 1048576-blocks Used Available Capacity Mounted on\n'
printf 'fixture 1000000 1 %s 1%% /fixture\n' "$available"
''')
            mock_df.chmod(0o755)
            stubs = '''
const LOCALNET_DIR = "localnet"
const TRACY_SAMPLING_HZ = 100
def parse-cli-args [value] { [] }
def cleanup-local-e2e-processes [] {}
def bench-restore-at [...args] {}
def e2e-regenesis [...args] {}
def apply-system-tuning [] { "tuned" | save tuning-effect; {tuned:true} }
def build-base-args [...args] { [] }
def build-e2e-consensus-args [...args] { [] }
def log-filter-args [...args] { [] }
def benchmark-otlp-args [...args] { [] }
def dedup-args [...args] { [] }
def mark-schelk-dirty-at [...args] {}
'''
            ctx = dict(genesis='genesis', baseline_args='', feature_args='', baseline_env='',
                       feature_env='', baseline_local_reth_args=[], feature_local_reth_args=[],
                       results_dir='results', tune=True, gas_limit='', general_gas_limit='',
                       samply=False, tracy='off', tracing_otlp=False, loud=False,
                       lifecycle=True, lifecycle_detail='full', lifecycle_prewarm_cpu='disabled', trusted_peers='',
                       benchmark_id='', reference_epoch=0)
            for node in ('a', 'b'):
                ctx[node] = dict(state_path=node, mount=node, datadir=node, node_dir=node,
                                 consensus_port=0, ip='')
            script = (f'source {json.dumps(str(ROOT / "contrib/bench/lifecycle/disk.nu"))}\n'
                      + f'source {json.dumps(str(ROOT / "contrib/bench/lifecycle/run-plan.nu"))}\n'
                      + stubs + '\ndef fixture [run: record, ctx: record] {' + prefix
                      + '\nprint admitted\n}\nfixture '
                      + "('{\"phase\":\"feature-1\",\"side\":\"feature\",\"ref\":\"fixture\"}' | from json) "
                      + "('" + json.dumps(ctx) + "' | from json)\n")
            (root / 'fixture.nu').write_text(script)
            result = subprocess.run(['nu', '--no-config-file', 'fixture.nu'], cwd=root,
                                    env=dict(os.environ, PATH=str(root)+os.pathsep+os.environ['PATH'],
                                             LIFECYCLE_TEST_FAILURE=failure),
                                    text=True, capture_output=True)
            return result, (root / 'tuning-effect').exists()

    def test_each_capacity_rejection_precedes_host_tuning(self):
        for failure in ('results', 'root'):
            with self.subTest(failure=failure):
                result, tuned = self.phase(failure)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn('Insufficient lifecycle disk space', result.stderr)
                self.assertFalse(tuned, 'rejected phase changed host tuning')

    def test_successful_admission_still_applies_tuning(self):
        result, tuned = self.phase('none')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('admitted', result.stdout)
        self.assertTrue(tuned)


if __name__ == '__main__':
    unittest.main()
