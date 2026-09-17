"""Exercise workflow argv and actual Nu phase-mode expression without launching nodes."""
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[3]
WORKFLOW = ROOT / '.github/workflows/bench-e2e.yml'
NU = ROOT / 'bench-e2e.nu'


class AsyncRoutingTests(unittest.TestCase):
    def test_workflow_passes_selected_mode_to_nu_not_txgen(self):
        source = WORKFLOW.read_text()
        source = source[source.index('      - name: Run e2e benchmark'):]
        body = source.split('        run: |\n', 1)[1].split('          quote_arg()', 1)[0]
        body = '\n'.join(line[10:] for line in body.splitlines())
        env = {name: '' for name in set(re.findall(r'\$(?:\{)?([A-Z][A-Z0-9_]*)', body))}
        env.update(PATH=os.environ['PATH'], BENCH_RUN_PAIRS='2', BENCH_RUN_SIDE='comparison',
                   BENCH_TOKEN_COUNT='1', BENCH_LIFECYCLE='true', BENCH_LIFECYCLE_DETAIL='full',
                   BENCH_LIFECYCLE_ASYNC_TASKS='selected_v1', BENCH_FEATURES='jemalloc',
                   BASELINE_REF='a'*40, FEATURE_REF='b'*40, BENCH_BENCH_ARGS='--fixture-txgen-option')
        # Execute the actual shell argument construction. Only the final command
        # is replaced with argv serialization; no Nu benchmark body runs.
        body += '\npython3 -c \'import json,sys;print(json.dumps(sys.argv[1:]))\' "${cmd[@]}"\n'
        argv = json.loads(subprocess.run(['bash', '-e', '-c', body], env=env,
                                        text=True, capture_output=True, check=True).stdout)
        self.assertEqual(argv[:3], ['nu', 'bench-e2e.nu', 'e2e'])
        self.assertEqual(argv[argv.index('--lifecycle-async-tasks')+1], 'selected_v1')
        self.assertEqual(argv[argv.index('--features')+1], 'jemalloc,lifecycle-task-capture')
        self.assertEqual(argv[argv.index('--baseline')+1], 'a'*40)
        self.assertEqual(argv[argv.index('--feature')+1], 'b'*40)
        self.assertIn('--bench-args=--fixture-txgen-option', argv)
        self.assertFalse(any('async' in x for x in argv if x.startswith('--bench-args=')))

    @unittest.skipUnless(shutil.which('nu'), 'Nushell required')
    def test_actual_phase_expression_selects_both_variants_and_preserves_off_on(self):
        source = NU.read_text()
        expression = source.split('    let capture_tasks = ', 1)[1].split('\n    let a_capture', 1)[0]
        for mode in ('disabled', 'selected_v1', 'compare'):
            for side in ('baseline', 'feature'):
                script = ('let ctx = {lifecycle_async_tasks: '+json.dumps(mode)+'}; '
                          'let run = {side: '+json.dumps(side)+'}; '+expression+' | to json --raw')
                actual = json.loads(subprocess.run(['nu', '-c', script], text=True,
                                                   capture_output=True, check=True).stdout)
                self.assertEqual(actual, ('disabled' if side == 'baseline' else 'selected_v1')
                                 if mode == 'compare' else mode)
        for role in ('a', 'b'):
            line = next(x for x in source.splitlines() if x.startswith(f'    let {role}_capture ='))
            self.assertIn('TEMPO_LIFECYCLE_ASYNC_TASKS=($capture_tasks)', line)
        self.assertIn('--expected $capture_tasks', source)
        self.assertIn('--expected-async-tasks $capture_tasks', source)
        # The old off/on observer control keeps its byte-equality admission;
        # selected mode permits independently pinned optimization variants.
        gate = source.split('    if $lifecycle_async_tasks == "compare" {')[-1].split('\n    }', 1)[0]
        self.assertIn('cmp -s $baseline_tempo $feature_tempo', gate)

    @unittest.skipUnless(shutil.which('nu'), 'Nushell required')
    def test_real_nu_signature_accepts_dedicated_option(self):
        result = subprocess.run(['nu', 'bench-e2e.nu', 'e2e', '--help'], cwd=ROOT,
                                text=True, capture_output=True, check=True)
        self.assertIn('--lifecycle-async-tasks', result.stdout)


if __name__ == '__main__':
    unittest.main()
