"""Execute the actual dedicated five-slot fault workflow argv construction."""
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
import textwrap
import unittest

ROOT=Path(__file__).resolve().parents[4]

class WorkflowTests(unittest.TestCase):
    def command(self,enabled=True,**changes):
        source=(ROOT/'.github/workflows/bench-e2e.yml').read_text()
        chunk=source[source.index('          cmd=(nu bench-e2e.nu e2e)'):source.index('          quote_arg()')]
        names=set(re.findall(r'\$([A-Z_]+)',chunk));env={name:'' for name in names}
        env.update(BASELINE_REF='a'*40,FEATURE_REF='a'*40,BENCH_RUN_SIDE='feature',BENCH_RUN_PAIRS='1',
            BENCH_LIFECYCLE='true',BENCH_LIFECYCLE_DETAIL='full',BENCH_LIFECYCLE_PREWARM_CPU='disabled',
            BENCH_LIFECYCLE_SCHEDULER='true' if enabled else 'false',BENCH_TRACY='off',
            BENCH_KERNEL_FAULT_BASELINE_EMPTY='true',BENCH_KERNEL_FAULT_FEATURE='a'*40)
        env.update(changes)
        return subprocess.run(['bash','-c',textwrap.dedent(chunk)+"\nprintf '%s\\0' \"${cmd[@]}\"\n"],env=dict(os.environ,**env),capture_output=True)

    def test_exact_fault_flag_routes_to_nu_not_txgen(self):
        result=self.command();self.assertEqual(result.returncode,0,result.stderr)
        args=result.stdout.decode().split('\0');self.assertIn('--lifecycle-scheduler',args)
        self.assertFalse(any(x.startswith(('--bench-args','--feature-env','--baseline-env')) for x in args))
        self.assertNotIn(b'--lifecycle-scheduler',self.command(False).stdout)
        source=(ROOT/'bench-e2e.nu').read_text()
        line=next(x for x in source.splitlines() if 'let scheduler_env =' in x)
        for x in ('TEMPO_LIFECYCLE_KERNEL_WAITS=2','TEMPO_LIFECYCLE_PREWARM_CPU=disabled','TEMPO_LIFECYCLE_PROCESS_CPU=disabled'):
            self.assertIn(x,line)

    def test_ref_phase_observer_and_override_mismatches_reject(self):
        for delta in [dict(BENCH_KERNEL_FAULT_BASELINE_EMPTY='false'),dict(BENCH_KERNEL_FAULT_FEATURE='main'),
            dict(FEATURE_REF='b'*40),dict(BENCH_RUN_SIDE='comparison'),dict(BENCH_RUN_PAIRS='2'),
            dict(BENCH_BASELINE_ENV='PRIVATE'),dict(BENCH_FEATURE_ENV='PRIVATE'),dict(BENCH_BENCH_ENV='PRIVATE'),
            dict(BENCH_SAMPLY='true'),dict(BENCH_TRACY='tracy')]:
            failed=self.command(**delta);self.assertNotEqual(failed.returncode,0)
            self.assertNotIn(b'PRIVATE',failed.stdout+failed.stderr)

    def test_capability_is_selected_dedicated_live_and_owned_scratch(self):
        source=(ROOT/'.github/workflows/bench-e2e.yml').read_text()
        step=source.split('      - name: Admit kernel fault diagnostic capability\n')[1].split('\n      - name:')[0]
        self.assertIn("steps.capacity-election.outputs.selected == 'true'",step)
        self.assertIn("env.BENCH_LIFECYCLE_SCHEDULER == 'true'",step)
        chunk=textwrap.dedent(step.split('        run: |\n')[1])
        script='sudo() { printf "%s\\0" "$@"; return 0; }; export -f sudo\n'+chunk.replace('>/dev/null 2>&1','')
        result=subprocess.run(['bash','-c',script],env=dict(os.environ,RUNNER_TEMP='/unrelated runner scratch',TMPDIR='/owned scratch'),capture_output=True)
        self.assertEqual(result.returncode,0)
        for x in ('TMPDIR=/owned scratch','TEMPO_SCHEDULER_FAULT_SCRATCH=/owned scratch','test_fault_reasons.py','TEMPO_SCHEDULER_LIVE_TEST=1'):
            self.assertIn(x,result.stdout.decode().split('\0'))

    def test_nu_full_capture_is_required(self):
        source=(ROOT/'bench-e2e.nu').read_text()
        start=source.index('    if $lifecycle_scheduler and ');body=source[start:source.index('    if $lifecycle_prewarm_cpu',start)]
        with tempfile.TemporaryDirectory() as tmp:
            path=Path(tmp)/'fixture.nu'
            for values,ok in [(dict(lifecycle=True,lifecycle_detail='full',lifecycle_prewarm_cpu='disabled',samply=False,tracy='off'),True),
                              (dict(lifecycle=True,lifecycle_detail='milestones',lifecycle_prewarm_cpu='disabled',samply=False,tracy='off'),False)]:
                path.write_text('let lifecycle_scheduler = true\n'+''.join(f'let {k} = {json.dumps(v)}\n' for k,v in values.items())+body)
                result=subprocess.run(['nu',str(path)],capture_output=True);self.assertEqual(result.returncode==0,ok)

if __name__=='__main__':unittest.main()
