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
    def command(self,enabled,**changes):
        source=(ROOT/'.github/workflows/bench-e2e.yml').read_text()
        chunk=source[source.index('          cmd=(nu bench-e2e.nu e2e)'):source.index('          quote_arg()')]
        names=set(re.findall(r'\$([A-Z_]+)',chunk))
        env={name:'' for name in names}
        env.update(BASELINE_REF='a'*40,FEATURE_REF='a'*40,BENCH_RUN_SIDE='comparison',BENCH_LIFECYCLE='true',BENCH_LIFECYCLE_DETAIL='full',BENCH_LIFECYCLE_SCHEDULER='true',BENCH_TRACY='off',BENCH_LIFECYCLE_KERNEL_WAITS='true' if enabled else 'false')
        env.update(changes)
        return subprocess.run(['bash','-c',textwrap.dedent(chunk)+"\nprintf '%s\\0' \"${cmd[@]}\"\n"],env=dict(os.environ,**env),capture_output=True)

    def test_exact_bash_argv_routes_modes_to_nu_not_txgen(self):
        result=self.command(True);self.assertEqual(result.returncode,0)
        args=result.stdout.decode().split('\0')
        for arg in ['--lifecycle-scheduler','--require-identical-binaries','--baseline-env=TEMPO_LIFECYCLE_KERNEL_WAITS=0','--feature-env=TEMPO_LIFECYCLE_KERNEL_WAITS=1']:self.assertIn(arg,args)
        self.assertFalse(any(x.startswith('--bench-args') for x in args))
        ordinary=self.command(False);self.assertEqual(ordinary.returncode,0)
        self.assertNotIn(b'--require-identical-binaries',ordinary.stdout)
        self.assertNotIn(b'TEMPO_LIFECYCLE_KERNEL_WAITS=',ordinary.stdout)

    def test_reject_different_binary_refs_env_or_runtime_options(self):
        for delta in [dict(FEATURE_REF='b'*40),dict(BASELINE_REF='main'),dict(BENCH_BASELINE_ENV='PRIVATE'),dict(BENCH_FEATURE_ARGS='PRIVATE'),dict(BENCH_FEATURE_HARDFORK='PRIVATE'),dict(BENCH_RUN_SIDE='feature')]:
            result=self.command(True,**delta)
            self.assertNotEqual(result.returncode,0)
            self.assertNotIn(b'PRIVATE',result.stdout+result.stderr)

    def test_positive_wait_preflight_only_runs_in_dedicated_mode(self):
        source=(ROOT/'.github/workflows/bench-e2e.yml').read_text()
        start=source.index('          if [ "$BENCH_LIFECYCLE_KERNEL_WAITS" = "true" ] && ! sudo')
        chunk=source[start:source.index('          fi',start)+len('          fi')]
        for enabled,expected in [('false',''),('true','called')]:
            script='sudo() { echo called; return 0; }; export -f sudo\n'+textwrap.dedent(chunk).replace('>/dev/null 2>&1','')
            result=subprocess.run(['bash','-c',script],env=dict(os.environ,BENCH_LIFECYCLE_KERNEL_WAITS=enabled),capture_output=True,text=True)
            self.assertEqual(result.returncode,0)
            self.assertEqual(result.stdout.strip(),expected)

    def test_actual_nu_identical_binary_guard(self):
        source=(ROOT/'bench-e2e.nu').read_text()
        function=source[source.index('def require-identical-bench-binaries'):source.index('# Run the e2e sequence on one runner.')]
        with tempfile.TemporaryDirectory() as name:
            root=Path(name);(root/'a').write_bytes(b'first');(root/'b').write_bytes(b'first');(root/'c').write_bytes(b'different')
            for other,expected in [('b',0),('c',1),('missing',1)]:
                script=root/'test.nu';script.write_text(function+'\nrequire-identical-bench-binaries '+json.dumps(str(root/'a'))+' '+json.dumps(str(root/other)))
                result=subprocess.run(['nu',str(script)],capture_output=True)
                self.assertEqual(result.returncode==0,expected==0)
                self.assertNotIn(b'different',result.stdout+result.stderr)

if __name__=='__main__':unittest.main()
