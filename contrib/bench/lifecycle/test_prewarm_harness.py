import json,os,re,shutil,subprocess,tempfile,unittest
from pathlib import Path
from prewarm import admission
from report import build
from test_report import fixture
ROOT=Path(__file__).resolve().parents[3]
class PrewarmHarness(unittest.TestCase):
    def test_explicit_milestone_header_admission(self):
        with tempfile.TemporaryDirectory() as directory:
            paths=[Path(directory)/name for name in ('a.jsonl','b.jsonl')]
            header=dict(type='header',schema=1,clock='shared_monotonic_relative_ns',detail='milestones',prewarm_cpu='leaf_v1')
            for p in paths:p.write_text(json.dumps(header)+'\n')
            self.assertTrue(admission(paths,'leaf_v1'))
            for change in ({'prewarm_cpu':'disabled'},{'detail':'full'},{'schema':True},{'prewarm_cpu':None}):
                paths[0].write_text(json.dumps({**header,**change})+'\n');self.assertFalse(admission(paths,'leaf_v1'))
            paths[0].write_text('{');self.assertFalse(admission(paths,'leaf_v1'))
            paths[0].unlink();self.assertFalse(admission(paths,'leaf_v1'))
            self.assertFalse(admission(paths,'leaf_v1',float('inf')))
    def test_report_requires_explicit_expected_header(self):
        with tempfile.TemporaryDirectory() as directory:
            paths=[Path(directory)/name for name in ('a.jsonl','b.jsonl')]
            for path in paths:fixture(path)
            self.assertTrue(build(paths,0,expected_prewarm_cpu='disabled')['bad_capture'])
            for path in paths:
                rows=[json.loads(line) for line in path.read_text().splitlines()];rows[0]['prewarm_cpu']='disabled';path.write_text('\n'.join(map(json.dumps,rows))+'\n')
            self.assertFalse(build(paths,0,expected_prewarm_cpu='disabled')['bad_capture'])
            self.assertTrue(build(paths,0,expected_prewarm_cpu='leaf_v1')['bad_capture'])
    @unittest.skipUnless(shutil.which('nu'),'Nushell required')
    def test_actual_workflow_routes_observer_to_nu_not_txgen(self):
        workflow=(ROOT/'.github/workflows/bench-e2e.yml').read_text()
        for setting in ('BENCH_LIFECYCLE: "true"', 'BENCH_LIFECYCLE_DETAIL: "milestones"',
                        'BENCH_LIFECYCLE_PREWARM_CPU: "disabled"',
                        'BENCH_READ_READINESS: "true"', 'BENCH_RUN_SIDE: "comparison"'):
            self.assertIn(setting, workflow)
        snippet=workflow.split('          cmd=(nu bench-e2e.nu e2e)',1)[1].split('          quote_arg()',1)[0]
        script='set -e\ncmd=(nu bench-e2e.nu e2e)\n'+snippet+'\nprintf "%s\\0" "${cmd[@]}"\n'
        environment={**os.environ,**{name:'' for name in re.findall(r'\$([A-Z_]+)',script)}}
        environment.update(BENCH_LIFECYCLE='true',BENCH_LIFECYCLE_DETAIL='milestones',BENCH_LIFECYCLE_PREWARM_CPU='disabled',BENCH_READ_READINESS='true',BENCH_RUN_SIDE='feature',BENCH_TRACY='off',BENCH_BENCH_ARGS='--existing-txgen-flag 7')
        args=subprocess.check_output(['bash','-c',script],env=environment).decode().rstrip('\0').split('\0')
        self.assertEqual(args[args.index('--lifecycle-prewarm-cpu')+1],'disabled')
        self.assertEqual([a for a in args if a.startswith('--bench-args=')],['--bench-args=--existing-txgen-flag 7'])
        self.assertFalse(any('TEMPO_LIFECYCLE_PREWARM_CPU' in a or a.startswith(('--baseline-env','--feature-env')) for a in args))
        help=subprocess.check_output(['nu','bench-e2e.nu','e2e','--help'],cwd=ROOT,text=True);self.assertIn('--lifecycle-prewarm-cpu',help)
        for side,value,expected in [('baseline','disabled','disabled'),('feature','leaf_v1','leaf_v1')]:
            out=subprocess.check_output(['nu','-c',f'source contrib/bench/lifecycle/run-plan.nu; lifecycle-prewarm-config compare {side} | to json --raw'],cwd=ROOT,text=True)
            self.assertEqual(json.loads(out),dict(expected=expected,env=f'TEMPO_LIFECYCLE_PREWARM_CPU={value} '))
        for side in ('baseline','feature'):
            out=subprocess.check_output(['nu','-c',f'source contrib/bench/lifecycle/run-plan.nu; lifecycle-prewarm-config disabled {side} | to json --raw'],cwd=ROOT,text=True)
            self.assertEqual(json.loads(out),dict(expected='',env=''))
    @unittest.skipUnless(shutil.which('nu'),'Nushell required')
    def test_same_binary_guard_and_invalid_modes_before_work(self):
        source=(ROOT/'bench-e2e.nu').read_text()
        guard='    if $lifecycle_prewarm_cpu == "compare" {'+source.split('    if $lifecycle_prewarm_cpu == "compare" {',1)[1].split('    let baseline_base_label',1)[0]
        with tempfile.TemporaryDirectory() as directory:
            a,b=Path(directory)/'a',Path(directory)/'b';a.write_bytes(b'validator');b.write_bytes(b'validator')
            command=f'let lifecycle_prewarm_cpu = "compare"; let baseline_tempo = "{a}"; let feature_tempo = "{b}"; '+guard
            self.assertEqual(subprocess.run(['nu','-c',command],capture_output=True).returncode,0)
            b.write_bytes(b'different');self.assertNotEqual(subprocess.run(['nu','-c',command],capture_output=True).returncode,0)
        for args in (['--lifecycle-prewarm-cpu','compare'],['--lifecycle','--lifecycle-prewarm-cpu','compare','--run-side','feature'],['--lifecycle','--lifecycle-detail','full','--lifecycle-prewarm-cpu','compare']):
            result=subprocess.run(['nu','bench-e2e.nu','e2e',*args],cwd=ROOT,text=True,capture_output=True,env={**os.environ,'BENCH_BINARY_MODE':'build_v1','BENCH_RUN_CLEANUP':'false','BENCH_READ_READINESS':'false','BENCH_SELECTIVE_RETRY_TRIAL':''})
            self.assertNotEqual(result.returncode,0);self.assertIn('Prewarm CPU comparison requires milestone lifecycle',result.stderr)
    @unittest.skipUnless(shutil.which('nu'),'Nushell required')
    def test_immutable_same_inputs_and_no_environment_override(self):
        base=['nu','bench-e2e.nu','e2e','--lifecycle','--lifecycle-detail','milestones','--lifecycle-prewarm-cpu','compare']
        sha='1'*40
        for extra in ([],['--baseline',sha,'--feature','2'*40],['--baseline',sha,'--feature',sha,'--baseline-env','CUSTOM=1'],['--baseline',sha,'--feature',sha,'--feature-args=--engine.prewarm-threads 32']):
            result=subprocess.run(base+extra,cwd=ROOT,text=True,capture_output=True,env={**os.environ,'BENCH_BINARY_MODE':'build_v1','BENCH_RUN_CLEANUP':'false','BENCH_READ_READINESS':'false','BENCH_SELECTIVE_RETRY_TRIAL':''})
            self.assertNotEqual(result.returncode,0)
            self.assertIn('identical immutable refs and node inputs',result.stderr)
if __name__=='__main__':unittest.main()
