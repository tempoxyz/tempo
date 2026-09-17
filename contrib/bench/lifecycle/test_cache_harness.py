import json,os,re,shutil,subprocess,tempfile,unittest
from pathlib import Path
from cache_insert import admission
from report import build
from test_report import fixture
ROOT=Path(__file__).resolve().parents[3]
class CacheHarness(unittest.TestCase):
    def test_explicit_full_header_admission(self):
        with tempfile.TemporaryDirectory() as directory:
            paths=[Path(directory)/name for name in ('a.jsonl','b.jsonl')]
            header=dict(type='header',schema=1,clock='shared_monotonic_relative_ns',detail='full',cache_insert='counts_v1')
            for p in paths:p.write_text(json.dumps(header)+'\n')
            self.assertTrue(admission(paths,'counts_v1'))
            for change in ({'cache_insert':'disabled'},{'detail':'milestones'},{'schema':True},{'cache_insert':None}):
                paths[0].write_text(json.dumps({**header,**change})+'\n');self.assertFalse(admission(paths,'counts_v1'))
            paths[0].write_text('{');self.assertFalse(admission(paths,'counts_v1'))
            paths[0].unlink();self.assertFalse(admission(paths,'counts_v1'))
            self.assertFalse(admission(paths,'counts_v1',float('inf')))
    def test_report_requires_explicit_expected_header(self):
        with tempfile.TemporaryDirectory() as directory:
            paths=[Path(directory)/name for name in ('a.jsonl','b.jsonl')]
            for path in paths:fixture(path)
            self.assertTrue(build(paths,0,expected_cache_insert='disabled')['bad_capture'])
            for path in paths:
                rows=[json.loads(line) for line in path.read_text().splitlines()];rows[0]['cache_insert']='disabled';path.write_text('\n'.join(map(json.dumps,rows))+'\n')
            self.assertFalse(build(paths,0,expected_cache_insert='disabled')['bad_capture'])
            self.assertTrue(build(paths,0,expected_cache_insert='counts_v1')['bad_capture'])
    @unittest.skipUnless(shutil.which('nu'),'Nushell required')
    def test_actual_workflow_routes_observer_to_nu_not_txgen(self):
        workflow=(ROOT/'.github/workflows/bench-e2e.yml').read_text()
        self.assertIn("BENCH_LIFECYCLE_CACHE_INSERT: ${{ inputs.profiling == 'lifecycle-compare-cache-insert' && 'compare' || 'disabled' }}",workflow)
        for key in ('BENCH_LIFECYCLE:','BENCH_OTLP:','BENCH_VALSCOPE:','BENCH_RUN_SIDE:'):
            self.assertIn('lifecycle-compare-cache-insert',next(line for line in workflow.splitlines() if key in line))
        snippet=workflow.split('          cmd=(nu bench-e2e.nu e2e)',1)[1].split('          quote_arg()',1)[0]
        script='set -e\ncmd=(nu bench-e2e.nu e2e)\n'+snippet+'\nprintf "%s\\0" "${cmd[@]}"\n'
        environment={**os.environ,**{name:'' for name in re.findall(r'\$([A-Z_]+)',script)}}
        environment.update(BENCH_LIFECYCLE='true',BENCH_LIFECYCLE_DETAIL='full',BENCH_LIFECYCLE_CACHE_INSERT='compare',BENCH_TRACY='off',BENCH_BENCH_ARGS='--existing-txgen-flag 7')
        args=subprocess.check_output(['bash','-c',script],env=environment).decode().rstrip('\0').split('\0')
        self.assertEqual(args[args.index('--lifecycle-cache-insert')+1],'compare')
        self.assertEqual([a for a in args if a.startswith('--bench-args=')],['--bench-args=--existing-txgen-flag 7'])
        self.assertFalse(any('TEMPO_LIFECYCLE_CACHE_INSERT' in a or a.startswith(('--baseline-env','--feature-env')) for a in args))
        help=subprocess.check_output(['nu','bench-e2e.nu','e2e','--help'],cwd=ROOT,text=True);self.assertIn('--lifecycle-cache-insert',help)
        for side,value,expected in [('baseline','0','disabled'),('feature','1','counts_v1')]:
            out=subprocess.check_output(['nu','-c',f'source contrib/bench/lifecycle/run-plan.nu; lifecycle-cache-config compare {side} | to json --raw'],cwd=ROOT,text=True)
            self.assertEqual(json.loads(out),dict(expected=expected,env=f'TEMPO_LIFECYCLE_CACHE_INSERT={value} '))
        for side in ('baseline','feature'):
            out=subprocess.check_output(['nu','-c',f'source contrib/bench/lifecycle/run-plan.nu; lifecycle-cache-config disabled {side} | to json --raw'],cwd=ROOT,text=True)
            self.assertEqual(json.loads(out),dict(expected='',env=''))
    @unittest.skipUnless(shutil.which('nu'),'Nushell required')
    def test_same_binary_guard_and_invalid_modes_before_work(self):
        source=(ROOT/'bench-e2e.nu').read_text()
        guard='    if $lifecycle_cache_insert == "compare" {'+source.split('    if $lifecycle_cache_insert == "compare" {',1)[1].split('    let baseline_base_label',1)[0]
        with tempfile.TemporaryDirectory() as directory:
            a,b=Path(directory)/'a',Path(directory)/'b';a.write_bytes(b'validator');b.write_bytes(b'validator')
            command=f'let lifecycle_cache_insert = "compare"; let baseline_tempo = "{a}"; let feature_tempo = "{b}"; '+guard
            self.assertEqual(subprocess.run(['nu','-c',command],capture_output=True).returncode,0)
            b.write_bytes(b'different');self.assertNotEqual(subprocess.run(['nu','-c',command],capture_output=True).returncode,0)
        for args in (['--lifecycle-cache-insert','compare'],['--lifecycle','--lifecycle-cache-insert','compare','--run-side','feature'],['--lifecycle','--lifecycle-detail','milestones','--lifecycle-cache-insert','compare']):
            result=subprocess.run(['nu','bench-e2e.nu','e2e',*args],cwd=ROOT,text=True,capture_output=True)
            self.assertNotEqual(result.returncode,0);self.assertIn('Cache observer comparison requires full lifecycle',result.stderr)
if __name__=='__main__':unittest.main()
