import copy
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
import yaml

HERE = Path(__file__).parent
spec = importlib.util.spec_from_file_location('cleanup', HERE/'bench-prebuilt-cleanup.py')
m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)

class CleanupTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.work = self.base/'work'; self.work.mkdir()
        self.scratch = self.base/'scratch'; self.scratch.mkdir()
        self.state = m.initialize(str(self.work), str(self.scratch), '12', '1')
        self.roots = [Path(r['parent'])/r['name'] for r in self.state['roots']]
        self.report = dict(processes_stopped=0, removed_entries=0, roots_removed=0)

    def test_full_owned_tree_and_external_symlink(self):
        foreign = self.base/'shared-cache'; foreign.mkdir(); (foreign/'keep').write_text('keep')
        for root in self.roots:
            (root/'repo'/'target').mkdir(parents=True)
            (root/'repo'/'target'/'binary').write_bytes(b'compiled')
            (root/'external').symlink_to(foreign, target_is_directory=True)
        m.cleanup(self.state, self.report)
        self.assertEqual(self.report['roots_removed'], 2)
        self.assertEqual((foreign/'keep').read_text(), 'keep')
        self.assertTrue(self.work.is_dir() and self.scratch.is_dir())

    def test_all_identities_before_any_delete(self):
        (self.roots[0]/'keep').write_text('owned')
        bad = copy.deepcopy(self.state); bad['roots'][1]['owner']['ino'] += 1
        with self.assertRaises(m.Rejected): m.cleanup(bad, self.report)
        self.assertTrue((self.roots[0]/'keep').exists())
        self.assertEqual(self.report['removed_entries'], 0)

    def test_parent_symlink_and_replaced_root(self):
        alias = self.base/'alias'; alias.symlink_to(self.work, target_is_directory=True)
        bad = copy.deepcopy(self.state); bad['roots'][0]['parent'] = str(alias)
        with self.assertRaises(OSError): m.cleanup(bad, self.report)
        old = self.roots[1].with_name('prior'); self.roots[1].rename(old); self.roots[1].mkdir()
        with self.assertRaises(m.Rejected): m.cleanup(self.state, self.report)
        self.assertTrue(self.roots[0].exists())

    def test_existing_directory_not_adopted_and_partial_init_rolled_back(self):
        with self.assertRaises(FileExistsError): m.initialize(str(self.work), str(self.scratch), '12', '1')
        name = '.prebuilt-owned-13-1'; (self.scratch/name).mkdir()
        with self.assertRaises(FileExistsError): m.initialize(str(self.work), str(self.scratch), '13', '1')
        self.assertFalse((self.work/name).exists())
        self.assertTrue((self.scratch/name).exists())

    def test_mount_or_process_guard_refuses_deletion(self):
        with patch.object(m, 'no_mounts', side_effect=m.Rejected):
            with self.assertRaises(m.Rejected): m.cleanup(self.state, self.report)
        with patch.object(m, 'stop_processes', side_effect=m.Rejected):
            with self.assertRaises(m.Rejected): m.cleanup(self.state, self.report)
        self.assertTrue(all(p.exists() for p in self.roots))

    def test_cancelled_build_process_and_foreign_process(self):
        owned = subprocess.Popen([sys.executable, '-c', "import signal,time,pathlib;signal.signal(signal.SIGTERM,signal.SIG_IGN);pathlib.Path('ready').touch();time.sleep(60)"], cwd=self.roots[0])
        foreign = subprocess.Popen(['sleep', '60'], cwd=self.base)
        try:
            import time
            end = time.monotonic() + 5
            while not (self.roots[0]/'ready').exists() and time.monotonic() < end: time.sleep(.01)
            self.assertTrue((self.roots[0]/'ready').exists())
            m.cleanup(self.state, self.report)
            self.assertEqual(owned.wait(timeout=1), -9)
            self.assertIsNone(foreign.poll())
            self.assertGreaterEqual(self.report['processes_stopped'], 1)
        finally:
            for proc in (owned, foreign):
                if proc.poll() is None: proc.kill()
                proc.wait()

    def test_cli_failure_is_numeric_only(self):
        result = subprocess.run([sys.executable, str(HERE/'bench-prebuilt-cleanup.py'), 'clean'], input='{"private_path":"secret"}', text=True, capture_output=True)
        self.assertEqual(result.returncode, 1)
        self.assertFalse(result.stderr)
        row = json.loads(result.stdout)
        self.assertEqual(set(row), {'schema','status','processes_stopped','removed_entries','roots_removed'})
        self.assertTrue(all(type(v) is int for v in row.values()))

    def test_compiler_temporary_files_stay_in_private_build_root(self):
        loader = importlib.util.spec_from_file_location('producer', HERE/'bench-prebuilt-producer.py')
        producer = importlib.util.module_from_spec(loader); loader.loader.exec_module(producer)
        private = self.roots[1]/'build'; private.mkdir()
        env = producer.build_environment({'PATH':'/usr/bin', 'HOME':'/root', 'TMPDIR':'/foreign'}, private/'cargo', private/'target', Path('/rustc'))
        self.assertEqual(env['TMPDIR'], str(private))
        child = subprocess.run([sys.executable, '-c', 'import tempfile; print(tempfile.gettempdir())'], env=env, capture_output=True, text=True, check=True)
        self.assertEqual(child.stdout.strip(), str(private))

    def test_current_workflow_paths_flags_and_order(self):
        workflow = yaml.safe_load((HERE.parent/'workflows/build.yml').read_text())
        steps = workflow['jobs']['prebuilt']['steps']
        names = [s['name'] for s in steps]
        self.assertLess(names.index('Reserve exclusive producer directories'), names.index('Checkout producer'))
        self.assertEqual(names[-1], 'Remove owned producer files')
        self.assertEqual(names[-2], 'Upload private prebuilt transport')
        self.assertIn('always()', steps[-1]['if'])
        for role, name in [('producer','Checkout producer'),('runtime','Checkout exact validator runtime'),('tools','Checkout exact workload tools')]:
            self.assertEqual(steps[names.index(name)]['with']['path'], '${{ steps.owned.outputs.relative }}/'+role)
        build = steps[names.index('Build and validate private bundle')]['run']
        self.assertIn('"$PREBUILT_TEMP/bundle"', build)
        self.assertEqual(steps[-2]['with']['path'], '${{ env.PREBUILT_TEMP }}/bundle/*')
        self.assertNotIn('cargo ', build)

    def test_actual_workflow_bootstrap_and_cleanup_source_binding(self):
        steps = yaml.safe_load((HERE.parent/'workflows/build.yml').read_text())['jobs']['prebuilt']['steps']
        init = next(s for s in steps if s.get('id') == 'owned')['with']['script']
        clean = steps[-1]['with']['script']
        source = (HERE/'bench-prebuilt-cleanup.py').read_text()
        driver = '''const input=JSON.parse(require('fs').readFileSync(0,'utf8'));
const outputs={}; const environment={}; const github={rest:{repos:{getContent:async()=>({data:{encoding:'base64',size:Buffer.byteLength(input.source),content:Buffer.from(input.source).toString('base64')}})}}};
const core={setOutput:(k,v)=>outputs[k]=v,exportVariable:(k,v)=>environment[k]=v,info:()=>{}};
(async()=>{await new (Object.getPrototypeOf(async function(){}).constructor)('github','context','core','require',input.script)(github,{repo:{owner:'test',repo:'test'},sha:'a'.repeat(40)},core,require); console.log(JSON.stringify({outputs,environment}));})().catch(()=>process.exit(1));'''
        env = dict(os.environ, GITHUB_WORKSPACE=str(self.work), RUNNER_TEMP=str(self.scratch), GITHUB_RUN_ID='99', GITHUB_RUN_ATTEMPT='1')
        def run(script, text=source):
            return subprocess.run(['node','-e',driver], input=json.dumps(dict(script=script, source=text)), env=env, text=True, capture_output=True)
        invalid = run(init, source+'\n'); self.assertEqual(invalid.returncode, 1)
        self.assertFalse((self.work/'.prebuilt-owned-99-1').exists())
        result = run(init); self.assertEqual(result.returncode, 0, result.stderr)
        generated = json.loads(result.stdout)
        state = generated['outputs']['state']
        for row in json.loads(state)['roots']:
            root=Path(row['parent'])/row['name']; (root/'cancelled-output').write_text('generated')
        env['PREBUILT_OWNED_STATE'] = state
        env['PREBUILT_CLEANUP_SOURCE'] = generated['outputs']['cleanup_source']
        result = run(clean); self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse((self.work/'.prebuilt-owned-99-1').exists())
        self.assertFalse((self.scratch/'.prebuilt-owned-99-1').exists())

if __name__ == '__main__': unittest.main()
