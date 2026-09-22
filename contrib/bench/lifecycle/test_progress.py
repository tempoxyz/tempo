import os
from pathlib import Path
import selectors
import shutil
import signal
import subprocess
import sys
import tempfile
import unittest
from types import ModuleType
from unittest.mock import patch, Mock

import progress

ROOT = Path(__file__).resolve().parents[3]


class ProgressTests(unittest.TestCase):
    def fixture(self, root, body):
        directory = root/'contrib/bench/lifecycle'
        directory.mkdir(parents=True)
        shutil.copyfile(Path(progress.__file__), directory/'progress.py')
        (directory/'report.py').write_text('import os,sys,time\nfrom pathlib import Path\nfrom progress import emit,FD_ENV\n'+body)
        return directory/'progress.py'

    def test_actual_nu_snippet_streams_before_completion_and_preserves_failure(self):
        source = (ROOT/'bench-e2e.nu').read_text()
        start = source.index('        let report = (^python3 contrib/bench/lifecycle/progress.py')
        end = source.index('        if $report.exit_code == 0 {', start)
        snippet = source[start:end]
        for code in (0, 7):
            with tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                self.fixture(root, '''assert sys.argv[sys.argv.index('--workload-report')+1] == 'results/report-feature-1.json'
emit('lifecycle_build','begin')
print('PRIVATE-PAYLOAD',flush=True)
print('PRIVATE-TRACEBACK',file=sys.stderr,flush=True)
for _ in range(500):
 if Path('release').exists(): break
 time.sleep(.01)
else: sys.exit(9)
emit('lifecycle_build','end')
'''+f'sys.exit({code})\n')
                script = root/'test.nu'
                script.write_text('let prewarm_report_args = []\nlet scheduler_report_args = []\nlet capture_detail = "full"\nlet lifecycle_report_dir = "out"\nlet lifecycle_dir = "private"\nlet ctx = {summary_warmup_blocks: 0, results_dir: "results"}\nlet phase = "feature-1"\nmut phase_exit = 0\n'+snippet+'\nprint $"phase_exit=($phase_exit)"\n')
                child = subprocess.Popen(['nu',str(script)],cwd=root,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
                try:
                    with selectors.DefaultSelector() as ready:
                        ready.register(child.stderr,selectors.EVENT_READ)
                        # Read bytes one at a time: no TextIO read-ahead can hide an already
                        # buffered marker from the readiness assertion.
                        text=''
                        while 'stage=lifecycle_build edge=begin' not in text:
                            self.assertTrue(ready.select(3),'progress buffered until completion')
                            byte=os.read(child.stderr.fileno(),1)
                            self.assertTrue(byte,text);text+=byte.decode()
                        self.assertIsNone(child.poll())
                    (root/'release').touch()
                    stdout,stderr=child.communicate(timeout=5)
                    output=text+stdout+stderr
                    self.assertEqual(child.returncode,0)
                    self.assertIn(f'phase_exit={int(code!=0)}',output)
                    self.assertIn(f'status={code}',output)
                    self.assertNotIn('PRIVATE',output)
                    self.assertIn('stage=lifecycle_build edge=end',output)
                finally:
                    if child.poll() is None:child.kill();child.wait()
                    child.stdout.close();child.stderr.close()

    def test_untrusted_diagnostics_cannot_impersonate_progress_or_deadlock(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)
            wrapper=self.fixture(root,"print('lifecycle_report stage=PRIVATE '*20000,flush=True)\nprint('SECRET '*20000,file=sys.stderr,flush=True)\nemit('package','begin')\nemit('package','end')\n")
            result=subprocess.run([sys.executable,str(wrapper)],capture_output=True,timeout=5,text=True)
            self.assertEqual(result.returncode,0)
            self.assertEqual(result.stdout,'')
            self.assertNotIn('PRIVATE',result.stderr);self.assertNotIn('SECRET',result.stderr)
            self.assertIn('stage=package edge=end',result.stderr)
            self.assertLess(len(result.stderr),1000)

    def test_invalid_private_channel_rejects_without_leaking(self):
        for raw in (b'PRIVATE|begin|0\n',b'package|begin|2\n',b'PRIVATE'*1000,b'package|begin|0'):
            with tempfile.TemporaryDirectory() as directory:
                root=Path(directory)
                wrapper=self.fixture(root,f'os.write(int(os.environ[FD_ENV]),{raw!r})\n')
                result=subprocess.run([sys.executable,str(wrapper)],capture_output=True,timeout=5,text=True)
                self.assertEqual(result.returncode,2)
                self.assertNotIn('PRIVATE',result.stdout+result.stderr)
                self.assertNotIn(directory,result.stdout+result.stderr)
                self.assertIn('stage=wrapper_failure',result.stderr)

    def test_wrapper_termination_reaps_its_owned_reporter(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)
            wrapper=self.fixture(root,"import signal\ndef stop(*_):\n Path('terminated').touch()\n sys.exit(0)\nsignal.signal(signal.SIGTERM,stop)\nemit('package','begin')\ntime.sleep(10)\n")
            child=subprocess.Popen([sys.executable,str(wrapper)],cwd=root,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
            try:
                with selectors.DefaultSelector() as ready:
                    ready.register(child.stderr,selectors.EVENT_READ)
                    seen=b''
                    while b'stage=package edge=begin' not in seen:
                        self.assertTrue(ready.select(3))
                        byte=os.read(child.stderr.fileno(),1);self.assertTrue(byte);seen+=byte
                child.terminate()
                out,err=child.communicate(timeout=5)
                self.assertNotEqual(child.returncode,0)
                self.assertTrue((root/'terminated').exists())
                self.assertNotIn(b'Traceback',out+err)
            finally:
                if child.poll() is None:child.kill();child.wait()
                child.stdout.close();child.stderr.close()

    def test_production_stage_failure_has_no_false_end(self):
        import report
        events=[]
        with tempfile.TemporaryDirectory() as directory:
            data={'bad_capture':False,'detail_valid':True}
            with patch.object(progress,'emit',side_effect=lambda *args:events.append(args)), patch.object(report,'build',return_value=data), patch.object(report,'write_package',side_effect=ValueError('PRIVATE')):
                with self.assertRaises(ValueError):report.write_report([],Path(directory))
            self.assertIn(('lifecycle_build','end'),events)
            self.assertIn(('report_write','end'),events)
            self.assertIn(('package','begin'),events)
            self.assertNotIn(('package','end'),events)

    def test_broken_progress_after_scheduler_load_closes_capture(self):
        import report
        fake=ModuleType('scheduler.report'); capture=object()
        fake.load=Mock(return_value=([capture],[]));fake.publish=Mock();fake.close=Mock()
        def marker(stage,edge,*_):
            if (stage,edge)==('scheduler_load','end'):raise OSError('PRIVATE')
        with tempfile.TemporaryDirectory() as directory:
            with patch.dict(sys.modules,{'scheduler.report':fake}), patch.object(progress,'emit',side_effect=marker), patch.object(report,'prepare_captures',return_value=([],{})), patch.object(report,'build',return_value={'bad_capture':False,'detail_valid':True}):
                with self.assertRaises(OSError):report.write_report([],Path(directory),prune=True,scheduler_dir=Path(directory))
        fake.close.assert_called_once_with([capture]);fake.publish.assert_not_called()

    def test_broken_progress_after_index_closes_new_owner(self):
        from scheduler import report as scheduler
        sentinel=object()
        def marker(stage,edge,*_):
            if (stage,edge)==('scheduler_index','end'):raise OSError('PRIVATE')
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)
            for role in 'ab':
                (root/f'scheduler-{role}.json.gz').touch()
                (root/f'{role}.jsonl').write_text('{"scheduler":"registered_threads_v1"}\n')
            with patch.object(progress,'emit',side_effect=marker), patch.object(scheduler,'indexed_capture',return_value=sentinel), patch.object(scheduler,'close') as close:
                with self.assertRaises(OSError):scheduler.load(root,root,{'backpressure':{'ts':1}})
                close.assert_called_once_with([sentinel])

    def test_reporter_failure_suppresses_exception_details(self):
        with tempfile.TemporaryDirectory() as directory:
            wrapper=self.fixture(Path(directory),"emit('package','begin')\nraise ValueError('PRIVATE-NATIVE-PATH')\n")
            result=subprocess.run([sys.executable,str(wrapper)],capture_output=True,text=True)
            self.assertEqual(result.returncode,1)
            self.assertNotIn('PRIVATE',result.stdout+result.stderr)
            self.assertNotIn('Traceback',result.stderr)
            self.assertIn('stage=package edge=begin',result.stderr)
            self.assertNotIn('stage=package edge=end',result.stderr)
            self.assertIn('status=1',result.stderr)


if __name__ == '__main__':unittest.main()
