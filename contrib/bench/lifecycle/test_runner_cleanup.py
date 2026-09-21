import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('cleanup', Path(__file__).with_name('runner_cleanup.py'))
c = importlib.util.module_from_spec(spec);spec.loader.exec_module(c)


def report():
    return dict(schema=1, status=1, processes_stopped=0, snapshots_cleaned=0, removed_entries=0)


def config(path):
    st = path.stat()
    return dict(workspace=str(path), owner=dict(dev=st.st_dev, ino=st.st_ino, uid=st.st_uid), capacity_paths=[])


class CleanupTests(unittest.TestCase):
    def test_check_only_never_deletes_and_has_distinct_receipt(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d); (root/'keep').write_text('baseline')
            result = subprocess.run([sys.executable, '-I', str(Path(c.__file__)),
                                     '--check-workspace', str(root)], capture_output=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(json.loads(result.stdout), dict(schema=1, status=0, workspace_checked=1))
            self.assertEqual((root/'keep').read_text(), 'baseline')

    def test_snapshot_paths_and_ancestors_reject_before_open_or_delete(self):
        for value in ('/', '/mnt', '/mnt/virgin', '/mnt/virgin/reth-data',
                      '/reth-bench-a', '/reth-bench-b/tempo_e2e_100000mb',
                      '/var/lib', '/var/lib/schelk', '//reth-bench-a'):
            with self.subTest(path=value), patch.object(c, 'open_dir') as opened:
                with self.assertRaises(c.Rejected): c.check_workspace(Path(value))
                opened.assert_not_called()

    def test_workspace_and_nested_bind_mounts_reject_before_cleanup(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d); (root/'snapshot').write_text('keep')
            for mount in (root, root/'nested-snapshot'):
                # A bind mount can use the same device; --one-file-system alone
                # is insufficient. Inspect the mount table before any deletion.
                mounts = f'123 1 8:1 / {mount} rw - ext4 /dev/fixture rw\n'
                with self.subTest(mount=mount), patch.object(Path, 'read_text', return_value=mounts):
                    with patch.object(c, 'stop_processes') as stopped:
                        with self.assertRaises(c.Rejected): c.cleanup(config(root), report())
                        stopped.assert_not_called()
            self.assertEqual((root/'snapshot').read_text(), 'keep')

    def test_selected_clears_owned_children_preserves_root_and_symlink_target(self):
        with tempfile.TemporaryDirectory() as d:
            base=Path(d);root=base/'workspace';root.mkdir();external=base/'external';external.mkdir()
            (external/'sentinel').write_text('keep');(root/'link').symlink_to(external,target_is_directory=True)
            (root/'outputs').mkdir();(root/'outputs/a').write_text('owned')
            before=root.stat();result=report()
            c.cleanup(config(root),result)
            self.assertEqual(list(root.iterdir()),[]);self.assertEqual(c.identity(root.stat()),c.identity(before))
            self.assertEqual((external/'sentinel').read_text(),'keep');self.assertEqual(result['removed_entries'],3)

    def test_wrong_owner_identity_and_symlink_ancestors_reject(self):
        with tempfile.TemporaryDirectory() as d:
            base=Path(d);root=base/'workspace';root.mkdir();(root/'keep').write_text('safe')
            for key in ('dev','ino','uid'):
                value=config(root);value['owner'][key]+=1
                with self.subTest(key=key),self.assertRaises(c.Rejected):c.cleanup(value,report())
            link=base/'link';link.symlink_to(root,target_is_directory=True)
            with self.assertRaises(OSError):c.cleanup({**config(root),'workspace':str(link)},report())
            self.assertEqual((root/'keep').read_text(),'safe')

    def test_exact_losing_paths_only_and_extra_or_redirected_entries_reject(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);owned=root/'.capacity-reservation-own';owned.mkdir();(owned/'receipt.json').write_text('{}')
            unrelated=root/'.capacity-reservation-other';unrelated.mkdir();(unrelated/'receipt.json').write_text('keep')
            value=dict(workspace=str(root),owner=None,capacity_paths=['.capacity-reservation-own/receipt.json'])
            c.cleanup(value,report());self.assertFalse(owned.exists());self.assertTrue(unrelated.exists())
            owned.mkdir();(owned/'extra').write_text('keep')
            with self.assertRaises(c.Rejected):c.cleanup(value,report())
            for relative in ['../receipt.json','.capacity-reservation-own/no.json','/tmp/x/receipt.json','ordinary/receipt.json']:
                with self.subTest(relative=relative),self.assertRaises(c.Rejected):
                    c.cleanup({**value,'capacity_paths':[relative]},report())
            shutil.rmtree(owned);owned.symlink_to(unrelated,target_is_directory=True)
            with self.assertRaises(OSError):c.cleanup(value,report())
            self.assertEqual((unrelated/'receipt.json').read_text(),'keep')

    def test_snapshot_or_process_failure_preserves_workspace(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);(root/'keep').write_text('safe')
            for function in ['stop_processes']:
                with self.subTest(function=function),patch.object(c,function,side_effect=c.Rejected),self.assertRaises(c.Rejected):
                    c.cleanup(config(root),report())
                self.assertTrue((root/'keep').exists())
            with patch.object(c,'no_mounts',side_effect=c.Rejected),self.assertRaises(c.Rejected):c.cleanup(config(root),report())
            self.assertTrue((root/'keep').exists())
            with patch.object(c,'snapshot_cleanup',side_effect=c.Rejected),self.assertRaises(c.Rejected):c.cleanup(config(root),report())
            self.assertEqual(list(root.iterdir()),[])

    def test_actual_owned_executable_is_stopped_foreign_sibling_survives(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);binary=root/'owned-sleep';shutil.copyfile('/bin/sleep',binary);binary.chmod(0o700)
            owned=subprocess.Popen([str(binary),'60']);foreign=subprocess.Popen(['/bin/sleep','60'])
            try:
                result=report();c.cleanup(config(root),result)
                self.assertIsNotNone(owned.poll());self.assertIsNone(foreign.poll())
                self.assertGreaterEqual(result['processes_stopped'],1);self.assertEqual(list(root.iterdir()),[])
            finally:
                for process in (owned,foreign):
                    if process.poll() is None:process.kill()
                    process.wait()

    def test_actual_known_script_descendant_and_term_ignored_cancel_path(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);script=root/'contrib/bench/lifecycle/scheduler/runtime.py';script.parent.mkdir(parents=True)
            script.write_text('import signal,subprocess,time\nsignal.signal(signal.SIGTERM,signal.SIG_IGN)\np=subprocess.Popen(["/bin/sleep","60"])\nprint("ready",flush=True)\ntime.sleep(60)\n')
            process=subprocess.Popen([sys.executable,str(script.relative_to(root))],cwd=root,stdout=subprocess.PIPE,text=True)
            try:
                self.assertEqual(process.stdout.readline().strip(),'ready')
                result=report();c.cleanup(config(root),result)
                self.assertIsNotNone(process.poll());self.assertGreaterEqual(result['processes_stopped'],2)
            finally:
                if process.poll() is None:process.kill()
                process.wait();process.stdout.close()

    def test_foreign_python_data_argument_is_not_a_known_script(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d)
            process=subprocess.Popen([sys.executable,'-c','import time;time.sleep(60)','bench-e2e.nu'],cwd=root)
            try:
                fd=c.open_dir(root)
                try:self.assertFalse(c.owned_process(process.pid,root,fd))
                finally:os.close(fd)
                self.assertIsNone(process.poll())
            finally:process.kill();process.wait()

    def test_same_path_replacement_does_not_match_old_executable_inode(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);binary=root/'owned-sleep';shutil.copyfile('/bin/sleep',binary);binary.chmod(0o700)
            process=subprocess.Popen([str(binary),'60'])
            try:
                binary.unlink();shutil.copyfile('/bin/sleep',binary);binary.chmod(0o700)
                fd=c.open_dir(root)
                try:self.assertFalse(c.owned_process(process.pid,root,fd))
                finally:os.close(fd)
            finally:process.kill();process.wait()

    def test_snapshot_both_attempted_after_first_error_artifacts_still_removed(self):
        with tempfile.TemporaryDirectory() as d:
            base=Path(d);root=base/'workspace';root.mkdir();states=base/'state';states.mkdir()
            (root/'.bench-snapshot-dirty').write_text('')
            script=root/'bench-schelk.nu';script.write_text('owned fixture')
            (root/'retained.zip').write_bytes(b'artifact')
            for role in ('a','b'):
                (states/(role+'.json')).write_text(json.dumps({'mount_point':'/reth-bench-'+role,'dm_era_name':'fixture-'+role}))
            class Process:
                def __init__(self,code):self.code=code
                def wait(self,timeout):return self.code
                def poll(self):return self.code
            result=report()
            with patch.object(c,'STATE_ROOT',states),patch.object(c,'SCHELK_SHA',c.hashlib.sha256(script.read_bytes()).hexdigest()),patch.object(c.subprocess,'Popen',side_effect=[Process(125),Process(0)]) as spawn:
                with self.assertRaises(c.Rejected):c.cleanup(config(root),result)
            self.assertEqual(spawn.call_count,2);self.assertEqual(result['snapshots_cleaned'],1)
            self.assertEqual(list(root.iterdir()),[]);self.assertEqual(len(list(states.iterdir())),2)

    def test_cli_error_emits_only_numeric_schema(self):
        result=subprocess.run([sys.executable,'-I',str(Path(c.__file__))],input=b'{"workspace":"private-path"}',stdout=subprocess.PIPE,stderr=subprocess.PIPE)
        self.assertEqual(result.returncode,1);self.assertEqual(result.stderr,b'')
        value=json.loads(result.stdout);self.assertEqual(set(value),set(report()))
        self.assertTrue(all(type(v)is int for v in value.values()));self.assertNotIn(b'private',result.stdout)


if __name__=='__main__':unittest.main()
