from pathlib import Path
from unittest.mock import patch
import unittest
from provision import API, BPF_COMPILE, IMPORT, NATIVE, PYTHON, command, setup


class ProvisionTests(unittest.TestCase):
    def run_setup(self, outcomes, mode='true'):
        calls = []
        def run(argv, **options):
            calls.append((argv, options))
            return next(outcomes)
        result = setup({'BENCH_LIFECYCLE_SCHEDULER':mode}, run=run, package_manager=Path(__file__))
        return result, calls

    def test_missing_package_manager_and_command_failure_are_closed(self):
        with patch('provision.Path.is_file',return_value=False):
            self.assertEqual(self.run_setup(iter([True,False,True]))[0], 'scheduler_setup_package_manager')
        with patch('provision.subprocess.run',side_effect=OSError('private runner details')):
            self.assertFalse(command(['unavailable']))

    def test_root_probes_use_owned_scratch_only_when_cleanup_enabled(self):
        with patch('provision.subprocess.run') as run:
            run.return_value.returncode = 0
            with patch.dict('provision.os.environ', {'BENCH_RUN_CLEANUP':'true','TMPDIR':'/owned/scratch path'}, clear=True):
                self.assertTrue(command(NATIVE))
                self.assertEqual(run.call_args.args[0][:5], ['sudo','-n','env','TMPDIR=/owned/scratch path',PYTHON])
            with patch.dict('provision.os.environ', {}, clear=True):
                self.assertTrue(command(NATIVE))
                self.assertEqual(run.call_args.args[0], NATIVE)

    def test_normal_mode_never_checks_or_installs(self):
        for mode in ('false','', 'lifecycle'):
            self.assertEqual(self.run_setup(iter([]),mode), ('scheduler_setup_skipped',[]))

    def test_present_dependencies_do_not_install(self):
        result,calls = self.run_setup(iter([True]*7))
        self.assertEqual(result,'scheduler_setup_ready')
        self.assertEqual([command for command,_ in calls], [['sudo','-n','true'],IMPORT,NATIVE,IMPORT,NATIVE,API,BPF_COMPILE])
        self.assertTrue(all(PYTHON in command for command,_ in calls[1:]))

    def test_missing_bcc_installs_only_distro_bcc_packages(self):
        result,calls = self.run_setup(iter([True,False,True,True,True,True,True,True,True]))
        self.assertEqual(result,'scheduler_setup_ready')
        install = next(command for command,_ in calls if 'install' in command)
        self.assertEqual(install[-2:],['python3-bpfcc','libbpfcc'])
        self.assertIn('NEEDRESTART_MODE=l',install)
        self.assertIn('--no-install-recommends',install)
        self.assertNotIn('gcc',install)

    def test_missing_compiler_installs_only_c_support(self):
        result,calls = self.run_setup(iter([True,True,False,True,True,True,True,True,True]))
        self.assertEqual(result,'scheduler_setup_ready')
        self.assertEqual(next(c for c,_ in calls if 'install' in c)[-2:],['gcc','libc6-dev'])

    def test_closed_failures_never_continue_to_capture(self):
        for outcomes, expected in [
            ([False], 'scheduler_setup_root'),
            ([True,False,True,False], 'scheduler_setup_packages'),
            ([True,False,True,True,False], 'scheduler_setup_packages'),
            ([True,True,True,False], 'scheduler_setup_bcc_import'),
            ([True,True,True,True,False], 'scheduler_setup_native_compile'),
            ([True,True,True,True,True,False], 'scheduler_setup_bcc_api'),
            ([True,True,True,True,True,True,False], 'scheduler_setup_bpf_compile')]:
            with self.subTest(expected=expected):
                self.assertEqual(self.run_setup(iter(outcomes))[0],expected)


if __name__=='__main__':
    unittest.main()
