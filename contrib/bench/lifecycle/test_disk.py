import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


@unittest.skipUnless(shutil.which('nu'), 'Nushell is required for disk helper tests')
class DiskTests(unittest.TestCase):
    intermediates = ('incremental', 'build', 'deps', '.fingerprint', 'examples')

    def fixture(self, directory, exit_code=0):
        root = Path(directory)
        worktree = root / 'owned-worktree'
        profile = worktree / 'target' / 'profiling'
        profile.mkdir(parents=True)
        binary = profile / 'tempo'
        binary.write_text(f'#!/bin/sh\ntest "$1" = "--version" || exit 2\nexit {exit_code}\n')
        binary.chmod(0o755)
        for name in self.intermediates:
            (profile / name).mkdir()
            (profile / name / 'intermediate').write_text('build output')
        for path in (worktree / 'source.rs', profile / 'unrelated', root / 'shared-cache'):
            path.write_text('keep')
        other = worktree / 'target' / 'other-profile'
        other.mkdir()
        (other / 'unrelated').write_text('keep')
        return worktree, profile, binary

    def trim(self, worktree):
        return subprocess.run(
            ['nu', '--no-config-file', '-c',
             'source disk.nu; lifecycle-trim-worktree $env.LIFECYCLE_TEST_WORKTREE profiling'],
            cwd=Path(__file__).parent,
            env=dict(os.environ, LIFECYCLE_TEST_WORKTREE=str(worktree)),
            capture_output=True, text=True,
        )

    def require_disk(self, available, minimum, df_exit_code=0):
        with tempfile.TemporaryDirectory() as directory:
            mock_df = Path(directory) / 'df'
            mock_df.write_text(
                '#!/bin/sh\n'
                'printf "Filesystem 1048576-blocks Used Available Capacity Mounted on\\n"\n'
                'printf "private-filesystem 1000000 1 %s 1%% /private-mount\\n" "$LIFECYCLE_TEST_AVAILABLE"\n'
                'exit "$LIFECYCLE_TEST_DF_EXIT"\n'
            )
            mock_df.chmod(0o755)
            return subprocess.run(
                ['nu', '--no-config-file', '-c',
                 'source disk.nu; lifecycle-require-disk fixture . '
                 '($env.LIFECYCLE_TEST_MINIMUM | into int); print accepted'],
                cwd=Path(__file__).parent,
                env=dict(os.environ, PATH=directory + os.pathsep + os.environ['PATH'],
                         LIFECYCLE_TEST_AVAILABLE=str(available),
                         LIFECYCLE_TEST_MINIMUM=str(minimum),
                         LIFECYCLE_TEST_DF_EXIT=str(df_exit_code)),
                capture_output=True, text=True,
            )

    def test_build_and_capture_thresholds_accept_exact_headroom(self):
        for minimum in (65536, 49152):
            with self.subTest(minimum=minimum):
                result = self.require_disk(minimum, minimum)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertIn('accepted', result.stdout)
                self.assertIn(f'{minimum} MiB available', result.stdout)
                self.assertNotIn('private-', result.stdout + result.stderr)

    def test_build_and_capture_thresholds_reject_insufficient_headroom(self):
        for minimum in (65536, 49152):
            with self.subTest(minimum=minimum):
                result = self.require_disk(minimum - 1, minimum)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn('Insufficient lifecycle disk space', result.stderr)
                self.assertNotIn('accepted', result.stdout)
                self.assertNotIn('private-', result.stdout + result.stderr)

    def test_failed_disk_inspection_fails_closed(self):
        result = self.require_disk(1000000, 65536, df_exit_code=1)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('Unable to inspect lifecycle disk space', result.stderr)
        self.assertNotIn('accepted', result.stdout)

    def test_invalid_disk_availability_fails_closed(self):
        for available in ('unknown', '-1'):
            with self.subTest(available=available):
                result = self.require_disk(available, 65536)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn('Invalid lifecycle disk-space report', result.stderr)
                self.assertNotIn('accepted', result.stdout)

    def test_trim_preserves_binary_source_other_profile_and_unrelated_files(self):
        with tempfile.TemporaryDirectory() as directory:
            worktree, profile, binary = self.fixture(directory)
            original = binary.read_bytes()
            result = self.trim(worktree)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(binary.read_bytes(), original)
            self.assertEqual(subprocess.run([binary, '--version']).returncode, 0)
            for name in self.intermediates:
                self.assertFalse((profile / name).exists())
            for path in (worktree / 'source.rs', profile / 'unrelated',
                         worktree / 'target' / 'other-profile' / 'unrelated',
                         Path(directory) / 'shared-cache'):
                self.assertEqual(path.read_text(), 'keep')

    def test_failed_binary_verification_deletes_nothing(self):
        with tempfile.TemporaryDirectory() as directory:
            worktree, profile, binary = self.fixture(directory, exit_code=1)
            result = self.trim(worktree)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn('intermediates retained', result.stderr)
            self.assertTrue(binary.exists())
            for name in self.intermediates:
                self.assertEqual((profile / name / 'intermediate').read_text(), 'build output')

    def test_redirected_intermediate_deletes_nothing(self):
        with tempfile.TemporaryDirectory() as directory:
            worktree, profile, _ = self.fixture(directory)
            shared = Path(directory) / 'shared-deps'
            shared.mkdir()
            (shared / 'keep').write_text('keep')
            shutil.rmtree(profile / 'deps')
            (profile / 'deps').symlink_to(shared, target_is_directory=True)
            result = self.trim(worktree)
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual((shared / 'keep').read_text(), 'keep')
            for name in self.intermediates:
                self.assertTrue((profile / name).exists())

    def test_redirected_target_deletes_nothing(self):
        with tempfile.TemporaryDirectory() as directory:
            worktree, _, _ = self.fixture(directory)
            shared = Path(directory) / 'shared-target'
            (worktree / 'target').rename(shared)
            (worktree / 'target').symlink_to(shared, target_is_directory=True)
            result = self.trim(worktree)
            self.assertNotEqual(result.returncode, 0)
            for name in self.intermediates:
                self.assertTrue((shared / 'profiling' / name / 'intermediate').exists())

    def test_binary_linked_into_intermediates_deletes_nothing(self):
        with tempfile.TemporaryDirectory() as directory:
            worktree, profile, binary = self.fixture(directory)
            linked = profile / 'deps' / 'tempo'
            binary.rename(linked)
            binary.symlink_to(linked)
            result = self.trim(worktree)
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(subprocess.run([binary, '--version']).returncode, 0)
            for name in self.intermediates:
                self.assertTrue((profile / name / 'intermediate').exists())


if __name__ == '__main__':
    unittest.main()
