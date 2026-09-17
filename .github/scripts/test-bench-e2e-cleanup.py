"""Exercise destructive cleanup only inside disposable fixture directories.

Run with: uv run python .github/scripts/test-bench-e2e-cleanup.py
"""

import os
from pathlib import Path
import subprocess
import tempfile
import unittest


SCRIPT = Path(__file__).with_name("bench-e2e-cleanup.sh")


class CleanupTest(unittest.TestCase):
    def setUp(self):
        self.scratch = tempfile.TemporaryDirectory(prefix="test-bench-cleanup-")
        self.addCleanup(self.scratch.cleanup)
        self.root = Path(self.scratch.name)
        self.workspace = self.root / "checkout"
        self.workspace.mkdir()
        subprocess.run(["git", "init", "-q", str(self.workspace)], check=True)
        self.runner_temp = self.root / "runner-temp"
        self.runner_temp.mkdir()
        self.job_temp = self.runner_temp / "tempo-bench-e2e.fixture"
        self.job_temp.mkdir()
        self.unrelated = self.runner_temp / "other-job"
        self.unrelated.mkdir()
        (self.unrelated / "keep").touch()
        (self.job_temp / "profile").touch()
        for path in (".bench-worktrees", ".bench-tmp", "target", "localnet",
                     "valscope/target", "tempo-bench-valscope-static", "bench-results"):
            directory = self.workspace / path
            directory.mkdir(parents=True)
            (directory / "data").touch()
        (self.workspace / "source.rs").touch()
        (self.workspace / "valscope/.git").mkdir()

        # Keep privilege escalation and host service management out of tests.
        mock_bin = self.root / "bin"
        mock_bin.mkdir()
        sudo = mock_bin / "sudo"
        sudo.write_text('#!/bin/bash\n'
                        'if [[ "$1" == systemctl ]]; then\n'
                        '  [[ "$2" == stop && "$3" == "tempo-e2e-*.scope" ]] || exit 99\n'
                        '  exit "${STOP_STATUS:-0}"\n'
                        'fi\n'
                        'exec "$@"\n')
        sudo.chmod(0o755)
        self.env = dict(os.environ, GITHUB_WORKSPACE=str(self.workspace),
                        RUNNER_TEMP=str(self.runner_temp),
                        BENCH_JOB_TMPDIR=str(self.job_temp),
                        BENCH_RESULTS_UPLOADED="success",
                        PATH=f"{mock_bin}:{os.environ['PATH']}")

    def run_cleanup(self, **overrides):
        return subprocess.run(["bash", str(SCRIPT)], env=dict(self.env, **overrides),
                              capture_output=True, text=True)

    def test_success_removes_generated_files_and_preserves_checkouts(self):
        result = self.run_cleanup()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(self.job_temp.is_dir())
        self.assertEqual(list(self.job_temp.iterdir()), [])
        self.assertFalse((self.workspace / "target").exists())
        self.assertFalse((self.workspace / ".bench-worktrees").exists())
        self.assertFalse((self.workspace / "bench-results").exists())
        self.assertTrue((self.workspace / "source.rs").exists())
        self.assertTrue((self.workspace / ".git").exists())
        self.assertTrue((self.workspace / "valscope/.git").exists())
        self.assertTrue((self.unrelated / "keep").exists())

    def test_failed_or_skipped_upload_preserves_results(self):
        for outcome in ("failure", "skipped", "cancelled"):
            with self.subTest(outcome=outcome):
                result = self.run_cleanup(BENCH_RESULTS_UPLOADED=outcome)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertTrue((self.workspace / "bench-results/data").exists())

    def test_rejects_unscoped_temporary_paths_before_deleting(self):
        for target in ("/tmp", str(self.runner_temp), str(self.unrelated),
                       str(self.job_temp / "../other-job")):
            with self.subTest(target=target):
                self.assertNotEqual(self.run_cleanup(BENCH_JOB_TMPDIR=target).returncode, 0)
                self.assertTrue((self.workspace / "target/data").exists())
                self.assertTrue((self.unrelated / "keep").exists())

    def test_rejects_symlinked_cleanup_target(self):
        target = self.workspace / "target"
        (target / "data").unlink()
        target.rmdir()
        target.symlink_to(self.unrelated, target_is_directory=True)
        self.assertNotEqual(self.run_cleanup().returncode, 0)
        self.assertTrue((self.unrelated / "keep").exists())
        self.assertTrue((self.job_temp / "profile").exists())

    def test_failed_process_stop_prevents_deletion(self):
        self.assertNotEqual(self.run_cleanup(STOP_STATUS="1").returncode, 0)
        self.assertTrue((self.workspace / "target/data").exists())
        self.assertTrue((self.job_temp / "profile").exists())


if __name__ == "__main__":
    unittest.main()
