# /// script
# dependencies = ["pyyaml>=6,<7"]
# ///
"""Test the workflow's actual cleanup script inside disposable fixtures.

Run with: uv run .github/scripts/test-bench-e2e-cleanup.py
"""

import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

import yaml


WORKFLOW = Path(__file__).parents[1] / "workflows/bench-e2e.yml"
STEPS = yaml.safe_load(WORKFLOW.read_text())["jobs"]["bench-e2e"]["steps"]
CLEANUP = next(step for step in STEPS if step.get("name") == "Clean up benchmark files")
GENERATED = (".bench-worktrees", ".bench-tmp", "target", "localnet", "valscope/target",
             "tempo-bench-valscope-static", "bench-results")


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
        (self.job_temp / ".hidden-profile").touch()
        for path in GENERATED:
            directory = self.workspace / path
            directory.mkdir(parents=True)
            (directory / "data").touch()
        (self.workspace / "report.json").touch()
        (self.workspace / "source.rs").touch()
        (self.workspace / "valscope/.git").mkdir()
        self.env_file = self.root / "github-env"

        # Mock only privilege escalation and services; rm operates on real fixtures.
        mock_bin = self.root / "bin"
        mock_bin.mkdir()
        sudo = mock_bin / "sudo"
        sudo.write_text('''#!/bin/bash
if [[ "$1" == systemctl ]]; then
  printf '%s\n' "$*" >> "$CALL_LOG"
  if [[ "$2" == stop ]]; then
    [[ "$3" == 'tempo-e2e-*.scope' ]] || exit 99
    if [[ "${STOP_FAIL_ONCE:-}" == 1 && ! -e "$CALL_LOG.failed" ]]; then
      touch "$CALL_LOG.failed"
      exit 1
    fi
    exit "${STOP_STATUS:-0}"
  fi
  [[ "$2" == kill && "$3" == --kill-whom=all && "$4" == --signal=SIGKILL &&
     "$5" == 'tempo-e2e-*.scope' ]] || exit 99
  exit "${KILL_STATUS:-0}"
fi
if [[ "$1" == rm && "${@: -1}" == "${FAIL_RM_PATH:-}" ]]; then
  exit 1
fi
exec "$@"
''')
        sudo.chmod(0o755)
        mountpoint = mock_bin / "mountpoint"
        mountpoint.write_text('#!/bin/bash\n[[ "${@: -1}" == "${MOUNTED_PATH:-}" ]]\n')
        mountpoint.chmod(0o755)
        self.env = dict(os.environ, GITHUB_WORKSPACE=str(self.workspace),
                        RUNNER_TEMP=str(self.runner_temp), GITHUB_ENV=str(self.env_file),
                        BENCH_JOB_TMPDIR=str(self.job_temp), CALL_LOG=str(self.root / "calls"),
                        PATH=f"{mock_bin}:{os.environ['PATH']}")

    def run_cleanup(self, **overrides):
        return subprocess.run(["bash", "-e", "-c", CLEANUP["run"]],
                              env=dict(self.env, **overrides), cwd=self.runner_temp,
                              capture_output=True, text=True)

    def assert_cleaned(self):
        self.assertFalse(self.job_temp.exists())
        for path in (*GENERATED, "report.json"):
            self.assertFalse((self.workspace / path).exists(), path)
        self.assertTrue((self.unrelated / "keep").exists())

    def test_workflow_cleanup_runs_unconditionally_after_reporting(self):
        self.assertEqual(CLEANUP["if"], "always()")
        self.assertEqual(CLEANUP["working-directory"], "${{ runner.temp }}")
        self.assertEqual(STEPS[-1], CLEANUP)
        self.assertNotIn("BENCH_RESULTS_UPLOADED", CLEANUP.get("env", {}))

    def test_success_removes_generated_files_and_preserves_checkouts(self):
        result = self.run_cleanup()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assert_cleaned()
        self.assertTrue((self.workspace / "source.rs").exists())
        self.assertTrue((self.workspace / ".git").exists())
        self.assertTrue((self.workspace / "valscope/.git").exists())
        self.assertEqual(self.env_file.read_text(), f"TMPDIR={self.runner_temp}\n")

    def test_failed_or_skipped_upload_never_preserves_results(self):
        for outcome in ("failure", "skipped", "cancelled"):
            with self.subTest(outcome=outcome):
                for path in (self.job_temp, self.workspace / "bench-results"):
                    path.mkdir(exist_ok=True)
                    (path / "data").touch()
                # A stale retention variable from an old workflow must have no effect.
                result = self.run_cleanup(BENCH_RESULTS_UPLOADED=outcome)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assert_cleaned()

    def test_failed_checkout_without_git_metadata_still_cleans(self):
        shutil.rmtree(self.workspace / ".git")
        result = self.run_cleanup()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assert_cleaned()

    def test_missing_checkout_still_cleans_temporary_files(self):
        shutil.rmtree(self.workspace)
        result = self.run_cleanup()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assert_cleaned()

    def test_skipped_temp_setup_and_repeated_cleanup(self):
        result = self.run_cleanup(BENCH_JOB_TMPDIR="")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue((self.job_temp / "profile").exists())
        for _ in range(2):
            result = self.run_cleanup()
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assert_cleaned()

    def test_rejects_unscoped_temporary_paths_before_deleting(self):
        for target in ("/tmp", str(self.runner_temp), str(self.unrelated),
                       str(self.job_temp / "../other-job")):
            with self.subTest(target=target):
                self.assertNotEqual(self.run_cleanup(BENCH_JOB_TMPDIR=target).returncode, 0)
                self.assertTrue((self.workspace / "target/data").exists())
                self.assertTrue((self.unrelated / "keep").exists())

    def test_rejects_root_workspace(self):
        self.assertNotEqual(self.run_cleanup(GITHUB_WORKSPACE="/").returncode, 0)
        self.assertTrue((self.job_temp / "profile").exists())

    def test_post_job_environment_write_failure_does_not_skip_cleanup(self):
        self.env_file.mkdir()
        self.assertNotEqual(self.run_cleanup().returncode, 0)
        self.assert_cleaned()

    def test_rejects_symlink_but_cleans_other_targets(self):
        target = self.workspace / "target"
        shutil.rmtree(target)
        target.symlink_to(self.unrelated, target_is_directory=True)
        self.assertNotEqual(self.run_cleanup().returncode, 0)
        self.assertTrue((self.unrelated / "keep").exists())
        self.assertFalse(self.job_temp.exists())
        self.assertFalse((self.workspace / "bench-results").exists())

    def test_rejects_mount_but_cleans_other_targets(self):
        target = self.workspace / "target"
        self.assertNotEqual(self.run_cleanup(MOUNTED_PATH=str(target)).returncode, 0)
        self.assertTrue((target / "data").exists())
        self.assertFalse(self.job_temp.exists())
        self.assertFalse((self.workspace / "bench-results").exists())

    def test_removal_failure_does_not_skip_remaining_cleanup(self):
        target = self.workspace / ".bench-worktrees"
        self.assertNotEqual(self.run_cleanup(FAIL_RM_PATH=str(target)).returncode, 0)
        self.assertTrue(target.exists())
        self.assertFalse((self.workspace / "bench-results").exists())
        self.assertFalse(self.job_temp.exists())
        self.assertTrue((self.unrelated / "keep").exists())

    def test_failed_graceful_stop_falls_back_to_kill_then_cleanup(self):
        result = self.run_cleanup(STOP_FAIL_ONCE="1")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assert_cleaned()
        self.assertEqual((self.root / "calls").read_text().splitlines(), [
            "systemctl stop tempo-e2e-*.scope",
            "systemctl kill --kill-whom=all --signal=SIGKILL tempo-e2e-*.scope",
            "systemctl stop tempo-e2e-*.scope",
        ])

    def test_failed_stop_and_kill_reports_failure_without_unlinking_live_files(self):
        self.assertNotEqual(self.run_cleanup(STOP_STATUS="1", KILL_STATUS="1").returncode, 0)
        self.assertTrue((self.workspace / "target/data").exists())
        self.assertTrue((self.job_temp / "profile").exists())


if __name__ == "__main__":
    unittest.main()
