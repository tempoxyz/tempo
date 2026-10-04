#!/usr/bin/env python3
"""Exercise the replay runner's actual cleanup registration after scope unwind."""

import os
from pathlib import Path
import subprocess
import tempfile
import unittest


class CleanupTests(unittest.TestCase):
    def run_cleanup(self, fail):
        source = Path(__file__).with_name("bench-tempo-replay.sh").read_text()
        registration = source.split("  # Ensure node and tail", 1)[1]
        registration = registration[registration.index("  cleanup_run() {"):]
        registration = registration.split("  # Wait for RPC", 1)[0]
        success = source.split("  # Cleanup (runs via EXIT trap;", 1)[1]
        success = success[success.index("  cleanup_run "):].split("  echo ", 1)[0]
        with tempfile.TemporaryDirectory(prefix="replay-cleanup-") as root:
            trace = Path(root) / "trace"
            # Shell metacharacters and whitespace must remain a single path argument.
            output = str(Path(root) / "output ' ; $(touch injected) \n folder")
            script = """set -euo pipefail
TEMPO_SCOPE=tempo-replay.scope
SCHELK_STATE_PATH=snapshot-state
BENCH_SAMPLY=false
record() { printf '%s\\0' "$@" >> "$TRACE"; }
kill() { record kill "$@"; }
sudo() { record sudo "$@"; }
cleanup_reth_ipc() { record ipc; }
bench_schelk() { record schelk "$@"; }
run_single() {
  local tail_pid=12345 output_dir="$OUTPUT"
""" + registration + ("  return 33\n" if fail else success) + "}\nrun_single\n"
            result = subprocess.run(
                ["bash", "-c", script], cwd=root, capture_output=True, text=True,
                env={**os.environ, "TRACE": str(trace), "OUTPUT": output},
            )
            self.assertEqual(result.returncode, 33 if fail else 0, result.stderr)
            self.assertNotIn("unbound variable", result.stderr)
            calls = trace.read_bytes().decode().split("\0")
            self.assertEqual(calls.count("kill"), 1)
            self.assertEqual(calls[:5], ["kill", "12345", "sudo", "systemctl", "stop"])
            self.assertEqual(calls.count("tempo-replay.scope"), 2)
            self.assertIn(output, calls)
            self.assertEqual(calls[-4:], ["schelk", "cleanup", "snapshot-state", ""])
            self.assertFalse((Path(root) / "injected").exists())

    def test_failure_cleans_up_after_locals_unwind(self):
        self.run_cleanup(fail=True)

    def test_success_cleans_up_once(self):
        self.run_cleanup(fail=False)


if __name__ == "__main__":
    unittest.main()
