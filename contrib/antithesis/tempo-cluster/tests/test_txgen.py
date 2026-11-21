"""Exercise the burst pipeline without a cluster or fixture setup."""
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

SOURCE = Path(__file__).resolve().parents[1] / "scripts" / "txgen.sh"


class BurstPipeline(unittest.TestCase):
    def run_burst(self, generator_status):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            env_json = root / "env.json"
            env_json.write_text("{}")
            script = root / "txgen.sh"
            script.write_text(SOURCE.read_text().replace("/state/env.json", str(env_json)))
            generator = root / "txgen-tempo"
            generator.write_text(f"#!/bin/sh\nprintf 'transaction\\n'\nexit {generator_status}\n")
            sender = root / "bench"
            sender.write_text('#!/bin/sh\ncat >/dev/null\nprintf "%s\\n" "$@" > "$BENCH_ARGS"\n')
            generator.chmod(0o755)
            sender.chmod(0o755)
            args = root / "bench-args"
            result = subprocess.run(
                ["bash", str(script), "burst", "http://validator-0:8545", "99", str(root / "report.json")],
                env={**os.environ, "PATH": f"{root}:{os.environ['PATH']}", "BENCH_ARGS": str(args)},
                capture_output=True, text=True, timeout=5,
            )
            return result, args.read_text().splitlines()

    def test_burst_leaves_finality_checks_to_driver_not_pool_drain(self):
        result, args = self.run_burst(0)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(args[args.index("--drain-timeout") + 1], "0")
        self.assertIn("--skip-setup", args)

    def test_generator_failure_is_not_hidden_by_successful_sender(self):
        result, _ = self.run_burst(7)
        self.assertEqual(result.returncode, 7, result.stderr)


if __name__ == "__main__":
    unittest.main()
