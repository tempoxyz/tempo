#!/usr/bin/env python3
"""Range-selection fixtures and a mocked replay-script preflight."""

import importlib.util
import json
import os
from pathlib import Path
import shlex
import subprocess
import tempfile
import unittest

SCRIPTS = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("snapshot", SCRIPTS / "bench-replay-snapshot.py")
snapshot = importlib.util.module_from_spec(spec)
spec.loader.exec_module(snapshot)
LISTING = """[2026-10-02 00:00:00 UTC] 0B tempo-4217-42228813-100/
[2026-10-02 01:00:00 UTC] 0B tempo-4217-42254715-200/
[2026-10-02 02:00:00 UTC] 0B tempo-4217-42278000-300/
[2026-10-02 02:00:00 UTC] 1MB tempo-4217-42279000-400.tar.lz4
[2026-10-02 02:00:00 UTC] 0B tempo-42431-10000000-400/
"""
HEAD = json.dumps({"jsonrpc": "2.0", "result": hex(42291673), "id": 1})


class SnapshotTests(unittest.TestCase):
    def choose(self, listing=LISTING, response=HEAD, blocks=50000, warmup=12500):
        return snapshot.select_snapshot(listing, "tempo-4217-", response, blocks, warmup)

    def test_failed_live_window_selects_older_available_snapshot(self):
        self.assertEqual(self.choose(), ("tempo-4217-42228813-100", 42291673, 42228814, 42291313))

    def test_short_window_keeps_second_newest(self):
        self.assertEqual(self.choose(blocks=20000, warmup=5000)[0], "tempo-4217-42254715-200")

    def test_numeric_order_and_inclusive_boundary(self):
        listing = "tempo-4217-9-10/\ntempo-4217-100-30/\ntempo-4217-10-20/\n"
        self.assertEqual(self.choose(listing, '{"result":"0x14"}', 8, 2)[0], "tempo-4217-10-20")
        self.assertEqual(self.choose(listing, '{"result":"0x13"}', 8, 2)[0], "tempo-4217-9-10")

    def test_newest_is_excluded_even_when_it_fits(self):
        self.assertEqual(self.choose(response='{"result":"0x3000000"}')[0], "tempo-4217-42254715-200")

    def test_missing_source_capacity(self):
        with self.assertRaisesRegex(ValueError, "No snapshot excluding the newest"):
            self.choose(response='{"result":"0x100"}')

    def test_invalid_source_responses(self):
        for response in ('{"error":{"code":-32001}}', 'null', '{}', '{"result":42}',
                         '{"result":"0x"}', '{"result":"latest"}', 'invalid'):
            with self.subTest(response=response), self.assertRaises(ValueError):
                self.choose(response=response)

    def test_snapshot_count_and_negative_window(self):
        with self.assertRaisesRegex(ValueError, "at least 2 snapshots"):
            self.choose(listing="tempo-4217-10-20/\ntempo-4217-10-20/\n")
        with self.assertRaisesRegex(ValueError, "non-negative"):
            self.choose(warmup=-1)

    def test_full_script_checks_range_before_build_or_download(self):
        with tempfile.TemporaryDirectory(prefix="tempo-replay-preflight-") as directory:
            root = Path(directory)
            tools = root / "bin"
            tools.mkdir()
            listing = root / "listing"
            listing.write_text(LISTING)
            response = root / "response"
            cargo_called = root / "cargo-called"
            commands = {
                "nu": "printf 'SCHELK_MOUNT=/unused\\n'",
                "mc": 'test "$1" = ls || exit 98\ncat ' + shlex.quote(str(listing)),
                "curl": "cat " + shlex.quote(str(response)),
                "cargo": "touch " + shlex.quote(str(cargo_called)) + "\nexit 99",
            }
            for name, body in commands.items():
                path = tools / name
                path.write_text("#!/bin/sh\n" + body + "\n")
                path.chmod(0o700)
            env = {**os.environ, "PATH": str(tools) + os.pathsep + os.environ["PATH"],
                   "CARGO_HOME": str(root / "cargo"),
                   "BENCHMARK_ID": "snapshot-test", "BENCH_BLOCKS": "50000",
                   "BENCH_WARMUP_BLOCKS": "12500", "BENCH_WORK_DIR": str(root / "work")}
            for source, expected in [('{"result":"0x100"}', 1), ('{"error":{}}', 1), (HEAD, 99)]:
                with self.subTest(response=source):
                    response.write_text(source)
                    result = subprocess.run(["bash", str(SCRIPTS / "bench-tempo-replay.sh")],
                                            env=env, text=True, capture_output=True)
                    self.assertEqual(result.returncode, expected, result.stderr[-3000:])
                    self.assertEqual(cargo_called.exists(), expected == 99)
                    if expected == 99:
                        self.assertIn("Selected snapshot: tempo-4217-42228813-100", result.stdout)


if __name__ == "__main__":
    unittest.main()
