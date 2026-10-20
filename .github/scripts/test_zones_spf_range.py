"""Run with python -m unittest discover -s .github/scripts -p 'test_zones_*.py'."""

import json
from pathlib import Path
import runpy
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = runpy.run_path(str(ROOT / "zones/contrib/bench/validate-spf-range.py"))
ZERO_HASH = "0x" + "00" * 32
SUBMITTED_HASH = "0x" + "ab" * 32


class WaitForSubmissionTests(unittest.TestCase):
    def run_wait(self, portal_hashes, *, timeout=120, clock=None):
        commands = []
        hashes = iter(portal_hashes)

        def check_output(command, **_):
            commands.append(command)
            if command[1] == "call":
                return next(hashes) + "\n"
            self.assertEqual(command[:3], ["cast", "block", SUBMITTED_HASH])
            return "7\n"

        wait = SCRIPT["wait_for_submission"]
        with mock.patch("subprocess.check_output", side_effect=check_output), \
                mock.patch("time.sleep"), \
                mock.patch("time.monotonic", side_effect=clock or iter([0.0] * 10)):
            wait(5, "portal", "l1", "zone", timeout)
        return commands

    def test_zero_portal_hash_polls_until_the_first_submission(self):
        commands = self.run_wait([ZERO_HASH, ZERO_HASH, SUBMITTED_HASH])
        self.assertEqual([command[1] for command in commands], ["call", "call", "call", "block"])

    def test_zero_portal_hash_times_out_at_committed_height_zero(self):
        with self.assertRaisesRegex(TimeoutError, r"^Zone block 5 was not submitted; portal is at 0$"):
            self.run_wait([ZERO_HASH] * 2, timeout=10, clock=iter([0.0, 5.0, 10.0]))


class ValidateRangeTests(unittest.TestCase):
    def test_user_transactions_count_only_measured_blocks(self):
        # Setup traffic in block 1 and later traffic in block 5 share batches with the range.
        batches = {
            2: [(1, 2), (2, 0), (3, 1)],
            4: [(4, 0), (5, 3)],
        }

        def generate(cursor, output):
            blocks = [{"number": number, "transactions": ["0x00"] * count}
                      for number, count in batches[cursor]]
            output.write_text(json.dumps({"zoneBlocks": blocks}))

        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "manifest.json"
            with mock.patch("builtins.print"):
                result = SCRIPT["validate_range"](2, 4, output, generate)
            self.assertEqual(json.loads(output.read_text()), result)
        self.assertEqual(result, {
            "status": "complete",
            "from_block": 2,
            "to_block": 4,
            "user_transactions": 1,
            "batches": [{"from_block": 1, "to_block": 3}, {"from_block": 4, "to_block": 5}],
        })


if __name__ == "__main__":
    unittest.main()
