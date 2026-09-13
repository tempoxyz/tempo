"""Check SQL generation without credentials or external writes."""

import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


class ReceiptUploadTests(unittest.TestCase):
    def generate(self, blocks):
        script = Path(__file__).parents[1] / "upload-clickhouse-txgen.sh"
        generator = script.read_text().split("<< 'PYEOF'\n", 1)[1].split("\nPYEOF", 1)[0]
        with tempfile.TemporaryDirectory() as directory:
            report = Path(directory) / "report.json"
            report.write_text(json.dumps({"blocks": blocks}))
            return subprocess.run(
                [sys.executable, "-c", generator],
                env={**os.environ, "REPORT_PATH": str(report), "BENCH_RUN_LABEL": "baseline-1"},
                capture_output=True,
                text=True,
                check=True,
            )

    def test_known_outcomes_are_preserved(self):
        result = self.generate([{"tx_count": 10, "ok_count": 8, "err_count": 2}])
        self.assertEqual(result.stdout.count("INSERT INTO"), 2)
        self.assertIn(", 10, 8, 2, ", result.stdout)

    def test_no_partial_insert_for_unknown_outcomes(self):
        for block in [
            {"tx_count": 10},
            {"tx_count": 10, "ok_count": 10},
            {"tx_count": 10, "ok_count": 8, "err_count": 1},
            {"tx_count": 10, "ok_count": -1, "err_count": 11},
            {"tx_count": 10, "ok_count": True, "err_count": 9},
        ]:
            with self.subTest(block=block):
                result = self.generate([
                    {"tx_count": 10, "ok_count": 10, "err_count": 0}, block
                ])
                self.assertEqual(result.stdout, "")
                self.assertIn("Skipping report", result.stderr)

    def test_empty_block(self):
        self.assertEqual(self.generate([{"tx_count": 0}]).stdout.count("INSERT INTO"), 2)


if __name__ == "__main__":
    unittest.main()
