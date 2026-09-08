"""uv run --with pyyaml==6.0.1 python -m unittest discover -s contrib/bench/txgen/gas-calibration -p test_smoke.py"""

from pathlib import Path
import subprocess
import sys
import unittest

import yaml


class SmokeGenerationTests(unittest.TestCase):
    def test_original_family_regenerates_without_access_or_aa(self):
        root = Path(__file__).parent
        generated = yaml.safe_load(subprocess.check_output(
            [sys.executable, str(root / "smoke.py")], text=True
        ))
        committed = yaml.safe_load(
            (root.parent / "presets/gas-calibration-smoke.yml").read_text()
        )
        self.assertEqual(generated, committed)
        mix = generated["merge"]["mix"]
        self.assertEqual(len(mix), 29)
        self.assertEqual(len({row["template"] for row in mix}), 29)
        self.assertTrue(all("access" not in row["template"] for row in mix))


if __name__ == "__main__":
    unittest.main()
