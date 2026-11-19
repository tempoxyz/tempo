"""Run with python -m unittest discover -s .github/scripts -p 'test_reth_bump_ci.py'."""

import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

import yaml

ROOT = Path(__file__).resolve().parents[2]
SHA = "a" * 40
HARNESS = r"""
gh() {
  case "$1 $2" in
    "api repos/tempo/tempo/git/ref/heads/reth-auto-bump") echo "$EXPECTED_SHA" ;;
    "pr list") echo "$PR_DATA" ;;
    "pr checks")
      # specs success is not a branch-protection requirement.
      if [[ " $* " == *" --required "* ]]; then
        jq '[.[] | select(.name != "specs success")]' <<< "$CHECKS"
      else
        echo "$CHECKS"
      fi
      ;;
    *) echo "Unexpected gh arguments: $*" >&2; exit 98 ;;
  esac
}
# Stop at the first retry instead of waiting for the workflow's deadline.
sleep() { exit 99; }
"""


class RethBumpCiTests(unittest.TestCase):
    def run_gate(self, mergeable="MERGEABLE", specs_bucket="pass"):
        workflow = yaml.safe_load(
            (ROOT / ".github/workflows/build-reth-bump-image.yml").read_text()
        )
        script = next(
            step["run"]
            for step in workflow["jobs"]["wait_for_ci"]["steps"]
            if step.get("id") == "ci"
        )
        checks = [
            {"name": name, "bucket": bucket, "state": state}
            for name, bucket, state in [
                ("lint success", "pass", "SUCCESS"),
                ("test success", "pass", "SUCCESS"),
                ("specs success", specs_bucket, "SUCCESS" if specs_bucket == "pass" else "PENDING"),
                ("Review", "pending", "IN_PROGRESS"),
            ]
        ]
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp) / "output"
            output.touch()
            result = subprocess.run(
                ["bash", "-c", HARNESS + script],
                env={
                    **os.environ,
                    "EXPECTED_SHA": SHA,
                    "RETH_BUMP_BRANCH": "reth-auto-bump",
                    "GH_REPO": "tempo/tempo",
                    "GITHUB_OUTPUT": str(output),
                    "PR_DATA": json.dumps({"number": 9289, "headRefOid": SHA, "mergeable": mergeable}),
                    "CHECKS": json.dumps(checks),
                },
                capture_output=True,
                text=True,
                timeout=5,
            )
            return result, output.read_text()

    def test_green_ci_includes_non_required_specs(self):
        result, output = self.run_gate()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(output, "eligible=true\n")

    def test_conflicting_pr_does_not_wait_or_promote(self):
        result, output = self.run_gate(mergeable="CONFLICTING")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(output, "eligible=false\n")
        self.assertIn("has merge conflicts", result.stdout)

    def test_pending_specs_prevents_promotion(self):
        result, output = self.run_gate(specs_bucket="pending")
        self.assertEqual(result.returncode, 99, result.stderr)
        self.assertEqual(output, "")
        self.assertIn("specs success=PENDING", result.stdout)


if __name__ == "__main__":
    unittest.main()
