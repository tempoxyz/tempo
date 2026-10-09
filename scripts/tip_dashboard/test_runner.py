"""Collector regression cases: only actual completed attempts can supply evidence."""
import json
from pathlib import Path
import sys
import unittest
import tempfile
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).parent))
import run_pilot
from run_pilot import parse_attempt


class RunnerTests(unittest.TestCase):
    def marker(self, **overrides):
        data = {"requirement": "TIP-1116:R1", "case": "trailing_at", "test": "spec_dashboard_abi", "fork": "T12"}
        data.update(overrides)
        return "TIP_EVIDENCE " + json.dumps(data) + "\n"

    def good(self):
        return self.marker() + "test result: ok. 1 passed; 0 failed; 0 ignored; 17 filtered out; finished in 0.01s\n"

    def test_uninstrumented_main_never_builds_or_reuses_old_evidence(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / 'evidence.json'
            output.write_text('{"old_green": true}')
            with patch.object(run_pilot.report, 'evidence_context', return_value={'identity': {'sha': 'a' * 40}}), patch.object(run_pilot.report, 'Snapshot'), patch.object(run_pilot.report, 'scan', return_value=([], [])), patch.object(run_pilot, 'execute') as execute:
                self.assertEqual(run_pilot.main(['--repo', directory, '--output', str(output)]), 1)
            execute.assert_not_called()
            data = json.loads(output.read_text())
            self.assertNotIn('old_green', data)
            self.assertEqual(data['attempts'], [])
            self.assertIn('No annotated assertions', data['errors'][0])

    def test_real_attempt(self):
        result = parse_attempt(self.good(), "dispatch::tests::spec_dashboard_abi", 0)
        self.assertEqual(result["outcome"], "passed")
        self.assertEqual(len(result["markers"]), 1)

    def test_full_test_identity_is_retained(self):
        log = self.marker(test="dispatch::tests::spec_dashboard_abi") + "test result: ok. 1 passed; 0 failed; 0 ignored;"
        result = parse_attempt(log, "dispatch::tests::spec_dashboard_abi", 0)
        self.assertEqual(result["outcome"], "passed")
        self.assertEqual(result["markers"][0]["test"], result["test"])

    def test_marker_followed_by_failure_never_passes(self):
        result = parse_attempt(self.good(), "spec_dashboard_abi", 101)
        self.assertEqual(result["outcome"], "failed")

    def test_timeout_cannot_pass(self):
        self.assertEqual(parse_attempt(self.good(), "spec_dashboard_abi", 0, True)["outcome"], "failed")

    def test_zero_tests_cannot_pass(self):
        log = self.marker() + "test result: ok. 0 passed; 0 failed; 0 ignored;"
        self.assertEqual(parse_attempt(log, "spec_dashboard_abi", 0)["outcome"], "failed")

    def test_ignored_test_cannot_pass(self):
        log = self.marker() + "test result: ok. 0 passed; 0 failed; 1 ignored;"
        self.assertEqual(parse_attempt(log, "spec_dashboard_abi", 0)["outcome"], "failed")

    def test_early_return_has_no_case_evidence(self):
        result = parse_attempt("test result: ok. 1 passed; 0 failed; 0 ignored;", "spec_dashboard_abi", 0)
        self.assertEqual(result["markers"], [])

    def test_other_test_marker_invalidates_attempt(self):
        log = self.good() + self.marker(test="another_test")
        self.assertEqual(parse_attempt(log, "spec_dashboard_abi", 0)["outcome"], "failed")

    def test_malformed_marker_cannot_pass(self):
        self.assertEqual(parse_attempt(self.good() + "TIP_EVIDENCE {bad}\n", "spec_dashboard_abi", 0)["outcome"], "failed")


if __name__ == "__main__":
    unittest.main()
