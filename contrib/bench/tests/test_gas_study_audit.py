"""Offline report-consistency checks; no RPC or external writes."""

import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

spec = importlib.util.spec_from_file_location("audit", Path(__file__).parents[1] / "gas-study-audit.py")
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class GasStudyAuditTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name)
        self.summary = {"config": {"run_pairs": 1}, "per_run": []}
        self.raw = {}
        for label in ("baseline-1", "feature-1"):
            self.raw[label] = {"failed": 0, "blocks": [
                {"number": 1, "tx_count": 2, "ok_count": 2, "err_count": 0, "gas_used": 42000},
                {"number": 2, "tx_count": 3, "ok_count": 3, "err_count": 0, "gas_used": 63000},
            ]}
            self.summary["per_run"].append({
                "label": label, "summary_warmup_blocks": 1, "blocks": 1,
                "total_tx": 3, "ok": 3, "err": 0, "total_gas": 63000,
                "receipt_outcomes_complete": True,
            })

    def run_audit(self):
        (self.path / "summary.json").write_text(json.dumps(self.summary))
        for label, raw in self.raw.items():
            (self.path / f"report-{label}.json").write_text(json.dumps(raw))
        return module.audit(self.path)

    def test_consistent_is_not_pricing_ready(self):
        result = self.run_audit()
        self.assertTrue(result["ordinary_workload_data_valid"])
        self.assertFalse(result["pricing_ready"])

    def test_revert_in_warmup_is_still_rejected(self):
        self.raw["baseline-1"]["blocks"][0].update(ok_count=1, err_count=1)
        self.assertFalse(self.run_audit()["ordinary_workload_data_valid"])

    def test_missing_receipts(self):
        del self.raw["baseline-1"]["blocks"][0]["ok_count"]
        self.assertFalse(self.run_audit()["ordinary_workload_data_valid"])

    def test_summary_omission(self):
        self.summary["per_run"].pop()
        self.assertFalse(self.run_audit()["ordinary_workload_data_valid"])

    def test_empty_requested_pairs(self):
        self.summary["config"]["run_pairs"] = 0
        self.summary["per_run"] = []
        self.assertFalse(self.run_audit()["ordinary_workload_data_valid"])

    def test_summary_mismatch(self):
        self.summary["per_run"][0]["total_gas"] = 63001
        self.assertFalse(self.run_audit()["ordinary_workload_data_valid"])

    def test_failed_submission(self):
        self.raw["baseline-1"]["failed"] = 1
        self.assertFalse(self.run_audit()["ordinary_workload_data_valid"])

    def test_boolean_count(self):
        self.raw["baseline-1"]["blocks"][0]["ok_count"] = True
        self.assertFalse(self.run_audit()["ordinary_workload_data_valid"])

    def test_block_gap(self):
        self.raw["baseline-1"]["blocks"][1]["number"] = 3
        self.assertFalse(self.run_audit()["ordinary_workload_data_valid"])


if __name__ == "__main__":
    unittest.main()
