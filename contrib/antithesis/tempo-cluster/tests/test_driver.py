import importlib.util
from pathlib import Path
import signal
import sys
import unittest
from unittest.mock import patch

SOURCE = Path(__file__).resolve().parents[1] / "driver" / "driver.py"
spec = importlib.util.spec_from_file_location("cluster_driver", SOURCE)
driver = importlib.util.module_from_spec(spec)
spec.loader.exec_module(driver)


def make_block(height, fork="a", txs=None):
    return {"number": hex(height), "hash": "0x" + fork * 64, "stateRoot": "0x" + "b" * 64,
            "receiptsRoot": "0x" + "c" * 64, "transactionsRoot": "0x" + "d" * 64,
            "transactions": txs or []}


class Checks(unittest.TestCase):
    def setUp(self):
        self.calls = []
        self.checks = patch.object(driver.assertions, "always", side_effect=lambda ok, msg, details=None: self.calls.append((ok, msg)))
        self.checks.start()
        self.addCleanup(self.checks.stop)
        self.sometimes = patch.object(driver.assertions, "sometimes")
        self.sometimes.start()
        self.addCleanup(self.sometimes.stop)
        self.cluster = driver.Cluster(["a", "b", "c", "d"])
        self.cluster.scanned_height = 7

    def test_agreement_at_pinned_height_not_simultaneous_tips(self):
        heights = dict(a=8, b=9, c=10, d=11)
        def block(url, tag):
            return make_block(heights[url] if tag == "finalized" else int(tag, 16))
        with patch.object(driver, "block", side_effect=block):
            self.assertTrue(self.cluster.observe())
        self.assertTrue(all(ok for ok, _ in self.calls), self.calls)
        self.assertEqual(list(self.cluster.anchors), [8])

    def test_conflicting_finalized_block_is_safety_failure(self):
        with patch.object(driver, "block", side_effect=lambda url, tag: make_block(8, "f" if url == "d" else "a")):
            self.cluster.observe()
        self.assertIn((False, "Validators agree on finalized block and state roots"), self.calls)

    def test_finalized_regression_is_safety_failure(self):
        self.cluster.highest[0] = 9
        with patch.object(driver, "block", return_value=make_block(8)):
            self.cluster.observe()
        self.assertIn((False, "Finalized height never regresses"), self.calls)

    def test_changed_checkpoint_is_safety_failure(self):
        self.cluster.anchors[7] = driver.fingerprint(make_block(7))
        with patch.object(driver, "block", side_effect=lambda url, tag: make_block(8 if tag == "finalized" else int(tag,16), "f")):
            self.cluster.observe()
        self.assertIn((False, "Finalized checkpoints remain immutable"), self.calls)

    def test_unavailable_nodes_do_not_imply_safety_failure(self):
        with patch.object(driver, "block", side_effect=driver.RpcError("partition")):
            self.assertFalse(self.cluster.observe())
        self.assertEqual(self.calls, [])

    def test_rpc_receipt_mismatch_is_safety_failure(self):
        with patch.object(driver, "block", return_value=make_block(8, txs=["tx"])), patch.object(driver, "rpc", return_value={"blockHash": "wrong", "status": "0x1"}):
            self.cluster.observe()
        self.assertIn((False, "Finalized transaction receipts match their block"), self.calls)

    def test_model_memory_is_bounded(self):
        for height in range(70):
            with patch.object(driver, "block", side_effect=lambda url, tag, h=height: make_block(h if tag == "finalized" else int(tag,16))):
                self.cluster.observe()
        self.assertEqual(len(self.cluster.anchors), 64)

    def test_command_timeout_kills_child_group(self):
        self.assertEqual(driver.command([sys.executable, "-c", "import time; time.sleep(60)"], 0.01), -signal.SIGKILL)

    def test_rpc_error_response_is_unknown_outcome(self):
        class Response:
            def __enter__(self): return self
            def __exit__(self, *args): pass
            def read(self): return b'{"error":{"code":-32000}}'
        with patch.object(driver.urllib.request, "urlopen", return_value=Response()):
            with self.assertRaisesRegex(driver.RpcError, "-32000"):
                driver.rpc("http://example.invalid", "eth_chainId", [])

    def test_block_malformed_response_is_not_agreement_evidence(self):
        with patch.object(driver, "rpc", return_value={"number": "0x1"}):
            with self.assertRaisesRegex(driver.RpcError, "malformed block"):
                driver.block("a", "finalized")

    def test_on_demand_fault_pause_accepts_nested_hegel_machine(self):
        @driver.hegel.test(test_cases=1, phases=[driver.hegel.Phase.generate])
        def run(tc):
            with patch.object(self.cluster, "recover") as recover:
                self.cluster.recover_with_faults_paused(tc)
                self.assertGreaterEqual(recover.call_count, 1)
        run()

    def test_same_receipt_cannot_count_as_new_progress(self):
        with patch.object(driver, "block", return_value=make_block(8, txs=["tx"])), patch.object(driver, "rpc", return_value={"blockHash": "0x"+"a"*64, "status": "0x1"}):
            self.cluster.observe()
            self.cluster.observe()
        self.assertEqual(self.cluster.successful_receipts, 1)
        self.assertEqual(self.cluster.successful_height, 8)


if __name__ == "__main__":
    unittest.main()
