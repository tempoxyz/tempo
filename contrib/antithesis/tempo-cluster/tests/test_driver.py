import importlib.util
import importlib.metadata
import os
from pathlib import Path
import signal
import sys
import tempfile
import types
import unittest
from unittest.mock import Mock, patch

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
        @driver.hegel.test(test_cases=1, phases=[driver.hegel.Phase.generate], database="")
        def run(tc):
            with patch.dict(os.environ, {"ANTITHESIS_SDK_LOCAL_OUTPUT": "/state/sdk.jsonl"}, clear=True), \
                    patch.object(driver.Path, "exists", return_value=False), \
                    patch.object(self.cluster, "recover") as recover:
                self.cluster.recover_with_faults_paused(tc)
                self.assertGreaterEqual(recover.call_count, 1)
                recover.assert_called_with(None)
        run()

    def test_same_receipt_cannot_count_as_new_progress(self):
        with patch.object(driver, "block", return_value=make_block(8, txs=["tx"])), patch.object(driver, "rpc", return_value={"blockHash": "0x"+"a"*64, "status": "0x1"}):
            self.cluster.observe()
            self.cluster.observe()
        self.assertEqual(self.cluster.successful_receipts, 1)
        self.assertEqual(self.cluster.successful_height, 8)


class FaultPause(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.calls = self.root / "calls"
        self.helper = self.root / "stop faults"
        self.cluster = driver.Cluster(["a", "b", "c", "d"])

    def write_helper(self, tail="exit 0"):
        self.helper.write_text(f'#!/bin/sh\nprintf "%s\\n" "$*" >> "{self.calls}"\n{tail}\n')
        self.helper.chmod(0o755)

    def run_scope(self, env, recover):
        # Use the actual pinned engine, not a mock of Machine/invariant. This
        # catches accidental reintroduction of its incompatible pause protocol.
        self.assertEqual(importlib.metadata.version("hegeltest"), "0.4.7")
        @driver.hegel.test(test_cases=1, phases=[driver.hegel.Phase.generate], database="")
        def run(tc):
            with patch.dict(os.environ, env, clear=True), patch.object(self.cluster, "recover", recover):
                self.cluster.recover_with_faults_paused(tc)
        run()

    def test_real_hegel_scope_uses_duration_once_before_recovery_not_pause_flags(self):
        self.write_helper()
        seen = []
        def recover(deadline):
            self.assertEqual(self.calls.read_text().splitlines(), [str(driver.RECOVERY_PAUSE_SECONDS)])
            self.assertGreater(deadline, driver.time.monotonic() + driver.RECOVERY_TIMEOUT)
            seen.append(deadline)
        # If pause_faults=True were still used, this existing but non-executable
        # control path would make libhegel fail before calling the invariant.
        self.run_scope({"ANTITHESIS_STOP_FAULTS": str(self.helper),
                        "ANTITHESIS_FAULT_CONTROL": str(self.calls)}, recover)
        self.assertGreaterEqual(len(seen), 1)
        self.assertEqual(len(set(seen)), 1)
        # Returning/raising from a scope sends no --unpause: lease expiry is
        # platform-owned, so it also works when real recovery uses os._exit.
        self.assertEqual(self.calls.read_text().splitlines(), [str(driver.RECOVERY_PAUSE_SECONDS)])

    def test_real_hegel_scope_helper_error_never_runs_recovery(self):
        self.write_helper("exit 7")
        recover = Mock()
        with self.assertRaisesRegex(driver.FaultControlError, "status 7"):
            self.run_scope({"ANTITHESIS_STOP_FAULTS": str(self.helper)}, recover)
        recover.assert_not_called()

    def test_real_hegel_scope_missing_platform_helper_never_runs_recovery(self):
        recover = Mock()
        with self.assertRaisesRegex(driver.FaultControlError, "requires ANTITHESIS_STOP_FAULTS"):
            self.run_scope({"ANTITHESIS_OUTPUT_DIR": str(self.root),
                            "ANTITHESIS_SDK_LOCAL_OUTPUT": "/state/sdk.jsonl"}, recover)
        recover.assert_not_called()

    def test_real_hegel_scope_helper_timeout_never_runs_recovery(self):
        self.write_helper("/bin/sleep 60")
        recover = Mock()
        with patch.object(driver, "FAULT_CONTROL_TIMEOUT", 0.02):
            with self.assertRaisesRegex(driver.FaultControlError, "status -9"):
                self.run_scope({"ANTITHESIS_STOP_FAULTS": str(self.helper)}, recover)
        recover.assert_not_called()

    def test_explicit_local_output_is_required_to_skip_helper(self):
        with patch.dict(os.environ, {}, clear=True), patch.object(driver.Path, "exists", return_value=False):
            with self.assertRaises(driver.FaultControlError):
                driver.pause_faults_for_recovery()
        with patch.dict(os.environ, {"ANTITHESIS_SDK_LOCAL_OUTPUT": "/state/sdk.jsonl"}, clear=True), \
                patch.object(driver.Path, "exists", return_value=False):
            self.assertIsNone(driver.pause_faults_for_recovery())

    def test_platform_markers_override_local_sdk_output(self):
        for name in ("ANTITHESIS_OUTPUT_DIR", "ANTITHESIS_FAULT_CONTROL", "ANTITHESIS_STOP_FAULTS"):
            with self.subTest(marker=name), \
                    patch.dict(os.environ, {"ANTITHESIS_SDK_LOCAL_OUTPUT": "/state/sdk.jsonl", name: ""}, clear=True), \
                    patch.object(driver.Path, "exists", return_value=False):
                with self.assertRaises(driver.FaultControlError):
                    driver.pause_faults_for_recovery()
        with patch.dict(os.environ, {"ANTITHESIS_SDK_LOCAL_OUTPUT": "/state/sdk.jsonl"}, clear=True), \
                patch.object(driver.Path, "exists", return_value=True):
            with self.assertRaises(driver.FaultControlError):
                driver.pause_faults_for_recovery()

    def test_helper_missing_or_not_executable_is_not_a_local_fallback(self):
        for exists in (False, True):
            if exists:
                self.helper.write_text("#!/bin/sh\nexit 0\n")
            with self.subTest(exists=exists), \
                    patch.dict(os.environ, {"ANTITHESIS_STOP_FAULTS": str(self.helper),
                                            "ANTITHESIS_SDK_LOCAL_OUTPUT": "/state/sdk.jsonl"}, clear=True):
                with self.assertRaisesRegex(driver.FaultControlError, "Could not execute"):
                    driver.pause_faults_for_recovery()

    def test_lease_starts_before_helper_and_covers_recovery_overrun(self):
        # Observe can read 4 heads, 2 checkpoints/node, 4 pinned blocks and
        # 64 (block, receipt) pairs; a final burst is bounded to 20 seconds.
        overrun = (4 + 2 * 4 + 4 + 64 * 2) * driver.RPC_TIMEOUT + 20 + 1
        self.assertGreater(driver.RECOVERY_PAUSE_SECONDS,
                           driver.FAULT_CONTROL_TIMEOUT + driver.RECOVERY_TIMEOUT + overrun)
        self.assertLess(driver.RECOVERY_PAUSE_SECONDS, 86400)
        with patch.dict(os.environ, {"ANTITHESIS_STOP_FAULTS": "helper"}, clear=True), \
                patch.object(driver, "time", types.SimpleNamespace(monotonic=lambda: 100)), \
                patch.object(driver, "command", return_value=0) as command:
            self.assertEqual(driver.pause_faults_for_recovery(), 100 + driver.RECOVERY_PAUSE_SECONDS)
        command.assert_called_once_with(["helper", str(driver.RECOVERY_PAUSE_SECONDS)], driver.FAULT_CONTROL_TIMEOUT)

    def test_recovery_deadline_starts_after_handshake(self):
        self.write_helper()
        now = [100]
        original_command = driver.command
        def handshake(args, timeout):
            status = original_command(args, timeout)
            now[0] = 1000  # Model a long handshake before recovery begins.
            return status
        def observe():
            now[0] += driver.RECOVERY_TIMEOUT + 1
            return False
        original_recover = self.cluster.recover
        ended = []
        def recover(deadline):
            if not ended:
                original_recover(deadline)
                ended.append(True)  # Real recovery exits instead of returning.
        with patch.object(driver, "time", types.SimpleNamespace(monotonic=lambda: now[0], sleep=lambda _: None)), \
                patch.object(driver, "command", side_effect=handshake), \
                patch.object(self.cluster, "observe", side_effect=observe) as observed, \
                patch.object(driver.assertions, "always") as assertion, \
                patch.object(driver.Path, "write_text"), \
                patch.object(driver.os, "_exit") as exit_timeline:
            self.run_scope({"ANTITHESIS_STOP_FAULTS": str(self.helper)}, recover)
        # A deadline based on the request at time 100 would skip all reads at
        # time 1000. The successful handshake must precede starting the timer.
        observed.assert_called_once()
        assertion.assert_called_once()
        self.assertFalse(assertion.call_args.args[0])
        exit_timeline.assert_called_once_with(1)

    def test_normal_rounds_do_not_pause_faults(self):
        with patch.object(self.cluster, "observe"), patch.object(driver, "pause_faults_for_recovery") as pause:
            self.cluster.finalized_state(None)
        pause.assert_not_called()

    def test_expired_lease_is_a_harness_error_not_a_sut_liveness_failure(self):
        now = [10]
        def observe():
            now[0] = 10000
            return False
        with patch.object(driver, "time", types.SimpleNamespace(monotonic=lambda: now[0], sleep=lambda _: None)), \
                patch.object(self.cluster, "observe", side_effect=observe), \
                patch.object(driver.assertions, "always") as assertion:
            with self.assertRaisesRegex(driver.FaultControlError, "exceeded the fault-pause lease"):
                self.cluster.recover(100)
        assertion.assert_not_called()


if __name__ == "__main__":
    unittest.main()
