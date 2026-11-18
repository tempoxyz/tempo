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

    def test_lagging_finalized_marker_is_not_safety_failure(self):
        self.cluster.highest[0] = 9
        self.cluster.anchors[9] = driver.fingerprint(make_block(9))
        with patch.object(driver, "block", side_effect=lambda url, tag: make_block(8 if tag == "finalized" else int(tag, 16))):
            self.assertTrue(self.cluster.observe())
        self.assertTrue(all(ok for ok, _ in self.calls), self.calls)
        self.assertEqual(self.cluster.highest, [9, 8, 8, 8])
        self.assertEqual(self.cluster.heights, [8, 8, 8, 8])

    def test_lagging_marker_does_not_hide_changed_finalized_checkpoint(self):
        self.cluster.highest[0] = 9
        self.cluster.anchors[9] = driver.fingerprint(make_block(9))
        def block(url, tag):
            return make_block(8 if tag == "finalized" else int(tag, 16),
                              "f" if url == "a" and tag == "0x9" else "a")
        with patch.object(driver, "block", side_effect=block):
            self.cluster.observe()
        self.assertIn((False, "Finalized checkpoints remain immutable"), self.calls)

    def test_recovery_requires_current_catchup_not_historical_high_water(self):
        for catches_up in (False, True):
            with self.subTest(catches_up=catches_up):
                cluster = driver.Cluster(["a", "b", "c", "d"])
                cluster.highest = [9] * 4
                now = [0]
                rounds = [0]
                def observe():
                    rounds[0] += 1
                    # High waters advance, then one node serves an older marker.
                    cluster.highest = [20] * 4
                    cluster.heights = ([21 if rounds[0] > 2 else 13] * 4
                                       if catches_up and rounds[0] > 1 else [12, 12, 12, 8])
                    cluster.successful_receipts = rounds[0]
                    cluster.successful_height = min(cluster.heights)
                    return True
                with patch.object(cluster, "observe", side_effect=observe), \
                        patch.object(driver, "time", types.SimpleNamespace(
                            monotonic=lambda: now[0], sleep=lambda _: now.__setitem__(0, now[0] + 1))), \
                        patch.object(driver, "RECOVERY_TIMEOUT", 4), \
                        patch.object(driver.Cluster, "submit", return_value=True) as send, \
                        patch.object(driver.Path, "write_text"), \
                        patch.object(driver.os, "_exit") as exit_timeline:
                    cluster.recover(None)
                self.assertIn((catches_up, "Cluster resumes finality and successful transactions after faults stop"), self.calls)
                exit_timeline.assert_called_once_with(0 if catches_up else 1)
                self.assertEqual(send.call_count, 1 if catches_up else 0)
                self.calls.clear()

    def test_recovery_does_not_reuse_success_above_lagging_markers(self):
        self.cluster.highest = [9] * 4
        now = [0]
        def observe():
            self.cluster.highest = [20] * 4
            self.cluster.heights = [13] * 4
            self.cluster.successful_receipts = 1
            self.cluster.successful_height = 20
            return True
        with patch.object(self.cluster, "observe", side_effect=observe), \
                patch.object(driver, "time", types.SimpleNamespace(
                    monotonic=lambda: now[0], sleep=lambda _: now.__setitem__(0, now[0] + 1))), \
                patch.object(driver, "RECOVERY_TIMEOUT", 4), \
                patch.object(driver.Cluster, "submit", return_value=True) as send, \
                patch.object(driver.Path, "write_text"), \
                patch.object(driver.os, "_exit") as exit_timeline:
            self.cluster.recover(None)
        self.assertIn((False, "Cluster resumes finality and successful transactions after faults stop"), self.calls)
        send.assert_called_once()
        exit_timeline.assert_called_once_with(1)

    def test_changed_checkpoint_is_safety_failure(self):
        self.cluster.anchors[7] = driver.fingerprint(make_block(7))
        with patch.object(driver, "block", side_effect=lambda url, tag: make_block(8 if tag == "finalized" else int(tag,16), "f")):
            self.cluster.observe()
        self.assertIn((False, "Finalized checkpoints remain immutable"), self.calls)

    def test_unavailable_nodes_do_not_imply_safety_failure(self):
        self.cluster.heights = [8] * 4
        with patch.object(driver, "block", side_effect=driver.RpcError("partition")):
            self.assertFalse(self.cluster.observe())
        self.assertEqual(self.calls, [])
        self.assertEqual(self.cluster.heights, [None] * 4)

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

    def test_follower_is_optional_and_not_a_transaction_endpoint(self):
        self.assertEqual(self.cluster.observed_urls, self.cluster.urls)
        cluster = driver.Cluster(self.cluster.urls, follower_url="follower")
        self.assertEqual(cluster.urls, ["a", "b", "c", "d"])
        self.assertEqual(cluster.observed_urls, ["a", "b", "c", "d", "follower"])
        self.assertEqual(len(cluster.highest), 5)
        cluster.ledger = Mock(submit=Mock(return_value=True))
        for node in range(4):
            cluster.transfers(Mock(draw=Mock(side_effect=[node, 1, 2, 5, 3])))
            self.assertEqual(cluster.ledger.submit.call_args.args, (cluster.urls[node], "transfer", 3, 2, 5))

    def test_lagging_follower_participates_in_same_height_fingerprints(self):
        self.cluster = driver.Cluster(self.cluster.urls, follower_url="follower")
        self.cluster.scanned_height = 7
        for field in (None, "hash", "stateRoot", "receiptsRoot", "transactionsRoot"):
            with self.subTest(field=field):
                self.calls.clear()
                def block(url, tag):
                    value = make_block((8 if url == "follower" else 11)
                                       if tag == "finalized" else int(tag, 16))
                    if url == "follower" and field is not None:
                        value[field] = "0x" + "f" * 64
                    return value
                with patch.object(driver, "block", side_effect=block):
                    self.assertTrue(self.cluster.observe())
                self.assertEqual(self.cluster.heights, [11, 11, 11, 11, 8])
                if field is None:
                    self.assertTrue(all(ok for ok, _ in self.calls), self.calls)
                else:
                    self.assertIn((False, "Validators agree on finalized block and state roots"), self.calls)

    def test_lagging_follower_cannot_change_previously_finalized_checkpoint(self):
        self.cluster = driver.Cluster(self.cluster.urls, follower_url="follower")
        self.cluster.highest[-1] = 9
        self.cluster.anchors[9] = driver.fingerprint(make_block(9))
        def block(url, tag):
            return make_block(8 if tag == "finalized" else int(tag, 16),
                              "f" if url == "follower" and tag == "0x9" else "a")
        with patch.object(driver, "block", side_effect=block):
            self.cluster.observe()
        self.assertIn((False, "Finalized checkpoints remain immutable"), self.calls)

    def test_unavailable_follower_does_not_fail_validator_safety(self):
        self.cluster = driver.Cluster(self.cluster.urls, follower_url="follower")
        self.cluster.scanned_height = 7
        def block(url, tag):
            if url == "follower":
                raise driver.RpcError("partition")
            return make_block(8)
        with patch.object(driver, "block", side_effect=block):
            self.assertFalse(self.cluster.observe())
        self.assertEqual(self.cluster.heights, [8, 8, 8, 8, None])
        self.assertEqual(list(self.cluster.anchors), [8])
        self.assertTrue(all(ok for ok, _ in self.calls), self.calls)

    def test_follower_does_not_replace_validator_agreement_samples(self):
        self.cluster = driver.Cluster(self.cluster.urls, follower_url="follower")
        def block(url, tag):
            if url in ("b", "c", "d"):
                raise driver.RpcError("partition")
            return make_block(8)
        with patch.object(driver, "block", side_effect=block):
            self.assertFalse(self.cluster.observe())
        self.assertEqual(self.calls, [])

    def test_follower_receipts_are_checked_and_unknown_results_retried(self):
        for outcome in ("mismatch", "missing", "unavailable"):
            with self.subTest(outcome=outcome):
                self.calls.clear()
                self.cluster = driver.Cluster(self.cluster.urls, follower_url="follower")
                self.cluster.scanned_height = 7
                def rpc(url, method, params):
                    if url == "follower":
                        if outcome == "missing":
                            return None
                        if outcome == "unavailable":
                            raise driver.RpcError("partition")
                        return {"blockHash": "wrong", "status": "0x1"}
                    return {"blockHash": make_block(8)["hash"], "status": "0x1"}
                with patch.object(driver, "block", return_value=make_block(8, txs=["tx"])), \
                        patch.object(driver, "rpc", side_effect=rpc) as receipts:
                    self.cluster.observe()
                self.assertEqual([call.args[0] for call in receipts.call_args_list],
                                 self.cluster.observed_urls)
                if outcome == "mismatch":
                    self.assertIn((False, "Finalized transaction receipts match their block"), self.calls)
                else:
                    self.assertTrue(all(ok for ok, _ in self.calls), self.calls)
                    self.assertEqual(self.cluster.scanned_height, 7)
                    self.assertEqual(self.cluster.successful_receipts, 0)

    def test_recovery_requires_follower_availability_and_current_catchup(self):
        for follower in ("lagging", "unavailable", "recovers"):
            with self.subTest(follower=follower):
                self.calls.clear()
                cluster = driver.Cluster(self.cluster.urls, follower_url="follower")
                cluster.highest = [9] * 4 + [20]
                now, rounds = [0], [0]
                def observe():
                    rounds[0] += 1
                    height = 25 + rounds[0]
                    current = height if follower == "recovers" and rounds[0] > 1 else 8
                    if follower == "unavailable":
                        current = None
                    cluster.heights = [height] * 4 + [current]
                    cluster.highest = [height] * 4 + [max(20, current or 0)]
                    cluster.successful_height = min(h for h in cluster.heights if h is not None)
                    cluster.successful_receipts = rounds[0]
                    return current is not None
                with patch.object(cluster, "observe", side_effect=observe), \
                        patch.object(driver, "time", types.SimpleNamespace(
                            monotonic=lambda: now[0], sleep=lambda _: now.__setitem__(0, now[0] + 1))), \
                        patch.object(driver, "RECOVERY_TIMEOUT", 4), \
                        patch.object(driver.Cluster, "submit", return_value=True) as send, \
                        patch.object(driver.Path, "write_text"), \
                        patch.object(driver.os, "_exit") as exit_timeline:
                    cluster.recover(None)
                recovered = follower == "recovers"
                self.assertIn((recovered, "Cluster resumes finality and successful transactions after faults stop"), self.calls)
                exit_timeline.assert_called_once_with(0 if recovered else 1)
                if recovered:
                    self.assertEqual(send.call_args.args[0:2], (0, "transfer"))
                    self.assertEqual(rounds[0], 3)
                else:
                    send.assert_not_called()

    def test_readiness_validates_follower_chain_and_finality(self):
        for outcome in ("wrong_chain", "unavailable", "not_finalized"):
            with self.subTest(outcome=outcome):
                cluster = driver.Cluster(self.cluster.urls, follower_url="follower")
                attempts = [0]
                def rpc(url, method, params):
                    if url == "follower":
                        attempts[0] += 1
                        if attempts[0] == 1 and outcome == "wrong_chain":
                            return "0x1"
                        if attempts[0] == 1 and outcome == "unavailable":
                            raise driver.RpcError("partition")
                    return "0x539"
                def block(url, tag):
                    return make_block(1 if url == "follower" and attempts[0] == 1
                                      and outcome == "not_finalized" else 8)
                with patch.object(driver, "rpc", side_effect=rpc), \
                        patch.object(driver, "block", side_effect=block), \
                        patch.object(driver.time, "sleep") as sleep:
                    cluster.wait_ready()
                self.assertEqual(attempts[0], 2)
                sleep.assert_called_once_with(1)

    def test_workload_baselines_ledger_after_follower_setup_tail(self):
        urls = ["a", "b", "c", "d"]
        cluster = driver.Cluster(urls, follower_url="follower")
        follower_reads = [0]
        def block(url, tag):
            if url == "follower" and tag == "finalized":
                follower_reads[0] += 1
                return make_block(7 if follower_reads[0] == 1 else 8)
            return make_block(8)
        with patch.dict(os.environ, {"RPC_URLS": ",".join(urls), "FOLLOWER_RPC_URL": "follower"}), \
                patch.object(driver, "Cluster", return_value=cluster) as constructor, \
                patch.object(cluster, "wait_ready"), \
                patch.object(driver, "block", side_effect=block) as blocks, \
                patch.object(driver, "Ledger") as ledger, \
                patch.object(driver.time, "sleep") as sleep, \
                patch.object(driver.Path, "exists", return_value=True), \
                patch.object(driver.Path, "touch"), \
                patch.object(driver.lifecycle, "setup_complete") as setup, \
                patch.object(driver.assertions, "reachable"), \
                patch.object(driver.hegel, "run_state_machine"):
            driver.workload.__wrapped__(None)
        constructor.assert_called_once_with(urls, follower_url="follower", ledger=ledger.return_value)
        ledger.return_value.baseline.assert_called_once_with("a", 8)
        self.assertEqual(set(call.args[0] for call in blocks.call_args_list), set(urls + ["follower"]))
        sleep.assert_called_once_with(0.2)
        self.assertEqual(setup.call_args.args[0]["validators"], 4)
        self.assertEqual(setup.call_args.args[0]["followers"], 1)



class LedgerModel(unittest.TestCase):
    def setUp(self):
        self.checks = []
        for name in ("always", "sometimes"):
            patcher = patch.object(driver.assertions, name, side_effect=lambda ok, msg, details=None: self.checks.append((ok, msg)))
            patcher.start()
            self.addCleanup(patcher.stop)
        keys = {index: Mock(address="0x" + format(index, "040x")) for index in (driver.ISSUER, *driver.TRACKED)}
        self.ledger = driver.Ledger(keys)
        self.ledger.expected = {index: 100 for index in driver.TRACKED}
        self.ledger.supply = 10_000
        self.ledger.height = 10
        self.receipts = {}
        self.chain = {"balances": dict(self.ledger.expected), "supply": 10_000}

    def rpc(self, url, method, params):
        if method == "eth_getTransactionReceipt":
            return self.receipts.get(params[0])
        raise AssertionError(method)

    def block(self, url, tag):
        number = int(tag, 16)
        return make_block(number, txs=[txhash for txhash, receipt in self.receipts.items()
                                       if int(receipt["blockNumber"], 16) == number])

    def check(self, height):
        with patch.object(driver, "rpc", side_effect=self.rpc), \
                patch.object(driver, "block", side_effect=self.block), \
                patch.object(self.ledger, "read", return_value=(dict(self.chain["balances"]), self.chain["supply"])) as read:
            self.ledger.check("a", height)
        return read

    def test_finalized_transfer_and_mint_are_applied(self):
        self.ledger.pending = {"t": dict(kind="transfer", sender=1, nonce=0, recipient=2, amount=30),
                               "m": dict(kind="mint", sender=0, nonce=0, recipient=3, amount=5)}
        self.receipts = {"t": {"blockNumber": "0xb", "status": "0x1"}, "m": {"blockNumber": "0xb", "status": "0x1"}}
        self.chain["balances"].update({1: 70, 2: 130, 3: 105})
        self.chain["supply"] = 10_005
        self.check(11)
        self.assertIn((True, "Token balances and supply match the finalized ledger"), self.checks)
        self.assertEqual(self.ledger.pending, {})

    def test_receipt_above_finalized_height_waits(self):
        self.ledger.pending = {"t": dict(kind="transfer", sender=1, nonce=0, recipient=2, amount=30)}
        self.receipts = {"t": {"blockNumber": "0xc", "status": "0x1"}}
        self.check(11)
        self.assertIn((True, "Token balances and supply match the finalized ledger"), self.checks)
        self.assertIn("t", self.ledger.pending)

    def test_lost_balance_is_a_safety_failure(self):
        self.chain["balances"][4] = 99
        self.check(11)
        self.assertIn((False, "Token balances and supply match the finalized ledger"), self.checks)

    def test_unminted_supply_is_a_safety_failure(self):
        self.chain["supply"] = 10_001
        self.check(11)
        self.assertIn((False, "Token balances and supply match the finalized ledger"), self.checks)

    def test_replaced_nonce_is_dropped_not_applied(self):
        self.ledger.pending = {"a": dict(kind="transfer", sender=1, nonce=3, recipient=2, amount=30),
                               "b": dict(kind="transfer", sender=1, nonce=3, recipient=4, amount=7)}
        self.receipts = {"b": {"blockNumber": "0xb", "status": "0x1"}}
        self.chain["balances"].update({1: 93, 4: 107})
        self.check(11)
        self.assertIn((True, "Token balances and supply match the finalized ledger"), self.checks)
        self.assertEqual(self.ledger.pending, {})

    def test_reverted_transaction_changes_nothing(self):
        self.ledger.pending = {"t": dict(kind="transfer", sender=1, nonce=0, recipient=2, amount=30)}
        self.receipts = {"t": {"blockNumber": "0xb", "status": "0x0"}}
        self.check(11)
        self.assertIn((True, "Token balances and supply match the finalized ledger"), self.checks)

    def test_lost_transactions_do_not_block_settling_or_sends(self):
        # Transactions dropped from restarted pools never get receipts.
        self.ledger.pending = {f"lost{i}": dict(kind="transfer", sender=1 + i % 16, nonce=i, recipient=2, amount=1)
                               for i in range(1000)}
        self.ledger.pending["t"] = dict(kind="transfer", sender=1, nonce=5000, recipient=2, amount=30)
        self.receipts = {"t": {"blockNumber": "0xb", "status": "0x1"}}
        self.chain["balances"].update({1: 70, 2: 130})
        self.check(11)
        self.assertIn((True, "Token balances and supply match the finalized ledger"), self.checks)
        self.assertNotIn("t", self.ledger.pending)
        self.assertNotIn("lost0", self.ledger.pending)
        self.assertIn("lost1", self.ledger.pending)
        self.assertFalse(hasattr(driver, "MAX_PENDING"))

    def test_settling_is_bounded_per_check(self):
        read = self.check(10 + driver.SETTLE_BLOCKS + 50)
        self.assertEqual(self.ledger.height, 10 + driver.SETTLE_BLOCKS)
        self.assertEqual(read.call_args.args[1], 10 + driver.SETTLE_BLOCKS)

    def test_old_height_is_not_rechecked(self):
        self.check(10)
        self.assertEqual(self.checks, [])

    def test_signs_token_transactions(self):
        keys = driver.Ledger.derive()
        signed = keys[0].sign_transaction({
            "type": 2, "chainId": driver.CHAIN_ID, "nonce": 0, "to": driver.TOKEN, "value": 0,
            "gas": driver.GAS_LIMIT, "maxFeePerGas": 2, "maxPriorityFeePerGas": 0,
            "data": driver.call_data("mint", keys[1].address, 5),
        })
        self.assertTrue(bytes(signed.raw_transaction))

    def test_genesis_accounts_derive_from_localnet_mnemonic(self):
        keys = driver.Ledger.derive()
        self.assertEqual(keys[0].address, "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266")
        self.assertEqual(keys[1].address, "0x70997970C51812dc3A010C7d01b50e0d17dc79C8")


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
        # Four validators and a follower: heads, 2 checkpoints/node, pinned
        # blocks, and 64 blocks with a receipt/node; a burst takes 20 seconds.
        overrun = (5 + 2 * 5 + 5 + 64 * 6) * driver.RPC_TIMEOUT + 20 + 1
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
