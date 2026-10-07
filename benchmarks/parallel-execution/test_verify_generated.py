#!/usr/bin/env python3
"""Small deterministic RPC/log fixtures for the live generated correctness gate."""

import copy
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

SPEC = importlib.util.spec_from_file_location("verify_generated", Path(__file__).with_name("verify_generated.py"))
verify = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(verify)


def digest(number):
    return f"0x{number:064x}"


def event(message, fields=None, spans=None, second=2):
    return {"timestamp": f"2026-10-03T00:00:{second:02d}.000000Z", "level": "DEBUG",
            "fields": {"message": message, **(fields or {})}, "spans": spans or []}


def engine_span(block):
    return {"name": "insert_block_or_payload", "block_id":
            f"BlockWithParent {{ parent: {block['parentHash']}, block: NumHash {{ "
            f"number: {int(block['number'], 16)}, hash: {block['hash']} }} }}"}


class FakeRpc:
    def __init__(self, blocks, receipt_blocks):
        self.blocks, self.receipt_blocks = copy.deepcopy(blocks), copy.deepcopy(receipt_blocks)
        self.finalized = max(blocks)
        self.reads = {}
        self.replace_on_recheck = False

    def __call__(self, method, params):
        if method == "eth_getBlockByNumber":
            if params[0] == "finalized":
                return copy.deepcopy(self.blocks[self.finalized])
            number = int(params[0], 16)
            self.reads[number] = self.reads.get(number, 0) + 1
            block = copy.deepcopy(self.blocks[number])
            if self.replace_on_recheck and number == self.finalized and self.reads[number] > 1:
                block["hash"] = digest(999999)
            return block
        if method == "eth_getBlockReceipts":
            return copy.deepcopy(self.receipt_blocks[int(params[0], 16)])
        raise AssertionError(method)


class GeneratedTests(unittest.TestCase):
    def setUp(self):
        self.config = {"mode": "sequential-peer", "phase": "feature-1", "feature_ref": "a" * 40,
                       "binary_sha256": "b" * 64}
        for role, threads, port in (("a", "8", 8545), ("b", "0", 8645)):
            self.config[role] = {"rpc_url": f"http://127.0.0.1:{port}", "log_dir": f"/logs/{role}",
                "args": ["node", "--execution.threads", threads, "--log.file.format", "json"]}
        self.build_chain()

    def build_chain(self, transaction_counts=(6, 6, 6, 6, 6)):
        blocks, receipt_blocks, report_blocks = {}, {}, []
        self.events = [[], []]
        for number, count in enumerate((0, *transaction_counts)):
            txs = [digest(1000 + 1024 * number + index) for index in range(count)]
            block = {"number": hex(number), "hash": digest(number + 1), "parentHash": digest(number),
                     "stateRoot": digest(100 + number), "receiptsRoot": digest(200 + number),
                     "timestamp": hex(number), "timestampMillisPart": "0x0", "gasUsed": hex(21 * len(txs)),
                     "transactions": txs}
            blocks[number] = block
            receipt_blocks[number] = [{"transactionHash": tx, "transactionIndex": hex(index),
                "blockHash": block["hash"], "blockNumber": block["number"], "status": "0x1", "type": "0x76",
                "logs": [], "logsBloom": "0x" + "00" * 256, "gasUsed": hex(21),
                "cumulativeGasUsed": hex(21 * (index + 1)), "feeToken": "0x" + "11" * 20}
                for index, tx in enumerate(txs)]
            if number:
                report_blocks.append({"number": number, "tx_count": len(txs),
                                      "gas_used": 21 * len(txs), "timestamp_ms": number * 1000})
                owner = number % 2
                payload = f"0x{number:016x}"
                build_spans = [{"name": "build_payload", "id": payload, "parent_hash": block["parentHash"]}]
                self.events[owner].append(event("building new payload", spans=build_spans, second=0))
                self.events[owner].append(event("Built payload", {"number": number, "hash": block["hash"],
                    "parent_hash": block["parentHash"], "total_transactions": len(txs),
                    "pool_transactions_included": len(txs), "pool_transactions_yielded": len(txs),
                    "invalid_pool_transaction_execution_attempts": 0}, build_spans))
                self.events[1 - owner].append(event("Executed block", spans=[engine_span(block)]))
                self.events[1 - owner].append(event("execution layer reported payload status",
                    {"payload_status": f"PayloadStatus {{ status: VALID, latestValidHash: Some({block['hash']}) }}"},
                    [{"name": "execute_delivery", "block.digest": block["hash"]}], second=3))
                stats_spans = build_spans if owner == 0 else [engine_span(block)]
                self.events[0].append(event("Finished speculative block execution",
                    {"stats": "ExecutionStats { speculated: 6, reused: 3, bodies_reused: 0 }"}, stats_spans, second=1))
        self.report = {"metadata": {"measurement_send_start_unix_ms": "2000"}, "blocks": report_blocks}
        self.rpcs = [FakeRpc(blocks, receipt_blocks), FakeRpc(blocks, receipt_blocks)]

    def logs(self):
        return [verify.index_logs((event, f"{role}:{line}") for line, event in enumerate(events, 1))
                for role, events in zip("ab", self.events)]

    def run_check(self):
        return verify.verify(self.config, self.report, rpcs=self.rpcs, logs=self.logs())

    def use_reference_peer(self):
        self.config.update(reference_ref="c" * 40, reference_binary_sha256="d" * 64,
                           build_manifest={"shared_binary": False, "arms": [
                               {"side": "feature", "resolved_ref": "a" * 40, "sha256": "b" * 64},
                               {"side": "baseline", "resolved_ref": "c" * 40, "sha256": "d" * 64}]})
        for events, revision in zip(self.events, ("a" * 40, "c" * 40)):
            events.insert(0, event("Starting Tempo", {"version": f"1.0.0-dev-{revision[:8]}"}, second=0))

    def test_distinct_reference_checks_both_execution_roles(self):
        self.use_reference_peer()
        result = self.run_check()
        self.assertIn("distinct pinned sequential reference", result["scope"])
        self.assertIn("pinned reference", result["shared_changes"])
        self.assertEqual(set(result["binary_startups"]), {"a", "b"})
        self.assertEqual(result["verified_transactions"], 24)
        self.assertEqual(result["parallel_reused"], {"builder_a": 6, "engine_a": 6})

    def test_txpool_prewarming_requires_independent_reference(self):
        self.enable_txpool()
        for env in (None, {}, {"RETH_ENGINE_TXPOOL_PREWARMING": "true"}):
            with self.subTest(env=env):
                self.config["b"]["env"] = env
                with self.assertRaisesRegex(verify.VerificationError, "prewarming environment"):
                    self.run_check()
        self.config["b"]["env"] = {"RETH_ENGINE_TXPOOL_PREWARMING": "false"}
        self.assertEqual(self.run_check()["verified_transactions"], 24)
        for flag in ("--engine.txpool-prewarming", "--engine.txpool-prewarming=true"):
            with self.subTest(flag=flag):
                self.config["b"]["args"].append(flag)
                with self.assertRaisesRegex(verify.VerificationError, "independent reference"):
                    self.run_check()
                self.config["b"]["args"].pop()

    def enable_txpool(self):
        self.config["a"]["args"] += ["--engine.txpool-prewarming", "--engine.slow-block-threshold", "0"]
        self.config["b"]["env"] = {"RETH_ENGINE_TXPOOL_PREWARMING": "false"}
        for row in list(self.events[0]):
            if row["fields"]["message"] == "Executed block":
                number, digest, _ = verify.span_identity(row["spans"])
                cache = event("Slow block", {"block.hash": digest, "block.number": number,
                    "cache.txpool_snapshot.account.hits": 1,
                    "cache.txpool_snapshot.storage.hits": 5,
                    "cache.txpool_snapshot.code.hits": 0})
                cache["target"] = "reth::slow_block"
                self.events[0].append(cache)

    def test_txpool_requires_reads_on_fresh_canonical_cohort(self):
        self.enable_txpool()
        result = self.run_check()
        self.assertEqual(result["txpool_snapshot_hits"], {"account": 2, "storage": 10, "code": 0})
        for fault in ("absent", "zero", "wrong_fork", "wrong_height", "reference", "malformed"):
            with self.subTest(fault=fault):
                self.setUp()
                self.enable_txpool()
                for row in self.events[0]:
                    if row["fields"]["message"] != "Slow block":
                        continue
                    fields = row["fields"]
                    if fault == "absent":
                        fields["message"] = "unrelated"
                    elif fault == "zero":
                        for kind in ("account", "storage", "code"):
                            fields[f"cache.txpool_snapshot.{kind}.hits"] = 0
                    elif fault == "wrong_fork":
                        fields["block.hash"] = digest(90000 + fields["block.number"])
                    elif fault == "wrong_height":
                        fields["block.number"] += 1
                    elif fault == "reference":
                        self.events[1].append(copy.deepcopy(row))
                    else:
                        fields["cache.txpool_snapshot.storage.hits"] = -1
                with self.assertRaises(verify.VerificationError):
                    self.run_check()

    def test_txpool_persistence_reemit_does_not_double_count(self):
        self.enable_txpool()
        cache = next(row for row in self.events[0] if row["fields"]["message"] == "Slow block"
                     and row["fields"]["block.number"] == 3)
        self.events[0].append(copy.deepcopy(cache))
        self.assertEqual(self.run_check()["txpool_snapshot_hits"]["storage"], 10)
        self.events[0][-1]["fields"]["cache.txpool_snapshot.storage.hits"] = 6
        with self.assertRaisesRegex(verify.VerificationError, "contradictory txpool"):
            self.run_check()

    def test_reference_rejects_missing_ambiguous_or_swapped_startup(self):
        for role in range(2):
            for fault in ("missing", "duplicate", "wrong"):
                with self.subTest(role=role, fault=fault):
                    self.setUp()
                    self.use_reference_peer()
                    if fault == "missing":
                        self.events[role].pop(0)
                    elif fault == "duplicate":
                        self.events[role].insert(0, copy.deepcopy(self.events[role][0]))
                    else:
                        self.events[role][0]["fields"]["version"] = self.events[1 - role][0]["fields"]["version"]
                    with self.assertRaisesRegex(verify.VerificationError, "startup"):
                        self.run_check()

    def test_reference_requires_bound_distinct_builds(self):
        self.use_reference_peer()
        mutations = [
            lambda c: c.pop("reference_ref"),
            lambda c: c.pop("build_manifest"),
            lambda c: c.update(reference_ref=c["feature_ref"]),
            lambda c: c.update(reference_ref="main"),
            lambda c: c.update(reference_binary_sha256=c["binary_sha256"]),
            lambda c: c["build_manifest"].update(shared_binary=True),
            lambda c: c["build_manifest"]["arms"].pop(),
            lambda c: c["build_manifest"]["arms"][1].update(side="feature"),
            lambda c: c["build_manifest"]["arms"][1].update(resolved_ref="e" * 40),
            lambda c: c["build_manifest"]["arms"][1].update(sha256="f" * 64),
        ]
        for mutation in mutations:
            config = copy.deepcopy(self.config)
            mutation(config)
            with self.subTest(config=config), self.assertRaises(verify.VerificationError):
                verify.check_config(config)

    def test_reference_still_rejects_state_and_full_receipt_differences(self):
        for field in ("stateRoot", "feeToken"):
            with self.subTest(field=field):
                self.setUp()
                self.use_reference_peer()
                if field == "stateRoot":
                    self.rpcs[1].blocks[3][field] = digest(999)
                else:
                    self.rpcs[1].receipt_blocks[3][0][field] = "0x" + "22" * 20
                with self.assertRaises(verify.VerificationError):
                    self.run_check()

    def test_exact_dense_chain_both_directions_excludes_setup(self):
        result = self.run_check()
        self.assertEqual((result["from_block"], result["to_block"]), (2, 5))
        self.assertEqual(result["dense_blocks_by_producer"], {"a": 2, "b": 2})
        self.assertEqual(result["parallel_reused"], {"builder_a": 6, "engine_a": 6})
        self.assertFalse(result["speedup_claim"])
        self.assertIn("same candidate binary", result["scope"])
        self.assertEqual(len(result["blocks"]), 4)
        self.assertEqual(result["verified_transactions"], 24)
        self.assertEqual(result["dense_transactions"], 5)
        self.assertEqual(result["capture_window"], 128)
        self.assertFalse(result["capture_window_explicit"])

    def test_capture_window_configuration_matches_effective_peer_values(self):
        self.config["a"]["args"].extend(["--execution.capture-window", "128"])
        self.assertEqual(verify.check_config(self.config), (128, True))
        # An explicit default still requires blocks larger than that window.
        with self.assertRaisesRegex(verify.VerificationError, ">= 129 transactions"):
            self.run_check()
        for other in (None, "128", "256"):
            with self.subTest(other=other):
                self.setUp()
                self.config["a"]["args"].append("--execution.capture-window=512")
                if other is not None:
                    self.config["b"]["args"].extend(["--execution.capture-window", other])
                with self.assertRaisesRegex(verify.VerificationError, "capture windows must match"):
                    verify.check_config(self.config)

    def test_invalid_missing_and_duplicate_capture_window_fail_closed(self):
        for role in ("a", "b"):
            for value in ("", "0", "127", "129", "255", "513", "abc", "-128"):
                for spelling in (["--execution.capture-window", value],
                                 ["--execution.capture-window=" + value]):
                    with self.subTest(role=role, spelling=spelling):
                        config = copy.deepcopy(self.config)
                        config[role]["args"].extend(spelling)
                        with self.assertRaises(verify.VerificationError):
                            verify.check_config(config)
        for suffix in (["--execution.capture-window"],
                       ["--execution.capture-window", "128", "--execution.capture-window=128"]):
            config = copy.deepcopy(self.config)
            config["a"]["args"].extend(suffix)
            with self.assertRaisesRegex(verify.VerificationError, "missing value|duplicate"):
                verify.check_config(config)

    def test_explicit_capture_window_requires_larger_blocks_in_both_roles(self):
        for window in (128, 256, 512):
            with self.subTest(window=window):
                self.setUp()
                self.config["a"]["args"].extend(["--execution.capture-window", str(window)])
                self.config["b"]["args"].append(f"--execution.capture-window={window}")
                self.build_chain((window + 1,) * 5)
                result = self.run_check()
                self.assertEqual(result["capture_window"], window)
                self.assertTrue(result["capture_window_explicit"])
                self.assertEqual(result["dense_transactions"], window + 1)
                self.assertEqual(result["dense_blocks_by_producer"], {"a": 2, "b": 2})
                self.assertEqual(result["verified_transactions"], 4 * (window + 1))
                self.assertEqual(result["parallel_reused"], {"builder_a": 6, "engine_a": 6})
                self.build_chain((window,) * 5)
                with self.assertRaisesRegex(verify.VerificationError, "insufficient dense"):
                    self.run_check()
                # Four qualifying blocks are insufficient when only one producer
                # exceeds the window; the other role's roots/receipts still match.
                for large_role in (0, 1):
                    self.build_chain(tuple(window + (number % 2 == large_role)
                                           for number in range(1, 10)))
                    with self.assertRaisesRegex(verify.VerificationError, "both producer roles"):
                        self.run_check()

    def test_capture_window_coverage_still_requires_included_reuse(self):
        for role in ("a", "b"):
            self.config[role]["args"].extend(["--execution.capture-window", "512"])
        self.build_chain((513,) * 5)
        for item in self.events[0]:
            if item["fields"]["message"] == "Built payload":
                item["fields"]["invalid_pool_transaction_execution_attempts"] = 3
                item["fields"]["pool_transactions_yielded"] += 3
        with self.assertRaisesRegex(verify.VerificationError, "positive canonical parallel reuse"):
            self.run_check()

    def test_header_parent_and_body_mismatches(self):
        for field in ("hash", "stateRoot", "receiptsRoot", "parentHash", "transactions"):
            with self.subTest(field=field):
                self.setUp()
                self.rpcs[1].blocks[3][field] = [digest(999)] if field == "transactions" else digest(999)
                with self.assertRaisesRegex(verify.VerificationError, "mismatch"):
                    self.run_check()

    def test_receipt_full_object_and_identity_mismatches(self):
        for field, value in (("feeToken", "0x" + "22" * 20), ("status", "0x0"),
                             ("transactionHash", digest(999)), ("blockHash", digest(999)), ("type", "0x2")):
            with self.subTest(field=field):
                self.setUp()
                self.rpcs[1].receipt_blocks[3][0][field] = value
                with self.assertRaisesRegex(verify.VerificationError, "receipt.*mismatch"):
                    self.run_check()

    def test_receipt_types_cover_only_verified_interval_once(self):
        for rpc in self.rpcs:
            # Block 1 is setup: it must not contribute to observed workload coverage.
            rpc.receipt_blocks[1][0]["type"] = "0x4"
            rpc.receipt_blocks[2][0]["type"] = "0x0"
            rpc.receipt_blocks[3][0]["type"] = "0x2"
            rpc.receipt_blocks[5][0]["type"] = "0x2"
        result = self.run_check()
        self.assertEqual(result["receipt_types"], {"0x0": 1, "0x2": 2, "0x76": 21})
        self.assertEqual(sum(result["receipt_types"].values()), result["verified_transactions"])
        for block in result["blocks"]:
            self.assertEqual(sum(block["receipt_types"].values()), block["tx_count"])
        self.assertEqual(result["blocks"][1]["receipt_types"], {"0x2": 1, "0x76": 5})

    def test_missing_or_malformed_receipt_type_fails_even_when_peers_agree(self):
        for value in (None, "0x076", 118, "", "0X76"):
            with self.subTest(value=value):
                self.setUp()
                for rpc in self.rpcs:
                    rpc.receipt_blocks[3][0]["type"] = value
                with self.assertRaisesRegex(verify.VerificationError, "invalid RPC receipt type"):
                    self.run_check()

    def test_reorg_during_verification_fails(self):
        self.rpcs[1].replace_on_recheck = True
        with self.assertRaisesRegex(verify.VerificationError, "endpoint changed"):
            self.run_check()

    def test_stale_report_timestamp_and_wrong_anchor_height(self):
        self.report["blocks"][2]["timestamp_ms"] += 1
        with self.assertRaisesRegex(verify.VerificationError, "report disagrees"):
            self.run_check()
        self.setUp()
        for rpc in self.rpcs:
            rpc.blocks[1]["number"] = "0x0"
        with self.assertRaisesRegex(verify.VerificationError, "anchor height"):
            self.run_check()

    def test_rotations_and_repeated_discarded_attempt_do_not_supply_reuse(self):
        # The latest file is enumerated first, and a discarded retry reuses id and
        # parent. Its positive stats must not overwrite the earlier canonical zero.
        stats = next(item for item in self.events[0]
                     if item["fields"]["message"] == "Finished speculative block execution"
                     and item["spans"][0]["name"] == "build_payload")
        digest_value = digest(3)
        original = copy.deepcopy(stats)
        stats["fields"]["stats"] = "ExecutionStats { speculated: 6, reused: 0, bodies_reused: 0 }"
        later = copy.deepcopy(original)
        later["timestamp"] = "2026-10-03T00:00:05Z"
        self.events[0].insert(0, later)
        self.events[0].insert(0, event("building new payload", spans=stats["spans"], second=4))
        indexed = self.logs()[0]
        self.assertEqual(indexed["builder_reuse"][digest_value]["reused"], 0)
        self.assertEqual(indexed["builder_reuse"][digest_value]["completed_time"], "2026-10-03T00:00:02+00:00")
        # A finish whose start rotated away is never attributed to a built hash.
        self.events[0] = [item for item in self.events[0]
                          if not (item["fields"]["message"] == "building new payload"
                                  and item["spans"] == stats["spans"])]
        self.assertNotIn(digest_value, self.logs()[0]["builder_reuse"])

    def test_report_mismatch_and_missing_data(self):
        self.report["blocks"][2]["tx_count"] += 1
        with self.assertRaisesRegex(verify.VerificationError, "report disagrees"):
            self.run_check()
        self.setUp()
        self.rpcs[1].receipt_blocks[3].pop()
        with self.assertRaisesRegex(verify.VerificationError, "missing receipts"):
            self.run_check()

    def test_fresh_peer_execution_required_even_with_valid_already_seen(self):
        self.events[1] = [item for item in self.events[1] if item["fields"]["message"] != "Executed block"]
        self.events[1].append(event("Inserted new payload", {"result": "AlreadySeen(Valid)"}))
        with self.assertRaisesRegex(verify.VerificationError, "fresh opposite-peer"):
            self.run_check()

    def test_post_execution_valid_and_real_producer_required(self):
        for message in ("Built payload", "execution layer reported payload status"):
            with self.subTest(message=message):
                self.setUp()
                self.events[1] = [item for item in self.events[1] if item["fields"]["message"] != message]
                with self.assertRaisesRegex(verify.VerificationError, "producer|VALID"):
                    self.run_check()
        self.setUp()
        for item in self.events[1]:
            if item["fields"]["message"] == "execution layer reported payload status":
                item["timestamp"] = "2026-10-03T00:00:01Z"
        with self.assertRaisesRegex(verify.VerificationError, "post-execution"):
            self.run_check()

    def test_outer_delivery_cannot_substitute_for_actual_engine_block(self):
        for item in self.events[0]:
            if item["fields"]["message"] == "Executed block":
                item["spans"].insert(0, {"name": "on_new_payload", "block_hash": digest(999), "block_num": "999"})
        self.run_check()
        self.events[0] = [item for item in self.events[0] if item["fields"]["message"] != "Executed block"]
        self.events[0].append(event("Executed block", spans=[{"name": "on_new_payload", "block_hash": digest(4)}]))
        with self.assertRaisesRegex(verify.VerificationError, "missing fresh Engine identity"):
            self.logs()

    def test_both_roles_and_reuse_in_both_parallel_paths_required(self):
        self.report["metadata"]["measurement_send_start_unix_ms"] = "5000"
        with self.assertRaisesRegex(verify.VerificationError, "insufficient dense"):
            self.run_check()
        for scope in ("build_payload", "insert_block_or_payload"):
            self.setUp()
            for item in self.events[0]:
                if item["fields"]["message"] == "Finished speculative block execution" and item["spans"][0]["name"] == scope:
                    item["fields"]["stats"] = "ExecutionStats { speculated: 6, reused: 0, bodies_reused: 0 }"
            with self.subTest(scope=scope), self.assertRaisesRegex(verify.VerificationError, "positive canonical parallel reuse"):
                self.run_check()

    def test_discarded_builder_reuse_cannot_establish_included_coverage(self):
        for item in self.events[0]:
            if item["fields"]["message"] == "Built payload":
                item["fields"]["invalid_pool_transaction_execution_attempts"] = 3
                item["fields"]["pool_transactions_yielded"] = 9
        # All three reused attempts could be among the three rejected executions.
        with self.assertRaisesRegex(verify.VerificationError, "positive canonical parallel reuse"):
            self.run_check()

    def test_raw_builder_reuse_may_exceed_block_size_with_positive_lower_bound(self):
        for item in self.events[0]:
            if item["fields"]["message"] == "Built payload":
                item["fields"]["invalid_pool_transaction_execution_attempts"] = 3
                item["fields"]["pool_transactions_yielded"] = 9
            elif (item["fields"]["message"] == "Finished speculative block execution"
                  and item["spans"][0]["name"] == "build_payload"):
                item["fields"]["stats"] = "ExecutionStats { speculated: 9, reused: 8, bodies_reused: 0 }"
        result = self.run_check()
        self.assertEqual(result["parallel_reused"], {"builder_a": 10, "engine_a": 6})
        for block in result["blocks"]:
            if block["producer"] == "a":
                self.assertEqual(block["parallel_reuse"]["reused"], 8)
                self.assertEqual(block["parallel_reuse"]["included_lower_bound"], 5)
                self.assertEqual(block["parallel_reuse"]["discarded_execution_attempts_bound"], 3)
            else:
                self.assertEqual(block["parallel_reuse"]["included_exact"], 3)

    def test_disabled_validation_and_wrong_executor_guards(self):
        for flag in ("--debug.skip-state-root", "--builder.parallel", "--builder.disable-prewarming",
                     "--engine.disable-prewarming", "--engine.disable-caching-and-prewarming"):
            for spelling in (flag, flag + "=true", flag + "=false"):
                with self.subTest(flag=spelling):
                    config = copy.deepcopy(self.config)
                    config["b"]["args"].append(spelling)
                    with self.assertRaises(verify.VerificationError):
                        verify.check_config(config)
        self.config["b"]["args"][2] = "8"
        with self.assertRaisesRegex(verify.VerificationError, "sequential B"):
            verify.check_config(self.config)

    def test_malformed_rpc_and_log_status_fail_closed(self):
        for envelope in ({}, {"jsonrpc": "2.0", "id": 1, "result": None},
                         {"jsonrpc": "2.0", "id": 2, "result": {}},
                         {"jsonrpc": "2.0", "id": 1, "error": {"code": -1}}, []):
            with self.subTest(envelope=envelope), self.assertRaises(verify.VerificationError):
                verify.rpc_result(envelope, 1)
        self.events[0].append(event("execution layer reported payload status",
            {"payload_status": "PayloadStatus { status: INVALID, latestValidHash: None }"}))
        with self.assertRaisesRegex(verify.VerificationError, "rejected payload"):
            self.logs()

    def test_bounded_finality_wait(self):
        self.rpcs[1].finalized = 4
        now = [0]
        def advance(seconds):
            now[0] += seconds
        with self.assertRaisesRegex(verify.VerificationError, "finality did not reach"):
            verify.wait_finalized(self.rpcs, 5, 3, clock=lambda: now[0], sleep=advance)
        self.assertEqual(now[0], 3)

    def test_live_json_tail_and_cli_config_smoke(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)
            (path / "reth.log").write_text(json.dumps(event("irrelevant")) + '\n{"partial":')
            self.assertEqual(len(list(verify.log_events(path))), 1)
            (path / "reth.log").write_text('{"malformed":\n')
            with self.assertRaisesRegex(verify.VerificationError, "malformed node JSON"):
                list(verify.log_events(path))
            config_path = path / "config.json"
            command = [sys.executable, str(Path(verify.__file__)), "--config", str(config_path), "--check-config"]
            config_path.write_text(json.dumps(self.config))
            self.assertEqual(subprocess.run(command, capture_output=True).returncode, 0)
            self.config["a"]["args"].append("--debug.skip-state-root")
            config_path.write_text(json.dumps(self.config))
            self.assertEqual(subprocess.run(command, capture_output=True).returncode, 1)


if __name__ == "__main__":
    unittest.main()
