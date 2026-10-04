#!/usr/bin/env python3
"""Synthetic RPC fixtures; no historical execution coverage is claimed."""

import copy
import contextlib
import gzip
import importlib.util
import io
import json
import os
from pathlib import Path
import tempfile
import time
import sys
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location("receipts", Path(__file__).with_name("bench-replay-receipts.py"))
oracle = importlib.util.module_from_spec(spec)
spec.loader.exec_module(oracle)
SHA = "a" * 40


def h(number):
    return "0x" + f"{number:064x}"


def fixture():
    headers, receipts, blocks = {}, {}, []
    for number in (100, 101):
        txs = [h(1000), h(1001)] if number == 100 else []
        headers[number] = {"number": hex(number), "hash": h(number), "parentHash": h(number - 1),
                           "stateRoot": h(2000 + number), "receiptsRoot": h(3000 + number),
                           "transactionsRoot": h(4000 + number), "timestamp": hex(1700000000 + number),
                           "timestampMillisPart": "0x7b", "gasUsed": hex(len(txs) * 21000),
                           "gasLimit": hex(500000000), "transactions": txs}
        receipts[number] = [{"blockHash": h(number), "blockNumber": hex(number),
                             "transactionHash": tx, "transactionIndex": hex(i), "type": "0x0",
                             "status": "0x1", "cumulativeGasUsed": hex((i + 1) * 21000),
                             "gasUsed": hex(21000), "effectiveGasPrice": "0x1", "logs": [],
                             "logsBloom": "0x" + "00" * 256, "from": "0x" + "01" * 20,
                             "to": "0x" + "02" * 20, "contractAddress": None,
                             "tempoExtension": {"ordered": [1, 2]}} for i, tx in enumerate(txs)]
        blocks.append({"number": number, "tx_count": len(txs), "gas_used": len(txs) * 21000,
                       "gas_limit": 500000000, "timestamp_ms": (1700000000 + number) * 1000})
    receipts[100][0]["logs"] = [{"blockHash": h(100), "blockNumber": hex(100),
                               "transactionHash": h(1000), "transactionIndex": "0x0",
                               "logIndex": "0x0", "removed": False, "address": "0x" + "03" * 20,
                               "topics": [h(5000)], "data": "0x1234"}]
    return headers, receipts, blocks


class FakeRpc:
    def __init__(self, headers, receipts):
        self.headers, self.receipts = copy.deepcopy(headers), copy.deepcopy(receipts)
        self.bad_canonical_number = False

    def batch(self, calls):
        result = []
        for method, params in calls:
            if method == "eth_chainId":
                value = hex(4217)
            elif method == "eth_getBlockByNumber":
                value = copy.deepcopy(self.headers[int(params[0], 16)])
                if self.bad_canonical_number:
                    value["number"] = "0xdead"
            else:
                number = next(n for n, header in self.headers.items() if header["hash"] == params[0])
                value = self.headers[number] if method == "eth_getBlockByHash" else self.receipts[number]
            result.append(copy.deepcopy(value))
        return result


class ReceiptTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="tempo-receipt-fixtures-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        headers, receipts, self.blocks = fixture()
        self.node, self.source = FakeRpc(headers, receipts), FakeRpc(headers, receipts)
        self.reference = self.root / "reference.gz"

    def capture(self, label="feature-1"):
        output_dir = self.root / label
        output_dir.mkdir(exist_ok=True)
        meta = {"schema": 1, "benchmark_id": "fixture", "chain_id": 4217, "first": 100,
                "last": 101, "label": label, "git_sha": SHA}
        stats = oracle.verify(self.blocks, self.node, self.source, self.reference,
                              output_dir / "receipt-oracle.jsonl.gz", meta, oracle.Budget(10))
        summary = {**meta, **stats, "status": "passed", "scope": "synthetic fixture",
                   "report_sha256": "b" * 64}
        (output_dir / "receipt-oracle-summary.json").write_text(json.dumps(summary))
        return summary

    def test_complete_live_comparison_empty_block_and_millisecond_report_semantics(self):
        first = self.capture()
        # JSON object order is irrelevant; array order and all fields remain relevant.
        self.node.receipts[100][0] = dict(reversed(list(self.node.receipts[100][0].items())))
        second = self.capture("baseline-1")
        self.assertEqual(first["receipts"], 2)
        self.assertFalse(second["first_pass"])
        with gzip.open(self.reference, "rt") as reader:
            rows = [json.loads(line) for line in reader]
        self.assertEqual(len(rows), 3)
        self.assertIn("receipts_sha256", rows[1])
        self.assertNotIn("tempoExtension", rows[1])
        (self.root / "run-order.txt").write_text("feature-1\nbaseline-1\n")
        self.assertEqual(oracle.finalize(self.root)["status"], "passed")

    def test_unknown_receipt_fields_and_array_order_are_compared(self):
        self.capture()
        self.node.receipts[100][0]["tempoExtension"]["ordered"] = [2, 1]
        with self.assertRaisesRegex(ValueError, "full receipt mismatch"):
            self.capture("baseline-1")

    def test_missing_reordered_and_wrong_block_receipts_fail(self):
        original = copy.deepcopy(self.node.receipts)
        variants = [original[100][:1], list(reversed(original[100]))]
        wrong = copy.deepcopy(original[100])
        wrong[0]["blockHash"] = h(999)
        variants.append(wrong)
        for receipts in variants:
            with self.subTest(receipts=receipts), self.assertRaises(ValueError):
                self.node.receipts[100] = receipts
                self.capture()
            self.assertFalse(self.reference.exists())

    def test_source_root_disagreement_and_bad_final_canonical_height_fail(self):
        self.node.headers[100]["stateRoot"] = h(999)
        with self.assertRaisesRegex(ValueError, "commitment mismatch"):
            self.capture()
        self.node.headers[100]["stateRoot"] = self.source.headers[100]["stateRoot"]
        self.node.bad_canonical_number = True
        with self.assertRaisesRegex(ValueError, "canonical"):
            self.capture()
        self.assertFalse(self.reference.exists())

    def test_reference_missing_or_extra_records_fail(self):
        self.capture()
        with gzip.open(self.reference, "rb") as reader:
            original = reader.read()
        for data in (b"\n".join(original.splitlines()[:-1]) + b"\n", original + b"{}\n"):
            with gzip.open(self.reference, "wb") as writer:
                writer.write(data)
            with self.assertRaises(ValueError):
                self.capture("baseline-1")

    def test_report_rejects_wrong_binding_gaps_and_non_objects(self):
        report = {"metadata": {"benchmark_run": "feature-1", "git-sha": SHA, "benchmark_id": "fixture"},
                  "blocks": self.blocks}
        path = self.root / "report.json"
        for value in ([], {"metadata": []}, {**report, "blocks": self.blocks[::-1]},
                      {**report, "metadata": {**report["metadata"], "git-sha": "c" * 40}}):
            path.write_text(json.dumps(value))
            with self.assertRaises(ValueError):
                oracle.read_report(path, 100, 101, "feature-1", SHA)

    def test_finalizer_rejects_missing_fields_and_changed_ledger(self):
        (self.root / "run-order.txt").write_text("feature-1\nbaseline-1\n")
        for i, label in enumerate(("feature-1", "baseline-1")):
            folder = self.root / label
            folder.mkdir()
            (folder / "receipt-oracle-summary.json").write_text(json.dumps(
                {"status": "passed", "label": label, "first_pass": i == 0, "scope": "fixture"}))
        with self.assertRaises(ValueError):
            oracle.finalize(self.root)
        self.capture()
        self.capture("baseline-1")
        (self.root / "baseline-1/receipt-oracle.jsonl.gz").write_bytes(b"changed")
        with self.assertRaisesRegex(ValueError, "ledger digest"):
            oracle.finalize(self.root)

    def test_rpc_missing_duplicate_null_responses_and_limits(self):
        rpc = oracle.Rpc("https://example.invalid", oracle.Budget(10), "source")
        for replies in ([], [{"jsonrpc": "2.0", "id": 0, "result": None}],
                        [{"jsonrpc": "2.0", "id": False, "result": "0x1"}],
                        [{"jsonrpc": "2.0", "id": 0, "result": "0x1"}] * 2):
            with patch.object(oracle.urllib.request, "urlopen", return_value=io.BytesIO(json.dumps(replies).encode())):
                with self.assertRaises(ValueError):
                    rpc.batch([("eth_chainId", [])])
        reply = b'[{"jsonrpc":"2.0","id":0,"result":"0x1"}]'
        for limit in ("MAX_RESPONSE_BYTES", "MAX_TOTAL_BYTES"):
            with patch.object(oracle, limit, 1), patch.object(oracle.urllib.request, "urlopen", return_value=io.BytesIO(reply)):
                with self.assertRaisesRegex(ValueError, "byte limit"):
                    rpc.batch([("eth_chainId", [])])
        with self.assertRaises(ValueError):
            oracle.decode('{"result":1,"result":2}')

    def test_deadline_and_source_url_sanitization(self):
        with self.assertRaisesRegex(ValueError, "deadline"):
            oracle.Budget(-1).remaining()
        rpc = oracle.Rpc("secret-invalid-url", oracle.Budget(10), "source")
        with self.assertRaisesRegex(ValueError, "^source RPC request failed$"):
            rpc.batch([("eth_chainId", [])])

    def test_cli_deadline_interrupts_stalled_response_and_writes_failure(self):
        report = self.root / "report.json"
        report.write_text(json.dumps({"metadata": {"benchmark_run": "feature-1", "git-sha": SHA,
                                                   "benchmark_id": "fixture"}, "blocks": self.blocks}))
        class StalledResponse(io.BytesIO):
            def read(self, *args):
                time.sleep(5)
                return super().read(*args)

        argv = ["oracle", "capture", "--report", str(report), "--reference", str(self.reference),
                "--output-dir", str(self.root), "--first", "100", "--last", "101", "--chain-id", "4217",
                "--label", "feature-1", "--git-sha", SHA, "--deadline-seconds", "1"]
        output = io.StringIO()
        started = time.monotonic()
        with patch.object(sys, "argv", argv), patch.dict(os.environ, {"REPLAY_RPC_URL": "https://user:password@example.invalid"}), \
                patch.object(oracle.urllib.request, "urlopen", return_value=StalledResponse()), \
                contextlib.redirect_stdout(output):
            self.assertEqual(oracle.main(), 1)
        self.assertLess(time.monotonic() - started, 3)
        self.assertEqual(json.loads((self.root / "receipt-oracle-summary.json").read_text())["status"], "failed")
        self.assertNotIn("password", output.getvalue())


if __name__ == "__main__":
    unittest.main()
