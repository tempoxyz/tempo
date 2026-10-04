#!/usr/bin/env python3
"""Synthetic RPC fixtures; no historical execution coverage is claimed."""

import copy
import base64
import contextlib
import gzip
import importlib.util
import io
import http.client
import json
import os
from pathlib import Path
import signal
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
        with self.assertRaisesRegex(ValueError, r"^source RPC request failed \(ValueError\)$"):
            rpc.batch([("eth_chainId", [])])

    def test_rpc_url_credentials_become_basic_auth_before_http_transport(self):
        reply = b'[{"jsonrpc":"2.0","id":0,"result":"0x1079"}]'
        for authority in ("example.invalid", "example.invalid:443", "[::1]:8545"):
            def open_request(request, timeout):
                self.assertEqual(request.full_url, f"https://{authority}/rpc?token=fixture")
                self.assertEqual(request.get_header("Authorization"),
                                 "Basic " + base64.b64encode(b"user@example:pa:ss@word").decode())
                # Exercise the stdlib's actual host parsing, without opening a socket.
                connection = http.client.HTTPSConnection(request.host, timeout=timeout)
                self.assertNotIn("@", connection.host)
                connection.close()
                redirected = oracle.urllib.request.HTTPRedirectHandler().redirect_request(
                    request, None, 302, "redirect", {}, "https://different.invalid/rpc")
                self.assertIsNone(redirected.get_header("Authorization"))
                return io.BytesIO(reply)
            rpc = oracle.Rpc(f"https://user%40example:pa%3Ass%40word@{authority}/rpc?token=fixture",
                             oracle.Budget(10), "source")
            with patch.object(oracle.urllib.request, "urlopen", side_effect=open_request):
                self.assertEqual(rpc.batch([("eth_chainId", [])]), ["0x1079"])

    def test_rpc_errors_preserve_status_or_type_without_secret_details(self):
        url = "https://user:password@example.invalid/rpc?token=secret"
        for error, diagnostic in (
            (oracle.urllib.error.HTTPError(url, 403, url, {}, None), "HTTP 403"),
            (oracle.urllib.error.URLError(url), "URLError"),
            (http.client.InvalidURL(url), "InvalidURL"),
        ):
            rpc = oracle.Rpc(url, oracle.Budget(10), "source")
            with patch.object(oracle.urllib.request, "urlopen", side_effect=error):
                with self.assertRaises(ValueError) as caught:
                    rpc.batch([("eth_chainId", [])])
            self.assertEqual(str(caught.exception), f"source RPC request failed ({diagnostic})")

    def test_preflight_checks_source_batch_transport_and_chain(self):
        replies = [{"jsonrpc": "2.0", "id": 0, "result": "0x1079"},
                   {"jsonrpc": "2.0", "id": 1, "result": "0x100"}]
        for expected_chain, expected_status in ((4217, 0), (1, 1)):
            with patch.object(sys, "argv", ["oracle", "preflight", "--chain-id", str(expected_chain)]), \
                    patch.dict(os.environ, {"REPLAY_RPC_URL": "https://user:password@example.invalid"}), \
                    patch.object(oracle.urllib.request, "urlopen", return_value=io.BytesIO(json.dumps(replies).encode())) as call, \
                    contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(oracle.main(), expected_status)
                self.assertEqual([item["method"] for item in json.loads(call.call_args.args[0].data)],
                                 ["eth_chainId", "eth_blockNumber"])

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


class DiagnosticTests(unittest.TestCase):
    url = 'https://user:password@example.invalid/rpc?token=secret'
    batch = [{"jsonrpc": "2.0", "id": i, "method": method, "params": []}
             for i, method in enumerate(("eth_chainId", "eth_blockNumber"))]
    replies = [{"jsonrpc": "2.0", "id": 0, "result": "0x1079"},
               {"jsonrpc": "2.0", "id": 1, "result": "0x100"}]

    def test_paired_transport_branches_are_bounded_and_use_identical_initial_body(self):
        for curl_ok, urllib_ok, expected in ((True, True, 2), (False, True, 5),
                                            (False, False, 5), (True, False, 5)):
            calls = []
            def fake_probe(url, request, chain, budget, transport, label, **kwargs):
                calls.append((transport, label, copy.deepcopy(request), kwargs))
                passed = curl_ok if transport == "curl" else urllib_ok
                return {"status": "response", "http_status": 200 if passed else 403,
                        "ids_valid": passed, "quantities_valid": passed, "chain_match": True}
            with patch.object(oracle, "diagnostic_probe", side_effect=fake_probe), \
                    patch.object(oracle, "bounded_command", return_value=(0, b"curl 8.5.0 (fixture)\n")):
                result = oracle.diagnose(self.url, 4217)
            self.assertEqual(result["status"], "completed")
            self.assertEqual(len(calls), expected)
            self.assertEqual(calls[0][2], self.batch)
            self.assertEqual(calls[0][2], calls[1][2])
            if not curl_ok:
                self.assertEqual([call[2] for call in calls[2:]], [self.batch[0], self.batch[1], [self.batch[1]]])
            elif not urllib_ok:
                self.assertTrue(calls[2][3]["user_agent"].startswith("Python-urllib/"))
                self.assertEqual(calls[3][3]["user_agent"], "curl/8.5.0")
                self.assertTrue(calls[4][3]["http1"])

    def test_curl_config_escapes_quotes_backslashes_and_rejects_control_injection(self):
        url = self.url + '&x="\\$(touch /tmp/never);`false`'
        config = oracle.curl_config(url, oracle.canonical(self.batch), None).decode()
        self.assertEqual(len(config.splitlines()), 3)
        self.assertIn('url = "' + url.replace('\\', '\\\\').replace('"', '\\"') + '"\n', config)
        for bad in (self.url + '\noutput = "/tmp/never"', self.url + '\rheader = "secret"',
                    self.url + '\x00', self.url + '\x7f', self.url + 'x' * 17000):
            with self.assertRaises(ValueError):
                oracle.curl_config(bad, b"{}", None)

    def test_curl_keeps_secrets_off_argv_and_discards_server_error_text(self):
        def command(args, data, timeout, limit):
            self.assertEqual(args[:2], ["curl", "--disable"])
            self.assertIn("--globoff", args)
            self.assertLessEqual(timeout, 8)
            self.assertEqual(limit, 65540)
            self.assertNotIn("password", " ".join(args))
            self.assertNotIn("secret", " ".join(args))
            self.assertIn(self.url.encode(), data)
            return 0, self.url.encode() + b"\n403"
        with patch.object(oracle, "bounded_command", side_effect=command), \
                patch.object(oracle.signal, "setitimer"):
            result = oracle.diagnostic_probe(self.url, self.batch, 4217, oracle.Budget(60), "curl", "curl_batch")
        self.assertEqual(result["http_status"], 403)
        self.assertEqual(result["response_shape"], "non_json")
        self.assertNotIn("password", json.dumps(result))
        self.assertNotIn("secret", json.dumps(result))

    def test_response_metadata_rejects_wrong_ids_shape_and_chain_without_echoing_fields(self):
        cases = [(self.replies, "array", True, True),
                 (self.replies[::-1], "array", True, True),
                 (self.replies[0], "object", False, None),
                 ([self.replies[0], self.replies[0]], "array", False, None),
                 ([{**self.replies[0], "id": False}, self.replies[1]], "array", False, None),
                 ([{**self.replies[0], "result": "0x1"}, self.replies[1]], "array", True, False),
                 ([{**self.replies[0], "error": {"message": self.url}}, self.replies[1]], "array", True, None)]
        for replies, shape, ids, chain in cases:
            result = oracle.diagnostic_response(json.dumps(replies).encode(), self.batch, 4217)
            self.assertEqual((result["response_shape"], result["ids_valid"], result["chain_match"]),
                             (shape, ids, chain))
            self.assertNotIn("secret", json.dumps(result))

    def test_urllib_reuses_auth_and_caps_read_even_for_http_errors(self):
        payload = json.dumps(self.replies).encode()
        for status, data in ((200, payload), (403, self.url.encode()), (200, b"x" * 65537)):
            response = oracle.urllib.error.HTTPError(self.url, status, self.url, {}, io.BytesIO(data))
            def open_request(request, timeout):
                self.assertEqual(request.full_url, self.url.replace("user:password@", ""))
                self.assertTrue(request.get_header("Authorization").startswith("Basic "))
                self.assertLessEqual(timeout, 8)
                raise response
            with patch.object(oracle.urllib.request, "urlopen", side_effect=open_request), \
                    patch.object(oracle.signal, "setitimer"):
                result = oracle.diagnostic_probe(self.url, self.batch, 4217, oracle.Budget(60), "urllib", "urllib_batch")
            self.assertEqual(result["http_status"], status)
            if len(data) > 65536:
                self.assertEqual(result["status"], "response_too_large")
            self.assertNotIn("secret", json.dumps(result))

    def test_bounded_subprocess_does_not_invoke_shell_and_reaps_on_timeout_or_overflow(self):
        with tempfile.TemporaryDirectory() as folder:
            target = Path(folder) / "never"
            payload = f'$(touch "{target}"); `touch "{target}"`'.encode()
            code, output = oracle.bounded_command(
                [sys.executable, "-c", "import sys; sys.stdout.buffer.write(sys.stdin.buffer.read())"],
                payload, 2, 4096)
            self.assertEqual((code, output), (0, payload))
            self.assertFalse(target.exists())
            real_popen = oracle.subprocess.Popen
            children = []
            def popen(*args, **kwargs):
                child = real_popen(*args, **kwargs)
                children.append(child)
                return child
            for script, expected in (("import time; time.sleep(10)", TimeoutError),
                                     ("import os,time; os.write(1,b'x'*4096); time.sleep(10)", OverflowError)):
                with patch.object(oracle.subprocess, "Popen", side_effect=popen), self.assertRaises(expected):
                    oracle.bounded_command([sys.executable, "-c", script], b"", .2, 1024)
                self.assertIsNotNone(children[-1].poll())
                with self.assertRaises(ChildProcessError):
                    os.waitpid(children[-1].pid, os.WNOHANG)

    def test_urllib_wall_deadline_interrupts_a_stalled_body_read(self):
        class StalledResponse(io.BytesIO):
            code = 200
            def read(self, *_args):
                time.sleep(2)
                return b""
        def expired(_signum, _frame):
            raise TimeoutError()
        previous_handler = signal.signal(signal.SIGALRM, expired)
        started = time.monotonic()
        try:
            with patch.object(oracle.urllib.request, "urlopen", return_value=StalledResponse()):
                result = oracle.diagnostic_probe(self.url, self.batch, 4217, oracle.Budget(.05),
                                                 "urllib", "urllib_batch")
            self.assertEqual(result["status"], "timeout")
            self.assertLess(time.monotonic() - started, .5)
        finally:
            signal.setitimer(signal.ITIMER_REAL, 0)
            signal.signal(signal.SIGALRM, previous_handler)

    def test_diagnostic_cli_never_prints_unexpected_exception_text(self):
        output = io.StringIO()
        previous_handler = signal.getsignal(signal.SIGALRM)
        try:
            with patch.object(sys, "argv", ["oracle", "diagnose", "--chain-id", "4217"]), \
                    patch.dict(os.environ, {"REPLAY_RPC_URL": self.url}), \
                    patch.object(oracle, "diagnose", side_effect=ValueError(self.url)), \
                    contextlib.redirect_stdout(output), contextlib.redirect_stderr(output):
                self.assertEqual(oracle.main(), 1)
            self.assertEqual(json.loads(output.getvalue()), {"status": "stopped"})
            self.assertEqual(signal.getitimer(signal.ITIMER_REAL)[0], 0)
        finally:
            signal.signal(signal.SIGALRM, previous_handler)


if __name__ == "__main__":
    unittest.main()
