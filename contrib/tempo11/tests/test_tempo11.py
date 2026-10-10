import contextlib
import io
import json
import random
import subprocess
import sys
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from tempo11 import ROOT, Ledger, NodeError, Rpc, Store, block_fields, follow, ingest

MASK = 2**256 - 1


def block(height, parent=0, block_hash=None):
    return {
        "number": hex(height),
        "hash": f"0x{block_hash or height + 1:064x}",
        "parentHash": f"0x{parent:064x}",
        "transactions": [],
    }


def execute(code, *, ok=True):
    result = subprocess.run(
        [str(ROOT / "build/evm"), code], capture_output=True, text=True, timeout=10
    )
    if not ok:
        return result
    if result.returncode:
        raise AssertionError(result.stdout + result.stderr)
    lines = result.stdout.splitlines()
    if lines[0] != f"STACK {len(lines) - 1}":
        raise AssertionError(result.stdout)
    return [int(word, 16) for word in lines[1:]]


def push(word):
    return "7f" + f"{word:064x}"


class EvmTests(unittest.TestCase):
    def test_arithmetic_against_independent_integer_model(self):
        rng = random.Random(11)
        pairs = [
            (0, 0),
            (MASK, 1),
            (0, 1),
            (MASK, MASK),
            (2**255, 2),
            (2**128 - 1, 2**128 + 1),
        ]
        pairs += [(rng.getrandbits(256), rng.getrandbits(256)) for _ in range(50)]
        operations = {
            "01": lambda a, b: (a + b) & MASK,
            "02": lambda a, b: (a * b) & MASK,
            "03": lambda a, b: (a - b) & MASK,
            "10": lambda a, b: int(a < b),
            "11": lambda a, b: int(a > b),
            "14": lambda a, b: int(a == b),
            "16": lambda a, b: a & b,
            "17": lambda a, b: a | b,
            "18": lambda a, b: a ^ b,
        }
        for opcode, model in operations.items():
            for a, b in pairs:
                with self.subTest(opcode=opcode, a=a, b=b):
                    self.assertEqual(execute(push(b) + push(a) + opcode), [model(a, b)])

    def test_unary_byte_and_pc(self):
        self.assertEqual(execute("5f15"), [1])
        self.assertEqual(execute("600115"), [0])
        self.assertEqual(execute("5f19"), [MASK])
        self.assertEqual(execute(push(MASK) + "19"), [0])
        for index, expected in [(0, 0xAB), (31, 0xCD), (32, 0), (MASK, 0)]:
            value = (0xAB << 248) | 0xCD
            self.assertEqual(execute(push(value) + push(index) + "1a"), [expected])
        self.assertEqual(execute("585f58"), [0, 0, 2])

    def test_push_padding_stop_and_stack_manipulation(self):
        self.assertEqual(execute("61ff"), [0xFF00])
        self.assertEqual(execute("7f"), [0])
        self.assertEqual(execute("60006000"), [0, 0])
        self.assertEqual(execute("600100fe"), [1])
        self.assertEqual(execute("600160028190"), [1, 1, 2])
        self.assertEqual(execute("600150"), [])
        for n in range(1, 17):
            prefix = "".join(f"60{i:02x}" for i in range(1, 18))
            self.assertEqual(execute(prefix + f"{127 + n:02x}")[-1], 18 - n)
            expected = list(range(1, 18))
            expected[-1], expected[-1 - n] = expected[-1 - n], expected[-1]
            self.assertEqual(execute(prefix + f"{143 + n:02x}"), expected)

    def test_bounds_and_unsupported_instructions_fail(self):
        for code, message in [
            ("01", "STACK-UNDERFLOW"),
            ("5f01", "STACK-UNDERFLOW"),
            ("80", "STACK-UNDERFLOW"),
            ("90", "STACK-UNDERFLOW"),
            ("5f" * 1025, "STACK-OVERFLOW"),
            ("fe", "UNSUPPORTED-OPCODE"),
            ("f", "INVALID-HEX"),
            ("gg", "INVALID-HEX"),
            ("00" * 32769, "INVALID-HEX"),
        ]:
            with self.subTest(code=code[:20]):
                result = execute(code, ok=False)
                self.assertEqual(result.returncode, 1)
                self.assertEqual(result.stdout, f"ERROR {message}\n")
        self.assertEqual(len(execute("5f" * 1024)), 1024)


class StoreFixture(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / "ledger.sqlite"

    def ledger(self):
        ledger = Ledger(ROOT / "build/ledger")
        self.addCleanup(ledger.close)
        return ledger

    def store(self, chain_id=4217):
        store = Store(self.path, chain_id)
        self.addCleanup(store.close)
        return store


class LedgerTests(StoreFixture):
    def test_indexed_zone_e_header_continuity(self):
        headers = [
            json.loads(line)
            for line in (ROOT / "fixtures/zone-e-headers.jsonl")
            .read_text()
            .splitlines()
        ]
        ledger = self.ledger()
        ledger.accept(headers[0], anchor=True)
        ledger.accept(headers[1])

    def test_durable_restart_and_cobol_anchor(self):
        store = self.store()
        ledger = self.ledger()
        with contextlib.redirect_stdout(io.StringIO()):
            ingest(store, ledger, [block(0), block(1, 1)])
        restarted = self.store()
        other_ledger = self.ledger()
        other_ledger.accept(restarted.head(), anchor=True)
        with contextlib.redirect_stdout(io.StringIO()):
            ingest(restarted, other_ledger, [block(2, 2)])
        self.assertEqual(block_fields(restarted.head())[0], 2)

    def test_reject_bad_parent_without_committing(self):
        store, ledger = self.store(), self.ledger()
        with contextlib.redirect_stdout(io.StringIO()):
            ingest(store, ledger, [block(0)])
            with self.assertRaisesRegex(NodeError, "PARENT-MISMATCH"):
                ingest(store, ledger, [block(1, 999)])
        self.assertEqual(block_fields(store.head())[0], 0)

    def test_chain_identity_and_concurrent_write_guard(self):
        store = self.store()
        with self.assertRaisesRegex(NodeError, "chain ID"):
            self.store(42431)
        store.append(block(0))
        other_store = self.store()
        other_store.append(block(1, 1))
        with self.assertRaisesRegex(NodeError, "head changed"):
            store.append(block(1, 1, 555))
        self.assertEqual(block_fields(store.head())[0], 1)

    def test_cobol_rejects_gap_and_missing_genesis(self):
        ledger = self.ledger()
        with self.assertRaisesRegex(NodeError, "MISSING-GENESIS"):
            ledger.accept(block(1, 1))
        ledger = self.ledger()
        ledger.accept(block(0))
        with self.assertRaisesRegex(NodeError, "NONCONTIGUOUS-HEIGHT"):
            ledger.accept(block(2, 1))

    def test_malformed_records_and_late_anchor(self):
        h = "a" * 64
        for line in [
            f"BLOCK -1 {h} {h}",
            f"BLOCK 1x {h} {h}",
            f"BLOCK 9223372036854775807 {h} {h}",
            f"BLOCK 0 {'g' * 64} {h}",
            f"BLOCK 0 {h[:63]} {h}",
            f"BLOCK 0 {h} {h} surplus",
            "BOGUS",
            "",
        ]:
            with self.subTest(line=line):
                result = subprocess.run(
                    [str(ROOT / "build/ledger")],
                    input=line + "\n",
                    text=True,
                    capture_output=True,
                    timeout=5,
                )
                self.assertEqual(result.returncode, 1)
        ledger = self.ledger()
        ledger.accept(block(0))
        with self.assertRaisesRegex(NodeError, "MALFORMED-RECORD"):
            ledger.accept(block(3), anchor=True)

    def test_invalid_rpc_fields(self):
        for invalid in [
            None,
            {},
            {**block(0), "number": "0x00"},
            {**block(0), "number": hex(2**63)},
            {**block(0), "hash": "0x01"},
        ]:
            with self.assertRaises(NodeError):
                block_fields(invalid)


@contextlib.contextmanager
def rpc_server(handler):
    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):
            request = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
            answer = handler(request)
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps(answer).encode())

        def log_message(self, *args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}"
    finally:
        server.shutdown()
        server.server_close()
        thread.join()


class RpcTests(StoreFixture):
    def test_follower_end_to_end_and_restart(self):
        chain = [block(0), block(1, 1), block(2, 2)]

        def handler(request):
            if request["method"] == "eth_chainId":
                value = hex(4217)
            else:
                tag = request["params"][0]
                value = chain[-1] if tag == "finalized" else chain[int(tag, 16)]
            return {"jsonrpc": "2.0", "id": request["id"], "result": value}

        with rpc_server(handler) as url:
            command = [
                sys.executable,
                str(ROOT / "tempo11.py"),
                "follow",
                "--rpc",
                url,
                "--chain-id",
                "4217",
                "--database",
                str(self.path),
                "--once",
                "--limit",
                "2",
            ]
            first = subprocess.run(command, text=True, capture_output=True, timeout=10)
            self.assertEqual(first.returncode, 0, first.stderr)
            self.assertEqual(first.stdout.count("CLOSED "), 2)
            second = subprocess.run(command, text=True, capture_output=True, timeout=10)
            self.assertEqual(second.returncode, 0, second.stderr)
            self.assertEqual(second.stdout.count("CLOSED "), 1)
            # A conflicting upstream must never rewrite the durable ledger.
            chain[2] = block(2, 2, 999)
            conflict = subprocess.run(
                command, text=True, capture_output=True, timeout=10
            )
            self.assertEqual(conflict.returncode, 1)
            self.assertEqual(
                conflict.stderr,
                "THE BOOKS DO NOT BALANCE: upstream conflicts with durable head; refusing rewind\n",
            )
        self.assertEqual(block_fields(self.store().head())[1], f"{3:064x}")

    def test_reject_mismatched_rpc_id_and_chain(self):
        with rpc_server(
            lambda req: {"jsonrpc": "2.0", "id": 999, "result": "0x1"}
        ) as url:
            with self.assertRaisesRegex(NodeError, "envelope"):
                Rpc(url).call("eth_chainId", [])
        with rpc_server(
            lambda req: {"jsonrpc": "2.0", "id": req["id"], "result": "0x1"}
        ) as url:
            args = SimpleNamespace(rpc=url, chain_id=4217, once=True, limit=10, poll=1)
            with self.assertRaisesRegex(NodeError, "chain ID"):
                follow(args, self.store(), self.ledger())
        self.assertIsNone(self.store().head())


if __name__ == "__main__":
    unittest.main()
