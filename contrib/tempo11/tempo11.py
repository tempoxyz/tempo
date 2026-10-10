#!/usr/bin/env python3
"""Transport and durable block storage for the experimental COBOL follower."""

import argparse
import contextlib
import json
import re
import sqlite3
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent
HASH = re.compile(r"0x[0-9a-fA-F]{64}\Z")
QUANTITY = re.compile(r"0x(?:0|[1-9a-fA-F][0-9a-fA-F]*)\Z")
MAX_HEIGHT = 2**63 - 2
MAX_RESPONSE = 16 * 1024 * 1024


class NodeError(Exception):
    pass


def quantity(value):
    if not isinstance(value, str) or not QUANTITY.fullmatch(value):
        raise NodeError("invalid RPC quantity")
    return int(value, 16)


def block_fields(block):
    if not isinstance(block, dict):
        raise NodeError("missing or invalid block")
    height = quantity(block.get("number"))
    if height > MAX_HEIGHT:
        raise NodeError("block height exceeds durable storage range")
    hashes = [block.get("hash"), block.get("parentHash")]
    if any(not isinstance(h, str) or not HASH.fullmatch(h) for h in hashes):
        raise NodeError("invalid block hash")
    return height, hashes[0][2:].lower(), hashes[1][2:].lower()


class Ledger:
    def __init__(self, executable):
        self.process = subprocess.Popen(
            [str(executable)],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            text=True,
            bufsize=1,
        )

    def accept(self, block, *, anchor=False):
        height, block_hash, parent = block_fields(block)
        command = "ANCHOR" if anchor else "BLOCK"
        try:
            self.process.stdin.write(f"{command} {height} {block_hash} {parent}\n")
            self.process.stdin.flush()
            answer = self.process.stdout.readline().rstrip("\n")
        except BrokenPipeError as exc:
            raise NodeError("COBOL ledger terminated") from exc
        if answer != f"OK {height} {block_hash}":
            raise NodeError(answer or "COBOL ledger terminated")

    def close(self):
        try:
            if self.process.poll() is None:
                self.process.stdin.write("QUIT\n")
                self.process.stdin.flush()
                self.process.stdout.readline()
        except BrokenPipeError:
            pass
        finally:
            self.process.stdin.close()
            self.process.stdout.close()
            self.process.wait(timeout=5)


class Store:
    def __init__(self, path, chain_id):
        self.db = sqlite3.connect(path)
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.execute("PRAGMA synchronous=FULL")
        self.db.execute("""CREATE TABLE IF NOT EXISTS identity (
            singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
            chain_id TEXT NOT NULL)""")
        self.db.execute("""CREATE TABLE IF NOT EXISTS blocks (
            height INTEGER PRIMARY KEY, hash TEXT NOT NULL UNIQUE,
            body TEXT NOT NULL)""")
        try:
            with self.db:
                self.db.execute(
                    "INSERT OR IGNORE INTO identity VALUES (1, ?)", (str(chain_id),)
                )
                row = self.db.execute("SELECT chain_id FROM identity").fetchone()
                if row[0] != str(chain_id):
                    raise NodeError("database chain ID differs from requested chain")
        except BaseException:
            self.db.close()
            raise

    def head(self):
        row = self.db.execute(
            "SELECT body FROM blocks ORDER BY height DESC LIMIT 1"
        ).fetchone()
        return json.loads(row[0]) if row else None

    def append(self, block):
        height, block_hash, _ = block_fields(block)
        # Recheck within the write transaction so concurrent followers cannot
        # commit conflicting or skipped heights after their COBOL checks.
        self.db.execute("BEGIN IMMEDIATE")
        try:
            head = self.head()
            if head is None:
                if height != 0:
                    raise NodeError("database must begin at genesis")
            else:
                last_height, last_hash, _ = block_fields(head)
                if height != last_height + 1 or block_fields(block)[2] != last_hash:
                    raise NodeError("database head changed; restart follower")
            self.db.execute(
                "INSERT INTO blocks VALUES (?, ?, ?)",
                (height, block_hash, json.dumps(block)),
            )
            self.db.commit()
        except BaseException:
            self.db.rollback()
            raise

    def close(self):
        self.db.close()


class Rpc:
    def __init__(self, url):
        if not url.startswith(("https://", "http://")):
            raise NodeError("RPC URL must use HTTP or HTTPS")
        self.url = url
        self.request_id = 0

    def call(self, method, params):
        self.request_id += 1
        body = json.dumps(
            {
                "jsonrpc": "2.0",
                "id": self.request_id,
                "method": method,
                "params": params,
            }
        ).encode()
        request = urllib.request.Request(
            self.url, data=body, headers={"Content-Type": "application/json"}
        )
        with urllib.request.urlopen(request, timeout=30) as response:
            raw = response.read(MAX_RESPONSE + 1)
        if len(raw) > MAX_RESPONSE:
            raise NodeError("RPC response exceeds 16 MiB limit")
        answer = json.loads(raw)
        if (
            not isinstance(answer, dict)
            or answer.get("jsonrpc") != "2.0"
            or type(answer.get("id")) is not int
            or answer["id"] != self.request_id
        ):
            raise NodeError("invalid RPC response envelope")
        if "error" in answer or "result" not in answer:
            raise NodeError("upstream RPC rejected request")
        return answer["result"]

    def block(self, height):
        block = self.call("eth_getBlockByNumber", [hex(height), False])
        if block_fields(block)[0] != height:
            raise NodeError("RPC returned a different block height")
        return block


def ingest(store, ledger, blocks):
    count = 0
    for block in blocks:
        ledger.accept(block)
        store.append(block)
        height, block_hash, _ = block_fields(block)
        print(f"CLOSED {height} 0x{block_hash}", flush=True)
        count += 1
    return count


def follow(args, store, ledger):
    rpc = Rpc(args.rpc)
    if quantity(rpc.call("eth_chainId", [])) != args.chain_id:
        raise NodeError("upstream chain ID differs from requested chain")
    total = 0
    while True:
        head = store.head()
        if head is not None:
            height, block_hash, _ = block_fields(head)
            if block_fields(rpc.block(height))[1] != block_hash:
                raise NodeError("upstream conflicts with durable head; refusing rewind")
        else:
            height = -1
        # 'finalized' is an upstream assertion, not a verified certificate.
        finalized = rpc.call("eth_getBlockByNumber", ["finalized", False])
        target, target_hash, _ = block_fields(finalized)
        if target < height:
            raise NodeError("upstream finalized height regressed")
        end = min(target, height + args.limit - total)

        def pending():
            for number in range(height + 1, end + 1):
                block = rpc.block(number)
                if number == target and block_fields(block)[1] != target_hash:
                    raise NodeError("upstream finalized block changed during fetch")
                yield block

        total += ingest(store, ledger, pending())
        if args.once or total >= args.limit:
            return
        time.sleep(args.poll)


def replay(args, store, ledger):
    with args.blocks.open() as source:
        # Replay files contain only the next blocks, not already stored blocks.
        ingest(store, ledger, (json.loads(line) for line in source if line.strip()))


def positive(value):
    number = int(value)
    if number <= 0:
        raise argparse.ArgumentTypeError("must be positive")
    return number


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    subcommands = parser.add_subparsers(dest="mode", required=True)
    for mode in ("follow", "replay"):
        command = subcommands.add_parser(mode)
        command.add_argument("--chain-id", type=positive, required=True)
        command.add_argument("--database", type=Path, default=Path("tempo11.sqlite"))
        command.add_argument("--ledger", type=Path, default=ROOT / "build/ledger")
        if mode == "follow":
            command.add_argument("--rpc", required=True)
            command.add_argument("--once", action="store_true")
            command.add_argument("--limit", type=positive, default=1000)
            command.add_argument("--poll", type=positive, default=1)
        else:
            command.add_argument("--blocks", type=Path, required=True)
    evm = subcommands.add_parser("evm")
    evm.add_argument("bytecode", help="hex bytecode, with optional 0x prefix")
    args = parser.parse_args()
    try:
        if args.mode == "evm":
            code = args.bytecode.removeprefix("0x")
            if len(code) > 65536 or re.fullmatch("[0-9a-fA-F]*", code) is None:
                raise NodeError("invalid or oversized hex bytecode")
            return subprocess.run(
                [str(ROOT / "build/evm"), code], check=False
            ).returncode
        with contextlib.ExitStack() as stack:
            store = Store(args.database, args.chain_id)
            stack.callback(store.close)
            ledger = Ledger(args.ledger.resolve())
            stack.callback(ledger.close)
            if (head := store.head()) is not None:
                ledger.accept(head, anchor=True)
            if args.mode == "follow":
                follow(args, store, ledger)
            else:
                replay(args, store, ledger)
        return 0
    except urllib.error.HTTPError as exc:
        print(f"THE BOOKS DO NOT BALANCE: upstream HTTP {exc.code}", file=sys.stderr)
        return 1
    except (NodeError, OSError, ValueError, sqlite3.Error) as exc:
        # Network exception strings can contain credentials from the RPC URL.
        message = str(exc) if isinstance(exc, NodeError) else type(exc).__name__
        print(f"THE BOOKS DO NOT BALANCE: {message}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
