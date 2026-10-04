#!/usr/bin/env python3
"""Compare live historical receipts; retain commitments, not full receipt bodies."""

import argparse
import base64
import datetime
import gzip
import hashlib
import json
import os
from pathlib import Path
import re
import selectors
import shutil
import signal
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

MAX_BLOCKS = 50_000
MAX_RESPONSE_BYTES = 32 * 1024 * 1024
MAX_TOTAL_BYTES = 512 * 1024 * 1024
MAX_LEDGER_BYTES = 64 * 1024 * 1024
BATCH_BLOCKS = 8
MAX_DIAGNOSTIC_BYTES = 64 * 1024
RPC_USER_AGENT = "tempo-bench-receipts/1.0"


def require(condition, message):
    if not condition:
        raise ValueError(message)


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, "duplicate JSON object key")
        result[key] = value
    return result


def decode(data):
    return json.loads(data, object_pairs_hook=unique_object)


def canonical(value):
    # Sort object keys only. Preserve every field, value, and array position.
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


def digest(value):
    return hashlib.sha256(canonical(value)).hexdigest()


def quantity(value):
    require(isinstance(value, str) and re.fullmatch(r"0x(?:0|[1-9a-fA-F][0-9a-fA-F]*)", value),
            "missing or malformed RPC quantity")
    return int(value, 16)


def hex_bytes(value, size):
    require(isinstance(value, str) and re.fullmatch(r"0x[0-9a-fA-F]{" + str(size * 2) + r"}", value),
            f"missing or malformed {size}-byte RPC field")
    return value.lower()


class Budget:
    def __init__(self, seconds):
        self.deadline = time.monotonic() + seconds
        self.bytes = 0

    def remaining(self):
        remaining = self.deadline - time.monotonic()
        require(remaining > 0, "receipt verification deadline exceeded")
        return min(15, remaining)


def rpc_request(url, data, user_agent=None):
    parts = urllib.parse.urlsplit(url)
    headers = {"Content-Type": "application/json",
               "User-Agent": RPC_USER_AGENT if user_agent is None else user_agent}
    authorization = None
    if parts.username is not None:
        # urllib does not translate URL userinfo to HTTP Basic authentication.
        credentials = urllib.parse.unquote(parts.username) + ":" + urllib.parse.unquote(parts.password or "")
        authorization = "Basic " + base64.b64encode(credentials.encode()).decode("ascii")
        parts = parts._replace(netloc=parts.netloc.rsplit("@", 1)[1])
    request = urllib.request.Request(urllib.parse.urlunsplit(parts), data, headers)
    if authorization is not None:
        # Credentials belong to this endpoint, never a redirect destination.
        request.add_unredirected_header("Authorization", authorization)
    return request


class Rpc:
    def __init__(self, url, budget, name):
        self.url, self.budget, self.name = url, budget, name

    def batch(self, calls):
        requests = [{"jsonrpc": "2.0", "id": i, "method": method, "params": params}
                    for i, (method, params) in enumerate(calls)]
        timeout = self.budget.remaining()
        # Never include the source URL (which may contain credentials) in failures.
        try:
            request = rpc_request(self.url, canonical(requests))
            with urllib.request.urlopen(request, timeout=timeout) as response:
                data = response.read(MAX_RESPONSE_BYTES + 1)
        except urllib.error.HTTPError as error:
            raise ValueError(f"{self.name} RPC request failed (HTTP {error.code})") from None
        except Exception as error:
            # Exception messages/reasons can contain credentials, paths or query tokens.
            raise ValueError(f"{self.name} RPC request failed ({type(error).__name__})") from None
        require(len(data) <= MAX_RESPONSE_BYTES, "RPC response exceeds byte limit")
        self.budget.bytes += len(data)
        require(self.budget.bytes <= MAX_TOTAL_BYTES, "RPC total exceeds byte limit")
        self.budget.remaining()
        replies = decode(data)
        require(isinstance(replies, list) and len(replies) == len(calls), "missing RPC responses")
        indexed = {}
        for reply in replies:
            require(isinstance(reply, dict) and reply.get("jsonrpc") == "2.0", "malformed RPC response")
            index = reply.get("id")
            require(type(index) is int and 0 <= index < len(calls) and index not in indexed,
                    "duplicate or unexpected RPC response id")
            require("error" not in reply and reply.get("result") is not None, "RPC returned error or null")
            indexed[index] = reply["result"]
        return [indexed[i] for i in range(len(calls))]


def bounded_command(args, data, timeout, limit):
    """Bound output while draining it; always reap a timed-out/oversized child."""
    deadline = time.monotonic() + timeout
    process = subprocess.Popen(args, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                               stderr=subprocess.DEVNULL)
    output = bytearray()
    try:
        with selectors.DefaultSelector() as selector:
            os.set_blocking(process.stdin.fileno(), False)
            os.set_blocking(process.stdout.fileno(), False)
            if data:
                selector.register(process.stdin, selectors.EVENT_WRITE)
            else:
                process.stdin.close()
            selector.register(process.stdout, selectors.EVENT_READ)
            pending = memoryview(data)
            while selector.get_map():
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise TimeoutError()
                for key, _ in selector.select(remaining):
                    if key.fileobj is process.stdin:
                        pending = pending[os.write(process.stdin.fileno(), pending):]
                        if not pending:
                            selector.unregister(process.stdin)
                            process.stdin.close()
                    else:
                        chunk = os.read(process.stdout.fileno(), min(8192, limit + 1 - len(output)))
                        if not chunk:
                            selector.unregister(process.stdout)
                        output.extend(chunk)
                        if len(output) > limit:
                            raise OverflowError()
            returncode = process.wait(timeout=max(0.001, deadline - time.monotonic()))
        return returncode, bytes(output)
    finally:
        if process.poll() is None:
            process.kill()
        process.wait()
        process.stdin.close()
        process.stdout.close()


def curl_config(url, payload, user_agent):
    # curl's quoted config syntax, not shell syntax. Reject controls outright so
    # neither a URL nor credentials can create an additional config directive.
    def quoted(value):
        require(not any(ord(char) < 32 or ord(char) == 127 for char in value), "invalid diagnostic input")
        return '"' + value.replace('\\', '\\\\').replace('"', '\\"') + '"'
    lines = ["url = " + quoted(url), 'header = "Content-Type: application/json"',
             "data-raw = " + quoted(payload.decode("ascii"))]
    if user_agent is not None:
        lines.append("user-agent = " + quoted(user_agent))
    config = ("\n".join(lines) + "\n").encode()
    require(len(config) <= 16 * 1024, "excessive diagnostic input")
    return config


def diagnostic_response(data, request, chain_id):
    result = {"response_shape": "non_json", "ids_valid": False,
              "quantities_valid": False, "chain_match": None}
    try:
        reply = decode(data)
        result["response_shape"] = "array" if isinstance(reply, list) else "object" if isinstance(reply, dict) else "scalar"
        calls = request if isinstance(request, list) else [request]
        replies = reply if isinstance(reply, list) else [reply]
        require(isinstance(request, list) == isinstance(reply, list), "shape")
        require(len(replies) == len(calls), "count")
        indexed = {}
        for item in replies:
            require(isinstance(item, dict) and item.get("jsonrpc") == "2.0", "reply")
            index = item.get("id")
            require(type(index) is int and index not in indexed, "id")
            indexed[index] = item
        require(set(indexed) == {call["id"] for call in calls}, "ids")
        result["ids_valid"] = True
        for call in calls:
            item = indexed[call["id"]]
            require("error" not in item, "RPC error")
            value = quantity(item.get("result"))
            if call["method"] == "eth_chainId":
                result["chain_match"] = value == chain_id
        result["quantities_valid"] = True
    except Exception:
        pass  # The server's response and error text must never reach the log.
    return result


def diagnostic_probe(url, request, chain_id, budget, transport, label, user_agent=None, http1=False):
    result = {"probe": label, "status": "transport_error", "http_status": None,
              "response_shape": "unavailable", "ids_valid": False,
              "quantities_valid": False, "chain_match": None}
    timeout = min(8, budget.remaining())
    signal.setitimer(signal.ITIMER_REAL, timeout)
    try:
        payload = canonical(request)
        if transport == "curl":
            args = ["curl", "--disable", "--silent", "--globoff", "--config", "-", "--proto", "=http,https",
                    "--max-time", str(timeout), "--max-filesize", str(MAX_DIAGNOSTIC_BYTES),
                    "--write-out", "\n%{http_code}"]
            if http1:
                args.append("--http1.1")
            code, output = bounded_command(args, curl_config(url, payload, user_agent), timeout,
                                           MAX_DIAGNOSTIC_BYTES + 4)
            data, _, status = output.rpartition(b"\n")
            require(re.fullmatch(rb"[0-9]{3}", status), "missing HTTP status")
            result["http_status"] = int(status)
            if code != 0:
                return result
        else:
            try:
                response = urllib.request.urlopen(rpc_request(url, payload, user_agent), timeout=timeout)
            except urllib.error.HTTPError as error:
                response = error
            with response:
                result["http_status"] = response.code
                data = response.read(MAX_DIAGNOSTIC_BYTES + 1)
        if len(data) > MAX_DIAGNOSTIC_BYTES:
            raise OverflowError()
        result.update(diagnostic_response(data, request, chain_id), status="response")
    except (TimeoutError, subprocess.TimeoutExpired):
        result["status"] = "timeout"
    except OverflowError:
        result["status"] = "response_too_large"
    except Exception:
        pass
    finally:
        remaining = budget.deadline - time.monotonic()
        signal.setitimer(signal.ITIMER_REAL, max(0, remaining))
    return result


def diagnose(url, chain_id):
    """A bounded transport experiment only; never used as an oracle fallback."""
    budget = Budget(60)
    batch = [{"jsonrpc": "2.0", "id": i, "method": method, "params": []}
             for i, method in enumerate(("eth_chainId", "eth_blockNumber"))]
    probes = []
    def probe(transport, label, request=batch, **kwargs):
        result = diagnostic_probe(url, request, chain_id, budget, transport, label, **kwargs)
        probes.append(result)
        return (result["status"] == "response" and result["http_status"] == 200 and
                result["ids_valid"] and result["quantities_valid"] and result["chain_match"] is not False)
    curl_ok = probe("curl", "curl_batch")
    urllib_ok = probe("urllib", "urllib_batch")
    if not curl_ok:
        probe("curl", "curl_chain_object", batch[0])
        probe("curl", "curl_height_object", batch[1])
        probe("curl", "curl_height_array", [batch[1]])
    elif not urllib_ok:
        python_agent = "Python-urllib/" + str(sys.version_info.major) + "." + str(sys.version_info.minor)
        probe("curl", "curl_python_agent", user_agent=python_agent)
        code, version = bounded_command(["curl", "--disable", "--version"], b"",
                                        min(2, budget.remaining()), 4096)
        match = re.match(rb"curl ([0-9]+\.[0-9]+\.[0-9]+)(?:\s|$)", version)
        require(code == 0 and match is not None, "curl version unavailable")
        probe("urllib", "urllib_curl_agent", user_agent="curl/" + match[1].decode("ascii"))
        probe("curl", "curl_http1", http1=True)
    return {"status": "completed", "probes": probes}


def header_record(header):
    require(isinstance(header, dict), "missing block header")
    transactions = header.get("transactions")
    require(isinstance(transactions, list), "missing block transactions")
    hashes = [hex_bytes(tx, 32) for tx in transactions]
    require(len(set(hashes)) == len(hashes), "duplicate block transaction")
    record = {key: hex_bytes(header.get(key), 32)
              for key in ("hash", "parentHash", "stateRoot", "receiptsRoot", "transactionsRoot")}
    record.update({key: quantity(header.get(key))
                   for key in ("number", "timestamp", "gasUsed", "gasLimit")})
    record.update(transaction_count=len(hashes), transactions_sha256=digest(hashes))
    return record, hashes


def receipt_digest(receipts, header, transactions):
    require(isinstance(receipts, list) and len(receipts) == len(transactions), "receipt count mismatch")
    log_index = 0
    for index, (receipt, tx_hash) in enumerate(zip(receipts, transactions)):
        require(isinstance(receipt, dict), "malformed receipt")
        require(hex_bytes(receipt.get("blockHash"), 32) == header["hash"] and
                quantity(receipt.get("blockNumber")) == header["number"] and
                hex_bytes(receipt.get("transactionHash"), 32) == tx_hash and
                quantity(receipt.get("transactionIndex")) == index, "receipt identity/order mismatch")
        for key in ("cumulativeGasUsed", "gasUsed", "effectiveGasPrice", "type"):
            quantity(receipt.get(key))
        require(("status" in receipt) != ("root" in receipt), "missing or ambiguous receipt status/root")
        if "status" in receipt:
            require(quantity(receipt["status"]) in (0, 1), "invalid receipt status")
        else:
            hex_bytes(receipt["root"], 32)
        hex_bytes(receipt.get("logsBloom"), 256)
        hex_bytes(receipt.get("from"), 20)
        for key in ("to", "contractAddress"):
            require(key in receipt, f"missing receipt {key}")
            if receipt[key] is not None:
                hex_bytes(receipt[key], 20)
        logs = receipt.get("logs")
        require(isinstance(logs, list), "missing receipt logs")
        for log in logs:
            require(isinstance(log, dict) and log.get("removed") is False, "malformed or removed log")
            require(hex_bytes(log.get("blockHash"), 32) == header["hash"] and
                    quantity(log.get("blockNumber")) == header["number"] and
                    hex_bytes(log.get("transactionHash"), 32) == tx_hash and
                    quantity(log.get("transactionIndex")) == index and
                    quantity(log.get("logIndex")) == log_index, "log identity/order mismatch")
            hex_bytes(log.get("address"), 20)
            require(isinstance(log.get("topics"), list), "missing log topics")
            for topic in log["topics"]:
                hex_bytes(topic, 32)
            require(isinstance(log.get("data"), str) and re.fullmatch(r"0x(?:[0-9a-fA-F]{2})*", log["data"]),
                    "malformed log data")
            log_index += 1
    return digest(receipts)


def read_report(path, first, last, label, git_sha):
    require(0 <= first <= last and last - first + 1 <= MAX_BLOCKS, "invalid or excessive receipt cohort")
    require(path.stat().st_size <= 128 * 1024 * 1024, "report exceeds byte limit")
    report = decode(path.read_bytes())
    require(isinstance(report, dict), "malformed replay report")
    metadata = report.get("metadata", {})
    require(isinstance(metadata, dict), "malformed replay metadata")
    require(metadata.get("benchmark_run") == label and metadata.get("git-sha") == git_sha,
            "report source/run binding mismatch")
    require(isinstance(metadata.get("benchmark_id"), str) and metadata["benchmark_id"], "missing benchmark id")
    blocks = report.get("blocks")
    require(isinstance(blocks, list) and len(blocks) == last - first + 1, "incomplete report cohort")
    for number, block in enumerate(blocks, first):
        require(isinstance(block, dict) and type(block.get("number")) is int and block["number"] == number,
                "report heights must be contiguous and ordered")
        for key in ("tx_count", "gas_used", "gas_limit", "timestamp_ms"):
            require(type(block.get(key)) is int and block[key] >= 0, f"malformed report {key}")
    return metadata["benchmark_id"], blocks


def verify(blocks, node, source, reference, output, meta, budget):
    """Stream one full cohort; create a reference only after all checks succeed."""
    chain_ids = [quantity(rpc.batch([("eth_chainId", [])])[0]) for rpc in (node, source)]
    require(chain_ids == [meta["chain_id"]] * 2, "RPC chain id mismatch")
    reader = gzip.open(reference, "rb") if reference.exists() else None
    first_pass = reader is None
    reference_bytes = 0

    def read_reference():
        nonlocal reference_bytes
        line = reader.readline(4097)
        reference_bytes += len(line)
        require(line and len(line) <= 4096 and reference_bytes <= MAX_LEDGER_BYTES,
                "missing or oversized reference record")
        return decode(line)

    reference_meta = meta if first_pass else read_reference()
    require(isinstance(reference_meta, dict), "malformed reference metadata")
    for key in ("schema", "benchmark_id", "chain_id", "first", "last"):
        require(reference_meta.get(key) == meta[key], f"reference {key} mismatch")
    written = 0
    receipt_count = 0
    previous_hash = None
    partial = output.with_suffix(output.suffix + ".partial")
    try:
        with gzip.open(partial, "wb") as writer:
            def write(record):
                nonlocal written
                line = canonical(record) + b"\n"
                written += len(line)
                require(written <= MAX_LEDGER_BYTES, "receipt ledger exceeds byte limit")
                writer.write(line)

            write(meta)
            for offset in range(0, len(blocks), BATCH_BLOCKS):
                budget.remaining()
                group = blocks[offset:offset + BATCH_BLOCKS]
                if first_pass:
                    headers = source.batch([("eth_getBlockByNumber", [hex(b["number"]), False]) for b in group])
                    expected = [header_record(header)[0] for header in headers]
                else:
                    expected = [read_reference() for _ in group]
                calls = []
                for record in expected:
                    require(isinstance(record, dict), "malformed reference record")
                    block_hash = hex_bytes(record.get("hash"), 32)
                    calls.extend([("eth_getBlockByHash", [block_hash, False]),
                                  ("eth_getBlockReceipts", [block_hash])])
                replies = node.batch(calls)
                for index, (block, expected_record) in enumerate(zip(group, expected)):
                    record, transactions = header_record(replies[index * 2])
                    # bench send-blocks records seconds * 1000; unlike E2E
                    # metrics it does not add Tempo's timestampMillisPart.
                    require(record["number"] == block["number"] and
                            record["transaction_count"] == block["tx_count"] and
                            record["gasUsed"] == block["gas_used"] and
                            record["gasLimit"] == block["gas_limit"] and
                            record["timestamp"] * 1000 == block["timestamp_ms"], "header/report mismatch")
                    require(previous_hash is None or record["parentHash"] == previous_hash, "broken block ancestry")
                    previous_hash = record["hash"]
                    require(all(record[key] == expected_record.get(key) for key in record),
                            f"header/source commitment mismatch at {record['number']}")
                    record["receipts_sha256"] = receipt_digest(replies[index * 2 + 1], record, transactions)
                    if not first_pass:
                        require(record == expected_record, f"full receipt mismatch at {record['number']}")
                    receipt_count += len(transactions)
                    write(record)
            if reader:
                require(reader.read(1) == b"", "extra reference records")
            # By-hash reads are immutable; this final check binds the linked cohort
            # to each RPC's canonical chain at verification completion.
            for rpc in (node, source):
                final, _ = header_record(rpc.batch([("eth_getBlockByNumber", [hex(meta["last"]), False])])[0])
                require(final == {key: value for key, value in record.items() if key != "receipts_sha256"},
                        "canonical cohort header changed or is malformed")
            budget.remaining()
        partial.replace(output)
        if first_pass:
            shutil.copyfile(output, reference)
    finally:
        if reader:
            reader.close()
    return {"blocks": len(blocks), "receipts": receipt_count, "first_pass": first_pass,
            "reference_label": reference_meta["label"], "reference_git_sha": reference_meta["git_sha"],
            "ledger_sha256": hashlib.sha256(output.read_bytes()).hexdigest(),
            "reference_sha256": hashlib.sha256(reference.read_bytes()).hexdigest(),
            "rpc_response_bytes": budget.bytes}


def finalize(work_dir):
    labels = (work_dir / "run-order.txt").read_text().splitlines()
    require(2 <= len(labels) <= 100 and len(set(labels)) == len(labels), "invalid oracle run order")
    require(all(re.fullmatch(r"(?:baseline|feature)-[1-9][0-9]*", label) for label in labels),
            "invalid oracle run label")
    require(sum(label.startswith("baseline-") for label in labels) ==
            sum(label.startswith("feature-") for label in labels), "missing oracle comparison arm")
    summaries = []
    for label in labels:
        path = work_dir / label / "receipt-oracle-summary.json"
        require(path.stat().st_size <= 64 * 1024, "oversized receipt summary")
        summary = decode(path.read_bytes())
        require(isinstance(summary, dict), "malformed receipt summary")
        require(summary.get("status") == "passed" and summary.get("label") == label,
                "receipt comparison did not complete")
        for key in ("chain_id", "first", "last", "blocks", "receipts", "rpc_response_bytes"):
            require(type(summary.get(key)) is int and summary[key] >= 0, f"missing or malformed summary {key}")
        require(summary.get("schema") == 1 and summary["chain_id"] > 0 and
                0 < summary["blocks"] <= MAX_BLOCKS and
                summary["last"] - summary["first"] + 1 == summary["blocks"] and
                summary["rpc_response_bytes"] <= MAX_TOTAL_BYTES, "invalid summary cohort/bounds")
        require(isinstance(summary.get("benchmark_id"), str) and summary["benchmark_id"] and
                isinstance(summary.get("scope"), str), "missing summary metadata")
        for key, size in (("git_sha", 40), ("reference_git_sha", 40),
                          ("ledger_sha256", 64), ("reference_sha256", 64), ("report_sha256", 64)):
            require(isinstance(summary.get(key), str) and re.fullmatch(r"[0-9a-f]{" + str(size) + r"}", summary[key]),
                    f"malformed summary {key}")
        require(summary.get("reference_label") == labels[0], "wrong reference label")
        ledger = work_dir / label / "receipt-oracle.jsonl.gz"
        require(ledger.stat().st_size <= MAX_LEDGER_BYTES and
                hashlib.sha256(ledger.read_bytes()).hexdigest() == summary["ledger_sha256"], "ledger digest mismatch")
        if not summaries:
            require(summary["reference_sha256"] == summary["ledger_sha256"] and
                    summary["reference_git_sha"] == summary["git_sha"], "reference identity mismatch")
        require(summary.get("first_pass") is (not summaries), "unexpected reference pass")
        if summaries:
            for key in ("benchmark_id", "chain_id", "first", "last", "blocks", "receipts",
                        "reference_label", "reference_git_sha", "reference_sha256"):
                require(summary.get(key) == summaries[0].get(key), f"receipt comparison {key} mismatch")
        summaries.append(summary)
    result = {"status": "passed", "scope": summaries[0]["scope"], "passes": summaries}
    (work_dir / "receipt-oracle-comparison.json").write_text(json.dumps(result, indent=2) + "\n")
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    diagnostic = sub.add_parser("diagnose")
    diagnostic.add_argument("--chain-id", type=int, required=True)
    preflight = sub.add_parser("preflight")
    preflight.add_argument("--chain-id", type=int, required=True)
    finish = sub.add_parser("finalize")
    finish.add_argument("--work-dir", type=Path, required=True)
    capture = sub.add_parser("capture")
    capture.add_argument("--rpc", default="http://127.0.0.1:8545")
    capture.add_argument("--report", type=Path, required=True)
    capture.add_argument("--reference", type=Path, required=True)
    capture.add_argument("--output-dir", type=Path, required=True)
    capture.add_argument("--first", type=int, required=True)
    capture.add_argument("--last", type=int, required=True)
    capture.add_argument("--chain-id", type=int, required=True)
    capture.add_argument("--label", required=True)
    capture.add_argument("--git-sha", required=True)
    capture.add_argument("--deadline-seconds", type=int, default=1200)
    args = parser.parse_args()
    if args.command == "diagnose":
        def diagnostic_expired(_signum, _frame):
            raise TimeoutError()
        signal.signal(signal.SIGALRM, diagnostic_expired)
        signal.alarm(60)
        try:
            result = diagnose(os.environ["REPLAY_RPC_URL"], args.chain_id)
        except Exception:
            result = {"status": "stopped"}
        finally:
            signal.setitimer(signal.ITIMER_REAL, 0)
        print(json.dumps(result))
        return 0 if result["status"] == "completed" else 1
    if args.command == "preflight":
        def preflight_expired(_signum, _frame):
            raise ValueError("receipt preflight deadline exceeded")
        try:
            signal.signal(signal.SIGALRM, preflight_expired)
            signal.alarm(60)
            rpc = Rpc(os.environ["REPLAY_RPC_URL"], Budget(60), "source")
            chain, height = rpc.batch([("eth_chainId", []), ("eth_blockNumber", [])])
            require(quantity(chain) == args.chain_id, "source RPC chain id mismatch")
            quantity(height)
        except (OSError, ValueError, KeyError, TypeError) as error:
            print(f"Receipt oracle preflight failed: {error}", file=sys.stderr)
            return 1
        finally:
            signal.alarm(0)
        print("Receipt oracle source RPC preflight passed")
        return 0
    if args.command == "finalize":
        try:
            result = finalize(args.work_dir)
        except (OSError, ValueError, KeyError, TypeError) as error:
            print(f"Receipt oracle finalization failed: {error}", file=sys.stderr)
            return 1
        print(f"Full receipt comparison passed for {len(result['passes'])} historical replay passes")
        return 0
    summary = {"status": "failed", "scope": "Historical live full-receipt comparison; retained ledger contains digests, not receipt bodies. Network headers independently commit state/receipt roots; they do not independently compare RPC receipt fields. No timing claim.", "label": args.label, "git_sha": args.git_sha,
               "started_at": datetime.datetime.now(datetime.timezone.utc).isoformat()}
    try:
        require(0 < args.deadline_seconds <= 3600, "deadline must be between 1 and 3600 seconds")
        require(re.fullmatch(r"[0-9a-f]{40}", args.git_sha), "invalid source SHA")
        def deadline_expired(_signum, _frame):
            raise ValueError("receipt verification deadline exceeded")
        signal.signal(signal.SIGALRM, deadline_expired)
        signal.alarm(args.deadline_seconds)
        budget = Budget(args.deadline_seconds)
        benchmark_id, blocks = read_report(args.report, args.first, args.last, args.label, args.git_sha)
        summary["report_sha256"] = hashlib.sha256(args.report.read_bytes()).hexdigest()
        meta = {"schema": 1, "benchmark_id": benchmark_id, "chain_id": args.chain_id,
                "first": args.first, "last": args.last, "label": args.label, "git_sha": args.git_sha}
        node = Rpc(args.rpc, budget, "node")
        source = Rpc(os.environ["REPLAY_RPC_URL"], budget, "source")
        summary.update(verify(blocks, node, source, args.reference,
                              args.output_dir / "receipt-oracle.jsonl.gz", meta, budget))
        summary.update(status="passed", **meta)
    except (OSError, ValueError, KeyError, TypeError) as error:
        # RPC transport exceptions have already been stripped of source URLs.
        summary["error"] = str(error)
    finally:
        signal.alarm(0)
    summary["finished_at"] = datetime.datetime.now(datetime.timezone.utc).isoformat()
    (args.output_dir / "receipt-oracle-summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    print(json.dumps(summary))
    return 0 if summary["status"] == "passed" else 1


if __name__ == "__main__":
    sys.exit(main())
