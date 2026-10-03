#!/usr/bin/env python3
"""Live, fail-closed generated-block differential check; never a speedup benchmark.

A builds/validates with speculation and B executes sequentially. Each finalized
payload is checked as producer execution plus fresh opposite-peer Engine execution,
not two fresh Engine executions. Both use the same candidate binary: shared
changes (including State commit) require their separate oracle tests. Full receipt JSON is compared one block at a time;
state-root correctness additionally relies on enabled canonical Engine validation.
"""

import argparse
import datetime
import gzip
import hashlib
import json
import re
import sys
import time
import urllib.request
from pathlib import Path
from urllib.parse import urlparse


class VerificationError(Exception):
    pass


def require(condition, message):
    if not condition:
        raise VerificationError(message)


def integer(value, label):
    require(type(value) is int and value >= 0, f"invalid {label}: {value!r}")
    return value


def quantity(value, label):
    require(isinstance(value, str) and re.fullmatch(r"0x(?:0|[1-9a-f][0-9a-f]*)", value),
            f"invalid RPC {label}: {value!r}")
    return int(value, 16)


def block_hash(value):
    require(isinstance(value, str) and re.fullmatch(r"0x[0-9a-f]{64}", value),
            f"invalid hash: {value!r}")
    return value


def option(args, name, default=None):
    values = []
    for index, arg in enumerate(args):
        if arg == name:
            require(index + 1 < len(args) and not args[index + 1].startswith("--"),
                    f"missing value for {name}")
            values.append(args[index + 1])
        elif arg.startswith(name + "="):
            values.append(arg.split("=", 1)[1])
    require(len(values) <= 1, f"duplicate {name}")
    return values[0] if values else default


def check_config(config):
    require(isinstance(config, dict) and config.get("mode") == "sequential-peer",
            "expected sequential-peer manifest")
    require(re.fullmatch(r"[0-9a-f]{64}", config.get("binary_sha256", "")),
            "missing binary SHA-256")
    require(isinstance(config.get("feature_ref"), str) and config["feature_ref"],
            "missing feature reference")
    forbidden = {"--debug.skip-state-root", "--builder.parallel", "--builder.disable-prewarming",
                 "--engine.disable-prewarming", "--engine.disable-caching-and-prewarming"}
    for role in ("a", "b"):
        node = config.get(role, {})
        args = node.get("args")
        require(isinstance(args, list) and all(isinstance(arg, str) for arg in args),
                f"{role}: missing exact node argv")
        require(not any(arg.split("=", 1)[0] in forbidden for arg in args),
                f"{role}: validation/prewarming disabled or alternate builder replay enabled")
        threads = option(args, "--execution.threads")
        require(threads is not None and threads.isdecimal(), f"{role}: explicit execution threads required")
        require(int(threads) > 0 if role == "a" else int(threads) == 0,
                f"{role}: expected parallel A and sequential B")
        require(option(args, "--log.file.format") == "json", f"{role}: JSON file logs required")
        parsed = urlparse(node.get("rpc_url", ""))
        require(parsed.scheme in ("http", "https") and parsed.hostname, f"{role}: invalid RPC URL")
        require(isinstance(node.get("log_dir"), str) and node["log_dir"], f"{role}: missing log directory")
    require(config["a"]["rpc_url"] != config["b"]["rpc_url"], "peer RPC URLs must differ")
    require(Path(config["a"]["log_dir"]).resolve() != Path(config["b"]["log_dir"]).resolve(),
            "peer log directories must differ")


def rpc_result(payload, request_id):
    require(isinstance(payload, dict) and payload.get("jsonrpc") == "2.0"
            and type(payload.get("id")) is int and payload["id"] == request_id,
            "malformed JSON-RPC envelope")
    require("error" not in payload and "result" in payload and payload["result"] is not None,
            f"RPC error or missing result: {str(payload)[:300]}")
    return payload["result"]


class Rpc:
    def __init__(self, url):
        self.url = url
        self.request_id = 0

    def __call__(self, method, params):
        self.request_id += 1
        request = urllib.request.Request(self.url, headers={"Content-Type": "application/json"},
            data=json.dumps({"jsonrpc": "2.0", "id": self.request_id,
                             "method": method, "params": params}).encode())
        with urllib.request.urlopen(request, timeout=20) as response:
            data = response.read(64 * 1024 * 1024 + 1)
        require(len(data) <= 64 * 1024 * 1024, "RPC response exceeds 64 MiB limit")
        return rpc_result(json.loads(data), self.request_id)


def header(block):
    require(isinstance(block, dict), "missing RPC block")
    for field in ("hash", "parentHash", "stateRoot", "receiptsRoot"):
        block_hash(block.get(field))
    for field in ("number", "gasUsed", "timestamp", "timestampMillisPart"):
        quantity(block.get(field), field)
    require(quantity(block["timestampMillisPart"], "timestampMillisPart") < 1000, "invalid timestamp millis")
    txs = block.get("transactions")
    require(isinstance(txs, list), "missing block transactions")
    for tx in txs:
        block_hash(tx)
    require(len(set(txs)) == len(txs), "duplicate block transaction")
    return {key: block[key] for key in
            ("number", "hash", "parentHash", "stateRoot", "receiptsRoot", "gasUsed", "timestamp", "timestampMillisPart", "transactions")}


def workload(report):
    require(isinstance(report, dict), "malformed txgen report")
    blocks = report.get("blocks")
    require(isinstance(blocks, list) and blocks, "txgen report has no block cohort")
    start = report.get("metadata", {}).get("measurement_send_start_unix_ms")
    require(isinstance(start, (str, int)) and str(start).isdecimal(), "missing txgen send-start timestamp")
    seen, selected = set(), []
    for block in blocks:
        require(isinstance(block, dict), "malformed txgen block")
        number = integer(block.get("number"), "report block number")
        count = integer(block.get("tx_count"), "report tx count")
        stamp = integer(block.get("timestamp_ms"), "report block timestamp")
        integer(block.get("gas_used"), "report gas used")
        require(number not in seen, f"duplicate report block {number}")
        seen.add(number)
        if stamp >= int(start) and count > 0:
            selected.append(block)
    require(selected, "no nonempty generated blocks after send start")
    selected.sort(key=lambda block: block["number"])
    require(selected[0]["number"] > 0, "generated cohort cannot include genesis")
    require(selected[-1]["number"] - selected[0]["number"] < 10000, "generated cohort exceeds 10000 blocks")
    return {block["number"]: block for block in selected}


def wait_finalized(rpcs, end, timeout, clock=time.monotonic, sleep=time.sleep):
    deadline = clock() + timeout
    while True:
        heads = [header(rpc("eth_getBlockByNumber", ["finalized", False])) for rpc in rpcs]
        if all(quantity(head["number"], "finalized number") >= end for head in heads):
            return
        require(clock() < deadline, f"finality did not reach generated block {end} within {timeout}s")
        sleep(min(1, max(0, deadline - clock())))


def receipts(rpc, block):
    result = rpc("eth_getBlockReceipts", [block["number"]])
    require(isinstance(result, list) and len(result) == len(block["transactions"]),
            f"missing receipts for {block['hash']}")
    previous_gas = 0
    for index, (receipt, tx) in enumerate(zip(result, block["transactions"])):
        require(isinstance(receipt, dict), "malformed receipt")
        require(receipt.get("blockHash") == block["hash"] and receipt.get("blockNumber") == block["number"]
                and receipt.get("transactionHash") == tx
                and quantity(receipt.get("transactionIndex"), "receipt index") == index,
                f"receipt identity mismatch at {block['number']}:{index}")
        require(receipt.get("status") in ("0x0", "0x1"), "missing receipt status")
        require(isinstance(receipt.get("logs"), list), "missing receipt logs")
        require(isinstance(receipt.get("logsBloom"), str)
                and re.fullmatch(r"0x[0-9a-f]{512}", receipt["logsBloom"]), "missing receipt bloom")
        gas = quantity(receipt.get("gasUsed"), "receipt gas")
        cumulative = quantity(receipt.get("cumulativeGasUsed"), "receipt cumulative gas")
        require(cumulative == previous_gas + gas, "inconsistent receipt gas accounting")
        previous_gas = cumulative
    require(previous_gas == quantity(block["gasUsed"], "block gas"), "receipts do not cover block gas")
    return result


BLOCK_ID = re.compile(r"BlockWithParent \{ parent: (0x[0-9a-f]{64}), block: NumHash \{ number: ([0-9]+), hash: (0x[0-9a-f]{64}) \} \}")
STATUS = re.compile(r"PayloadStatus \{ status: ([A-Z]+), latestValidHash: (?:Some\((0x[0-9a-f]{64})\)|None).*")


def span_identity(spans):
    # Buffered descendants need the innermost actual block, not outer on_new_payload.
    for span in reversed(spans):
        if span.get("name") == "insert_block_or_payload":
            match = BLOCK_ID.fullmatch(span.get("block_id", ""))
            require(match, "malformed actual Engine block-id span")
            parent, number, digest = match.groups()
            return int(number), digest, parent
    return None


def log_events(directory):
    paths = sorted(path for path in Path(directory).rglob("reth.log*") if path.is_file())
    require(paths, f"no node JSON logs in {directory}")
    for path in paths:
        opener = gzip.open if path.suffix == ".gz" else open
        with opener(path, "rt") as stream:
            for line, text in enumerate(stream, 1):
                # The live writer may be halfway through its final line; it cannot
                # establish any evidence. Missing completed cohort events still fail.
                if not text.endswith("\n"):
                    continue
                try:
                    event = json.loads(text)
                except (ValueError, UnicodeError) as error:
                    raise VerificationError(f"malformed node JSON at {path}:{line}") from error
                yield event, f"{path}:{line}"


def index_logs(events):
    index = {"built": {}, "executed": {}, "valid": {}, "engine_reuse": {}, "builder_reuse": {}}
    relevant = []
    messages = {"building new payload", "Built payload", "Executed block", "Executed block via BAL path",
                "execution layer reported payload status", "Finished speculative block execution"}
    for event, location in events:
        require(isinstance(event, dict) and isinstance(event.get("fields"), dict), f"malformed event at {location}")
        if event["fields"].get("message") not in messages:
            continue
        try:
            stamp = datetime.datetime.fromisoformat(event["timestamp"].replace("Z", "+00:00"))
            require(stamp.tzinfo is not None, f"missing timestamp zone at {location}")
        except (KeyError, ValueError, TypeError) as error:
            raise VerificationError(f"missing event timestamp at {location}") from error
        relevant.append((stamp, event, location))
    # Live reth.log sorts before its older rotations. Retain/sort only these few
    # lifecycle records, not the transaction logs or receipt bodies.
    relevant.sort(key=lambda item: item[0])
    attempts, engine_stats = {}, {}
    for stamp, event, location in relevant:
        fields, spans = event["fields"], event.get("spans", [])
        require(isinstance(spans, list) and all(isinstance(span, dict) for span in spans), f"malformed spans at {location}")
        message = fields["message"]
        proof = {"source": location, "time": stamp.isoformat()}
        builder_span = next((span for span in reversed(spans)
                            if span.get("name") == "build_payload" and span.get("id")), None)
        key = (builder_span["id"], builder_span.get("parent_hash")) if builder_span else None
        if message == "building new payload":
            require(key is not None, f"missing builder start identity at {location}")
            block_hash(key[1])
            attempts[key] = {"started": proof}
        elif message == "Built payload":
            digest = block_hash(fields.get("hash"))
            require(key is not None and key[1] == fields.get("parent_hash"), f"missing builder identity at {location}")
            attempt = attempts.pop(key, {})
            value = {**proof, "number": integer(fields.get("number"), "built block number"),
                     "parent": block_hash(fields.get("parent_hash")), "payload_id": key[0],
                     "tx_count": integer(fields.get("total_transactions"), "built transactions"),
                     "pool_included": integer(fields.get("pool_transactions_included"), "included pool transactions"),
                     "pool_yielded": integer(fields.get("pool_transactions_yielded"), "yielded pool transactions"),
                     "invalid_execution_attempts": integer(fields.get("invalid_pool_transaction_execution_attempts"), "invalid execution attempts"),
                     "started": attempt.get("started")}
            require(value["pool_included"] <= value["tx_count"]
                    and value["pool_included"] + value["invalid_execution_attempts"] <= value["pool_yielded"],
                    f"inconsistent builder inclusion counters at {location}")
            previous = index["built"].get(digest)
            require(previous is None or all(previous[field] == value[field] for field in ("number", "parent", "tx_count")),
                    f"contradictory builder evidence for {digest}")
            index["built"][digest] = value
            index["builder_reuse"].pop(digest, None)
            if "reuse" in attempt:
                index["builder_reuse"][digest] = {**attempt["reuse"], "completed_time": proof["time"]}
        elif message.startswith("Executed block"):
            identity = span_identity(spans)
            require(identity is not None, f"missing fresh Engine identity at {location}")
            number, digest, parent = identity
            value = {**proof, "number": number, "parent": parent}
            previous = index["executed"].get(digest)
            if previous is None or value["time"] < previous["time"]:
                index["executed"][digest] = value
            candidate = engine_stats.pop(identity, None)
            if candidate is not None:
                index["engine_reuse"][digest] = {**candidate, "completed_time": proof["time"]}
        elif message == "execution layer reported payload status":
            match = STATUS.fullmatch(fields.get("payload_status", ""))
            require(match, f"malformed Engine payload status at {location}")
            status, digest = match.groups()
            delivery = next((span for span in reversed(spans) if span.get("name") == "execute_delivery"), None)
            require(status != "INVALID", f"Engine rejected payload at {location}")
            if status == "VALID" and delivery is not None:
                require(digest == delivery.get("block.digest"), f"VALID hash does not match delivery at {location}")
                index["valid"][digest] = proof
        else:
            stats = fields.get("stats", "")
            counters = {name: re.search(r"\b" + name + r": ([0-9]+),", stats) for name in ("reused", "speculated")}
            require(all(counters.values()), f"missing speculative counters at {location}")
            reused, speculated = (int(counters[name].group(1)) for name in ("reused", "speculated"))
            require(reused <= speculated, f"impossible reuse counter at {location}")
            candidate = {**proof, "reused": reused, "speculated": speculated}
            identity = span_identity(spans)
            if identity is not None:
                engine_stats[identity] = candidate
            else:
                require(key is not None, f"unattributed speculative execution at {location}")
                if key in attempts:
                    require("reuse" not in attempts[key], f"ambiguous repeated builder finish at {location}")
                    attempts[key]["reuse"] = candidate
    return index


def verify(config, report, rpcs=None, logs=None, finality_timeout=60, dense_transactions=5, min_dense_blocks=4):
    check_config(config)
    cohort = workload(report)
    start, end = min(cohort), max(cohort)
    rpcs = rpcs or [Rpc(config[role]["rpc_url"]) for role in ("a", "b")]
    wait_finalized(rpcs, end, finality_timeout)
    anchor = [header(rpc("eth_getBlockByNumber", [hex(start - 1), False])) for rpc in rpcs]
    require(anchor[0] == anchor[1], "different canonical parent anchor")
    require(quantity(anchor[0]["number"], "anchor height") == start - 1, "wrong canonical anchor height")
    parent = anchor[0]["hash"]
    verified = []
    for number in range(start, end + 1):
        blocks = [header(rpc("eth_getBlockByNumber", [hex(number), False])) for rpc in rpcs]
        block = blocks[0]
        require(blocks[0] == blocks[1], f"canonical block/header/body mismatch at {number}")
        require(quantity(block["number"], "block number") == number and block["parentHash"] == parent,
                f"canonical chain discontinuity at {number}")
        if number in cohort:
            expected = cohort[number]
            require(len(block["transactions"]) == expected["tx_count"]
                    and quantity(block["gasUsed"], "block gas") == expected["gas_used"]
                    and quantity(block["timestamp"], "block timestamp") * 1000
                    + quantity(block["timestampMillisPart"], "timestamp millis") == expected["timestamp_ms"],
                    f"generated report disagrees with canonical block {number}")
        a_receipts, b_receipts = (receipts(rpc, block) for rpc in rpcs)
        require(a_receipts == b_receipts, f"full receipt mismatch at {number}")
        receipt_digest = hashlib.sha256(json.dumps(a_receipts, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
        verified.append({key: value for key, value in block.items() if key != "transactions"} |
                        {"tx_count": len(block["transactions"]), "receipt_json_sha256": receipt_digest})
        parent = block["hash"]
    # Detect any finality regression or canonical replacement during receipt reads.
    wait_finalized(rpcs, end, 0)
    for rpc in rpcs:
        require(header(rpc("eth_getBlockByNumber", [hex(end), False]))["hash"] == parent,
                "finalized canonical endpoint changed during verification")
        require(header(rpc("eth_getBlockByNumber", [hex(start - 1), False])) == anchor[0],
                "finalized canonical anchor changed during verification")
    logs = logs or [index_logs(log_events(config[role]["log_dir"])) for role in ("a", "b")]
    producers = {"a": 0, "b": 0}
    reuse = {"builder_a": 0, "engine_a": 0}
    for block in verified:
        number, digest = quantity(block["number"], "block number"), block["hash"]
        if not block["tx_count"]:
            continue
        owners = [index for index in range(2) if digest in logs[index]["built"]]
        require(len(owners) == 1, f"missing or ambiguous producer for block {number}")
        owner = owners[0]
        built = logs[owner]["built"][digest]
        executed = logs[1 - owner]["executed"].get(digest)
        valid = logs[1 - owner]["valid"].get(digest)
        require(built["started"] is not None and built["number"] == number and built["parent"] == block["parentHash"]
                and built["tx_count"] == block["tx_count"], f"producer identity mismatch at {number}")
        require(executed is not None and executed["number"] == number and executed["parent"] == block["parentHash"],
                f"missing fresh opposite-peer Engine execution at {number} (AlreadySeen is insufficient)")
        require(valid is not None and datetime.datetime.fromisoformat(valid["time"]) >= datetime.datetime.fromisoformat(executed["time"]),
                f"missing post-execution opposite-peer VALID at {number}")
        block.update(producer="ab"[owner], producer_evidence=built, peer_execution=executed, peer_valid=valid)
        if number in cohort and block["tx_count"] >= dense_transactions:
            producers["ab"[owner]] += 1
            kind = "builder_a" if owner == 0 else "engine_a"
            candidate = (logs[0]["builder_reuse"].get(digest) if owner == 0
                         else logs[0]["engine_reuse"].get(digest))
            if candidate is not None:
                if owner == 0:
                    # The EVM counts reuse before post-execution block validation.
                    # Every recoverable executed-but-excluded pool attempt is in
                    # this counter; other errors abort before Built payload. Gas/
                    # size filters precede EVM consumption. Reverts are included.
                    discarded = built["invalid_execution_attempts"]
                    require(candidate["reused"] <= built["pool_included"] + discarded,
                            f"reuse exceeds executed pool attempts at {number}")
                    included_reuse = max(candidate["reused"] - discarded, 0)
                else:
                    require(candidate["reused"] <= block["tx_count"], f"reuse exceeds canonical tx count at {number}")
                    included_reuse = candidate["reused"]
                require(datetime.datetime.fromisoformat(candidate["completed_time"])
                        <= datetime.datetime.fromisoformat(built["time"] if owner == 0 else valid["time"]),
                        f"reuse not followed by completed canonical validation at {number}")
                reuse[kind] += included_reuse
                inclusion = ({"included_lower_bound": included_reuse,
                              "discarded_execution_attempts_bound": discarded} if owner == 0
                             else {"included_exact": included_reuse})
                block["parallel_reuse"] = {**candidate, **inclusion}
    require(sum(producers.values()) >= min_dense_blocks and all(producers.values()),
            f"insufficient dense generated cohort / both producer roles: {producers}")
    require(all(reuse.values()), f"missing positive canonical parallel reuse in each role: {reuse}")
    return {"status": "passed", "mode": "generated-correctness", "speedup_claim": False,
            "scope": "same candidate binary with speculation on/off; exact finalized headers, bodies and full receipts for the interval; producer execution plus fresh opposite-peer Engine execution for every nonempty block",
            "shared_changes": "not independently checked against unmodified main; State commit has separate oracle tests",
            "config": config, "from_block": start, "to_block": end, "parent_anchor": anchor[0]["hash"],
            "verified_transactions": sum(block["tx_count"] for block in verified),
            "dense_transactions": dense_transactions, "minimum_dense_blocks": min_dense_blocks,
            "dense_blocks_by_producer": producers, "parallel_reused": reuse,
            "reuse_count_semantics": "builder_a is an included-reuse lower bound after subtracting all invalid execution attempts; engine_a is exact",
            "blocks": verified}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--check-config", action="store_true")
    parser.add_argument("--report", type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--finality-timeout", type=int, default=60)
    args = parser.parse_args()
    try:
        config = json.loads(args.config.read_text())
        check_config(config)
        if args.check_config:
            print("Generated correctness launch configuration checked")
            return 0
        require(args.report is not None and args.output is not None, "--report and --output are required")
        require(0 < args.finality_timeout <= 300, "finality timeout must be 1..300 seconds")
        result = verify(config, json.loads(args.report.read_text()), finality_timeout=args.finality_timeout)
    except (VerificationError, OSError, ValueError, TypeError, KeyError) as error:
        result = {"status": "failed", "mode": "generated-correctness", "error": str(error)}
        if args.output is not None:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(json.dumps(result, indent=2) + "\n")
        print(f"Generated correctness verification failed: {error}", file=sys.stderr)
        return 1
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2) + "\n")
    print(f"Generated correctness passed: blocks {result['from_block']}..{result['to_block']}, "
          f"{result['verified_transactions']} transactions, dense producers {result['dense_blocks_by_producer']}, "
          f"builder included reuse >= {result['parallel_reused']['builder_a']}, "
          f"Engine included reuse = {result['parallel_reused']['engine_a']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
