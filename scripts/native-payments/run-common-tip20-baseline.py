#!/usr/bin/env python3
"""Compare a common TIP-20 transfer on revm and EVM2 devnets.

Both nodes must use the same genesis, one-second block schedule, release
profile, and isolated datadirs. This is a shared-operation control benchmark,
not a substitute for a matched Earn/Zone workload.
"""

import argparse
import concurrent.futures
import gzip
import hashlib
import json
import math
import os
import subprocess
import time
import urllib.request
from pathlib import Path


def rpc(url, method, params):
    request = urllib.request.Request(
        url,
        json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).encode(),
        {"Content-Type": "application/json"},
    )
    with urllib.request.urlopen(request, timeout=15) as response:
        reply = json.load(response)
    if "error" in reply:
        raise RuntimeError(f"{method}: {reply['error']}")
    return reply["result"]


def metrics(url):
    with urllib.request.urlopen(url, timeout=2) as response:
        lines = response.read().decode().splitlines()
    names = {
        "reth_tempo_payload_builder_payment_gas_used_last": "paymentGas",
        "reth_tempo_payload_builder_general_gas_used_last": "generalGas",
    }
    values = {}
    for line in lines:
        name, _, value = line.partition(" ")
        if name in names:
            values[names[name]] = int(float(value))
    if len(values) != 2:
        raise RuntimeError(f"missing lane metrics at {url}")
    return values


def submit(url, key, token, recipient, nonce, gas_limit):
    command = [
        "cast", "send", "--async", token, "transfer(address,uint256)", recipient, "1",
        "--nonce", str(nonce), "--gas-limit", str(gas_limit), "--private-key", key,
        "--rpc-url", url,
    ]
    for attempt in range(3):
        result = subprocess.run(command, capture_output=True, text=True, timeout=30, check=False)
        if result.returncode == 0:
            return result.stdout.strip()
        time.sleep(0.2 * (attempt + 1))
    raise RuntimeError(f"nonce {nonce}: {result.stderr.strip()}")


def burst(url, metrics_url, key, token, recipient, first_nonce, count, workers, gas_limit):
    start = time.time()
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
        hashes = list(pool.map(
            lambda nonce: submit(url, key, token, recipient, nonce, gas_limit),
            range(first_nonce, first_nonce + count),
        ))
    sent = time.time()
    if len(set(hashes)) != count:
        raise RuntimeError("duplicate transaction hash")
    receipts = {}
    deadline = time.monotonic() + 120
    while len(receipts) < count and time.monotonic() < deadline:
        for tx_hash in hashes:
            if tx_hash not in receipts:
                receipt = rpc(url, "eth_getTransactionReceipt", [tx_hash])
                if receipt is not None:
                    receipts[tx_hash] = receipt
        if len(receipts) < count:
            time.sleep(0.1)
    end = time.time()
    if len(receipts) != count or any(receipt["status"] != "0x1" for receipt in receipts.values()):
        raise RuntimeError(f"only {len(receipts)}/{count} transfers succeeded")
    heights = {receipt["blockNumber"] for receipt in receipts.values()}
    if len(heights) != 1:
        raise RuntimeError(f"burst spans {len(heights)} blocks; reduce --count")
    block = rpc(url, "eth_getBlockByNumber", [next(iter(heights)), False])
    if any(receipt["blockHash"] != block["hash"] for receipt in receipts.values()):
        raise RuntimeError("noncanonical receipt")
    if set(block["transactions"]) != set(hashes):
        raise RuntimeError("measured block contains transactions outside this burst")
    if sum(int(receipt["gasUsed"], 16) for receipt in receipts.values()) != int(block["gasUsed"], 16):
        raise RuntimeError("receipt gas does not reconcile with block gas")
    lane = None
    deadline = time.monotonic() + 2
    while time.monotonic() < deadline:
        lane = metrics(metrics_url)
        if lane == {"paymentGas": int(block["gasUsed"], 16), "generalGas": 0}:
            break
        time.sleep(0.05)
    else:
        raise RuntimeError(f"no zero-general payment-lane sample for block {block['number']}: {lane}")
    return {
        "startedAt": start,
        "sentAt": sent,
        "finishedAt": end,
        "blockNumber": block["number"],
        "blockHash": block["hash"],
        "blockGasUsed": block["gasUsed"],
        "blockTransactionCount": len(block["transactions"]),
        "lane": lane,
        "hashes": hashes,
        "receipts": {tx_hash: {
            field: receipt[field] for field in (
                "blockNumber", "blockHash", "status", "gasUsed", "transactionIndex"
            )
        } for tx_hash, receipt in receipts.items()},
    }


def quantiles(values):
    values = sorted(values)
    return {label: values[math.ceil(q * len(values)) - 1]
            for label, q in (("p50", 0.5), ("p95", 0.95), ("p99", 0.99))}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--revm-rpc-url", required=True)
    parser.add_argument("--revm-metrics-url", required=True)
    parser.add_argument("--revm-binary", type=Path, required=True)
    parser.add_argument("--evm2-rpc-url", required=True)
    parser.add_argument("--evm2-metrics-url", required=True)
    parser.add_argument("--evm2-binary", type=Path, required=True)
    parser.add_argument("--token", required=True)
    parser.add_argument("--recipient", required=True)
    parser.add_argument("--cycles", type=int, default=10)
    parser.add_argument("--count", type=int, default=10)
    parser.add_argument("--workers", type=int, default=16)
    parser.add_argument("--gas-limit", type=int, default=3_000_000)
    parser.add_argument("--out-prefix", type=Path, required=True)
    args = parser.parse_args()
    if min(args.cycles, args.count, args.workers, args.gas_limit) < 1:
        parser.error("cycles, count, workers, and gas limit must be positive")
    key = os.environ.get("TEMPO_BENCH_KEY")
    if not key:
        parser.error("TEMPO_BENCH_KEY is required")
    sender = subprocess.check_output(
        ["cast", "wallet", "address", "--private-key", key], text=True
    ).strip()
    endpoints = {
        "revm": (args.revm_rpc_url, args.revm_metrics_url, args.revm_binary),
        "evm2": (args.evm2_rpc_url, args.evm2_metrics_url, args.evm2_binary),
    }
    genesis = {name: rpc(url, "eth_getBlockByNumber", ["0x0", False])["hash"]
               for name, (url, _, _) in endpoints.items()}
    if len(set(genesis.values())) != 1:
        raise RuntimeError(f"genesis mismatch: {genesis}")
    nonces = {name: int(rpc(url, "eth_getTransactionCount", [sender, "pending"]), 16)
              for name, (url, _, _) in endpoints.items()}
    raw = []
    for cycle in range(args.cycles):
        for name, (url, metrics_url, _) in endpoints.items():
            record = burst(url, metrics_url, key, args.token, args.recipient,
                           nonces[name], args.count, args.workers, args.gas_limit)
            raw.append({"cycle": cycle, "engine": name, "record": record})
            nonces[name] += args.count
        print(f"cycle {cycle + 1}/{args.cycles}: both engines settled {args.count} transfers", flush=True)
    result = {"kind": "matched common TIP-20 transfer control", "genesisHash": genesis["revm"],
              "cycles": args.cycles, "countPerCycle": args.count, "engines": {}}
    for name, (url, _, binary) in endpoints.items():
        records = [item["record"] for item in raw if item["engine"] == name]
        result["engines"][name] = {
            "clientVersion": rpc(url, "web3_clientVersion", []),
            "binarySha256": hashlib.sha256(binary.read_bytes()).hexdigest(),
            "receiptGasUsed": sum(int(receipt["gasUsed"], 16) for record in records
                                  for receipt in record["receipts"].values()),
            "blockGasUsed": sum(int(record["blockGasUsed"], 16) for record in records),
            "burstCompletionSeconds": quantiles(
                record["finishedAt"] - record["startedAt"] for record in records
            ),
            "firstBlock": records[0]["blockNumber"],
            "lastBlock": records[-1]["blockNumber"],
        }
    args.out_prefix.parent.mkdir(parents=True, exist_ok=True)
    with gzip.open(f"{args.out_prefix}-raw.json.gz", "wt") as file:
        json.dump(raw, file)
    Path(f"{args.out_prefix}-summary.json").write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
