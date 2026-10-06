#!/usr/bin/env python3
"""Check mixed-load receipts, custody checkpoints, and sampled L1 lane gas."""

import argparse
import gzip
import hashlib
import json
import statistics
import urllib.request
from collections import defaultdict
from pathlib import Path


def rpc(url, method, params):
    request = urllib.request.Request(
        url,
        data=json.dumps({"jsonrpc": "2.0", "id": 1, "method": method,
                         "params": params}).encode(),
        headers={"Content-Type": "application/json"},
    )
    with urllib.request.urlopen(request, timeout=30) as response:
        result = json.load(response)
    if "error" in result:
        raise RuntimeError(result["error"])
    return result["result"]


def entries(path):
    opener = gzip.open if path.suffix == ".gz" else Path.open
    with opener(path, "rt") as stream:
        return [json.loads(line) for line in stream]


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def check_receipt(url, expected):
    receipt = rpc(url, "eth_getTransactionReceipt", [expected["hash"]])
    assert receipt and receipt["status"] == "0x1", expected["hash"]
    for field, value in [("blockNumber", expected["block"]),
                         ("gasUsed", expected["gasUsed"])]:
        assert int(receipt[field], 16) == value, (field, expected["hash"])
    assert receipt["blockHash"] == expected["blockHash"], expected["hash"]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--load", type=Path, required=True)
    parser.add_argument("--metrics", type=Path, required=True)
    parser.add_argument("--l1-rpc-url", default="http://127.0.0.1:58545")
    parser.add_argument("--zone-rpc-url", default="http://127.0.0.1:59545")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    log = entries(args.load)
    assert log[0]["kind"] == "start" and log[-1]["kind"] == "finish"
    start, finish = log[0], log[-1]
    cycles = [row for row in log if row["kind"] == "cycle"]
    checkpoints = [row for row in log if row["kind"] == "checkpoint"]
    assert cycles and [row["cycle"] for row in cycles] == list(range(1, len(cycles) + 1))
    assert finish["cycles"] == len(cycles)
    assert finish["final"] == start["initial"]
    assert all(row["balances"] == start["initial"] for row in checkpoints)
    assert start["l1Genesis"] == rpc(args.l1_rpc_url, "eth_getBlockByNumber",
                                       ["0x0", False])["hash"]
    assert start["zoneGenesis"] == rpc(args.zone_rpc_url, "eth_getBlockByNumber",
                                         ["0x0", False])["hash"]

    blocks = defaultdict(list)
    for cycle in cycles:
        for name in ("deposit", "redeem"):
            tx = cycle[name]
            check_receipt(args.l1_rpc_url, tx)
            blocks[tx["block"]].append(tx)
        check_receipt(args.zone_rpc_url, cycle["privateTransfer"])

    samples = entries(args.metrics)
    observed = []
    missing = []
    mixed_general = []
    payment_deficit = []
    for number, transactions in sorted(blocks.items()):
        block = rpc(args.l1_rpc_url, "eth_getBlockByNumber", [hex(number), False])
        assert block["hash"] == transactions[0]["blockHash"]
        gas_used = int(block["gasUsed"], 16)
        timestamp = int(block.get("timestampMillis", "0x0"), 16) / 1000
        if not timestamp:
            timestamp = int(block["timestamp"], 16)
        matches = [sample for sample in samples
                   if abs(sample["time"] - timestamp) <= 2.5
                   and sample["gas_used_last"] == gas_used]
        if not matches:
            missing.append(number)
            continue
        earned_gas = sum(tx["gasUsed"] for tx in transactions)
        if not any(sample["payment_gas_used_last"] >= earned_gas
                   and sample["payment_gas_used_last"] +
                   sample["general_gas_used_last"] == gas_used for sample in matches):
            payment_deficit.append(number)
        if any(sample["general_gas_used_last"] != 0 for sample in matches):
            mixed_general.append({
                "block": number,
                "earnGas": earned_gas,
                "paymentGas": matches[0]["payment_gas_used_last"],
                "generalGas": matches[0]["general_gas_used_last"],
            })
        else:
            observed.append(number)

    duration = finish["time"] - start["time"]
    intervals = [b["time"] - a["time"] for a, b in zip(cycles, cycles[1:])]
    result = {
        "l1Genesis": start["l1Genesis"],
        "zoneGenesis": start["zoneGenesis"],
        "loadSha256": digest(args.load),
        "metricsSha256": digest(args.metrics),
        "durationSeconds": duration,
        "cycles": len(cycles),
        "l1EarnTransactions": 2 * len(cycles),
        "zonePrivateTransfers": len(cycles),
        "earnGasUsed": sum(c[name]["gasUsed"] for c in cycles
                           for name in ("deposit", "redeem")),
        "zonePrivateTransferGasUsed": sum(c["privateTransfer"]["gasUsed"]
                                          for c in cycles),
        "mixedCyclesPerSecond": len(cycles) / duration,
        "cycleIntervalMedianSeconds": statistics.median(intervals),
        "custody": start["initial"],
        "custodyCheckpoints": len(checkpoints),
        "l1EarnBlocks": len(blocks),
        "sampledZeroGeneralEarnBlocks": len(observed),
        "sampledMixedGeneralEarnBlocks": mixed_general,
        "sampledPaymentDeficitEarnBlocks": payment_deficit,
        "unsampledEarnBlocks": missing,
    }
    args.output.write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
