#!/usr/bin/env python3
"""Run repeated native Earn deposits, private Zone transfers, and redemptions.

The target devnet must already have T16 on L1, T15 on the Zone, a registered
Earn vault, a funded Zone sender, and the needed asset/share approvals. This
runner records raw receipts and lane samples; it reproduces the 60-cycle,
100-transaction-per-leg workload shape used for the checked-in evidence.
"""

import argparse
import concurrent.futures
import json
import os
import subprocess
import threading
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


def account(key):
    return subprocess.check_output(
        ["cast", "wallet", "address", "--private-key", key], text=True
    ).strip()


def allowance(url, token, owner, spender):
    data = "0xdd62ed3e" + owner[2:].lower().zfill(64) + spender[2:].lower().zfill(64)
    return int(rpc(url, "eth_call", [{"to": token, "data": data}, "latest"]), 16)


def send(nonce, target, signature, values, key, url):
    command = [
        "cast", "send", "--async", target, signature, *values,
        "--nonce", str(nonce), "--gas-limit", "3000000",
        "--private-key", key, "--rpc-url", url,
    ]
    for attempt in range(3):
        result = subprocess.run(command, capture_output=True, text=True, timeout=30, check=False)
        if result.returncode == 0:
            return result.stdout.strip()
        time.sleep(0.2 * (attempt + 1))
    raise RuntimeError(f"transaction nonce {nonce} failed: {result.stderr.strip()}")


def sample_metrics(url, rows, stop):
    names = {
        "reth_tempo_payload_builder_payment_gas_used_last": "paymentGas",
        "reth_tempo_payload_builder_general_gas_used_last": "generalGas",
    }
    while not stop.is_set():
        try:
            with urllib.request.urlopen(url, timeout=2) as response:
                body = response.read().decode()
            values = {}
            for line in body.splitlines():
                name, _, value = line.partition(" ")
                if name in names:
                    values[names[name]] = int(float(value))
            if len(values) == 2:
                rows.append({"time": time.time(), **values})
        except (OSError, ValueError):
            pass
        stop.wait(0.05)


def burst(url, key, target, signature, values, start_nonce, count, workers):
    started = time.time()
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
        hashes = list(pool.map(
            lambda nonce: send(nonce, target, signature, values, key, url),
            range(start_nonce, start_nonce + count),
        ))
    submitted = time.time()
    if len(set(hashes)) != count:
        raise RuntimeError("duplicate transaction hash in burst")
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
    if len(receipts) != count:
        raise RuntimeError(f"only {len(receipts)}/{count} receipts arrived")
    if any(receipt["status"] != "0x1" for receipt in receipts.values()):
        raise RuntimeError("a workload transaction reverted")
    blocks = {}
    for receipt in receipts.values():
        block = blocks.setdefault(receipt["blockNumber"], {"count": 0, "gasUsed": 0})
        block["count"] += 1
        block["gasUsed"] += int(receipt["gasUsed"], 16)
    return {
        "startNonce": start_nonce,
        "count": count,
        "startedAt": started,
        "submittedAt": submitted,
        "finishedAt": time.time(),
        "hashes": hashes,
        "receipts": {
            tx_hash: {key: receipt[key] for key in (
                "blockNumber", "blockHash", "status", "gasUsed", "transactionIndex"
            )} for tx_hash, receipt in receipts.items()
        },
        "blocks": blocks,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--l1-rpc-url", required=True)
    parser.add_argument("--zone-rpc-url", required=True)
    parser.add_argument("--metrics-url", required=True)
    parser.add_argument("--vault", required=True)
    parser.add_argument("--asset", required=True)
    parser.add_argument("--earn-share", required=True)
    parser.add_argument("--zone-token", required=True)
    parser.add_argument("--zone-recipient", required=True)
    parser.add_argument("--cycles", type=int, default=60)
    parser.add_argument("--count", type=int, default=100)
    parser.add_argument("--workers", type=int, default=16)
    parser.add_argument("--out-dir", type=Path, required=True)
    args = parser.parse_args()
    if min(args.cycles, args.count, args.workers) < 1:
        parser.error("cycles, count, and workers must be positive")
    l1_key = os.environ.get("TEMPO_BENCH_L1_KEY")
    zone_key = os.environ.get("TEMPO_BENCH_ZONE_KEY")
    if not l1_key or not zone_key:
        parser.error("TEMPO_BENCH_L1_KEY and TEMPO_BENCH_ZONE_KEY are required")
    args.out_dir.mkdir(parents=True, exist_ok=True)
    l1_sender = account(l1_key)
    required_allowance = args.cycles * args.count * 1000
    if allowance(args.l1_rpc_url, args.asset, l1_sender, args.vault) < required_allowance:
        parser.error(f"asset allowance to vault is below {required_allowance}; approve before the run")
    if allowance(args.l1_rpc_url, args.earn_share, l1_sender, args.vault) < required_allowance:
        parser.error(f"EarnShare allowance to vault is below {required_allowance}; approve before the run")
    l1_nonce = int(rpc(args.l1_rpc_url, "eth_getTransactionCount", [l1_sender, "pending"]), 16)
    zone_nonce = int(rpc(args.zone_rpc_url, "eth_getTransactionCount", [account(zone_key), "pending"]), 16)
    samples = []
    stop = threading.Event()
    sampler = threading.Thread(target=sample_metrics, args=(args.metrics_url, samples, stop), daemon=True)
    sampler.start()
    started = time.time()
    records = []
    try:
        for cycle in range(args.cycles):
            legs = (
                ("deposit", args.l1_rpc_url, l1_key, args.vault,
                 "deposit(uint256,uint256)", ["1000", "900"], l1_nonce),
                ("zone", args.zone_rpc_url, zone_key, args.zone_token,
                 "transfer(address,uint256)", [args.zone_recipient, "1"], zone_nonce),
                ("redeem", args.l1_rpc_url, l1_key, args.vault,
                 "redeem(uint256,uint256)", ["1000", "1000"], l1_nonce + args.count),
            )
            for mode, url, key, target, signature, values, nonce in legs:
                first_sample = len(samples)
                result = burst(url, key, target, signature, values, nonce, args.count, args.workers)
                result["mode"] = mode
                result["cycle"] = cycle
                if mode != "zone":
                    if len(result["blocks"]) != 1:
                        raise RuntimeError("Earn benchmark leg spanned multiple L1 blocks")
                    height = next(iter(result["blocks"]))
                    block = rpc(args.l1_rpc_url, "eth_getBlockByNumber", [height, False])
                    result["blockGasUsed"] = block["gasUsed"]
                    result["blockHash"] = block["hash"]
                    if any(receipt["blockHash"] != block["hash"] for receipt in result["receipts"].values()):
                        raise RuntimeError("Earn receipt is not in its recorded canonical block")
                    deadline = time.monotonic() + 2
                    while True:
                        result["samples"] = samples[first_sample:]
                        result["matchingLaneSamples"] = sum(
                            sample["paymentGas"] == int(block["gasUsed"], 16)
                            and sample["generalGas"] == 0 for sample in result["samples"]
                        )
                        if result["matchingLaneSamples"] or time.monotonic() >= deadline:
                            break
                        time.sleep(0.05)
                    if result["matchingLaneSamples"] == 0:
                        raise RuntimeError("Earn block has no matching zero-general payment-lane sample")
                else:
                    result["samples"] = samples[first_sample:]
                records.append(result)
                (args.out_dir / f"{cycle:02d}-{mode}.json").write_text(json.dumps(result, indent=2) + "\n")
            l1_nonce += 2 * args.count
            zone_nonce += args.count
            print(f"cycle {cycle + 1}/{args.cycles}: {3 * args.count} successful receipts", flush=True)
    finally:
        stop.set()
        sampler.join(timeout=3)
        (args.out_dir / "lane-samples.json").write_text(json.dumps(samples, indent=2) + "\n")
    summary = {
        "startedAt": started,
        "finishedAt": time.time(),
        "cycles": args.cycles,
        "countPerLeg": args.count,
        "successfulTransactions": sum(record["count"] for record in records),
        "l1GenesisHash": rpc(args.l1_rpc_url, "eth_getBlockByNumber", ["0x0", False])["hash"],
        "zoneGenesisHash": rpc(args.zone_rpc_url, "eth_getBlockByNumber", ["0x0", False])["hash"],
        "laneSamples": len(samples),
    }
    summary["transactionsPerSecond"] = summary["successfulTransactions"] / (
        summary["finishedAt"] - summary["startedAt"]
    )
    (args.out_dir / "run.json").write_text(json.dumps(summary, indent=2) + "\n")
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
