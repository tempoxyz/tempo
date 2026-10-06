#!/usr/bin/env python3
"""Run a reversible Earn deposit/redeem cycle plus a private Zone transfer.

This fixture is for the disposable T16 devnet recorded in
docs/evidence/EVM2_T16_EARN_ZONE_FORK.md. Signers come from environment variables.
Every transaction receipt and periodic custody checkpoint is written to JSONL.
"""

import argparse
import json
import os
import subprocess
import time
import urllib.request
from pathlib import Path


VAULT = "0x856e4424f806d16e8cbc702b3c0f2ede5468eae5"
ASSET = "0x20c0000000000000000000000000000000000000"
SHARE = "0x20c000000000000000000000e038c3bee7bf4591"
VENUE = "0x5FbDB2315678afecb367f032d93F642f64180aa3"
PORTAL = "0x5ad0000000000000000000000000000000000001"
SENDER = "0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266"
RECIPIENT = "0x70997970C51812dc3A010C7d01b50e0d17dc79C8"


def rpc(url, method, params):
    request = urllib.request.Request(
        url,
        data=json.dumps({"jsonrpc": "2.0", "method": method, "params": params, "id": 1}).encode(),
        headers={"Content-Type": "application/json"},
    )
    with urllib.request.urlopen(request, timeout=30) as response:
        value = json.load(response)
    if "error" in value:
        raise RuntimeError(value["error"])
    return value["result"]


def scalar(url, address, data):
    return int(rpc(url, "eth_call", [{"to": address, "data": data}, "latest"]), 16)


def balance_data(address):
    return "0x70a08231" + "0" * 24 + address[2:].lower()


def checkpoint(url):
    return {
        "shareSupply": scalar(url, SHARE, "0x18160ddd"),
        "vaultAssets": scalar(url, VAULT, "0x01e1d114"),
        "venueAssets": scalar(url, VENUE, "0x01e1d114"),
        "portalBacking": scalar(url, ASSET, balance_data(PORTAL)),
    }


def send(url, private_key, target, signature, args, gas_limit):
    command = [
        "cast", "send", target, signature, *[str(value) for value in args],
        "--rpc-url", url, "--private-key", private_key,
        "--gas-limit", str(gas_limit), "--json",
    ]
    receipt = json.loads(subprocess.check_output(command, text=True, timeout=60))
    if receipt["status"] != "0x1":
        raise RuntimeError(f"transaction reverted: {receipt['transactionHash']}")
    block = rpc(url, "eth_getBlockByNumber", [receipt["blockNumber"], False])
    return {
        "hash": receipt["transactionHash"],
        "block": int(receipt["blockNumber"], 16),
        "blockHash": receipt["blockHash"],
        "timestamp": int(block["timestamp"], 16),
        "gasUsed": int(receipt["gasUsed"], 16),
        "blockTransactions": len(block["transactions"]),
    }


def write(output, item):
    output.write(json.dumps(item, sort_keys=True) + "\n")
    output.flush()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--l1-rpc-url", default="http://127.0.0.1:58545")
    parser.add_argument("--zone-rpc-url", default="http://127.0.0.1:59545")
    parser.add_argument("--seconds", type=int, default=1800)
    parser.add_argument("--cycle-delay", type=float, default=1)
    parser.add_argument("--checkpoint-every", type=int, default=25)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    if args.seconds <= 0 or args.checkpoint_every <= 0:
        parser.error("seconds and checkpoint-every must be positive")
    sender_key = os.environ["EVM2_ZONE_SENDER_KEY"]
    recipient_key = os.environ["EVM2_ZONE_RECIPIENT_KEY"]

    l1, zone = args.l1_rpc_url, args.zone_rpc_url
    initial = checkpoint(l1)
    if initial != {
        "shareSupply": 700_000, "vaultAssets": 787_500,
        "venueAssets": 787_500, "portalBacking": 100_000,
    }:
        raise RuntimeError(f"unexpected starting custody: {initial}")
    if rpc(l1, "eth_chainId", []) != "0x539" or rpc(zone, "eth_chainId", []) != "0x53900000001":
        raise RuntimeError("wrong disposable devnet chain IDs")

    deadline = time.monotonic() + args.seconds
    path = Path(args.output)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w") as output:
        write(output, {"kind": "start", "time": time.time(), "seconds": args.seconds,
                       "initial": initial, "l1Genesis": rpc(l1, "eth_getBlockByNumber", ["0x0", False])["hash"],
                       "zoneGenesis": rpc(zone, "eth_getBlockByNumber", ["0x0", False])["hash"]})
        cycle = 0
        while time.monotonic() < deadline:
            cycle += 1
            deposit = send(l1, sender_key, VAULT, "deposit(uint256,uint256)",
                           [1125, 1000], 15_000_000)
            redeem = send(l1, sender_key, VAULT, "redeem(uint256,uint256)",
                          [1000, 1125], 15_000_000)
            if cycle % 2:
                transfer_key, target = sender_key, RECIPIENT
            else:
                transfer_key, target = recipient_key, SENDER
            transfer = send(zone, transfer_key, ASSET, "transfer(address,uint256)",
                            [target, 1], 1_000_000)
            write(output, {"kind": "cycle", "cycle": cycle, "time": time.time(),
                           "deposit": deposit, "redeem": redeem, "privateTransfer": transfer})
            if cycle % args.checkpoint_every == 0:
                current = checkpoint(l1)
                write(output, {"kind": "checkpoint", "cycle": cycle,
                               "time": time.time(), "balances": current})
                if current != initial:
                    raise RuntimeError(f"custody changed after cycle {cycle}: {current}")
            time.sleep(args.cycle_delay)
        final = checkpoint(l1)
        write(output, {"kind": "finish", "time": time.time(), "cycles": cycle,
                       "final": final})
        if final != initial:
            raise RuntimeError(f"custody changed after load: {final}")
    print(f"completed {cycle} mixed cycles in {args.seconds} seconds: {path}")


if __name__ == "__main__":
    main()
