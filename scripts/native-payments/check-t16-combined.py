#!/usr/bin/env python3
"""Recheck the recorded T16 Earn/Zone fork smoke test against the live devnet."""

import argparse
import json
import os
import subprocess
import time
import urllib.request
from pathlib import Path


def require(condition, message):
    if not condition:
        raise AssertionError(message)


def rpc(url, method, params, token=None):
    headers = {"Content-Type": "application/json"}
    if token:
        headers["X-Authorization-Token"] = token
    request = urllib.request.Request(
        url,
        data=json.dumps({"jsonrpc": "2.0", "method": method, "params": params, "id": 1}).encode(),
        headers=headers,
    )
    with urllib.request.urlopen(request, timeout=30) as response:
        value = json.load(response)
    if "error" in value:
        raise RuntimeError(f"{method}: {value['error']}")
    return value["result"]


def code_hash(url, address, block):
    code = rpc(url, "eth_getCode", [address, hex(block)])
    return subprocess.check_output(["cast", "keccak", code], text=True).strip().lower()


def scalar(url, address, selector, block, token=None):
    value = rpc(url, "eth_call", [{"to": address, "data": selector}, hex(block)], token)
    return int(value, 16)


def balance_selector(address):
    return "0x70a08231" + "0" * 24 + address[2:].lower()


def zone_auth_token(private_key, zone_id, chain_id):
    now = int(time.time())
    fields = (bytes([0]) + zone_id.to_bytes(4, "big") + chain_id.to_bytes(8, "big")
              + now.to_bytes(8, "big") + (now + 600).to_bytes(8, "big"))
    digest = subprocess.check_output(
        ["cast", "keccak", "0x" + (b"TempoZoneRPC".ljust(32, b"\0") + fields).hex()],
        text=True,
    ).strip()
    signature = subprocess.check_output(
        ["cast", "wallet", "sign", "--no-hash", digest, "--private-key", private_key],
        text=True,
    ).strip()
    return signature.removeprefix("0x") + fields.hex()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--record", default="docs/evidence/evm2-t16-native-earn-zone-smoke.json")
    parser.add_argument("--l1-rpc-url", default="http://127.0.0.1:58545")
    parser.add_argument("--zone-rpc-url", default="http://127.0.0.1:59545")
    parser.add_argument("--zone-private-rpc-url", default="http://127.0.0.1:59544")
    args = parser.parse_args()
    record = json.loads(Path(args.record).read_text())
    l1, zone = args.l1_rpc_url, args.zone_rpc_url
    addresses = record["addresses"]

    require(rpc(l1, "eth_chainId", []) == record["l1ChainId"], "L1 chain ID changed")
    require(rpc(zone, "eth_chainId", []) == record["zoneChainId"], "Zone chain ID changed")
    require(rpc(l1, "eth_getBlockByNumber", ["0x0", False])["hash"] == record["l1GenesisHash"],
            "L1 genesis changed")
    require(rpc(zone, "eth_getBlockByNumber", ["0x0", False])["hash"] == record["zoneGenesisHash"],
            "Zone genesis changed")

    for number, expected in record["forkBoundary"].items():
        block = rpc(l1, "eth_getBlockByNumber", [hex(int(number)), False])
        require(block["hash"] == expected["blockHash"], f"fork block {number} hash changed")
        require(int(block["timestamp"], 16) == expected["timestamp"],
                f"fork block {number} timestamp changed")
        for key, address in [("vaultCodeHash", "vault"), ("feeCodeHash", "fees")]:
            require(code_hash(l1, addresses[address], int(number)) == expected[key].lower(),
                    f"{address} code hash differs at block {number}")
    require(record["forkBoundary"]["1171"]["vaultCodeHash"] !=
            record["forkBoundary"]["1172"]["vaultCodeHash"], "vault runtime did not migrate")
    require(record["forkBoundary"]["1172"]["vaultCodeHash"] ==
            record["forkBoundary"]["1172"]["feeCodeHash"], "vault and fee dispatchers differ")

    for number, expected in record["snapshots"].items():
        block = int(number)
        actual = {
            "shareSupply": scalar(l1, addresses["share"], "0x18160ddd", block),
            "senderShares": scalar(l1, addresses["share"],
                                   balance_selector(addresses["sender"]), block),
            "vaultAssets": scalar(l1, addresses["vault"], "0x01e1d114", block),
            "venueAssets": scalar(l1, addresses["venue"], "0x01e1d114", block),
            "portalBacking": scalar(l1, addresses["asset"],
                                    balance_selector(addresses["portal"]), block),
            "recipientAssets": scalar(l1, addresses["asset"],
                                      balance_selector(addresses["recipient"]), block),
        }
        require(actual == expected, f"accounting differs at block {number}: {actual}")
        require(actual["vaultAssets"] == actual["venueAssets"],
                f"vault/venue custody differs at block {number}")

    states = record["snapshots"]
    require(states["1171"] == states["1172"], "fork changed funded Earn/Zone state")
    require(states["1192"]["shareSupply"] - states["1193"]["shareSupply"] == 400_000,
            "spend did not burn 400,000 shares")
    require(states["1193"]["recipientAssets"] - states["1192"]["recipientAssets"] == 400_000,
            "spend did not pay 400,000 assets")
    require(states["1230"]["shareSupply"] - states["1229"]["shareSupply"] == 200_000,
            "deposit did not mint 200,000 shares")
    require(states["1250"]["vaultAssets"] - states["1249"]["vaultAssets"] == 100_000,
            "venue gain was not recognized")
    require(states["1250"]["shareSupply"] == states["1249"]["shareSupply"],
            "venue gain rebased EarnShare")
    require(states["1266"]["vaultAssets"] - states["1267"]["vaultAssets"] == 112_500,
            "redeem paid wrong yield-adjusted amount")
    require(states["1266"]["shareSupply"] - states["1267"]["shareSupply"] == 100_000,
            "redeem burned wrong shares")
    require(states["1284"] == states["1285"], "failed redemption changed accounting")

    for name, expected in record["earnTransactions"].items():
        receipt = rpc(l1, "eth_getTransactionReceipt", [expected["hash"]])
        number = int(receipt["blockNumber"], 16)
        block = rpc(l1, "eth_getBlockByNumber", [hex(number), False])
        require(number == expected["block"] and receipt["blockHash"] == expected["blockHash"],
                f"{name} moved to a different block")
        require(int(receipt["status"], 16) == expected["status"], f"{name} status changed")
        require(int(receipt["gasUsed"], 16) == expected["gasUsed"], f"{name} gas changed")
        require(int(block["timestamp"], 16) == expected["timestamp"],
                f"{name} block timestamp changed")
        require(len(block["transactions"]) == 1, f"{name} block was not isolated")
        metric = expected["laneMetric"]
        require(metric and metric["payment_transactions_last"] == 1
                and metric["general_gas_used_last"] == 0
                and metric["payment_gas_used_last"] == expected["gasUsed"]
                and abs(metric["time"] - expected["timestamp"]) < 2,
                f"{name} has no matching zero-general-lane sample")

    zone_record = record["zone"]
    for key in ("depositTx", "settlementTx", "settlementTx2"):
        receipt = rpc(l1, "eth_getTransactionReceipt", [zone_record[key]])
        require(receipt and receipt["status"] == "0x1", f"{key} failed")
    for key in ("privateTransferTx", "privateTransferTx2"):
        receipt = rpc(zone, "eth_getTransactionReceipt", [zone_record[key]])
        require(receipt and receipt["status"] == "0x1", f"{key} failed")
        number = int(receipt["blockNumber"], 16)
        block = rpc(zone, "eth_getBlockByNumber", [hex(number), False])
        require(int(block["timestamp"], 16) >= record["zoneT15Time"],
                f"{key} preceded Zone T15")
    receipt = rpc(l1, "eth_getTransactionReceipt", [zone_record["settlementTx2"]])
    settlement_gas = int(receipt["gasUsed"], 16)
    metric = zone_record["settlementLaneMetric2"]
    require(metric["payment_transactions_last"] == 1
            and metric["payment_gas_used_last"] == settlement_gas
            and metric["general_gas_used_last"] == 0,
            "Zone settlement used general gas")
    require(scalar(l1, addresses["asset"], balance_selector(addresses["portal"]),
                   int(receipt["blockNumber"], 16)) == 100_000,
            "Zone portal backing differs from private supply")

    forged = record["forgedDispatcher"]
    require(code_hash(l1, forged["address"], forged["callBlock"]) ==
            forged["runtimeHash"].lower(), "forged dispatcher runtime differs")
    receipt = rpc(l1, "eth_getTransactionReceipt", [forged["callTx"]])
    block = rpc(l1, "eth_getBlockByNumber", [hex(forged["callBlock"]), False])
    require(int(receipt["status"], 16) == 0 and int(receipt["gasUsed"], 16) == 1_000_000,
            "forged dispatcher did not fail within its gas limit")
    require(len(block["transactions"]) == forged["blockTransactions"],
            "forged dispatcher block composition differs")
    metric = forged["laneMetric"]
    require(metric["general_gas_used_last"] == 1_000_000
            and metric["payment_gas_used_last"] == 218_120
            and metric["gas_used_last"] == int(block["gasUsed"], 16),
            "forged dispatcher obtained payment capacity")
    trace = rpc(l1, "debug_traceTransaction", [forged["callTx"], {"tracer": "callTracer"}])
    require(len(trace.get("calls", [])) == forged["childCalls"],
            "forged dispatcher executed a child call")

    sender_key = os.getenv("EVM2_ZONE_SENDER_KEY")
    recipient_key = os.getenv("EVM2_ZONE_RECIPIENT_KEY")
    if sender_key and recipient_key:
        block = zone_record["privateTransferBlock2"]
        for role, private_key in [("sender", sender_key), ("recipient", recipient_key)]:
            token = zone_auth_token(private_key, 1, int(record["zoneChainId"], 16))
            balance = scalar(args.zone_private_rpc_url, addresses["asset"],
                             balance_selector(addresses[role]), block, token)
            require(balance == zone_record["privateBalancesAfterSecondTransfer"][role],
                    f"Zone {role} private balance differs")
        token = zone_auth_token(sender_key, 1, int(record["zoneChainId"], 16))
        supply = scalar(args.zone_private_rpc_url, addresses["asset"], "0x18160ddd", block, token)
        require(supply == 100_000, "Zone private supply differs")
    else:
        print("private Zone balance check skipped; set EVM2_ZONE_SENDER_KEY and EVM2_ZONE_RECIPIENT_KEY")

    print("checked T16 fork, 12 accounting snapshots, 6 Earn receipts, Zone settlement, and forged admission")


if __name__ == "__main__":
    main()
