#!/usr/bin/env python3
"""Recheck the reviewed-binary T16 fork and combined Earn/Zone devnet."""

import argparse
import json
import os
import runpy
from pathlib import Path


helpers = runpy.run_path(str(Path(__file__).with_name("check-t16-combined.py")))
rpc = helpers["rpc"]
scalar = helpers["scalar"]
code_hash = helpers["code_hash"]
balance_selector = helpers["balance_selector"]
zone_auth_token = helpers["zone_auth_token"]
require = helpers["require"]


def check_receipt(url, expected, payment=False):
    receipt = rpc(url, "eth_getTransactionReceipt", [expected["hash"]])
    require(receipt is not None, f"missing receipt {expected['hash']}")
    number = int(receipt["blockNumber"], 16)
    block = rpc(url, "eth_getBlockByNumber", [hex(number), False])
    require(number == expected["block"] and receipt["blockHash"] == expected["blockHash"],
            f"receipt moved: {expected['hash']}")
    require(int(receipt["status"], 16) == expected["status"] == 1,
            f"receipt failed: {expected['hash']}")
    require(int(receipt["gasUsed"], 16) == expected["gasUsed"],
            f"gas differs: {expected['hash']}")
    require(int(block["timestamp"], 16) == expected["timestamp"],
            f"timestamp differs: {expected['hash']}")
    if payment:
        metric = expected["laneMetric"]
        require(metric["payment_transactions_last"] == 1
                and metric["payment_gas_used_last"] == expected["gasUsed"]
                and metric["general_gas_used_last"] == 0
                and metric["gas_used_last"] == int(block["gasUsed"], 16)
                and abs(metric["time"] - int(block["timestampMillis"], 16) / 1000) < 2,
                f"payment lane sample differs: {expected['hash']}")
    return number


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--record", default="docs/evidence/evm2-t16-reviewed-fork.json")
    parser.add_argument("--l1-rpc-url", default="http://127.0.0.1:61545")
    parser.add_argument("--zone-rpc-url", default="http://127.0.0.1:62545")
    parser.add_argument("--zone-private-rpc-url", default="http://127.0.0.1:62544")
    args = parser.parse_args()
    record = json.loads(Path(args.record).read_text())
    l1, zone = args.l1_rpc_url, args.zone_rpc_url
    address = record["addresses"]
    require(rpc(l1, "eth_chainId", []) == record["l1ChainId"], "L1 chain ID differs")
    require(rpc(zone, "eth_chainId", []) == record["zoneChainId"], "Zone chain ID differs")
    for url, key in [(l1, "l1GenesisHash"), (zone, "zoneGenesisHash")]:
        require(rpc(url, "eth_getBlockByNumber", ["0x0", False])["hash"] == record[key],
                f"{key} differs")

    for key, expected in record["forkBoundary"].items():
        number = int(key)
        block = rpc(l1, "eth_getBlockByNumber", [hex(number), False])
        require(block["hash"] == expected["blockHash"]
                and block["stateRoot"] == expected["stateRoot"]
                and int(block["timestamp"], 16) == expected["timestamp"],
                f"fork block {number} differs")
        for role in ("vault", "fees"):
            require(code_hash(l1, address[role], number) == expected[
                "vaultCodeHash" if role == "vault" else "feeCodeHash"
            ].lower(), f"{role} runtime differs at {number}")
    require(record["forkBoundary"]["1171"]["vaultCodeHash"] !=
            record["forkBoundary"]["1172"]["vaultCodeHash"],
            "vault runtime did not migrate")
    require(record["forkBoundary"]["1172"]["vaultCodeHash"] ==
            record["forkBoundary"]["1172"]["feeCodeHash"],
            "vault and fee dispatcher mismatch")

    for key, expected in record["snapshots"].items():
        number = int(key)
        actual = {
            "shareSupply": scalar(l1, address["share"], "0x18160ddd", number),
            "vaultAssets": scalar(l1, address["vault"], "0x01e1d114", number),
            "venueAssets": scalar(l1, address["venue"], "0x01e1d114", number),
            "portalBacking": scalar(l1, address["asset"],
                                    balance_selector(address["portal"]), number),
            "recipientAssets": scalar(l1, address["asset"],
                                      balance_selector(address["recipient"]), number),
        }
        require(actual == expected, f"accounting differs at {number}: {actual}")
        require(actual["vaultAssets"] == actual["venueAssets"],
                f"vault/venue custody differs at {number}")
    states = record["snapshots"]
    require(states["1171"] == states["1172"], "fork changed custody")
    require(states["2106"]["shareSupply"] - states["2107"]["shareSupply"] == 250,
            "spend burned wrong shares")
    require(states["2107"]["recipientAssets"] - states["2106"]["recipientAssets"] == 250,
            "spend paid wrong assets")

    for expected in record["earnTransactions"].values():
        check_receipt(l1, expected, payment=True)
    zone_data = record["zone"]
    check_receipt(l1, zone_data["deposit"], payment=True)
    private_block = check_receipt(zone, zone_data["privateTransfer"])
    require(zone_data["privateTransfer"]["timestamp"] >= record["zoneT15Time"],
            "private transfer preceded Zone T15")
    check_receipt(l1, zone_data["settlement"], payment=True)
    require(private_block <= zone_data["settledThroughZoneBlock"],
            "private transfer outside submitted batch")
    require(states["2107"]["portalBacking"] == 10_000,
            "portal backing differs from private supply")

    for role in ("sender", "recipient"):
        key = os.getenv(f"EVM2_ZONE_{role.upper()}_KEY")
        if key:
            token = zone_auth_token(key, zone_data["id"], int(record["zoneChainId"], 16))
            balance = scalar(args.zone_private_rpc_url, address["asset"],
                             balance_selector(address[role]), private_block, token)
            require(balance == zone_data["privateBalancesAfterTransfer"][role],
                    f"private {role} balance differs")
        else:
            print(f"private {role} balance check skipped; set EVM2_ZONE_{role.upper()}_KEY")
    sender_key = os.getenv("EVM2_ZONE_SENDER_KEY")
    if sender_key:
        token = zone_auth_token(sender_key, zone_data["id"], int(record["zoneChainId"], 16))
        require(scalar(args.zone_private_rpc_url, address["asset"], "0x18160ddd",
                       private_block, token) == zone_data["privateBalancesAfterTransfer"]["supply"],
                "private supply differs")
    print("checked reviewed T16 fork, Earn payment receipts, Zone deposit/transfer/settlement")


if __name__ == "__main__":
    main()
