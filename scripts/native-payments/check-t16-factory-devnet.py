#!/usr/bin/env python3
"""Verify the saved T16 native factory fork, receipts, lane samples, and balances."""

import argparse
import gzip
import hashlib
import json
import urllib.request
from pathlib import Path

EVIDENCE = Path(__file__).resolve().parents[2] / "docs/evidence"
PREFIX = "evm2-t16-native-factory"
GENERAL = "reth_tempo_payload_builder_general_gas_used_last"
PAYMENT = "reth_tempo_payload_builder_payment_gas_used_last"


def rpc(url, method, params):
    request = urllib.request.Request(
        url,
        data=json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).encode(),
        headers={"Content-Type": "application/json"},
    )
    with urllib.request.urlopen(request, timeout=30) as response:
        result = json.load(response)
    if "error" in result:
        raise RuntimeError(f"{method}: {result['error']}")
    return result["result"]


def address_word(address):
    return address.removeprefix("0x").lower().zfill(64)


def call_uint(url, address, data, block):
    return int(rpc(url, "eth_call", [{"to": address, "data": data}, block]), 16)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rpc-url", help="also verify archived blocks and current chain state")
    parser.add_argument("--legacy-rpc-url", help="also verify the replayed legacy Earn fork")
    parser.add_argument("--tempo-binary", type=Path, help="check the exact release binary used")
    args = parser.parse_args()

    summary = json.loads((EVIDENCE / f"{PREFIX}-devnet.json").read_text())
    genesis_bytes = gzip.decompress((EVIDENCE / f"{PREFIX}-genesis.json.gz").read_bytes())
    genesis = json.loads(genesis_bytes)
    receipts = json.loads(gzip.decompress((EVIDENCE / f"{PREFIX}-receipts.json.gz").read_bytes()))
    assert hashlib.sha256(genesis_bytes).hexdigest() == summary["genesisSha256"]
    assert genesis["config"]["t16Time"] == summary["t16Time"]
    assert genesis["config"]["nativeEarnFactory"]["address"].lower() == summary["factory"].lower()
    factory_config = genesis["config"]["nativeEarnFactory"]
    for field in ("codeHash", "vaultRuntimeHash", "vaultImplementation", "vaultImplementationHash", "feesImplementation", "feesImplementationHash"):
        assert factory_config[field].lower() == summary["factory" + field[0].upper() + field[1:]].lower()
    assert factory_config["approvedEngines"][0]["codeHash"].lower() == summary["engineHash"].lower()
    assert summary["failedRedeemBefore"] == summary["failedRedeemAfter"]
    assert summary["final"] == summary["failedRedeemAfter"]
    assert summary["final"] == {
        "shareSupply": 400_000,
        "vaultAssets": 440_000,
        "recipientAssets": 220_000,
    }
    if args.tempo_binary:
        assert hashlib.sha256(args.tempo_binary.read_bytes()).hexdigest() == summary["tempoBinarySha256"]

    sampled = 0
    for operation in summary["operations"]:
        name = operation["name"]
        receipt = receipts[name]
        for field in ("transactionHash", "blockNumber", "blockHash", "status", "gasUsed"):
            assert operation[field].lower() == receipt[field].lower(), (name, field)
        assert operation["gasUsed"] == operation["blockGasUsed"]
        if "laneSamples" in operation:
            samples = [
                json.loads(line)
                for line in gzip.decompress(
                    (EVIDENCE / f"{PREFIX}-{name}-lanes.jsonl.gz").read_bytes()
                ).splitlines()
            ]
            matches = sum(
                row.get(GENERAL) == 0 and row.get(PAYMENT) == int(receipt["gasUsed"], 16)
                for row in samples
            )
            assert matches == operation["laneSamples"]["matching"] > 0, name
            assert len(samples) == operation["laneSamples"]["total"]
            sampled += 1
    assert sampled == 4
    assert receipts["revert"]["status"] == "0x0"
    assert all(receipts[name]["status"] == "0x1" for name in ("deploy", "bind", "deposit", "yield", "spend", "redeem", "redeem2"))

    legacy = json.loads((EVIDENCE / f"{PREFIX}-legacy-replay.json").read_text())
    legacy_receipt = json.loads(gzip.decompress((EVIDENCE / f"{PREFIX}-legacy-receipt.json.gz").read_bytes()))
    legacy_samples = [
        json.loads(line)
        for line in gzip.decompress((EVIDENCE / f"{PREFIX}-legacy-lanes.jsonl.gz").read_bytes()).splitlines()
    ]
    assert legacy["deposit"]["transactionHash"] == legacy_receipt["transactionHash"]
    assert legacy["deposit"]["status"] == legacy_receipt["status"] == "0x1"
    assert legacy["deposit"]["gasUsed"] == legacy_receipt["gasUsed"]
    assert legacy["approvalBefore"] == "0x" + "0" * 64
    assert legacy["shareSupplyBefore"] == legacy["shareSupplyAtFork"] == 1_000_000
    assert legacy["vaultAssetsBefore"] == legacy["vaultAssetsAtFork"] == 1_000_000
    assert legacy["shareSupplyAfterDeposit"] == legacy["vaultAssetsAfterDeposit"] == 1_100_000
    matches = sum(
        row.get(GENERAL) == 0 and row.get(PAYMENT) == int(legacy_receipt["gasUsed"], 16)
        for row in legacy_samples
    )
    assert matches == legacy["deposit"]["matchingLaneSamples"] > 0
    assert len(legacy_samples) == legacy["deposit"]["totalLaneSamples"]

    if args.rpc_url:
        url = args.rpc_url
        assert rpc(url, "eth_chainId", []) == summary["chainId"]
        assert rpc(url, "eth_getBlockByNumber", ["0x0", False])["hash"] == summary["genesisHash"]
        parent = summary["forkParent"]
        fork = summary["forkBlock"]
        assert rpc(url, "eth_getBlockByNumber", [parent["number"], False])["hash"] == parent["hash"]
        assert rpc(url, "eth_getBlockByNumber", [fork["number"], False])["hash"] == fork["hash"]
        registrar = "0x5aea000000000000000000000000000000000000"
        assert rpc(url, "eth_getCode", [registrar, parent["number"]]) == "0x"
        assert rpc(url, "eth_getCode", [registrar, fork["number"]]) == "0xef"
        assert int(rpc(url, "eth_getStorageAt", [registrar, "0x0", "latest"]), 16) == int(summary["factory"], 16)
        dispatcher = (EVIDENCE.parents[1] / "crates/contracts/abi/NativeEarnDispatcherV1.bin").read_bytes()
        for account in (summary["vault"], summary["fees"]):
            assert bytes.fromhex(rpc(url, "eth_getCode", [account, "latest"])[2:]) == dispatcher
        for operation in summary["operations"]:
            receipt = rpc(url, "eth_getTransactionReceipt", [operation["transactionHash"]])
            assert receipt["blockHash"] == operation["blockHash"]
            assert receipt["gasUsed"] == operation["gasUsed"]
            block = rpc(url, "eth_getBlockByNumber", [operation["blockNumber"], False])
            assert block["transactions"] == [operation["transactionHash"]]
            assert block["gasUsed"] == operation["gasUsed"]
        failed_height = int(receipts["revert"]["blockNumber"], 16)
        for height, expected in ((failed_height - 1, summary["failedRedeemBefore"]), (failed_height, summary["failedRedeemAfter"])):
            block = hex(height)
            assert call_uint(url, summary["earnShare"], "0x18160ddd", block) == expected["shareSupply"]
            assert call_uint(url, summary["vault"], "0x01e1d114", block) == expected["vaultAssets"]
            assert call_uint(url, summary["asset"], "0x70a08231" + address_word(summary["recipient"]), block) == expected["recipientAssets"]
    if args.legacy_rpc_url:
        url = args.legacy_rpc_url
        assert rpc(url, "eth_getBlockByNumber", ["0x0", False])["hash"] == legacy["genesisHash"]
        for item in ("parent", "fork"):
            block = legacy[item]
            assert rpc(url, "eth_getBlockByNumber", [block["number"], False])["hash"] == block["hash"]
        registrar = "0x5aea000000000000000000000000000000000000"
        assert rpc(url, "eth_getCode", [registrar, legacy["parent"]["number"]]) == "0x"
        assert rpc(url, "eth_getCode", [registrar, legacy["fork"]["number"]]) == "0xef"
        assert rpc(url, "eth_getStorageAt", [registrar, legacy["engineApprovalSlot"], legacy["parent"]["number"]]) == legacy["approvalBefore"]
        assert rpc(url, "eth_getStorageAt", [registrar, legacy["engineApprovalSlot"], legacy["fork"]["number"]]) == legacy["engineHash"]
        for height, supply, assets in (
            (legacy["parent"]["number"], legacy["shareSupplyBefore"], legacy["vaultAssetsBefore"]),
            (legacy["fork"]["number"], legacy["shareSupplyAtFork"], legacy["vaultAssetsAtFork"]),
            (legacy["deposit"]["blockNumber"], legacy["shareSupplyAfterDeposit"], legacy["vaultAssetsAfterDeposit"]),
        ):
            assert call_uint(url, legacy["earnShare"], "0x18160ddd", height) == supply
            assert call_uint(url, legacy["vault"], "0x01e1d114", height) == assets
        assert rpc(url, "eth_getTransactionReceipt", [legacy["deposit"]["transactionHash"]])["status"] == "0x1"
    print(f"T16 factory and legacy forks, {len(summary['operations']) + 1} receipts, {sampled + 1} lane samples, and accounting verified")


if __name__ == "__main__":
    main()
