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
    parser.add_argument("--event-rpc-url", help="also verify registration on the event-enabled devnet")
    parser.add_argument("--tempo-binary", type=Path, help="check the exact release binary used")
    parser.add_argument("--event-binary", type=Path, help="check the event-enabled release binary")
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

    revocation = json.loads((EVIDENCE / f"{PREFIX}-revocation.json").read_text())
    lane_record = json.loads(gzip.decompress(
        (EVIDENCE / f"{PREFIX}-revocation-lanes.json.gz").read_bytes()
    ))
    revoked = revocation["states"]
    assert revoked["beforeRevoke"]["approval"] == summary["engineHash"]
    assert revoked["afterRevoke"]["approval"] == revoked["afterRejectedDeposit"]["approval"] == "0x" + "0" * 64
    assert revoked["afterApprove"]["approval"] == revoked["afterSampledDeposit"]["approval"] == summary["engineHash"]
    for stage in ("beforeRevoke", "afterRevoke", "afterRejectedDeposit", "afterApprove"):
        assert revoked[stage]["shareSupply"] == 402_727
        assert revoked[stage]["vaultAssets"] == 443_000
    assert revoked["afterSampledDeposit"]["shareSupply"] == 403_636
    assert revoked["afterSampledDeposit"]["vaultAssets"] == 444_000
    for name, status in (("revoke", "0x1"), ("rejectedDeposit", "0x0"), ("approve", "0x1"), ("sampledDeposit", "0x1")):
        tx = revocation["transactions"][name]
        assert tx["status"] == status
        assert tx["onlyTransaction"] and tx["gasUsed"] == tx["blockGasUsed"]
    sampled_deposit = revocation["transactions"]["sampledDeposit"]
    assert lane_record["receipt"]["transactionHash"] == sampled_deposit["transactionHash"]
    matches = sum(
        row["generalGas"] == 0 and row["paymentGas"] == int(sampled_deposit["gasUsed"], 16)
        for row in lane_record["samples"]
    )
    assert matches == revocation["sampledDepositLane"]["matching"] > 0
    assert len(lane_record["samples"]) == revocation["sampledDepositLane"]["total"]

    event_run = json.loads((EVIDENCE / "evm2-t16-native-registration-event.json").read_text())
    event_lanes = json.loads(gzip.decompress(
        (EVIDENCE / "evm2-t16-native-registration-event-lanes.json.gz").read_bytes()
    ))
    event = event_run["registrationLog"]
    assert event["address"] == "0x5aea000000000000000000000000000000000000"
    assert event["topics"] == [
        "0xe941985d5446028e43c141fc9de757ef0be628464c52a67b2e875d981f2c5d4b",
        "0x" + address_word(summary["vault"]),
        "0x" + address_word(summary["asset"]),
        "0x" + address_word(summary["earnShare"]),
    ]
    assert event["data"] == "0x" + address_word(summary["fees"]) + address_word(summary["engine"]) + summary["engineHash"][2:]
    assert event_run["shareSupply"] == event_run["vaultAssets"] == 1_000_000
    assert bytes.fromhex(event_run["vaultCode"][2:]) == (EVIDENCE.parents[1] / "crates/contracts/abi/NativeEarnDispatcherV1.bin").read_bytes()
    if args.event_binary:
        assert hashlib.sha256(args.event_binary.read_bytes()).hexdigest() == event_run["binarySha256"]
    assert all(operation["status"] == "0x1" and operation["onlyTransaction"] and operation["gasUsed"] == operation["blockGasUsed"] for operation in event_run["transactions"].values())
    event_deposit = event_run["transactions"]["deposit"]
    assert event_lanes["receipt"]["transactionHash"] == event_deposit["transactionHash"]
    event_matches = sum(row["generalGas"] == 0 and row["paymentGas"] == int(event_deposit["gasUsed"], 16) for row in event_lanes["samples"])
    assert event_matches == event_run["depositLane"]["matching"] > 0
    assert len(event_lanes["samples"]) == event_run["depositLane"]["total"]

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
        for stage in revoked.values():
            block = stage["block"]
            assert rpc(url, "eth_getStorageAt", [registrar, revocation["engineApprovalSlot"], block]) == stage["approval"]
            assert call_uint(url, summary["earnShare"], "0x18160ddd", block) == stage["shareSupply"]
            assert call_uint(url, summary["vault"], "0x01e1d114", block) == stage["vaultAssets"]
        for operation in revocation["transactions"].values():
            receipt = rpc(url, "eth_getTransactionReceipt", [operation["transactionHash"]])
            assert receipt["blockHash"] == operation["blockHash"]
            assert receipt["status"] == operation["status"]
            block = rpc(url, "eth_getBlockByNumber", [operation["blockNumber"], False])
            assert block["transactions"] == [operation["transactionHash"]]
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
    if args.event_rpc_url:
        url = args.event_rpc_url
        assert rpc(url, "eth_getBlockByNumber", ["0x0", False])["hash"] == event_run["genesisHash"]
        assert rpc(url, "eth_getBlockByNumber", ["0x1", False])["hash"] == event_run["activationBlock"]["hash"]
        for operation in event_run["transactions"].values():
            receipt = rpc(url, "eth_getTransactionReceipt", [operation["transactionHash"]])
            assert receipt["blockHash"] == operation["blockHash"]
            assert receipt["status"] == operation["status"]
            block = rpc(url, "eth_getBlockByNumber", [operation["blockNumber"], False])
            assert block["transactions"] == [operation["transactionHash"]]
        receipt = rpc(url, "eth_getTransactionReceipt", [event_run["transactions"]["deploy"]["transactionHash"]])
        assert [{key: log[key] for key in ("address", "topics", "data")} for log in receipt["logs"] if log["address"] == event["address"]] == [event]
        assert rpc(url, "eth_getCode", [summary["vault"], "latest"]) == event_run["vaultCode"]
    print(f"T16 factory and legacy forks, {len(summary['operations']) + 9} receipts, {sampled + 3} lane-sampled payments, revocation, registration event, and accounting verified")


if __name__ == "__main__":
    main()
