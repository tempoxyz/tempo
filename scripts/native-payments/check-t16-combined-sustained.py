#!/usr/bin/env python3
"""Check T16 mixed Earn/Zone load, private custody, settlement, and lane evidence."""

import argparse
import gzip
import hashlib
import json
import os
import runpy
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
EVIDENCE = ROOT / "docs/evidence"
PREFIX = "evm2-t16-native-combined-sustained"
helpers = runpy.run_path(str(Path(__file__).with_name("check-t16-combined.py")))
rpc = helpers["rpc"]
zone_auth_token = helpers["zone_auth_token"]
balance_selector = helpers["balance_selector"]


def dynamic_bytes(calldata, index):
    data = bytes.fromhex(calldata[10:])
    offset = int.from_bytes(data[32 * index:32 * (index + 1)], "big")
    assert offset % 32 == 0 and offset + 32 <= len(data)
    length = int.from_bytes(data[offset:offset + 32], "big")
    assert offset + 32 + length <= len(data)
    return data[offset + 32:offset + 32 + length]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--l1-rpc-url")
    parser.add_argument("--zone-rpc-url")
    parser.add_argument("--zone-private-rpc-url")
    parser.add_argument("--tempo-binary", type=Path)
    parser.add_argument("--zones-binary", type=Path)
    args = parser.parse_args()
    summary = json.loads((EVIDENCE / f"{PREFIX}-summary.json").read_text())
    records = json.loads(gzip.decompress((EVIDENCE / f"{PREFIX}-raw.json.gz").read_bytes()))
    metrics = json.loads(gzip.decompress((EVIDENCE / f"{PREFIX}-metrics.json.gz").read_bytes()))
    settlements = json.loads(gzip.decompress((EVIDENCE / f"{PREFIX}-settlements.json.gz").read_bytes()))
    if args.tempo_binary:
        assert hashlib.sha256(args.tempo_binary.read_bytes()).hexdigest() == summary["tempoBinarySha256"]
    if args.zones_binary:
        assert hashlib.sha256(args.zones_binary.read_bytes()).hexdigest() == summary["zonesBinarySha256"]
    assert summary["kind"] == "same-chain T16 native Earn and Zone mixed load"
    assert summary["cycles"] == 60 and len(records) == 180
    assert summary["earnPayments"] == 12_000 and summary["privateTransfers"] == 6_000
    assert summary["earnPaymentBlocks"] == 120 and summary["zoneTransferBlocks"] == 60
    assert summary["elapsedSeconds"] == summary["finishedAt"] - summary["startedAt"]
    assert summary["zoneT15Time"] > 0
    assert summary["preActivationBlock"]["senderBalance"] == summary["activationBlock"]["senderBalance"] == 1_000_000
    assert summary["zoneSupply"] == summary["portalBacking"] == 1_000_000
    assert summary["finalEarnSupply"] == summary["finalVaultAssets"] == 1_000_000
    assert int(summary["settledZoneBlock"], 16) >= int(summary["lastTransferZoneBlock"], 16)
    before, after = summary["privateBalances"].values()
    sender = "0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266"
    recipient = "0x70997970c51812dc3a010c7d01b50e0d17dc79c8"
    assert before[sender] - after[sender] == after[recipient] - before[recipient] == 6_000
    assert sum(before.values()) == sum(after.values()) == 1_000_000

    earn_gas = earn_block_gas = zone_gas = earn_matches = 0
    for i, item in enumerate(records):
        cycle, mode, record = item["cycle"], item["mode"], item["record"]
        assert cycle == i // 3 and mode == ("deposit", "zone", "redeem")[i % 3]
        assert record["count"] == len(record["hashes"]) == len(record["receipts"]) == 100
        assert len(set(record["hashes"])) == 100 and len(record["blocks"]) == 1
        height, block = next(iter(record["blocks"].items()))
        assert block["count"] == 100 and block["gasUsed"] <= int(record["blockGasUsed"], 16)
        assert all(r["status"] == "0x1" and r["blockNumber"] == height and
                   r["blockHash"] == record["blockHash"] for r in record["receipts"].values())
        assert sum(int(r["gasUsed"], 16) for r in record["receipts"].values()) == block["gasUsed"]
        if mode == "zone":
            assert record["verifiedReceiptCount"] >= 101
            zone_gas += block["gasUsed"]
        else:
            assert record["verifiedReceiptCount"] >= 100
            expected = 1_100_000 if mode == "deposit" else 1_000_000
            assert record["supply"] == record["assets"] == expected
            matches = sum(row["paymentGas"] == int(record["blockGasUsed"], 16) and row["generalGas"] == 0
                          for row in record["samples"])
            assert matches == record["matchingSamples"] > 0
            earn_matches += matches
            earn_gas += block["gasUsed"]
            earn_block_gas += int(record["blockGasUsed"], 16)
        url = args.zone_rpc_url if mode == "zone" else args.l1_rpc_url
        if url:
            chain_block = rpc(url, "eth_getBlockByNumber", [height, False])
            chain_receipts = rpc(url, "eth_getBlockReceipts", [height])
            assert chain_block["hash"] == record["blockHash"]
            assert chain_block["gasUsed"] == record["blockGasUsed"]
            assert len(chain_receipts) == record["verifiedReceiptCount"]
            by_hash = {receipt["transactionHash"]: receipt for receipt in chain_receipts}
            assert set(record["hashes"]).issubset(by_hash)
            for tx_hash, saved in record["receipts"].items():
                assert all(by_hash[tx_hash][key] == saved[key] for key in
                           ("blockNumber", "blockHash", "status", "gasUsed", "transactionIndex"))
            if mode == "zone":
                assert all(receipt["gasUsed"] == "0x0" for receipt in chain_receipts
                           if receipt["transactionHash"] not in record["hashes"])
            else:
                for name, address, data in [("supply", summary["earnShare"], "0x18160ddd"),
                                             ("assets", summary["vault"], "0x01e1d114")]:
                    assert int(rpc(url, "eth_call", [{"to": address, "data": data}, height]), 16) == record[name]
    assert earn_gas == summary["earnPaymentGas"] and earn_block_gas == summary["earnBlockGas"]
    assert zone_gas == summary["zoneTransferGas"]
    assert earn_matches == summary["earnMatchingMetricSamples"]

    assert len(settlements) == summary["settlementCount"] == 26
    sampled = 0
    for saved in settlements:
        assert saved["status"] == "0x1" and saved["noProof"]
        assert saved["batchEvent"]["topics"][0] == "0x2ad9ed3f2b3ff263b7a3cf97621dfc164b1d2303160c10d0dc421f866d0d54ef"
        gas = int(saved["gasUsed"], 16)
        matches = sum(row["paymentGas"] == gas and row["generalGas"] == 0 and
                      saved["blockTimestamp"] <= row["time"] < saved["blockTimestamp"] + 2
                      for row in metrics)
        assert matches == saved["matchingMetricSamples"]
        sampled += int(matches > 0)
        if args.l1_rpc_url:
            receipt = rpc(args.l1_rpc_url, "eth_getTransactionReceipt", [saved["hash"]])
            tx = rpc(args.l1_rpc_url, "eth_getTransactionByHash", [saved["hash"]])
            block = rpc(args.l1_rpc_url, "eth_getBlockByNumber", [saved["blockNumber"], False])
            assert receipt["blockHash"] == saved["blockHash"] and receipt["status"] == "0x1"
            assert receipt["gasUsed"] == saved["gasUsed"] and block["transactions"] == saved["blockTransactions"]
            assert saved["batchEvent"] in receipt["logs"]
            assert len(tx["calls"]) == 1 and tx["calls"][0]["to"].lower() == summary["portal"]
            calldata = tx["calls"][0]["input"]
            assert calldata.startswith("0x4cd6c7c7")
            assert dynamic_bytes(calldata, 11) == b"\x02" and dynamic_bytes(calldata, 12) == b""
    assert sampled == summary["settlementLaneSampledCount"] == 2

    if args.l1_rpc_url and args.zone_rpc_url:
        assert rpc(args.l1_rpc_url, "eth_getBlockByNumber", ["0x0", False])["hash"] == summary["l1GenesisHash"]
        assert rpc(args.zone_rpc_url, "eth_getBlockByNumber", ["0x0", False])["hash"] == summary["zoneGenesisHash"]
        for key in ["preActivationBlock", "activationBlock"]:
            block = rpc(args.zone_rpc_url, "eth_getBlockByNumber", [summary[key]["number"], False])
            assert block["hash"] == summary[key]["hash"]
        settled = rpc(args.zone_rpc_url, "eth_getBlockByHash", [summary["settledZoneBlockHash"], False])
        assert settled["number"] == summary["settledZoneBlock"]
    keys = [(sender, os.getenv("EVM2_ZONE_SENDER_KEY")), (recipient, os.getenv("EVM2_ZONE_RECIPIENT_KEY"))]
    if args.zone_private_rpc_url and all(key for _, key in keys):
        for address, key in keys:
            token = zone_auth_token(key, summary["zoneId"], summary["zoneChainId"])
            for height, balances in summary["privateBalances"].items():
                value = rpc(args.zone_private_rpc_url, "eth_call", [
                    {"to": summary["asset"], "data": balance_selector(address)}, height,
                ], token)
                assert int(value, 16) == balances[address]
    print("verified 12,000 Earn payments, 6,000 private transfers, 26 NoProof settlements, custody, and lane samples")


if __name__ == "__main__":
    main()
