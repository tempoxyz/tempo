#!/usr/bin/env python3
"""Check saved T16 Earn payment-lane bursts against receipts, metrics, and custody."""

import argparse
import gzip
import hashlib
import json
import urllib.request
from pathlib import Path


EVIDENCE = Path(__file__).resolve().parents[2] / "docs/evidence"
PREFIX = "evm2-t16-native-earn-sustained"


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


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rpc-url", help="also verify archived blocks and receipts")
    parser.add_argument("--tempo-binary", type=Path, help="check the exact release binary")
    args = parser.parse_args()
    summary = json.loads((EVIDENCE / f"{PREFIX}-summary.json").read_text())
    records = json.loads(gzip.decompress((EVIDENCE / f"{PREFIX}-raw.json.gz").read_bytes()))
    if args.tempo_binary:
        assert hashlib.sha256(args.tempo_binary.read_bytes()).hexdigest() == summary["tempoBinarySha256"]
    assert len(records) == summary["paymentBlocks"] == 40
    assert summary["cycles"] == 20
    assert summary["deposits"] == summary["redemptions"] == 2_000
    assert summary["successfulPayments"] == 4_000
    assert summary["elapsedSeconds"] == summary["finishedAt"] - summary["startedAt"]
    assert summary["transactionsPerSecond"] == 4_000 / summary["elapsedSeconds"]
    assert summary["firstBlock"] == next(iter(records[0]["blocks"]))
    assert summary["lastBlock"] == next(iter(records[-1]["blocks"]))
    total_gas = 0
    metric_matches = 0
    for i, record in enumerate(records):
        mode = "deposit" if i % 2 == 0 else "redeem"
        assert record["mode"] == mode and record["count"] == 100
        assert len(record["hashes"]) == len(set(record["hashes"])) == len(record["receipts"]) == 100
        assert len(record["blocks"]) == 1
        height, block = next(iter(record["blocks"].items()))
        assert block["count"] == 100 and block["gasUsed"] == int(record["blockGasUsed"], 16)
        assert {r["blockNumber"] for r in record["receipts"].values()} == {height}
        assert {r["blockHash"] for r in record["receipts"].values()} == {record["blockHash"]}
        assert all(r["status"] == "0x1" for r in record["receipts"].values())
        assert sum(int(r["gasUsed"], 16) for r in record["receipts"].values()) == block["gasUsed"]
        matches = sum(row["paymentGas"] == block["gasUsed"] and row["generalGas"] == 0
                      for row in record["samples"])
        assert matches == record["matchingSamples"] > 0
        assert record["supply"] == record["assets"] == (1_100_000 if mode == "deposit" else 1_000_000)
        if args.rpc_url:
            chain_block = rpc(args.rpc_url, "eth_getBlockByNumber", [height, False])
            chain_receipts = rpc(args.rpc_url, "eth_getBlockReceipts", [height])
            assert chain_block["hash"] == record["blockHash"]
            assert chain_block["gasUsed"] == record["blockGasUsed"]
            assert set(chain_block["transactions"]) == set(record["hashes"])
            assert {r["transactionHash"] for r in chain_receipts} == set(record["hashes"])
            for receipt in chain_receipts:
                saved = record["receipts"][receipt["transactionHash"]]
                assert all(receipt[key] == saved[key] for key in
                           ("blockNumber", "blockHash", "status", "gasUsed", "transactionIndex"))
            for name, address, data in [
                ("supply", summary["earnShare"], "0x18160ddd"),
                ("assets", summary["vault"], "0x01e1d114"),
            ]:
                assert int(rpc(args.rpc_url, "eth_call", [{"to": address, "data": data}, height]), 16) == record[name]
        total_gas += block["gasUsed"]
        metric_matches += matches
    assert total_gas == summary["paymentGas"]
    assert metric_matches == summary["matchingMetricSamples"]
    assert summary["initialSupply"] == summary["finalSupply"] == summary["finalVaultAssets"] == 1_000_000
    if args.rpc_url:
        assert rpc(args.rpc_url, "eth_getBlockByNumber", ["0x0", False])["hash"] == summary["genesisHash"]
        assert rpc(args.rpc_url, "eth_getBlockByNumber", ["0x1", False])["hash"] == summary["activationBlockHash"]
    print(f"verified 4,000 T16 Earn payments over 40 blocks, {metric_matches} zero-general metric samples, and custody")


if __name__ == "__main__":
    main()
