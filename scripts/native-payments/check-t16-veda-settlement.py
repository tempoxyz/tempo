#!/usr/bin/env python3
"""Check real T16 Earn/Veda queue settlement receipts, accounting, and lane samples."""

import argparse
import gzip
import hashlib
import json
import urllib.request
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
EVIDENCE = ROOT / "docs/evidence"
PREFIX = "evm2-t16-native-veda-settlement"
EOA = "0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266"


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


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rpc-url", help="also verify archived chain state and receipts")
    parser.add_argument("--tempo-binary", type=Path, help="check the exact release binary")
    args = parser.parse_args()
    summary = json.loads((EVIDENCE / f"{PREFIX}.json").read_text())
    receipts = json.loads(gzip.decompress((EVIDENCE / f"{PREFIX}-receipts.json.gz").read_bytes()))
    lanes = json.loads(gzip.decompress((EVIDENCE / f"{PREFIX}-lanes.json.gz").read_bytes()))
    assert summary["kind"] == "local Veda periphery with production VedaEngine and VedaForwardingSolver"
    if args.tempo_binary:
        assert hashlib.sha256(args.tempo_binary.read_bytes()).hexdigest() == summary["tempoBinarySha256"]
    assert set(receipts) == set(summary["operations"])
    assert len(receipts) == 20
    for name, receipt in receipts.items():
        operation = summary["operations"][name]
        assert all(receipt[key] == operation[key] for key in
                   ("transactionHash", "blockNumber", "blockHash", "status", "gasUsed"))
        assert operation["status"] == "0x1"
        assert operation["onlyTransaction"] and operation["blockGasUsed"] == operation["gasUsed"]

    addresses = summary["addresses"]
    registration = [log for log in receipts["registerForwarder"]["logs"]
                    if log["address"].lower() == addresses["nativeRegistry"].lower()]
    assert len(registration) == 1
    event = registration[0]
    assert event["topics"] == [
        "0x33fa7d22474f00bf494ffc95430f0ed292a66b5bce1f7c35e6f8b20fbd0c48b1",
        "0x" + address_word(addresses["forwarder"]),
        "0x" + address_word(addresses["vault"]),
        "0x" + address_word(addresses["engine"]),
    ]
    assert event["data"] == "0x" + address_word(addresses["snapshot"]) + summary["forwarderOriginalCodeHash"][2:]
    assert summary["forwarderDispatcherCode"] == "0x" + (ROOT / "crates/contracts/abi/NativeEarnDispatcherV1.bin").read_bytes().hex()
    assert any(log["address"].lower() == addresses["vault"].lower() and
               log["topics"][:2] == ["0xaa7dc873a7d37b94883eae5b185beafe0223de340014bc7a1690496363d5bb28", summary["requestId"]]
               for log in receipts["request"]["logs"])
    assert any(log["address"].lower() == addresses["forwarder"].lower() and
               log["topics"][0] == "0x56a6f058ac366257c60153be8fb6cf54504c691c3bd6794d503f6815fca43cbb"
               for log in receipts["solve"]["logs"])
    pre = summary["reads"][hex(int(summary["operations"]["solve"]["blockNumber"], 16) - 1)]
    post = summary["reads"][summary["operations"]["solve"]["blockNumber"]]
    assert post["recipientAsset"] - pre["recipientAsset"] == 100_000
    assert pre["shareSupply"] == post["shareSupply"] == 899_999
    assert pre["vaultAssets"] == post["vaultAssets"] == 899_999
    assert pre["vaultOpen"] == pre["engineOpen"] == pre["queueActive"] == 1
    assert post["vaultOpen"] == post["engineOpen"] == post["queueActive"] == 0
    assert pre["settled"] == post["settled"] == 0
    assert pre["accountingAligned"] == post["accountingAligned"] == 1
    replay = summary["replayFailure"]
    assert replay["status"] == "0x0"
    assert len(replay["reads"]) == 2
    assert replay["reads"][hex(int(replay["blockNumber"], 16) - 1)] == replay["reads"][replay["blockNumber"]]
    assert replay["reads"][replay["blockNumber"]]["vaultOpen"] == 0
    assert lanes["receipt"]["transactionHash"] == receipts["solve"]["transactionHash"]
    assert sum(row["paymentGas"] == int(receipts["solve"]["gasUsed"], 16) and row["generalGas"] == 0
               for row in lanes["samples"]) > 0

    if args.rpc_url:
        url = args.rpc_url
        assert rpc(url, "eth_getBlockByNumber", ["0x0", False])["hash"] == summary["genesisHash"]
        assert rpc(url, "eth_getBlockByNumber", ["0x1", False])["hash"] == summary["activationBlockHash"]
        assert rpc(url, "eth_getBlockByNumber", [summary["proofBlock"], False])["stateRoot"] == summary["stateRoot"]
        for name, operation in summary["operations"].items():
            actual = rpc(url, "eth_getTransactionReceipt", [operation["transactionHash"]])
            assert actual["status"] == operation["status"] and actual["blockHash"] == operation["blockHash"]
            assert actual["logs"] == receipts[name]["logs"]
        replay_receipt = rpc(url, "eth_getTransactionReceipt", [replay["transactionHash"]])
        assert replay_receipt["status"] == "0x0" and replay_receipt["blockHash"] == replay["blockHash"]
        assert rpc(url, "eth_getCode", [addresses["forwarder"], summary["proofBlock"]]) == summary["forwarderDispatcherCode"]
        for height, readings in summary["reads"].items():
            checks = [
                ("recipientAsset", addresses["asset"], "0x70a08231" + address_word(EOA)),
                ("shareSupply", addresses["earnShare"], "0x18160ddd"),
                ("vaultAssets", addresses["vault"], "0x01e1d114"),
                ("vaultOpen", addresses["vault"], "0x777af82d"),
                ("engineOpen", addresses["engine"], "0xb080045f"),
            ]
            for name, address, calldata in checks:
                assert int(rpc(url, "eth_call", [{"to": address, "data": calldata}, height]), 16) == readings[name]
    print("T16 local Veda solve/finalize, 20 receipts, accounting, and payment lane verified")


if __name__ == "__main__":
    main()
