#!/usr/bin/env python3
"""Check T16 mock forwarding admission, code snapshot, receipts, and lane samples."""

import argparse
import gzip
import hashlib
import json
import urllib.request
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
EVIDENCE = ROOT / "docs/evidence"
PREFIX = "evm2-t16-native-settlement-forwarder-mock"


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
    parser.add_argument("--rpc-url", help="also verify archived receipts and current state")
    parser.add_argument("--tempo-binary", type=Path, help="check the exact release binary")
    args = parser.parse_args()
    run = json.loads((EVIDENCE / f"{PREFIX}.json").read_text())
    lanes = json.loads(gzip.decompress((EVIDENCE / f"{PREFIX}-lanes.json.gz").read_bytes()))
    assert run["kind"] == "mock admission and delegatecall, not Veda settlement"
    if args.tempo_binary:
        assert hashlib.sha256(args.tempo_binary.read_bytes()).hexdigest() == run["binarySha256"]

    txs = run["transactions"]
    assert all(tx["status"] == "0x1" and tx["onlyTransaction"] and
               tx["gasUsed"] == tx["blockGasUsed"] for tx in txs.values())
    assert txs["mockDeployment"]["contractAddress"].lower() == run["forwarder"].lower()
    event = txs["registration"]["logs"][0]
    assert event["address"].lower() == "0x5aea000000000000000000000000000000000000"
    assert event["topics"] == [
        "0x33fa7d22474f00bf494ffc95430f0ed292a66b5bce1f7c35e6f8b20fbd0c48b1",
        "0x" + address_word(run["forwarder"]),
        "0x" + address_word(run["vault"]),
        "0x" + address_word("0xe7f1725e7734ce288f8367e1bb143e90bb3f0512"),
    ]
    assert event["data"] == "0x" + address_word(run["snapshot"]) + run["mockOriginalCodeHash"][2:]
    assert run["forwarderCode"] == "0x" + (ROOT / "crates/contracts/abi/NativeEarnDispatcherV1.bin").read_bytes().hex()
    assert run["snapshotCode"] == "0x366004146018573660241460365733602b55602a602a55005b73e7f1725e7734ce288f8367e1bb143e90bb3f051260005260206000f35b600160005260206000f3"
    assert run["forwardInput"] == "0xbf8d3f22" + f"{64:064x}" + "0" * 64 + f"{1:064x}" + "11" * 32
    assert run["mockMarker"] == "0x" + f"{42:064x}"
    assert run["observedCaller"] == "0x" + address_word("0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266")
    assert run["shareSupply"] == run["vaultAssets"] == 1_000_000
    forward = txs["forward"]
    assert lanes["receipt"]["transactionHash"] == forward["transactionHash"]
    assert lanes["receipt"]["gasUsed"] == forward["gasUsed"]
    assert sum(row["generalGas"] == 0 and row["paymentGas"] == int(forward["gasUsed"], 16)
               for row in lanes["samples"]) > 0

    if args.rpc_url:
        url = args.rpc_url
        assert rpc(url, "eth_getBlockByNumber", ["0x0", False])["hash"] == run["genesisHash"]
        assert rpc(url, "eth_getBlockByNumber", ["0x1", False])["hash"] == run["activationBlockHash"]
        for tx in txs.values():
            receipt = rpc(url, "eth_getTransactionReceipt", [tx["transactionHash"]])
            block = rpc(url, "eth_getBlockByNumber", [tx["blockNumber"], False])
            assert receipt["blockHash"] == tx["blockHash"]
            assert receipt["status"] == tx["status"]
            assert block["transactions"] == [tx["transactionHash"]]
        assert rpc(url, "eth_getTransactionByHash", [forward["transactionHash"]])["input"] == run["forwardInput"]
        assert rpc(url, "eth_getCode", [run["snapshot"], "latest"]) == run["snapshotCode"]
        assert rpc(url, "eth_getCode", [run["forwarder"], "latest"]) == run["forwarderCode"]
        assert rpc(url, "eth_getStorageAt", [run["forwarder"], hex(42), "latest"]) == run["mockMarker"]
        assert rpc(url, "eth_getStorageAt", [run["forwarder"], hex(43), "latest"]) == run["observedCaller"]
        assert int(rpc(url, "eth_call", [{"to": run["share"], "data": "0x18160ddd"}, "latest"]), 16) == run["shareSupply"]
        assert int(rpc(url, "eth_call", [{"to": run["vault"], "data": "0x01e1d114"}, "latest"]), 16) == run["vaultAssets"]
    print("T16 mock forwarder snapshot, delegatecall caller, accounting, receipts, and payment lane verified")


if __name__ == "__main__":
    main()
