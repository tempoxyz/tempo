# /// script
# requires-python = ">=3.11"
# dependencies = ["eth-account==0.13.7", "cryptography==46.0.5", "PyYAML==6.0.3"]
# ///
"""Smoke-test the rendered preset on an already-running, disposable local Tempo node."""

import argparse
import json
import subprocess
import sys
import tempfile
from pathlib import Path
from urllib.parse import urlparse
from urllib.request import Request, urlopen

import rlp
import yaml
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from eth_abi import encode
from eth_utils import keccak, to_checksum_address
from render import TOKEN, WITHDRAWAL_TYPE, ZERO, render

SENDER = "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"
DEPOSIT = (
    "0x"
    + keccak(
        text="DepositMade(bytes32,address,address,uint128,uint128,uint256,bytes32,uint8,bytes,bytes12,bytes16,address,uint64)"
    ).hex()
)
WITHDRAWAL = (
    "0x"
    + keccak(text="WithdrawalProcessed(address,bytes32,address,uint128,bool)").hex()
)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rpc", default="http://127.0.0.1:18545")
    parser.add_argument("--txgen-bin", default="txgen-tempo")
    parser.add_argument("--bench-bin", default="bench")
    parser.add_argument("--count", type=int, default=6)
    args = parser.parse_args()
    if urlparse(args.rpc).hostname not in ("localhost", "127.0.0.1", "::1"):
        parser.error("only a disposable loopback node is supported")
    if args.count < 4:
        parser.error("count must be at least 4 to test an incorrect withdrawal suffix")

    def rpc(method, *params):
        request = Request(
            args.rpc,
            json.dumps(
                {"jsonrpc": "2.0", "id": 1, "method": method, "params": params}
            ).encode(),
            {"Content-Type": "application/json"},
        )
        with urlopen(request, timeout=30) as response:
            result = json.load(response)
        if "error" in result:
            raise RuntimeError(result["error"])
        return result["result"]

    assert int(rpc("eth_chainId"), 16) == 1337
    source = Path(__file__).resolve().parent.parent / "presets/zones.yml"
    with tempfile.TemporaryDirectory(prefix="zone-preset-check-") as directory:
        directory = Path(directory)
        for mode in ("mixed", "deposit", "withdraw"):
            nonce = int(rpc("eth_getTransactionCount", SENDER, "latest"), 16)
            portal = to_checksum_address(
                keccak(rlp.encode([bytes.fromhex(SENDER[2:]), nonce]))[-20:]
            )
            spec = render(source, args.count, nonce, mode)
            portals = [
                to_checksum_address(
                    keccak(rlp.encode([bytes.fromhex(SENDER[2:]), nonce + offset]))[
                        -20:
                    ]
                )
                for offset in range(0, len(spec["setup"]["steps"]), 2)
            ]
            # Portal acceptance alone does not prove the recipient can be decrypted.
            for index, address in enumerate(portals):
                template = "zone_deposit" if index == 0 else f"zone_deposit_{index}"
                payload = spec["templates"][template]["call"]["args"][3]
                x = bytes.fromhex(payload[0][2:])
                ephemeral_public = ec.EllipticCurvePublicKey.from_encoded_point(
                    ec.SECP256K1(), bytes([payload[1]]) + x
                )
                shared = ec.derive_private_key(1, ec.SECP256K1()).exchange(
                    ec.ECDH(), ephemeral_public
                )
                key = HKDF(
                    algorithm=hashes.SHA256(),
                    length=32,
                    salt=b"ecies-aes-key",
                    info=bytes.fromhex(address[2:])
                    + ZERO
                    + x
                    + bytes.fromhex(SENDER[2:]),
                ).derive(shared)
                plaintext = AESGCM(key).decrypt(
                    bytes.fromhex(payload[3][2:]),
                    bytes.fromhex(payload[2][2:] + payload[4][2:]),
                    None,
                )
                assert plaintext == bytes.fromhex(SENDER[2:]) + ZERO + bytes(12)
            spec_file = directory / "spec.yml"
            spec_file.write_text(yaml.safe_dump(spec, sort_keys=False))
            tx_file = directory / "transactions.ndjson"
            report = directory / "report.json"
            # First run setup alone, then send the pre-generated workload without regenerating nonces.
            subprocess.run(
                [
                    args.txgen_bin,
                    "generate",
                    "-s",
                    str(spec_file),
                    "-n",
                    str(args.count),
                    "--rpc",
                    args.rpc,
                    "-o",
                    str(tx_file),
                ],
                check=True,
            )
            filtered = subprocess.run(
                [sys.executable, str(Path(__file__).with_name("stream.py"))],
                input=tx_file.read_bytes(),
                capture_output=True,
                check=True,
            )
            tx_file.write_bytes(filtered.stdout)
            transactions = [
                json.loads(line) for line in tx_file.read_text().splitlines()
            ]
            setup_file = directory / "setup.ndjson"
            setup_file.write_text(
                "\n".join(
                    json.dumps(tx) for tx in transactions if tx["phase"] == "setup"
                )
                + "\n"
            )
            send = [
                args.bench_bin,
                "send",
                "--rpc-url",
                args.rpc,
                "--tps",
                "10",
                "--retries",
                "0",
                "--drain-timeout",
                "10",
            ]
            subprocess.run(
                send + ["--input", str(setup_file), "--report", "json:" + str(report)],
                check=True,
            )
            expected_proxy = "0x363d3d373d3d3d363d735ad10000000000000000000000000000000000005af43d82803e903d91602b57fd5bf3"
            assert all(
                rpc("eth_getCode", address, "latest") == expected_proxy
                for address in portals
            )
            slot = "0x" + keccak(encode(["uint256", "uint256"], [0, 11])).hex()
            for offset, address in enumerate(portals):
                root = spec["setup"]["steps"][offset * 2]["deploy"]["constructor_args"][
                    2
                ]
                assert rpc("eth_getStorageAt", address, slot, "latest") == root
            if mode != "deposit":
                withdrawal = (TOKEN, ZERO, SENDER, 1, ZERO, 0, 1, b"", b"")
                selector = keccak(
                    text=f"processWithdrawals({WITHDRAWAL_TYPE}[],bytes32)"
                )[:4]
                bad_data = selector + encode(
                    [WITHDRAWAL_TYPE + "[]", "bytes32"], [[withdrawal], ZERO]
                )
                try:
                    rpc(
                        "eth_call",
                        {"from": SENDER, "to": portal, "data": "0x" + bad_data.hex()},
                        "latest",
                    )
                except RuntimeError as error:
                    assert "revert" in str(error).lower()
                else:
                    raise AssertionError("wrong suffix was accepted")
            subprocess.run(
                send
                + [
                    "--input",
                    str(tx_file),
                    "--skip-setup",
                    "--report",
                    "json:" + str(report),
                ],
                check=True,
            )
            logs = rpc(
                "eth_getLogs",
                {"address": portals, "fromBlock": "0x0", "toBlock": "latest"},
            )
            deposits = [log for log in logs if log["topics"][0] == DEPOSIT]
            withdrawals = [log for log in logs if log["topics"][0] == WITHDRAWAL]
            assert len(deposits) == (
                args.count
                if mode == "deposit"
                else 0
                if mode == "withdraw"
                else (args.count + 1) // 2
            )
            assert len(withdrawals) == args.count - len(deposits)
            assert all(int(log["data"][-64:], 16) == 1 for log in withdrawals)
            assert all(
                rpc("eth_getStorageAt", address, slot, "latest") == "0x" + ZERO.hex()
                for address in portals
            )
            print(
                f"{mode}: setup + {args.count} calls passed; {len(deposits)} deposits, {len(withdrawals)} successful withdrawals"
            )


if __name__ == "__main__":
    main()
