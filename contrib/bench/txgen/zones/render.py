# /// script
# requires-python = ">=3.11"
# dependencies = ["eth-account==0.13.7", "cryptography==46.0.5", "PyYAML==6.0.3"]
# ///
"""Render a finite local portal workload; no network access or signing of settlement proofs."""

import argparse
from pathlib import Path

import rlp
import yaml
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from eth_abi import encode
from eth_account import Account
from eth_utils import keccak, to_checksum_address

TOKEN = "0x20c0000000000000000000000000000000000000"
ZERO = bytes(32)
WITHDRAWAL_TYPE = "(address,bytes32,address,uint128,bytes32,uint64,uint64,bytes,bytes)"


def encrypted_payload(sender, portal):
    # Deterministic fixture material only. Encrypt exactly as txgen-tempo/src/zone.rs.
    recipient_key = ec.derive_private_key(1, ec.SECP256K1())
    ephemeral_key = ec.derive_private_key(2, ec.SECP256K1())
    public = ephemeral_key.public_key().public_numbers()
    x = public.x.to_bytes(32, "big")
    info = bytes.fromhex(portal[2:]) + ZERO + x + bytes.fromhex(sender[2:])
    shared = ephemeral_key.exchange(ec.ECDH(), recipient_key.public_key())
    key = HKDF(
        algorithm=hashes.SHA256(), length=32, salt=b"ecies-aes-key", info=info
    ).derive(shared)
    nonce = bytes(12)
    plaintext = bytes.fromhex(sender[2:]) + ZERO + bytes(12)
    sealed = AESGCM(key).encrypt(nonce, plaintext, None)
    return [
        "0x" + x.hex(),
        2 + (public.y & 1),
        "0x" + sealed[:-16].hex(),
        "0x" + nonce.hex(),
        "0x" + sealed[-16:].hex(),
    ]


def render(source, count, nonce, mode):
    if count < 1 or nonce < 0:
        raise ValueError("count must be positive and nonce nonnegative")
    spec = yaml.safe_load(source.read_text())
    Account.enable_unaudited_hdwallet_features()
    sender = Account.from_mnemonic(spec["accounts"]["users"]["mnemonic"]).address
    portal = to_checksum_address(
        keccak(rlp.encode([bytes.fromhex(sender[2:]), nonce]))[-20:]
    )
    # One protocol-nonce lane preserves the queue order, including interleaved deposits.
    kinds = [
        mode if mode != "mixed" else ("deposit" if i % 2 == 0 else "withdraw")
        for i in range(count)
    ]
    withdrawals = kinds.count("withdraw")
    # No callbacks. Nonzero fallbackNonce distinguishes user withdrawals from deposit refunds.
    withdrawal = (TOKEN, ZERO, sender, 1, ZERO, 0, 1, b"", b"")
    suffixes = [ZERO] * (withdrawals + 1)
    for i in range(withdrawals - 1, -1, -1):
        suffixes[i] = keccak(
            encode([WITHDRAWAL_TYPE, "bytes32"], [withdrawal, suffixes[i + 1]])
        )
    encoded_withdrawal = [
        "0x" + v.hex() if isinstance(v, bytes) else v for v in withdrawal
    ]
    spec["setup"]["steps"][0]["deploy"]["constructor_args"] = [
        sender,
        TOKEN,
        "0x" + suffixes[0].hex(),
    ]
    portal_var = {"var": "setup.portal.address"}
    calls = []
    if withdrawals:
        calls.append(
            {
                "to": TOKEN,
                "abi": "ERC20",
                "function": "transfer",
                "args": [portal_var, withdrawals],
            }
        )
    if count > withdrawals:
        calls.append(
            {
                "to": TOKEN,
                "abi": "ERC20",
                "function": "approve",
                "args": [portal_var, count - withdrawals],
            }
        )
    spec["setup"]["steps"][1]["tx"]["calls"] = calls
    spec["templates"]["zone_deposit"]["call"]["args"] = [
        TOKEN,
        1,
        0,
        encrypted_payload(sender, portal),
        sender,
    ]
    steps = []
    index = 0
    for kind in kinds:
        step = {"template": "zone_" + kind}
        if kind == "withdraw":
            step["with"] = {
                "call": {
                    "args": [[encoded_withdrawal], "0x" + suffixes[index + 1].hex()]
                }
            }
            index += 1
        steps.append(step)
    spec["sequences"]["zone_operations"]["steps"] = steps
    # Rendered files live in .bench-tmp, so retain source-relative artifact semantics.
    spec["artifacts"] = {
        name: str((source.parent / path).resolve())
        for name, path in spec["artifacts"].items()
    }
    return spec


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--source",
        type=Path,
        default=Path(__file__).resolve().parent.parent / "presets/zones.yml",
    )
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--count", type=int, required=True)
    parser.add_argument(
        "--nonce", type=int, required=True, help="Current protocol nonce of users[0]"
    )
    parser.add_argument(
        "--mode", choices=["mixed", "deposit", "withdraw"], default="mixed"
    )
    args = parser.parse_args()
    spec = render(args.source.resolve(), args.count, args.nonce, args.mode)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(yaml.safe_dump(spec, sort_keys=False))


if __name__ == "__main__":
    main()
