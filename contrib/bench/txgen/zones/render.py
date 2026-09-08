# /// script
# requires-python = ">=3.11"
# dependencies = ["eth-account==0.13.7", "cryptography==46.0.5", "PyYAML==6.0.3"]
# ///
"""Prepare the local portal address and encrypted deposit payload for txgen."""

import argparse
import copy
import math
from collections import Counter
from pathlib import Path

import rlp
import yaml
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from eth_account import Account
from eth_utils import keccak, to_checksum_address

TOKEN = "0x20c0000000000000000000000000000000000000"
ZERO = bytes(32)


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


def render(source, count, nonce, mode, accounts=1, zones=1):
    if count < 1 or nonce < 0 or not 1 <= accounts <= 100000 or zones < 1:
        raise ValueError(
            "count/zones must be positive, nonce nonnegative, accounts 1–100000"
        )
    spec = yaml.safe_load(source.read_text())
    spec["accounts"]["users"]["range"] = [0, accounts]
    Account.enable_unaudited_hdwallet_features()
    mnemonic = spec["accounts"]["users"]["mnemonic"]
    users = [
        Account.from_mnemonic(mnemonic, account_path=f"m/44'/60'/0'/0/{i}").address
        for i in range(accounts)
    ]
    deployer = Account.from_mnemonic(
        mnemonic, account_path="m/44'/60'/0'/0/100001"
    ).address
    portals = [
        to_checksum_address(
            keccak(rlp.encode([bytes.fromhex(deployer[2:]), nonce + 1 + i]))[-20:]
        )
        for i in range(zones)
    ]
    settlement, portal_step, funding = spec["setup"]["steps"]
    steps = [settlement]
    for i in range(zones):
        step = copy.deepcopy(portal_step)
        step["id"] = f"portal_{i}"
        step["deploy"]["constructor_args"][0] = deployer
        steps.append(step)
    for i in range(zones):
        step = copy.deepcopy(funding)
        step["id"] = f"fund_{i}"
        step["tx"]["calls"][0]["args"] = [{"var": f"setup.portal_{i}.address"}, count]
        steps.append(step)
    # Use every account and portal independently, without an accounts × portals expansion.
    pairs = [(i % accounts, i % zones) for i in range(max(accounts, zones))]
    per_zone = Counter(zone for _, zone in pairs)
    weight = math.lcm(*per_zone.values())
    templates = spec["templates"]
    spec["templates"] = {}
    spec["mix"] = []
    for user, zone in pairs:
        sender = users[user]
        portal = {"var": f"setup.portal_{zone}.address"}
        account = {"pool": "users", "select": {"index": user}}
        if mode != "withdraw":
            approval = copy.deepcopy(funding)
            approval["id"] = f"approve_{user}_{zone}"
            approval["tx"]["from"] = account
            approval["tx"]["calls"] = [
                {
                    "to": TOKEN,
                    "abi": "ERC20",
                    "function": "approve",
                    "args": [portal, "0x" + "ff" * 32],
                }
            ]
            steps.append(approval)
        for kind in ["deposit", "withdraw"] if mode == "mixed" else [mode]:
            name = f"zone_{kind}_{user}_{zone}"
            template = copy.deepcopy(templates["zone_" + kind])
            template["from"] = account
            if kind == "deposit":
                template["calls"][0]["to"] = portal
                template["calls"][0]["args"] = [
                    TOKEN,
                    1,
                    0,
                    encrypted_payload(sender, portals[zone]),
                    sender,
                ]
            settlement_call = next(
                call for call in template["calls"] if call["function"] == "settle"
            )
            settlement_call["args"][:3] = [portal, TOKEN, sender]
            spec["templates"][name] = template
            spec["mix"].append({"template": name, "weight": weight // per_zone[zone]})
    spec["setup"]["steps"] = steps
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
        "--nonce", type=int, required=True, help="Current protocol nonce of deployer[0]"
    )
    parser.add_argument(
        "--mode", choices=["mixed", "deposit", "withdraw"], default="mixed"
    )
    parser.add_argument("--accounts", type=int, default=1)
    parser.add_argument("--zones", type=int, default=1)
    args = parser.parse_args()
    spec = render(
        args.source.resolve(),
        args.count,
        args.nonce,
        args.mode,
        args.accounts,
        args.zones,
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(yaml.safe_dump(spec, sort_keys=False))


if __name__ == "__main__":
    main()
