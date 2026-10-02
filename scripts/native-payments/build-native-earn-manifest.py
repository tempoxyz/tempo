#!/usr/bin/env python3
"""Reconcile a legacy Earn stack at one pre-fork block and emit its T16 manifest.

Requires `cast` for Keccak-256. The output includes eth_getProof responses as
audit material; consensus performs its own code and storage checks at T16.
"""

import argparse
import json
import subprocess
import urllib.request
from pathlib import Path

IMPLEMENTATION_SLOT = "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc"
CLONE_PREFIX = "363d3d373d3d3d363d73"
CLONE_SUFFIX = "5af43d82803e903d91602b57fd5bf3"


def rpc(url, method, params):
    payload = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).encode()
    request = urllib.request.Request(url, data=payload, headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(request, timeout=30) as response:
        result = json.load(response)
    if "error" in result:
        raise RuntimeError(f"{method}: {result['error']}")
    return result["result"]


def code_hash(code):
    if code == "0x":
        raise ValueError("expected deployed code")
    return subprocess.check_output(["cast", "keccak", code], text=True).strip()


def keccak_hex(value):
    return subprocess.check_output(["cast", "keccak", "0x" + value], text=True).strip()


def address_from_slot(value):
    return "0x" + value[-40:].lower()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rpc-url", required=True)
    parser.add_argument("--vault", required=True)
    parser.add_argument("--block", default="latest", help="pre-T16 block number or tag")
    parser.add_argument("--factory", help="predeployed NativeEarnFactory admitted at T16")
    parser.add_argument("--governor", help="engine approval and migration authority")
    parser.add_argument("--approved-engine", action="append", default=[], help="additional preapproved engine address")
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    if bool(args.factory) != bool(args.governor):
        parser.error("--factory and --governor must be supplied together")
    if args.approved_engine and not args.factory:
        parser.error("--approved-engine requires --factory")

    block = rpc(args.rpc_url, "eth_getBlockByNumber", [args.block, False])
    tag = block["number"]
    vault = args.vault.lower()
    slot = lambda address, key: rpc(args.rpc_url, "eth_getStorageAt", [address, key, tag])
    code = lambda address: rpc(args.rpc_url, "eth_getCode", [address, tag])
    vault_runtime = code(vault)
    vault_implementation = address_from_slot(slot(vault, IMPLEMENTATION_SLOT))
    engine = address_from_slot(slot(vault, "0x0"))
    asset = address_from_slot(slot(vault, "0x1"))
    earn_share = address_from_slot(slot(vault, "0x2"))
    fees = address_from_slot(slot(vault, "0x3"))
    fees_runtime = code(fees)
    raw_clone = fees_runtime.removeprefix("0x").lower()
    if len(raw_clone) != 90 or not raw_clone.startswith(CLONE_PREFIX) or not raw_clone.endswith(CLONE_SUFFIX):
        raise ValueError("EarnFees is not a canonical 45-byte EIP-1167 clone")
    fees_implementation = "0x" + raw_clone[20:60]
    if address_from_slot(slot(fees, "0x0")) != vault:
        raise ValueError("EarnFees vault binding differs from the requested vault")
    if address_from_slot(slot(fees, "0x1")) != earn_share:
        raise ValueError("EarnFees share binding differs from the vault")
    if int(slot(fees, IMPLEMENTATION_SLOT), 16) != 0:
        raise ValueError("EarnFees ERC-1967 dispatcher slot is already occupied")
    entry = {
        "vault": vault,
        "vaultRuntimeHash": code_hash(vault_runtime),
        "vaultImplementation": vault_implementation,
        "vaultImplementationHash": code_hash(code(vault_implementation)),
        "fees": fees,
        "feesRuntimeHash": code_hash(fees_runtime),
        "feesImplementation": fees_implementation,
        "feesImplementationHash": code_hash(code(fees_implementation)),
        "asset": asset,
        "earnShare": earn_share,
        "engine": engine,
        "engineHash": code_hash(code(engine)),
    }
    issuer_role = rpc(args.rpc_url, "eth_call", [{"to": earn_share, "data":
                       keccak_hex("ISSUER_ROLE()".encode().hex())[:10]}, tag])
    expected_role = keccak_hex("ISSUER_ROLE".encode().hex())
    if issuer_role.lower() != expected_role.lower():
        raise ValueError("EarnShare ISSUER_ROLE differs from the canonical TIP-20 role")
    has_role_selector = keccak_hex("hasRole(address,bytes32)".encode().hex())[:10]
    has_role_input = has_role_selector + vault[2:].zfill(64) + issuer_role[2:]
    if int(rpc(args.rpc_url, "eth_call", [{"to": earn_share, "data": has_role_input}, tag]), 16) != 1:
        raise ValueError("EarnVault lacks EarnShare ISSUER_ROLE")
    outer_role_slot = keccak_hex(vault[2:].zfill(64) + "0" * 64)
    issuer_role_slot = keccak_hex(issuer_role[2:] + outer_role_slot[2:])
    proofs = {}
    for address, slots in [
        (vault, [IMPLEMENTATION_SLOT, "0x0", "0x1", "0x2", "0x3"]),
        (fees, [IMPLEMENTATION_SLOT, "0x0", "0x1"]),
        (vault_implementation, []),
        (fees_implementation, []),
        (engine, []),
        (earn_share, [issuer_role_slot]),
    ]:
        proofs[address] = rpc(args.rpc_url, "eth_getProof", [address, slots, tag])
    result = {
        "chainId": rpc(args.rpc_url, "eth_chainId", []),
        "blockNumber": tag,
        "blockHash": block["hash"],
        "stateRoot": block["stateRoot"],
        "nativeEarnManifest": [entry],
        "earnShareIssuerRole": {
            "vault": vault,
            "earnShare": earn_share,
            "role": issuer_role,
            "slot": issuer_role_slot,
        },
        "proofs": proofs,
    }
    if args.factory:
        factory = args.factory.lower()
        governor = args.governor.lower()
        if int(factory, 16) == 0 or int(governor, 16) == 0:
            raise ValueError("factory and governor must be nonzero")
        def factory_address(signature):
            data = keccak_hex(signature.encode().hex())[:10]
            return address_from_slot(rpc(args.rpc_url, "eth_call", [{"to": factory, "data": data}, tag]))
        if factory_address("registrar()") != "0x5aea000000000000000000000000000000000000":
            raise ValueError("NativeEarnFactory registrar is not the T16 registry precompile")
        if factory_address("tip20Factory()") != "0x20fc000000000000000000000000000000000000":
            raise ValueError("NativeEarnFactory is not bound to the canonical TIP20 factory")
        factory_vault_impl = factory_address("earnVaultImplementation()")
        factory_fees_impl = factory_address("earnFeesImplementation()")
        approved = sorted(set([engine] + [address.lower() for address in args.approved_engine]))
        result["nativeEarnFactory"] = {
            "address": factory,
            "codeHash": code_hash(code(factory)),
            "governor": governor,
            "vaultRuntimeHash": entry["vaultRuntimeHash"],
            "vaultImplementation": factory_vault_impl,
            "vaultImplementationHash": code_hash(code(factory_vault_impl)),
            "feesImplementation": factory_fees_impl,
            "feesImplementationHash": code_hash(code(factory_fees_impl)),
            "approvedEngines": [
                {"address": address, "codeHash": code_hash(code(address))} for address in approved
            ],
        }
        for address in [factory, factory_vault_impl, factory_fees_impl] + approved:
            proofs[address] = rpc(args.rpc_url, "eth_getProof", [address, [], tag])
    Path(args.output).write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps({"blockNumber": tag, "vault": vault, "fees": fees, "manifestEntries": 1}))


if __name__ == "__main__":
    main()
