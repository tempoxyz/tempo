#!/usr/bin/env -S uv run --no-project python
"""Compare versioned Zone Portal builds with protocol bytecode, including metadata."""

import json
import re
import subprocess
import sys
from pathlib import Path


CONTRACTS = Path(__file__).resolve().parents[1]
REPO = CONTRACTS.parents[2]
PORTAL_ADDRESS = "0x5ad1000000000000000000000000000000000000"


def embedded_runtime(bindings, constant):
    matches = re.findall(
        rf"pub const {constant}: Bytes = bytes!\((.*?)\n\);", bindings, re.DOTALL
    )
    if len(matches) != 1:
        raise ValueError(f"Expected exactly one {constant} in crates/contracts/src/zones.rs")
    literals = re.findall(r'"(0x[0-9a-fA-F]*|[0-9a-fA-F]+)"', matches[0])
    return bytes.fromhex("".join(literals).removeprefix("0x"))


def check():
    sources = list(CONTRACTS.glob("src/runtime/tempo/ZonePortalT*.sol"))
    if not sources:
        raise ValueError("No versioned Zone Portal sources found")
    versions = sorted(
        (int(re.fullmatch(r"ZonePortalT(\d+)", source.stem)[1]), source)
        for source in sources
    )
    bindings = (REPO / "crates/contracts/src/zones.rs").read_text()
    genesis = json.loads((REPO / "crates/chainspec/src/genesis/dev.json").read_text())
    genesis_timestamp = genesis.get("timestamp", 0)
    if isinstance(genesis_timestamp, str):
        genesis_timestamp = int(genesis_timestamp, 0)
    genesis_constant = "ZONE_PORTAL_RUNTIME"
    activation = genesis["config"].get("t13Time")
    if activation is not None and activation <= genesis_timestamp:
        genesis_constant = "T13_ZONE_PORTAL_RUNTIME"
    for version, source in versions:
        contract = f"{source.relative_to(CONTRACTS)}:{source.stem}"
        compiled = bytes.fromhex(
            subprocess.check_output(
                ["forge", "inspect", contract, "deployedBytecode"],
                cwd=CONTRACTS,
                text=True,
            ).strip().removeprefix("0x")
        )
        constant = f"T{version}_ZONE_PORTAL_RUNTIME"
        if compiled != embedded_runtime(bindings, constant):
            raise ValueError(f"{contract} does not match {constant} (including metadata)")
        print(f"{constant}: exact match ({len(compiled)} bytes)")
        activation = genesis["config"].get(f"t{version}Time")
        if activation is not None and activation <= genesis_timestamp:
            genesis_constant = constant

    deployed = bytes.fromhex(genesis["alloc"][PORTAL_ADDRESS]["code"].removeprefix("0x"))
    if deployed != embedded_runtime(bindings, genesis_constant):
        raise ValueError(f"Dev genesis Zone Portal does not match {genesis_constant}")
    print(f"Dev genesis Zone Portal: exact match ({genesis_constant})")


if __name__ == "__main__":
    try:
        check()
    except (ValueError, subprocess.CalledProcessError) as error:
        sys.exit(str(error))
