#!/usr/bin/env python3
"""Validate every submitted batch intersecting a measured Zone block range."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import subprocess
import tempfile
import time


def validate_range(first, last, output, generate):
    if first < 1 or last < first:
        raise ValueError("requires a nonempty range after genesis")
    batches = []
    cursor = first
    with tempfile.TemporaryDirectory(prefix="zones-spf-") as directory:
        witness = Path(directory) / "witness.json"
        while cursor <= last:
            witness.unlink(missing_ok=True)
            generate(cursor, witness)
            blocks = json.loads(witness.read_text())["zoneBlocks"]
            numbers = [block["number"] for block in blocks]
            if (not numbers or any(type(n) is not int for n in numbers)
                    or numbers != list(range(numbers[0], numbers[-1] + 1))
                    or not numbers[0] <= cursor <= numbers[-1]
                    or (batches and numbers[0] != cursor)):
                raise ValueError(f"validated batch does not cover the next block {cursor} contiguously")
            batches.append({"from_block": numbers[0], "to_block": numbers[-1]})
            print(f"Validated submitted batch {numbers[0]}..{numbers[-1]}", flush=True)
            cursor = numbers[-1] + 1
    result = {"status": "complete", "from_block": first, "to_block": last,
              "batches": batches}
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(result, indent=2) + "\n")
    return result


def wait_for_submission(last, portal, tempo_rpc, zone_rpc, timeout):
    deadline = time.monotonic() + timeout
    while True:
        block_hash = subprocess.check_output([
            "cast", "call", portal, "blockHash()(bytes32)", "--rpc-url", tempo_rpc],
            text=True, timeout=30).strip()
        number = subprocess.check_output([
            "cast", "block", block_hash, "--field", "number", "--rpc-url", zone_rpc],
            text=True, timeout=30).strip()
        committed = int(number, 16) if number.startswith("0x") else int(number)
        if committed >= last:
            return
        if time.monotonic() >= deadline:
            raise TimeoutError(f"Zone block {last} was not submitted; portal is at {committed}")
        time.sleep(1)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--spf-bin", required=True)
    parser.add_argument("--tempo-rpc-url", required=True)
    parser.add_argument("--zone-rpc-url", required=True)
    parser.add_argument("--portal", required=True)
    parser.add_argument("--chain", required=True)
    parser.add_argument("--from-block", type=int, required=True)
    parser.add_argument("--to-block", type=int, required=True)
    parser.add_argument("--output", type=Path, required=True, help="Batch coverage manifest, not a single witness")
    parser.add_argument("--wait-timeout", type=int, default=120)
    args = parser.parse_args()
    wait_for_submission(args.to_block, args.portal, args.tempo_rpc_url, args.zone_rpc_url, args.wait_timeout)

    def generate(block, output):
        subprocess.run([args.spf_bin, "generate-input", "--tempo-rpc-url", args.tempo_rpc_url,
                        "--zone-rpc-url", args.zone_rpc_url, "--chain", args.chain,
                        "--block", str(block), "--output", str(output)], check=True)

    validate_range(args.from_block, args.to_block, args.output, generate)


if __name__ == "__main__":
    main()
