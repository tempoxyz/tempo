"""Extract two ordinary fixtures from the pinned revm-precompile 42.0.1 crate.

Prints JSON only; does not benchmark or send transactions.
Usage: uv run python crypto-fixtures.py /path/to/revm-precompile-42.0.1
"""

import hashlib
import json
from pathlib import Path
import re
import sys
import tomllib

root = Path(sys.argv[1])
assert tomllib.loads((root / "Cargo.toml").read_text())["package"]["version"] == "42.0.1"
kzg = (root / "src/kzg_point_evaluation.rs").read_text().split("fn basic_test()", 1)[1].split("#[test]", 1)[0]


def extract(name):
    return bytes.fromhex(re.search(rf'let {name} = hex!\("([0-9a-f]+)"\)', kzg)[1])


commitment = extract("commitment")
versioned_hash = b"\x01" + hashlib.sha256(commitment).digest()[1:]
kzg_input = versioned_hash + extract("z") + extract("y") + commitment + extract("proof")
kzg_output = extract("expected_output")
blake_bench = (root / "bench/blake2.rs").read_text()
# Select the standard twelve-round abc vector, never the extended-round benches.
blake_input = bytes.fromhex(re.search(r'hex!\("(0000000c[0-9a-f]+)"\)', blake_bench)[1])
blake_output = hashlib.blake2b(b"abc").digest()
assert len(kzg_input) == 192 and len(kzg_output) == 64
assert len(blake_input) == 213 and int.from_bytes(blake_input[:4], "big") == 12
fixtures = [
    {
        "name": "kzg-point-evaluation", "address": f"0x{10:040x}",
        "input": "0x" + kzg_input.hex(), "expected": "0x" + kzg_output.hex(),
        "source": "https://docs.rs/crate/revm-precompile/42.0.1/source/src/kzg_point_evaluation.rs",
        "case": "basic_test; upstream c-kzg correct_proof_4_4",
    },
    {
        "name": "blake2b-12", "address": f"0x{9:040x}",
        "input": "0x" + blake_input.hex(), "expected": "0x" + blake_output.hex(),
        "source": "https://docs.rs/crate/revm-precompile/42.0.1/source/bench/blake2.rs",
        "case": "standard 12-round abc input; expected digest independently computed with hashlib.blake2b",
    },
]
print(json.dumps(fixtures, indent=2))
