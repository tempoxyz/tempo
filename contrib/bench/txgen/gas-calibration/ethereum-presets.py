"""Emit JSON filename-to-YAML mapping for the pinned ordinary Ethereum fixtures.

uv run --with pyyaml==6.0.1 python ethereum-presets.py
"""

from copy import deepcopy
import argparse
import json
from pathlib import Path

import yaml

root = Path(__file__).parent
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--mainnet-sizes", action="store_true")
options = parser.parse_args()
fixture_file = "mainnet-size-fixtures.json" if options.mainnet_sizes else "ethereum-fixtures.json"
rows = json.loads((root / fixture_file).read_text())
expected_addresses = {2, 5, 8} if options.mainnet_sizes else set(range(1, 18)) | {256}
assert len(rows) == len(expected_addresses)
assert {int(row["address"], 16) for row in rows} == expected_addresses
assert len({row["name"] for row in rows}) == len(rows)
assert all(0 < len(bytes.fromhex(row["input"][2:])) <= 1024 for row in rows)
base = yaml.safe_load((root / "crypto-base.yml").read_text().replace(
    "${TXGEN_ACCOUNTS}", '"${TXGEN_ACCOUNTS}"'
))
include = ["../gas-calibration/crypto-base.yml"]


def setup(fixtures):
    return {"steps": [{"id": "fixture", "deploy": {
        "type": "eip1559", "from": {"pool": "users", "select": {"index": 0}},
        "artifact": "PrecompileCalibration", "gas_limit": 10000000,
        "constructor_args": [[row[field] for row in fixtures]
                             for field in ("address", "input", "expected")],
    }}]}


files = {}
templates = {}
for row in rows:
    args = [row["address"], row["input"]]
    files[f"precompile-{row['name']}.yml"] = yaml.safe_dump({
        "include": include,
        "merge": {"setup": setup([row]), "templates": {
            "precompile": {"call": {"args": args}},
        }},
    }, sort_keys=False)
    template = deepcopy(base["merge"]["templates"]["precompile"])
    template["call"]["args"] = args
    templates[row["name"].replace("-", "_")] = template
smoke_name = "precompile-mainnet-size-smoke.yml" if options.mainnet_sizes else "precompile-ethereum-smoke.yml"
files[smoke_name] = yaml.safe_dump({
    "include": include,
    "merge": {"setup": setup(rows), "templates": templates,
              "mix": [{"template": name, "weight": 1} for name in templates]},
}, sort_keys=False)
print(json.dumps(files, indent=2))
