"""Emit JSON filename-to-YAML mapping for the pinned ordinary Ethereum fixtures.

uv run --with pyyaml==6.0.1 python ethereum-presets.py
"""

from copy import deepcopy
import json
from pathlib import Path

import yaml

root = Path(__file__).parent
rows = json.loads((root / "ethereum-fixtures.json").read_text())
assert len(rows) == 18
assert {int(row["address"], 16) for row in rows} == set(range(1, 18)) | {256}
assert len({row["name"] for row in rows}) == 18
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
files["precompile-ethereum-smoke.yml"] = yaml.safe_dump({
    "include": include,
    "merge": {"setup": setup(rows), "templates": templates,
              "mix": [{"template": name, "weight": 1} for name in templates]},
}, sort_keys=False)
print(json.dumps(files, indent=2))
