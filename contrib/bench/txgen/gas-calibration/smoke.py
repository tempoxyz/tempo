"""Emit a smoke-only mix of the individual presets, not a pricing workload.

uv run --with pyyaml==6.0.1 python contrib/bench/txgen/gas-calibration/smoke.py
"""

from copy import deepcopy
from pathlib import Path
import sys

import yaml


class NoAliases(yaml.SafeDumper):
    def ignore_aliases(self, data):
        return True


root = Path(__file__).parent
# Txgen expands this flow-sequence placeholder before YAML parsing. Accounts are
# inherited via include, not copied into the output; quote it for this parser.
base = yaml.safe_load((root / "base.yml").read_text().replace(
    "${TXGEN_ACCOUNTS}", '"${TXGEN_ACCOUNTS}"'
))
templates = {}
for path in sorted((root.parent / "presets").glob("gas-*.yml")):
    if path.name == "gas-calibration-smoke.yml":
        continue
    preset = yaml.safe_load(path.read_text())
    # Other gas-* families use different artifacts/templates and separate mixes.
    if preset.get("include") != ["../gas-calibration/base.yml"]:
        continue
    template = deepcopy(base["merge"]["templates"]["calibration"])
    template["call"].update(preset["merge"]["templates"]["calibration"]["call"])
    templates[path.stem.replace("-", "_")] = template
assert templates, "No calibration presets found"
yaml.dump({
    "include": ["../gas-calibration/base.yml"],
    "merge": {
        "templates": templates,
        "mix": [{"template": name, "weight": 1} for name in templates],
    },
}, sys.stdout, Dumper=NoAliases, sort_keys=False)
