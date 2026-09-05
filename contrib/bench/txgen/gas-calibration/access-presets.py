"""Emit seven bounded access presets and their smoke mix as a JSON YAML map."""
from copy import deepcopy
import argparse
import json
from pathlib import Path

import yaml

root = Path(__file__).parent
parser = argparse.ArgumentParser()
parser.add_argument("--aa-batches", action="store_true", help="Emit bounded two-call AA batches")
options = parser.parse_args()
methods = {
    "control": "control", "slot-once": "slotOnce",
    "slot-twice-warm": "slotTwiceWarm", "slot-twice-cold": "slotTwiceCold",
    "call-once": "callOnce", "call-twice-warm": "callTwiceWarm",
    "call-twice-cold": "callTwiceCold",
}
artifact = json.loads((root / "AccessCalibration.json").read_text())
assert artifact["settings"]["optimizer"]["enabled"] is False
assert set(artifact["methodIdentifiers"]) == {f"{method}()" for method in methods.values()}
base = yaml.safe_load((root / "access-base.yml").read_text().replace(
    "${TXGEN_ACCOUNTS}", '"${TXGEN_ACCOUNTS}"'
))
include = ["../gas-calibration/access-base.yml"]
files, templates = {}, {}
for name, method in methods.items():
    files[f"gas-access-{name}.yml"] = yaml.safe_dump({
        "include": include,
        "merge": {"templates": {"access": {"call": {"function": method}}}},
    }, sort_keys=False)
    template = deepcopy(base["merge"]["templates"]["access"])
    template["call"]["function"] = method
    templates[name.replace("-", "_")] = template
files["gas-access-smoke.yml"] = yaml.safe_dump({
    "include": include,
    "merge": {"templates": templates, "mix": [
        {"template": name, "weight": 1} for name in templates
    ]},
}, sort_keys=False)
if options.aa_batches:
    files, templates = {}, {}
    for name, method in {"control": "control", "slot-once": "slotOnce", "call-once": "callOnce"}.items():
        template = deepcopy(base["merge"]["templates"]["access"])
        call = template.pop("call")
        call["function"] = method
        template["calls"] = [deepcopy(call), deepcopy(call)]
        template_id = name.replace("-", "_")
        templates[template_id] = template
        files[f"gas-aa-access-{name}-2.yml"] = yaml.safe_dump({
            "include": include,
            "merge": {"templates": {"aa_access": template}, "mix": [{"template": "aa_access", "weight": 1}]},
        }, sort_keys=False)
    files["gas-aa-access-smoke.yml"] = yaml.safe_dump({
        "include": include,
        "merge": {"templates": templates, "mix": [
            {"template": name, "weight": 1} for name in templates
        ]},
    }, sort_keys=False)
print(json.dumps(files, indent=2))
