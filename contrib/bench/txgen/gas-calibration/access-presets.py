"""Emit seven bounded access presets and their smoke mix as a JSON YAML map."""
from copy import deepcopy
import json
from pathlib import Path

import yaml

root = Path(__file__).parent
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
print(json.dumps(files, indent=2))
