"""Emit a JSON filename-to-YAML map of public-read presets and their smoke mix.

uv run --with pyyaml==6.0.1 python native-presets.py
All selectors below were checked against T10 dispatch gates, not only ABI names.
"""

from copy import deepcopy
import json
from pathlib import Path
import re

import yaml

root = Path(__file__).parent
contracts = root.parents[3] / "crates/contracts/src/precompiles"
registry = (contracts / "mod.rs").read_text()
declarations = "\n".join(path.read_text() for path in contracts.glob("*.rs"))
addresses = dict(re.findall(
    r'pub const (\w+_ADDRESS): Address\s*=\s*address!\("0x([0-9a-fA-F]+)"\)', declarations
))
symbols = set(re.findall(r'\((\w+_ADDRESS), TempoHardfork::', registry))
symbols.remove("SIGNATURE_VERIFIER_ADDRESS")
expected = {addresses[symbol].lower() for symbol in symbols}
expected.add("20c0000000000000000000000000000000000000")
used = set(re.findall(r'hex"([0-9a-f]{40})"', (root / "NativeReadCalibration.sol").read_text()))
assert used == expected, "Native fixture addresses must match the source registry"
base = yaml.safe_load((root / "native-base.yml").read_text().replace(
    "${TXGEN_ACCOUNTS}", '"${TXGEN_ACCOUNTS}"'
))
methods = {
    "tip20": "tokenBalance", "factory": "factoryTokenCheck",
    "policy": "policyCounter", "fee": "feeToken", "dex": "dexBalance",
    "nonce": "nonceValue", "validator-v1": "legacyValidatorCount",
    "validator-v2": "validatorCount", "keychain": "adminKeyCheck",
    "address": "resolveRecipient", "channel": "channelCredits",
    "guard": "guardBalance", "credits": "storageCredits",
    "committee": "committee", "zone": "zoneOwner",
}
artifact = json.loads((root / "NativeReadCalibration.json").read_text())
assert {f"{name}()" for name in methods.values()} == set(artifact["methodIdentifiers"])
include = ["../gas-calibration/native-base.yml"]
files = {}
templates = {}
for family, method in methods.items():
    files[f"native-read-{family}.yml"] = yaml.safe_dump({
        "include": include,
        "merge": {"templates": {"native_read": {"call": {"function": method}}}},
    }, sort_keys=False)
    template = deepcopy(base["merge"]["templates"]["native_read"])
    template["call"]["function"] = method
    templates[family.replace("-", "_")] = template
files["native-read-smoke.yml"] = yaml.safe_dump({
    "include": include,
    "merge": {"templates": templates, "mix": [
        {"template": name, "weight": 1} for name in templates
    ]},
}, sort_keys=False)
print(json.dumps(files, indent=2))
