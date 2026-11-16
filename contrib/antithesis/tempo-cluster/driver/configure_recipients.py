"""Use genesis BIP39 recipients instead of state-bloat's fast address derivation."""
from pathlib import Path
import sys
import yaml

path = Path(sys.argv[1])
spec = yaml.safe_load(path.read_text())
# Keep templates and mix intact, replacing only the destination-address derivation.
spec["address_pools"]["existing_recipients"] = {
    "mnemonic": "test test test test test test test test test test test junk",
    "range": [16, 64],
}
path.write_text(yaml.safe_dump(spec, sort_keys=False))
