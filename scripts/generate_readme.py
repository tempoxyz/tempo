#!/usr/bin/env python3
"""Render README.md from the template and shared network identity files."""

import json
from pathlib import Path
from string import Template


def main() -> None:
    root = Path(__file__).resolve().parent.parent
    values = {}
    for network in ("mainnet", "testnet"):
        identity = json.loads(
            (root / f"{network}-network-identity.json").read_text(encoding="utf-8")
        )
        for field in ("from_epoch", "identity"):
            values[f"{network}_{field}"] = identity[field]

    template = Template((root / "README.md.template").read_text(encoding="utf-8"))
    (root / "README.md").write_text(template.substitute(values), encoding="utf-8")


if __name__ == "__main__":
    main()
