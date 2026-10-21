"""Render README.md from its template and the published network identities."""

import argparse
import difflib
import json
import sys
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="fail if README.md is stale")
    args = parser.parse_args()

    root = Path(__file__).resolve().parents[1]
    rendered = (root / "README.md.in").read_text(encoding="utf-8")
    for network, name in [("mainnet", "Mainnet"), ("testnet", "Testnet (Moderato)")]:
        filename = f"{network}-network-identity.json"
        identity = json.loads((root / filename).read_text(encoding="utf-8"))
        placeholder = "{{" + network.upper() + "_NETWORK_IDENTITY}}"
        if rendered.count(placeholder) != 1:
            parser.error(f"README.md.in must contain exactly one {placeholder}")
        block = (
            f"**[{name}](./{filename}) — from epoch {identity['from_epoch']}**\n\n"
            f"```text\n{identity['identity']}\n```"
        )
        rendered = rendered.replace(placeholder, block)

    readme = root / "README.md"
    if args.check:
        current = readme.read_text(encoding="utf-8") if readme.exists() else ""
        if current != rendered:
            sys.stdout.writelines(
                difflib.unified_diff(
                    current.splitlines(keepends=True),
                    rendered.splitlines(keepends=True),
                    fromfile="README.md",
                    tofile="generated README.md",
                )
            )
            print("README.md is stale; run: uv run python scripts/generate-readme.py", file=sys.stderr)
            return 1
        return 0

    readme.write_text(rendered, encoding="utf-8")
    return 0


if __name__ == "__main__":
    sys.exit(main())
