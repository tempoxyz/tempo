#!/usr/bin/env python3
"""Print Cargo overrides for a local checkout of the benchmark's pinned Reth."""
import argparse
import json
from pathlib import Path
import subprocess
import tomllib

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("checkout", type=Path)
args = parser.parse_args()
root = args.checkout.resolve(strict=True)
expected = json.loads(Path(__file__).with_name("manifest.json").read_text())["reth"]["base"]
actual = subprocess.check_output(["git", "-C", str(root), "rev-parse", "HEAD"], text=True).strip()
if actual != expected:
    parser.error(f"expected Reth {expected}, found {actual}")
print('[patch."https://github.com/paradigmxyz/reth"]')
files = subprocess.check_output(["git", "-C", str(root), "ls-files", "*Cargo.toml"], text=True)
for name in sorted(files.splitlines()):
    if name.startswith("docs/"):
        continue  # Standalone documentation snippets are not workspace packages.
    path = root / name
    package = tomllib.loads(path.read_text()).get("package", {})
    if package.get("name"):
        print(f'{json.dumps(package["name"])} = {{ path = {json.dumps(str(path.parent))} }}')
