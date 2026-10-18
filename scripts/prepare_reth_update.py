#!/usr/bin/env python3
"""Resolve reth main once and apply only the selected Git revision pins."""

import argparse
import base64
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import subprocess
import tomllib
from urllib.parse import quote

REPOSITORY = "tempoxyz/tempo"
RETH = "paradigmxyz/reth"
URL = "https://github.com/" + RETH
SHA = re.compile(r"[0-9a-f]{40}")


def api(path):
    return json.loads(subprocess.check_output(["gh", "api", path], text=True))


def revisions(document):
    found = []
    for value in document.values():
        if not isinstance(value, dict):
            continue
        if value.get("git", "").removesuffix(".git") == URL:
            if "rev" not in value or "branch" in value or "tag" in value:
                raise ValueError("reth dependencies must use explicit revision pins")
            found.append(value["rev"])
        found.extend(revisions(value))
    return found


def resolve():
    if os.environ.get("GITHUB_REPOSITORY") != REPOSITORY:
        raise ValueError("unexpected updater repository")
    if os.environ.get("UPDATE_REQUESTED_REF", "main") not in ("", "main"):
        raise ValueError("the reth updater only selects upstream main")
    selected = api(f"repos/{RETH}/commits/main")["sha"]
    if not SHA.fullmatch(selected):
        raise ValueError("upstream must resolve to a full commit SHA")
    encoded = api(f"repos/{REPOSITORY}/contents/Cargo.toml?ref=main")
    current = set(revisions(tomllib.loads(base64.b64decode(encoded["content"]).decode())))
    if len(current) != 1:
        raise ValueError("expected one current reth revision")
    prior = api(f"repos/{RETH}/commits/{quote(current.pop(), safe='')}")["sha"]
    if not SHA.fullmatch(prior):
        raise ValueError("baseline must resolve to a full commit SHA")
    if prior == selected:
        return {"schema_version": 1, "skip": True}
    date = datetime.now(timezone.utc).date().isoformat()
    return {
        "schema_version": 1,
        "update_id": selected,
        "branch": "reth-auto-bump",
        "closed_pr_policy": "new-pr",
        "title": f"deps: update reth from main ({date})",
        "body": (f"Update reth from `{prior}` to `{selected}`.\n\n"
                 f"[Upstream commits](https://github.com/{RETH}/compare/{prior}...{selected})\n\n"
                 "Audit scope: review every upstream reth commit in this revision diff, "
                 "including compatibility migrations and invariant preservation."),
        "pins": {URL: selected},
    }


def bump(text, selected):
    pattern = re.compile(r'(?m)(^[^#\n]*?\bgit\s*=\s*["\']' + re.escape(URL) +
                         r'(?:\.git)?["\']\s*,\s*rev\s*=\s*["\'])[0-9a-f]+(["\'])')
    # Preserve comments/features and refuse unsupported manifest layouts.
    updated = pattern.sub(lambda match: match[1] + selected + match[2], text)
    pins = revisions(tomllib.loads(updated))
    if pins and any(pin != selected for pin in pins):
        raise ValueError("unsupported reth pin layout; refusing a partial bump")
    return updated


def apply(plan, root):
    if plan.get("schema_version") != 1 or set(plan.get("pins", {})) != {URL}:
        raise ValueError("unexpected update plan")
    selected = plan["pins"][URL]
    if not SHA.fullmatch(selected):
        raise ValueError("selected reth revision must be a full SHA")
    count = 0
    for path in sorted(root.rglob("Cargo.toml")):
        if path.is_symlink():
            raise ValueError("manifest symlinks are unsupported")
        original = path.read_text()
        pins = revisions(tomllib.loads(original))
        if pins:
            path.write_text(bump(original, selected))
            count += len(pins)
    if not count:
        raise ValueError("no reth revision pins found")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("operation", choices=("resolve", "apply"))
    parser.add_argument("--plan")
    args = parser.parse_args()
    if args.operation == "resolve":
        print(json.dumps(resolve()))
    else:
        if not args.plan:
            parser.error("apply requires --plan")
        apply(json.loads(Path(args.plan).read_text()), Path.cwd())


if __name__ == "__main__":
    main()
