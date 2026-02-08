#!/usr/bin/env python3
"""Determine which workspace crates need testing based on changed files.

Uses `cargo metadata` to build a reverse-dependency graph, then computes the
transitive closure of all crates affected by the changed files. Outputs
nextest package filter flags to stdout.

Output (stdout, one of):
  --workspace                          run all tests
  -p crate-a -p crate-b ...           run only affected crates
  (empty)                              no tests needed

Diagnostics go to stderr.
"""

import json
import os
import subprocess
import sys
from collections import defaultdict

GLOBAL_PATHS = [
    "Cargo.toml",
    "Cargo.lock",
    "rust-toolchain",
    "rust-toolchain.toml",
    ".cargo/",
    ".github/workflows/test.yml",
    ".github/scripts/",
    "rustfmt.toml",
    "clippy.toml",
    "deny.toml",
]


def log(msg: str) -> None:
    print(msg, file=sys.stderr)


def get_changed_files(base_sha: str) -> list[str]:
    result = subprocess.run(
        ["git", "diff", "--name-only", f"{base_sha}...HEAD"],
        capture_output=True,
        text=True,
        check=True,
    )
    return [f for f in result.stdout.strip().splitlines() if f]


def is_global_change(changed_files: list[str]) -> bool:
    for f in changed_files:
        for g in GLOBAL_PATHS:
            if g.endswith("/"):
                if f.startswith(g):
                    return True
            elif f == g:
                return True
    return False


def load_workspace_metadata() -> dict:
    result = subprocess.run(
        ["cargo", "metadata", "--format-version=1", "--no-deps"],
        capture_output=True,
        text=True,
        check=True,
    )
    return json.loads(result.stdout)


def build_crate_map(metadata: dict) -> tuple[dict[str, str], dict[str, str]]:
    """Returns (dir_to_name, name_to_dir) mappings for workspace crates."""
    workspace_members = set(metadata.get("workspace_members", []))
    workspace_root = metadata["workspace_root"]
    dir_to_name: dict[str, str] = {}
    name_to_dir: dict[str, str] = {}

    for pkg in metadata["packages"]:
        if pkg["id"] not in workspace_members:
            continue
        manifest = pkg["manifest_path"]
        crate_dir = os.path.relpath(os.path.dirname(manifest), workspace_root)
        dir_to_name[crate_dir] = pkg["name"]
        name_to_dir[pkg["name"]] = crate_dir

    return dir_to_name, name_to_dir


def build_reverse_dep_graph(metadata: dict) -> dict[str, set[str]]:
    """Build a mapping: crate_name -> set of crates that depend on it."""
    workspace_members = set(metadata.get("workspace_members", []))
    workspace_names = {
        pkg["name"]
        for pkg in metadata["packages"]
        if pkg["id"] in workspace_members
    }

    reverse: dict[str, set[str]] = defaultdict(set)
    for pkg in metadata["packages"]:
        if pkg["id"] not in workspace_members:
            continue
        for dep in pkg["dependencies"]:
            if dep.get("source") is None and dep["name"] in workspace_names:
                reverse[dep["name"]].add(pkg["name"])

    return reverse


def transitive_dependents(
    seeds: set[str], reverse_graph: dict[str, set[str]]
) -> set[str]:
    """Compute transitive closure of dependents."""
    result: set[str] = set()
    queue = list(seeds)
    while queue:
        crate = queue.pop()
        if crate in result:
            continue
        result.add(crate)
        for dependent in reverse_graph.get(crate, set()):
            if dependent not in result:
                queue.append(dependent)
    return result


def changed_files_to_crates(
    changed_files: list[str], dir_to_name: dict[str, str]
) -> tuple[set[str], list[str]]:
    """Map changed files to the workspace crates they belong to.

    Returns (matched_crates, unmapped_files).
    """
    crates: set[str] = set()
    unmapped: list[str] = []
    sorted_dirs = sorted(dir_to_name.keys(), key=len, reverse=True)

    for f in changed_files:
        matched = False
        for crate_dir in sorted_dirs:
            if f.startswith(crate_dir + "/") or f == crate_dir:
                crates.add(dir_to_name[crate_dir])
                matched = True
                break
        if not matched:
            unmapped.append(f)

    return crates, unmapped


def main() -> None:
    base_sha = os.environ.get("BASE_SHA", "")
    event_name = os.environ.get("EVENT_NAME", "pull_request")

    if event_name != "pull_request":
        log("Non-PR event, running full workspace")
        print("--workspace")
        return

    if not base_sha:
        log("No BASE_SHA provided, running full workspace")
        print("--workspace")
        return

    try:
        changed_files = get_changed_files(base_sha)
    except subprocess.CalledProcessError as e:
        log(f"git diff failed ({e}), running full workspace")
        print("--workspace")
        return

    if not changed_files:
        log("No changed files detected")
        print("")
        return

    log(f"Changed files: {len(changed_files)}")
    for f in changed_files:
        log(f"  {f}")

    if is_global_change(changed_files):
        log("Global file changed, running full workspace")
        print("--workspace")
        return

    metadata = load_workspace_metadata()
    dir_to_name, _ = build_crate_map(metadata)
    reverse_graph = build_reverse_dep_graph(metadata)

    directly_changed, unmapped = changed_files_to_crates(
        changed_files, dir_to_name
    )

    if unmapped:
        non_ignorable = [
            f
            for f in unmapped
            if not any(
                f.endswith(ext)
                for ext in (".md", ".txt", ".png", ".jpg", ".svg", ".gif")
            )
        ]
        if non_ignorable:
            log(
                f"Unmapped non-doc files changed ({non_ignorable}), "
                "running full workspace"
            )
            print("--workspace")
            return
        log(f"Unmapped files are all docs/assets, ignoring: {unmapped}")

    if not directly_changed:
        log("No workspace crates affected")
        print("")
        return

    all_affected = transitive_dependents(directly_changed, reverse_graph)

    log(
        f"Affected: {len(all_affected)} crates "
        f"(from {len(directly_changed)} changed: "
        f"{', '.join(sorted(directly_changed))})"
    )

    flags = " ".join(f"-p {name}" for name in sorted(all_affected))
    print(flags)


if __name__ == "__main__":
    main()
