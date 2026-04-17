#!/usr/bin/env python3
"""Shared Python utilities for the publish pipeline."""

import re
import sys
from pathlib import Path


def _tomllib():
    try:
        import tomllib

        return tomllib
    except ModuleNotFoundError:
        import tomli

        return tomli


GROUP_DIRS = {
    "alloy": {"contracts", "primitives", "alloy"},
    "revm": {"chainspec", "precompiles-macros", "precompiles", "revm"},
}

PUBLISH_GROUPS = {
    group: {f"tempo-{d}" for d in dirs} for group, dirs in GROUP_DIRS.items()
}


# File patterns (beyond crate dirs) that trigger a group's publish pipeline.
_SHARED_PATHS = [
    r"^scripts/publish/",
    r"^scripts/sanitize_toml\.py$",
    r"^Cargo\.toml$",
]
GROUP_EXTRA_PATHS = {
    "alloy": _SHARED_PATHS + [r"^scripts/sanitize_source\.py$"],
    "revm": _SHARED_PATHS,
}

EXTRA_WORKSPACE_DEPS = {
    "alloy": [],
    "revm": ["contracts", "primitives"],
}


def group_config(group):
    """Print shell variable assignments for the given publish group."""
    if group not in GROUP_DIRS:
        print(
            f"Unknown group '{group}', expected: {', '.join(GROUP_DIRS)}",
            file=sys.stderr,
        )
        sys.exit(1)
    dirs = sorted(GROUP_DIRS[group])
    crate_names = sorted(PUBLISH_GROUPS[group])
    all_crate_names = sorted(c for g in PUBLISH_GROUPS.values() for c in g)
    extra = EXTRA_WORKSPACE_DEPS.get(group, [])
    print(f"CRATE_DIRS=({' '.join(dirs)})")
    print(f"PUBLISH_CRATE_NAMES_CSV={','.join(crate_names)}")
    print(f"ALL_PUBLISHED={','.join(all_crate_names)}")
    print(f"EXTRA_WORKSPACE_DEPS=({' '.join(extra)})")


def detect_groups(files_text):
    """Print group=true/false lines for each group with changed files.

    Reads a newline-separated file list (e.g. from git diff --name-only).
    Checks crate dirs and extra path patterns.
    Exits 1 if no published group is affected.
    """
    files = files_text.strip().splitlines()

    results = {}
    for group, dirs in GROUP_DIRS.items():
        crate_pat = re.compile(rf"^crates/({'|'.join(re.escape(d) for d in dirs)})/")
        extra_pats = GROUP_EXTRA_PATHS.get(group, [])
        results[group] = any(crate_pat.match(f) for f in files) or any(
            re.search(p, f) for p in extra_pats for f in files
        )

    if not any(results.values()):
        print("No published crate groups detected.", file=sys.stderr)
        sys.exit(1)

    for group, matched in sorted(results.items()):
        print(f"{group}={'true' if matched else 'false'}")


def get_internal_path_deps(ws_toml_path, keep_csv):
    """Print internal path-only deps not in the keep set."""
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
    from sanitize_toml import parse_workspace_deps

    _, _, ws_path_deps, _, _, _ = parse_workspace_deps(ws_toml_path)
    keep = {entry for entry in keep_csv.split(",") if entry}
    for dep in sorted(ws_path_deps - keep):
        print(dep)


def release_type_for_crate(crate_name, repo_root):
    """Print the highest pending changelog bump level for a crate."""
    repo_root = Path(repo_root)
    config_path = repo_root / ".changelog" / "config.toml"

    bump_rank = {"patch": 0, "minor": 1, "major": 2}

    fixed_groups = []
    if config_path.exists():
        with config_path.open("rb") as fh:
            config = _tomllib().load(fh)
        for group in config.get("fixed", []):
            members = group.get("members", [])
            if isinstance(members, list):
                fixed_groups.append(set(members))

    explicit = {}
    for changelog in sorted((repo_root / ".changelog").glob("*.md")):
        lines = changelog.read_text(encoding="utf-8").splitlines()
        if not lines or lines[0].strip() != "---":
            continue
        try:
            end = next(
                i for i, line in enumerate(lines[1:], start=1) if line.strip() == "---"
            )
        except StopIteration:
            continue

        for line in lines[1:end]:
            match = re.match(
                r'^\s*"?([A-Za-z0-9_-]+)"?\s*:\s*(patch|minor|major)\s*$', line
            )
            if not match:
                continue
            name, bump = match.groups()
            current = explicit.get(name)
            if current is None or bump_rank[bump] > bump_rank[current]:
                explicit[name] = bump

    selected = explicit.get(crate_name)
    for members in fixed_groups:
        if crate_name not in members:
            continue
        group_bump = None
        for member in members:
            bump = explicit.get(member)
            if bump is None:
                continue
            if group_bump is None or bump_rank[bump] > bump_rank[group_bump]:
                group_bump = bump
        if group_bump is not None:
            selected = (
                group_bump
                if selected is None or bump_rank[group_bump] > bump_rank[selected]
                else selected
            )

    print(selected or "")


def _fail(msg):
    print(f"  \033[1;31m✗\033[0m {msg}", file=sys.stderr)
    sys.exit(1)


def write_workspace_manifest(out_path, members_csv, patches_csv=""):
    """Generate a minimal workspace Cargo.toml."""
    members = [m for m in members_csv.split(",") if m]
    rendered = ", ".join(f'"{m}"' for m in members)
    lines = [f'[workspace]\nmembers = [{rendered}]\nresolver = "3"\n']
    if patches_csv:
        lines.append("[patch.crates-io]")
        for patch in patches_csv.split(","):
            name, path = patch.split("=", 1)
            lines.append(f'{name} = {{ path = "{path}" }}')
    Path(out_path).write_text("\n".join(lines) + "\n", encoding="utf-8")


def validate_no_reth_or_internal(internal_deps_newline, *toml_paths):
    """Fail if any toml still references reth-* or internal path deps."""
    internal = {d for d in internal_deps_newline.split() if d}
    for toml_path in toml_paths:
        text = Path(toml_path).read_text(encoding="utf-8")
        name = Path(toml_path).parent.name
        if re.search(r"^\s*reth-", text, re.M):
            _fail(f"reth dependency still in {name}/Cargo.toml")
        for dep in sorted(internal):
            if re.search(rf"^\s*{re.escape(dep)}[\s.=]", text, re.M):
                _fail(f"Internal dep '{dep}' still in {name}/Cargo.toml")


def assert_no_features(toml_path, *features):
    """Fail if any listed feature is still defined in the manifest."""
    text = Path(toml_path).read_text(encoding="utf-8")
    name = Path(toml_path).parent.name
    for feat in features:
        if re.search(rf"^\s*{re.escape(feat)}\s*=", text, re.M):
            _fail(f"Feature '{feat}' still defined in {name}/Cargo.toml")


def assert_no_dep(toml_path, dep):
    """Fail if the dependency is still present in the manifest."""
    text = Path(toml_path).read_text(encoding="utf-8")
    name = Path(toml_path).parent.name
    if re.search(rf"^\s*{re.escape(dep)}[\s.=]", text, re.M):
        _fail(f"Dependency '{dep}' still in {name}/Cargo.toml")


def assert_no_source_refs(dir_path, *patterns):
    """Fail if any pattern is found in .rs files under dir."""
    name = Path(dir_path).name
    for pat in patterns:
        for f in Path(dir_path, "src").rglob("*.rs"):
            if pat in f.read_text(encoding="utf-8"):
                _fail(f"Forbidden pattern '{pat}' still in {name} source")


def validate_resolved(*toml_paths):
    """Fail if any manifest has unresolved workspace/path/git deps."""
    checks = [
        ("workspace = true", "Unresolved 'workspace = true'"),
        ("path = ", "Unresolved 'path = ' dep"),
        ("git = ", "Unresolved 'git = ' dep"),
    ]
    for toml_path in toml_paths:
        text = Path(toml_path).read_text(encoding="utf-8")
        name = Path(toml_path).parent.name
        for needle, label in checks:
            if needle in text:
                _fail(f"{label} in {name}/Cargo.toml")


def filter_changelogs(group):
    """Keep only changelog entries targeting a specific publish group."""
    if group not in PUBLISH_GROUPS:
        print(
            f"Unknown group '{group}', expected: {', '.join(PUBLISH_GROUPS)}",
            file=sys.stderr,
        )
        sys.exit(1)

    targets = PUBLISH_GROUPS[group]

    for path in Path(".changelog").glob("*.md"):
        text = path.read_text(encoding="utf-8")
        lines = text.splitlines(keepends=True)

        if not lines or lines[0].strip() != "---":
            print(f"Removing {path} (missing changelog frontmatter)")
            path.unlink()
            continue

        end = next(
            (i for i, line in enumerate(lines[1:], start=1) if line.strip() == "---"),
            None,
        )
        if end is None:
            print(f"Removing {path} (unterminated changelog frontmatter)")
            path.unlink()
            continue

        kept = []
        for line in lines[1:end]:
            match = re.match(r'^\s*"?([A-Za-z0-9_-]+)"?\s*:', line)
            if match and match.group(1) in targets:
                kept.append(line if line.endswith("\n") else f"{line}\n")

        if not kept:
            print(f"Removing {path} (does not target {group} crates)")
            path.unlink()
            continue

        body = "".join(lines[end + 1 :])
        path.write_text("---\n" + "".join(kept) + "---\n" + body, encoding="utf-8")


COMMANDS = {
    "internal_path_deps": lambda: get_internal_path_deps(sys.argv[2], sys.argv[3]),
    "release_type": lambda: release_type_for_crate(sys.argv[2], sys.argv[3]),
    "group_config": lambda: group_config(sys.argv[2]),
    "detect_groups": lambda: detect_groups(sys.stdin.read()),
    "filter_changelogs": lambda: filter_changelogs(sys.argv[2]),
    "write_workspace_manifest": lambda: write_workspace_manifest(
        sys.argv[2], sys.argv[3], sys.argv[4] if len(sys.argv) > 4 else ""
    ),
    "validate_no_reth_or_internal": lambda: validate_no_reth_or_internal(
        sys.argv[2], *sys.argv[3:]
    ),
    "assert_no_features": lambda: assert_no_features(sys.argv[2], *sys.argv[3:]),
    "assert_no_dep": lambda: assert_no_dep(sys.argv[2], sys.argv[3]),
    "assert_no_source_refs": lambda: assert_no_source_refs(sys.argv[2], *sys.argv[3:]),
    "validate_resolved": lambda: validate_resolved(*sys.argv[2:]),
}

if __name__ == "__main__":
    cmd = sys.argv[1] if len(sys.argv) > 1 else None
    if cmd not in COMMANDS:
        print(f"Usage: {sys.argv[0]} <{'|'.join(COMMANDS)}>", file=sys.stderr)
        sys.exit(1)
    COMMANDS[cmd]()
