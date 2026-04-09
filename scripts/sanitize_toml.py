#!/usr/bin/env python3
"""Sanitize Cargo.toml files for publishing outside the workspace."""
import re
import sys
from pathlib import Path


# ── Depth-aware line skipping ─────────────────────────────────────────────────

def _strip_comment(line):
    """Return line with trailing # comments removed (string-aware)."""
    in_str = False
    for i, c in enumerate(line):
        if c == '"' and (i == 0 or line[i - 1] != '\\'):
            in_str = not in_str
        elif c == '#' and not in_str:
            return line[:i]
    return line


def _depth_delta(line):
    """Return (brace_delta, bracket_delta) for a line, ignoring comments."""
    s = _strip_comment(line)
    return (s.count('{') - s.count('}'), s.count('[') - s.count(']'))


def strip_dep_lines(text, should_strip, removed=None):
    """Remove dependency entries (single- or multi-line) where should_strip(name) is True.

    Uses brace/bracket depth tracking to correctly handle multi-line deps like:
        foo = { version = "1", features = [
          "a",
        ] }

    Also handles dot-notation deps like:
        foo.workspace = true

    If `removed` is a set, stripped dep names are added to it for downstream use.
    """
    lines = text.split('\n')
    result = []
    skip = False
    brace_depth = 0
    bracket_depth = 0
    for line in lines:
        if not skip:
            # Match inline table: name = { ... } or name = "..."
            name_m = re.match(r'^([a-zA-Z0-9_-]+)\s*=\s', line)
            # Match dot-notation: name.key = value
            if not name_m:
                name_m = re.match(r'^([a-zA-Z0-9_-]+)\.', line)
            if name_m and should_strip(name_m.group(1)):
                if removed is not None:
                    removed.add(name_m.group(1))
                bd, kd = _depth_delta(line)
                brace_depth = bd
                bracket_depth = kd
                if brace_depth <= 0 and bracket_depth <= 0:
                    continue
                skip = True
                continue
            result.append(line)
        else:
            bd, kd = _depth_delta(line)
            brace_depth += bd
            bracket_depth += kd
            if brace_depth <= 0 and bracket_depth <= 0:
                skip = False
            continue
    return '\n'.join(result)


def strip_orphaned_feature_entries(text, removed_deps):
    """Remove feature array entries that reference removed dependencies.

    Strips entries like:
        "dep-name?/feature"   (optional dep feature activation)
        "dep-name/feature"    (dep feature activation)
        "dep:dep-name"        (dep activation)

    from [features] arrays. This prevents orphaned references to deps that
    were removed from [dependencies] or [dev-dependencies].
    """
    for dep in sorted(removed_deps):
        escaped = re.escape(dep)
        # "dep?/feature" and "dep/feature" entries (with optional trailing comma)
        text = re.sub(rf'\s*"{escaped}\??/[^"]*",?\n', '\n', text)
        # "dep:dep" entries
        text = re.sub(rf'\s*"dep:{escaped}",?\n', '\n', text)
    return text


def strip_feature_blocks(text, block_names):
    """Remove multi-line feature block definitions for the given feature names.

    Uses bracket depth tracking to handle nested arrays.
    """
    names = set(block_names)
    lines = text.split('\n')
    result = []
    skip = False
    bracket_depth = 0
    for line in lines:
        if not skip:
            m = re.match(r'^([a-zA-Z0-9_-]+)\s*=\s*\[', line)
            if m and m.group(1) in names:
                _, kd = _depth_delta(line)
                bracket_depth = kd
                if bracket_depth <= 0:
                    continue
                skip = True
                continue
            result.append(line)
        else:
            _, kd = _depth_delta(line)
            bracket_depth += kd
            if bracket_depth <= 0:
                skip = False
            continue
    return '\n'.join(result)


def strip_feature_array_entries(text, entries_to_remove):
    """Remove specific entries from [features] arrays.

    entries_to_remove: set of unquoted entry strings (e.g. {'reth', 'rand/serde'})
    """
    lines = text.split('\n')
    result = []
    in_features = False
    for line in lines:
        # Detect [features] section
        if re.match(r'^\[features\]', line):
            in_features = True
            result.append(line)
            continue
        if in_features and re.match(r'^\[', line):
            in_features = False

        if in_features:
            modified = line
            for entry in entries_to_remove:
                escaped = re.escape(entry)
                # Remove "entry", or "entry" (with comma handling)
                modified = re.sub(rf'\s*"{escaped}"\s*,', '', modified)
                modified = re.sub(rf',\s*"{escaped}"', '', modified)
                modified = re.sub(rf'"{escaped}"', '', modified)
            # Clean up artifacts: empty array elements, double commas
            modified = re.sub(r',\s*\]', ']', modified)  # trailing comma before ]
            modified = re.sub(r'\[\s*,', '[', modified)   # leading comma after [
            modified = re.sub(r',\s*,', ',', modified)    # double commas
            # Skip lines that became empty array entries (just whitespace/tabs)
            if modified.strip() == '' and line.strip() != '':
                continue
            result.append(modified)
        else:
            result.append(line)
    return '\n'.join(result)


# ── Workspace parsing helpers ─────────────────────────────────────────────────

def parse_workspace_package(ws_toml_path):
    """Parse [workspace.package] metadata from a workspace Cargo.toml."""
    ws_text = Path(ws_toml_path).read_text(encoding='utf-8')
    meta = {}
    for key in ('version', 'edition', 'rust-version', 'license'):
        m = re.search(rf'^{re.escape(key)}\s*=\s*"([^"]+)"', ws_text, re.MULTILINE)
        if m:
            meta[key] = m.group(1)
    return meta


def parse_workspace_deps(ws_toml_path):
    """Parse [workspace.dependencies] into structured data.

    Returns (ws_deps, ws_no_default, ws_path_deps, ws_pkg_version, ws_git_deps) where:
    - ws_deps: {name: version} for all deps with a version
    - ws_no_default: set of dep names with default-features = false
    - ws_path_deps: set of dep names that use path = "..."
    - ws_pkg_version: the workspace package version string
    - ws_git_deps: {name: {"git": url, ...}} for deps using git sources
    """
    ws_text = Path(ws_toml_path).read_text(encoding='utf-8')

    # Workspace package version
    ws_pkg_version = None
    m = re.search(
        r'^\[workspace\.package\]\s*\n(?:.*\n)*?version\s*=\s*"([^"]+)"',
        ws_text, re.MULTILINE,
    )
    if m:
        ws_pkg_version = m.group(1)

    # Extract [workspace.dependencies] section as individual dep blocks
    ws_deps = {}
    ws_no_default = set()
    ws_path_deps = set()
    ws_git_deps = {}

    # Match inline table deps: name = { ... } (possibly multi-line)
    # Use depth-aware extraction
    in_ws_deps = False
    lines = ws_text.split('\n')
    i = 0
    while i < len(lines):
        line = lines[i]
        if re.match(r'^\[workspace\.dependencies\]', line):
            in_ws_deps = True
            i += 1
            continue
        if in_ws_deps and re.match(r'^\[', line):
            break
        if not in_ws_deps:
            i += 1
            continue

        # Skip comments and blank lines
        stripped = line.strip()
        if not stripped or stripped.startswith('#'):
            i += 1
            continue

        # Try to match a dep start
        name_m = re.match(r'^([a-zA-Z0-9_-]+)\s*=\s*(.*)', line)
        if not name_m:
            i += 1
            continue

        name = name_m.group(1)
        rest = name_m.group(2).strip()

        # Simple string dep: name = "version"
        str_m = re.match(r'^"([^"]+)"', rest)
        if str_m:
            ws_deps[name] = str_m.group(1)
            i += 1
            continue

        # Inline table dep: collect full body across lines
        if rest.startswith('{'):
            body = rest
            bd, _ = _depth_delta(rest)
            while bd > 0 and i + 1 < len(lines):
                i += 1
                body += '\n' + lines[i]
                d, _ = _depth_delta(lines[i])
                bd += d

            # Extract version from body (version can appear anywhere)
            ver_m = re.search(r'version\s*=\s*"([^"]+)"', body)
            if ver_m:
                ws_deps[name] = ver_m.group(1)

            if 'default-features = false' in body:
                ws_no_default.add(name)

            if 'path = ' in body or 'path =' in body:
                ws_path_deps.add(name)
                # Path-only deps: read version from the crate's own Cargo.toml
                if name not in ws_deps:
                    path_m = re.search(r'path\s*=\s*"([^"]+)"', body)
                    if path_m:
                        crate_toml = Path(ws_toml_path).parent / path_m.group(1) / "Cargo.toml"
                        if crate_toml.exists():
                            crate_text = crate_toml.read_text(encoding='utf-8')
                            cv = re.search(r'^version\s*=\s*"([^"]+)"', crate_text, re.MULTILINE)
                            if cv:
                                ws_deps[name] = cv.group(1)
                    # Fall back to workspace version if crate uses version.workspace = true
                    if name not in ws_deps and ws_pkg_version:
                        ws_deps[name] = ws_pkg_version

            git_m = re.search(r'git\s*=\s*"([^"]+)"', body)
            if git_m and name not in ws_deps:
                git_info = {"git": git_m.group(1)}
                for key in ("branch", "rev", "tag"):
                    km = re.search(rf'{key}\s*=\s*"([^"]+)"', body)
                    if km:
                        git_info[key] = km.group(1)
                ws_git_deps[name] = git_info

        i += 1

    return ws_deps, ws_no_default, ws_path_deps, ws_pkg_version, ws_git_deps


# ── dot-notation dep matching ─────────────────────────────────────────────────

def _match_dot_dep(line):
    """Match lines like `name.workspace = true` or `name = { workspace = true }`."""
    m = re.match(r'^([a-zA-Z0-9_-]+)\.workspace\s*=\s*true', line)
    return m.group(1) if m else None


# ── Actions ───────────────────────────────────────────────────────────────────

def main():
    action = sys.argv[1]
    toml_path = sys.argv[2] if len(sys.argv) > 2 else None

    # Most actions operate on a target toml file; gen_workspace is the exception.
    text = Path(toml_path).read_text(encoding='utf-8') if toml_path and action not in ("gen_workspace", "get_version") else ""

    if action == "sanitize_base":
        ws_version = sys.argv[3]
        ws_toml_path = sys.argv[4] if len(sys.argv) > 4 else None

        if ws_toml_path:
            meta = parse_workspace_package(ws_toml_path)
            rust_version = meta.get('rust-version', '1.93.0')
            edition = meta.get('edition', '2024')
            license_val = meta.get('license', 'MIT OR Apache-2.0')
        else:
            rust_version = '1.93.0'
            edition = '2024'
            license_val = 'MIT OR Apache-2.0'

        # Remove [lints] section
        text = re.sub(r'\n\[lints\]\nworkspace = true\n', '\n', text)
        # Resolve workspace package fields (order matters: longer keys first)
        text = text.replace('rust-version.workspace = true', f'rust-version = "{rust_version}"')
        text = text.replace('version.workspace = true', f'version = "{ws_version}"')
        text = text.replace('edition.workspace = true', f'edition = "{edition}"')
        text = text.replace('license.workspace = true', f'license = "{license_val}"')
        # Remove publish.workspace = true
        text = re.sub(r'publish\.workspace = true\n', '', text)

    elif action == "sanitize_primitives":
        # Remove reth-related feature definitions (multi-line) FIRST,
        # before dependency removal which would strip the opening line
        # (e.g. "reth-codec = [") and orphan the block body.
        text = strip_feature_blocks(text, ['reth', 'reth-codec', 'serde-bincode-compat', 'rpc'])

        # Track removed deps so we can auto-strip orphaned feature entries
        removed = set()

        # Remove reth dependency lines (single- and multi-line)
        text = strip_dep_lines(text, lambda n: n.startswith('reth-'), removed)
        # Remove modular-bitfield
        text = strip_dep_lines(text, lambda n: n == 'modular-bitfield', removed)
        # Remove deps only used by the stripped rpc feature
        text = strip_dep_lines(text, lambda n: n in ('alloy-rpc-types-eth', 'alloy-network'), removed)
        # Remove # Reth comment
        text = re.sub(r'^# Reth\n', '', text, flags=re.MULTILINE)

        # Auto-strip feature entries referencing removed deps
        text = strip_orphaned_feature_entries(text, removed)

        # Remove stripped feature names and dev-dep-only entries from feature arrays
        text = strip_feature_array_entries(text, {
            'reth', 'reth-codec', 'serde-bincode-compat', 'rpc',
            'rand/serde', 'tracing-subscriber/serde',
        })

    elif action == "sanitize_alloy":
        # Remove reth dependency lines
        text = strip_dep_lines(text, lambda n: n.startswith('reth-'))
        # Remove internal non-publishable deps (path-only workspace crates, except
        # the crates we're publishing: tempo-contracts and tempo-primitives)
        ws_toml_path = sys.argv[3]
        _, _, ws_path_deps, _, _ = parse_workspace_deps(ws_toml_path)
        publish_keep = {'tempo-contracts', 'tempo-primitives', 'tempo-alloy'}
        internal_deps = ws_path_deps - publish_keep
        text = strip_dep_lines(text, lambda n: n in internal_deps)

        # Strip the `reth` feature block
        text = strip_feature_blocks(text, ['reth'])

        # Strip "rpc" from tempo-primitives features (rpc feature is stripped during publish)
        text = re.sub(r', "rpc"', '', text)
        text = re.sub(r'"rpc", ', '', text)

    elif action == "resolve_deps":
        ws_toml_path = sys.argv[3]
        ws_deps, ws_no_default, _, _, _ = parse_workspace_deps(ws_toml_path)

        def resolve_dep_line(line, name, body):
            """Resolve a single workspace dep to a concrete version."""
            version = ws_deps.get(name)
            if not version:
                print(
                    f"error: dep '{name}' has no version in workspace "
                    f"(git-only or missing) — cannot resolve for publish",
                    file=sys.stderr,
                )
                sys.exit(1)

            parts = [f'version = "{version}"']
            # Preserve default-features = false from either workspace or local spec
            if name in ws_no_default or 'default-features = false' in body:
                parts.append('default-features = false')
            features_match = re.search(r'features\s*=\s*\[[^\]]*\]', body)
            if features_match:
                parts.append(features_match.group(0))
            if 'optional = true' in body:
                parts.append('optional = true')
            if 'package = ' in body:
                pkg_match = re.search(r'package\s*=\s*"[^"]*"', body)
                if pkg_match:
                    parts.append(pkg_match.group(0))
            return f'{name} = {{ {", ".join(parts)} }}'

        # Resolve inline table deps: name = { workspace = true, ... }
        # Use depth-aware line-by-line processing
        lines = text.split('\n')
        result = []
        i = 0
        while i < len(lines):
            line = lines[i]
            name_m = re.match(r'^([a-zA-Z0-9_-]+)\s*=\s*(\{.*)', line)
            if name_m:
                name = name_m.group(1)
                rest = name_m.group(2)
                # Collect full body across lines if needed
                body = rest
                bd, _ = _depth_delta(rest)
                collected = [line]
                while bd > 0 and i + 1 < len(lines):
                    i += 1
                    collected.append(lines[i])
                    body += ' ' + lines[i]
                    d, _ = _depth_delta(lines[i])
                    bd += d

                if 'workspace = true' in body:
                    result.append(resolve_dep_line('\n'.join(collected), name, body))
                else:
                    result.extend(collected)
                i += 1
                continue

            # Handle simple: dep.workspace = true
            dot_name = _match_dot_dep(line)
            if dot_name:
                version = ws_deps.get(dot_name)
                if not version:
                    print(
                        f"error: dep '{dot_name}' has no version in workspace "
                        f"(git-only or missing) — cannot resolve for publish",
                        file=sys.stderr,
                    )
                    sys.exit(1)
                parts = [f'version = "{version}"']
                if dot_name in ws_no_default:
                    parts.append('default-features = false')
                result.append(f'{dot_name} = {{ {", ".join(parts)} }}')
                i += 1
                continue

            result.append(line)
            i += 1

        text = '\n'.join(result)

    elif action == "gen_workspace":
        # Generate a temporary workspace Cargo.toml with workspace deps,
        # filtering out reth-* and internal path-only deps dynamically.
        #
        # Usage: sanitize_toml.py gen_workspace <ws_toml> <out_toml> [crate1,crate2,...]
        ws_toml_path = sys.argv[2]
        out_path = sys.argv[3]
        publish_crates = set(sys.argv[4].split(',')) if len(sys.argv) > 4 else set()

        ws_deps, _, ws_path_deps, _, _ = parse_workspace_deps(ws_toml_path)

        # Read the [workspace.dependencies] section text
        ws_text = Path(ws_toml_path).read_text(encoding='utf-8')
        m = re.search(r'\[workspace\.dependencies\]\n((?:.*\n)*?)(?=\[|$)', ws_text)
        if not m:
            print("error: could not find [workspace.dependencies]", file=sys.stderr)
            sys.exit(1)

        deps_block = m.group(1)

        # Deps to strip: reth-*, all path deps (internal crates)
        strip_names = set()
        for name in ws_path_deps:
            strip_names.add(name)

        def should_strip(name):
            return name.startswith('reth-') or name in strip_names

        filtered = strip_dep_lines(deps_block, should_strip)

        # Build output
        existing = Path(out_path).read_text(encoding='utf-8')
        existing += '\n[workspace.dependencies]\n'
        existing += filtered + '\n'
        for crate in sorted(publish_crates):
            dirname = crate.removeprefix('tempo-')
            existing += f'{crate} = {{ path = "{dirname}" }}\n'

        Path(out_path).write_text(existing, encoding='utf-8')
        sys.exit(0)

    elif action == "get_version":
        ws_toml_path = sys.argv[2]
        meta = parse_workspace_package(ws_toml_path)
        version = meta.get('version')
        if not version:
            print("error: could not find workspace version", file=sys.stderr)
            sys.exit(1)
        print(version)
        sys.exit(0)

    else:
        print(f"error: unknown action '{action}'", file=sys.stderr)
        sys.exit(1)

    # Clean up excessive blank lines
    text = re.sub(r'\n{3,}', '\n\n', text)

    Path(toml_path).write_text(text, encoding='utf-8')


if __name__ == '__main__':
    main()
