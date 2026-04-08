#!/usr/bin/env python3
"""Sanitize Rust source files for publishing outside the workspace.

Every edit asserts an expected match count. If a pattern matches 0 times,
the source has drifted and the script fails — preventing silent breakage.

Usage:
    sanitize_source.py <primitives_dir> <alloy_dir>
"""
import os
import re
import sys
from pathlib import Path


def find_rs_files(directory):
    """Yield all .rs file paths under directory."""
    for root, _, files in os.walk(directory):
        for f in files:
            if f.endswith('.rs'):
                yield os.path.join(root, f)


def delete_lines(path, pattern, *, expected_min=0, expected=None):
    """Delete all lines matching `pattern` from `path`.

    When expected is set, fails if the match count != expected (exact).
    When expected_min >= 1, fails if fewer than that many lines are deleted.
    When both are 0/None (default), no-op if no matches.
    """
    text = Path(path).read_text(encoding='utf-8')
    count = len(re.findall(pattern, text, re.MULTILINE))
    if expected is not None and count != expected:
        print(
            f"error: delete_lines({path!r}, {pattern!r}): "
            f"expected {expected} matches, got {count}",
            file=sys.stderr,
        )
        sys.exit(1)
    if count == 0 and expected_min == 0 and expected is None:
        return 0
    if count < expected_min:
        print(
            f"error: delete_lines({path!r}, {pattern!r}): "
            f"expected >= {expected_min} matches, got {count}",
            file=sys.stderr,
        )
        sys.exit(1)
    text = re.sub(pattern, '', text, flags=re.MULTILINE)
    Path(path).write_text(text, encoding='utf-8')
    return count


def replace_text(path, old, new, *, expected=1):
    """Replace exact occurrences of `old` with `new` in `path`.

    Fails if the number of occurrences != `expected`.
    """
    text = Path(path).read_text(encoding='utf-8')
    count = text.count(old)
    if count != expected:
        print(
            f"error: replace_text({path!r}, {old!r}): "
            f"expected {expected} occurrences, got {count}",
            file=sys.stderr,
        )
        sys.exit(1)
    text = text.replace(old, new)
    Path(path).write_text(text, encoding='utf-8')


def delete_regex_block(path, pattern, *, expected=None):
    """Delete regex-matched blocks (with re.DOTALL) from `path`.

    When expected is an integer, fails if the number of matches != expected.
    When expected is None (default), no-op if no matches.
    """
    text = Path(path).read_text(encoding='utf-8')
    count = len(re.findall(pattern, text, re.DOTALL))
    if count == 0 and expected is None:
        return 0
    if expected is not None and count != expected:
        print(
            f"error: delete_regex_block({path!r}): "
            f"expected {expected} matches, got {count}",
            file=sys.stderr,
        )
        sys.exit(1)
    text = re.sub(pattern, '', text, flags=re.DOTALL)
    Path(path).write_text(text, encoding='utf-8')
    return count


def count_matches(path, pattern, flags=re.MULTILINE):
    """Count regex matches in a file without modifying it."""
    text = Path(path).read_text(encoding='utf-8')
    return len(re.findall(pattern, text, flags))


def count_matches_in_dir(directory, pattern, flags=re.MULTILINE):
    """Count regex matches across all .rs files under directory."""
    return sum(count_matches(f, pattern, flags) for f in find_rs_files(directory))


def sanitize_primitives(prim_dir):
    """Strip all reth-specific code from tempo-primitives source files."""
    src = f"{prim_dir}/src"

    # ── lib.rs ─────────────────────────────────────────────────────────────
    # Delete cfg + gated item as compound pairs. A new #[cfg(feature = "reth")]
    # for something else won't match and the pre-resolve grep will catch it.
    lib_rs = f"{src}/lib.rs"
    delete_lines(lib_rs, r'^#\[cfg\(feature = "reth"\)\]\nmod reth_compat;\n', expected=1)
    delete_lines(lib_rs, r'^#\[cfg\(feature = "reth"\)\]\npub use reth_compat::TempoReceipt;\n', expected=1)
    delete_lines(lib_rs, r'^#\[cfg\(not\(feature = "reth"\)\)\]\n', expected=1)

    # ── Struct-level derive/test attributes (directory-wide scan) ──────────
    # Scan all .rs files for reth-specific cfg_attr patterns instead of
    # maintaining a hardcoded file list. This way, adding a new struct with
    # reth derives in any file just works — no script update needed.

    # Patterns to strip.
    # Single-line: #[cfg_attr(feature = "reth-codec", derive(reth_codecs::Compact))]
    compact_pattern = r'^#\[cfg_attr\(feature = "reth-codec", derive\(reth_codecs::Compact\)\)\]\n'
    # Single-line: #[cfg_attr(test, reth_codecs::add_arbitrary_tests(...))]
    arb_test_pattern = r'^#\[cfg_attr\(test, reth_codecs::add_arbitrary_tests\([^)]*\)\)\]\n'
    # Multi-line: #[cfg_attr(\n    all(test, feature = "reth-codec"),\n    ...\n)]
    multi_arb_pattern = r'#\[cfg_attr\(\s*all\(test, feature = "reth-codec"\),\s*[^\]]*\)\]\n'

    # Pre-scan: count expected matches before any mutations.
    expected = {
        "Compact derive": count_matches_in_dir(src, compact_pattern),
        "add_arbitrary_tests": count_matches_in_dir(src, arb_test_pattern),
        "multi-line add_arbitrary_tests": count_matches_in_dir(src, multi_arb_pattern, re.DOTALL),
    }

    for label, exp in expected.items():
        if exp == 0:
            print(f"error: expected {label} attrs in src/, found 0", file=sys.stderr)
            sys.exit(1)

    compact_total = 0
    arb_test_total = 0
    multi_arb_total = 0

    for rs_file in find_rs_files(src):
        compact_total += delete_lines(rs_file, compact_pattern)
        arb_test_total += delete_lines(rs_file, arb_test_pattern)
        multi_arb_total += delete_regex_block(rs_file, multi_arb_pattern)

    # Assert exact counts match pre-scan (catches partial deletion bugs).
    actual = {
        "Compact derive": compact_total,
        "add_arbitrary_tests": arb_test_total,
        "multi-line add_arbitrary_tests": multi_arb_total,
    }
    for label in expected:
        if actual[label] != expected[label]:
            print(
                f"error: {label}: expected to strip {expected[label]}, "
                f"but only stripped {actual[label]}",
                file=sys.stderr,
            )
            sys.exit(1)
        print(f"  stripped {actual[label]} {label} attrs", file=sys.stderr)

    # ── #[cfg(feature = "rpc")] impl blocks in envelope.rs ────────────────
    delete_regex_block(
        f"{src}/transaction/envelope.rs",
        r'#\[cfg\(feature = "rpc"\)\]\nimpl [^{]*\{.*?\n\}\n',
        expected=2,
    )

    # ── #[cfg(all(test, feature = "reth-codec"))] compact test modules ────
    for rs_file in find_rs_files(src):
        _delete_cfg_gated_block(
            rs_file,
            '#[cfg(all(test, feature = "reth-codec"))]',
            expected=None,
        )


def _delete_cfg_gated_block(path, gate_line, *, expected=1):
    """Delete an exact cfg gate line and the block/item it gates.

    gate_line: the exact stripped line content, e.g. '#[cfg(feature = "node")]'

    If the gated item opens a brace-delimited block (fn, impl, mod block, etc.),
    the entire block is deleted using string-aware brace tracking.
    If it's a single-line item (use, mod decl, type alias), only that line is deleted.
    A preceding #[test] attribute is also removed if present.
    """
    text = Path(path).read_text(encoding='utf-8')
    lines = text.split('\n')
    result = []
    count = 0
    i = 0
    while i < len(lines):
        stripped = lines[i].strip()
        if stripped == gate_line:
            # Check what the next line is
            if i + 1 >= len(lines):
                print(
                    f"error: _delete_cfg_gated_block({path!r}): "
                    f"cfg gate at end of file with no gated item",
                    file=sys.stderr,
                )
                sys.exit(1)
            next_stripped = lines[i + 1].strip()
            # Determine if next line opens a brace block
            next_clean = _strip_rust_strings(lines[i + 1])
            has_open_brace = '{' in next_clean
            if has_open_brace:
                # Delete cfg line + entire brace-delimited block
                # Also remove preceding #[test] if present
                if result and result[-1].strip() == '#[test]':
                    result.pop()
                i += 1  # skip cfg line, now on block start
                brace_depth = 0
                while i < len(lines):
                    clean = _strip_rust_strings(lines[i])
                    brace_depth += clean.count('{') - clean.count('}')
                    i += 1
                    if brace_depth <= 0:
                        break
            else:
                # Single-line gated item: delete cfg line + next line
                i += 2
            count += 1
            continue
        result.append(lines[i])
        i += 1

    if expected is not None and count != expected:
        print(
            f"error: _delete_cfg_gated_block({path!r}, {gate_line!r}): "
            f"expected {expected} occurrences, got {count}",
            file=sys.stderr,
        )
        sys.exit(1)

    Path(path).write_text('\n'.join(result), encoding='utf-8')
    return count


def _strip_rust_strings(line):
    """Remove string literal contents from a line for safe brace counting.

    Handles double-quoted strings with escape sequences.
    """
    result = []
    in_str = False
    i = 0
    while i < len(line):
        c = line[i]
        if in_str:
            if c == '\\':
                i += 2  # skip escaped char
                continue
            if c == '"':
                in_str = False
            i += 1
            continue
        if c == '"':
            in_str = True
            i += 1
            continue
        # Strip line comments
        if c == '/' and i + 1 < len(line) and line[i + 1] == '/':
            break
        result.append(c)
        i += 1
    return ''.join(result)


def sanitize_alloy(alloy_dir):
    """Strip node-internal code from tempo-alloy source files.

    The reth_compat.rs file is already deleted by the shell script (publish-crates.sh).
    This function removes the cfg-gated `mod reth_compat;` declaration from rpc/mod.rs
    so the crate compiles without the file.
    """
    src = f"{alloy_dir}/src"

    # Delete the cfg-gated `mod reth_compat;` block from rpc/mod.rs
    delete_lines(f"{src}/rpc/mod.rs", r'^#\[cfg\(feature = "reth"\)\]\nmod reth_compat;\n', expected=1)
    print(f"  rpc/mod.rs: deleted mod reth_compat declaration", file=sys.stderr)


if __name__ == '__main__':
    if len(sys.argv) != 3:
        print("Usage: sanitize_source.py <primitives_dir> <alloy_dir>", file=sys.stderr)
        sys.exit(1)

    prim_dir = sys.argv[1]
    alloy_dir = sys.argv[2]

    sanitize_primitives(prim_dir)
    sanitize_alloy(alloy_dir)
