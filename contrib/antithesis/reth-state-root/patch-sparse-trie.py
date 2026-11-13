#!/usr/bin/env python3
"""Apply the workload-only sparse hook to the exact locked Reth checkout, fail closed."""

import hashlib
from pathlib import Path
import subprocess
import sys
import tempfile

REVISION = "4f58052785aed2f716faa2126ed57c3790cc0233"
SOURCE = Path("crates/trie/sparse/src/arena/mod.rs")
PRISTINE = "dfa6c2118863f6517f5bcc8783cb16e0a7f24a2269742108dd6fd6950fe48c0d"
PATCHED = "905d4879325b89c14a05995811a0410b1f57ca92b299fdacb7af0705ebd4aa6d"
# Also upgrade the previous combined encoder/proof hook from validated pristine HEAD.
COMBINED_PATCHED = "81c81398234421f726e8e672230d58fb71fe1b2fb7d062b293c93d580f1c9a2d"
# Docker/Cargo caches may contain the encoding-only observation hook at this revision.
LEGACY_PATCHED = "9a86698317c2997b338f6e00b6c414b130615a299176a5ea78e7ac4cd3b617e4"


def apply(checkouts):
    patch = Path(__file__).with_name("sparse-branch.patch").resolve()
    matches = []
    for source in Path(checkouts).glob("*/*/crates/trie/sparse/src/arena/mod.rs"):
        root = source.parents[5]
        revision = subprocess.check_output(
            ["git", "-C", str(root), "rev-parse", "HEAD"], text=True
        ).strip()
        if revision == REVISION:
            matches.append((root, source))
    if len(matches) != 1:
        raise RuntimeError(f"Expected one Reth checkout at {REVISION}, found {len(matches)}")
    root, source = matches[0]
    digest = hashlib.sha256(source.read_bytes()).hexdigest()
    if digest == PATCHED:
        print(f"Sparse branch hook already applied at {REVISION}")
        return
    pristine = source.read_bytes()
    if digest in (LEGACY_PATCHED, COMBINED_PATCHED):
        pristine = subprocess.check_output(["git", "-C", str(root), "show", f"HEAD:{SOURCE}"])
        if hashlib.sha256(pristine).hexdigest() != PRISTINE:
            raise RuntimeError("Committed Reth sparse source does not match pinned SHA256")
    elif digest != PRISTINE:
        raise RuntimeError(f"Reth sparse source does not match pinned SHA256: {digest}")

    # Validate in isolation: a corrupt patch/digest must never partly rewrite the checkout.
    with tempfile.TemporaryDirectory(prefix="reth-sparse-patch-") as directory:
        staged = Path(directory) / SOURCE
        staged.parent.mkdir(parents=True)
        staged.write_bytes(pristine)
        subprocess.run(["git", "-C", directory, "apply", "--check", str(patch)], check=True)
        subprocess.run(["git", "-C", directory, "apply", str(patch)], check=True)
        patched = staged.read_bytes()
        if hashlib.sha256(patched).hexdigest() != PATCHED:
            raise RuntimeError("Patched sparse source digest mismatch")
    source.chmod(source.stat().st_mode | 0o200)
    source.write_bytes(patched)
    print(f"Applied sparse branch hook at {REVISION}: {PATCHED}")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit("usage: patch-sparse-trie.py CARGO_GIT_CHECKOUTS")
    apply(sys.argv[1])
