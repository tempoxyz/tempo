#!/usr/bin/env python3
"""Apply the workload-only sparse hook to the exact locked Reth checkout, fail closed."""

import hashlib
from pathlib import Path
import subprocess
import sys
import tempfile

REVISION = "5d0dd5f6a88feb3c30a021f8f9c1b115e31d762b"
SOURCE = Path("crates/trie/sparse/src/arena/mod.rs")
PRISTINE = "74bb12dde3684e8aab826bc31e0a13a2f2774431f45ee3b8a03f76e1e8e16656"
PATCHED = "baaa3b1589cda8ae334d926c49fa09d77232ec6abb8719cb5a7766840f38876e"
# Docker/Cargo caches may contain the original encoding-only observation hook.
LEGACY_PATCHED = "6a40b91b8c587a394983f3f0fcf84a8638b50d2033083754afe66c124ca1dd60"


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
    if digest == LEGACY_PATCHED:
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
