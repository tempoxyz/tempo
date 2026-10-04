#!/usr/bin/env python3
"""Prepare the pinned Samply recorder used by the buffered diagnostic mode.

This patches only a disposable, clean upstream checkout. It does not build the
recorder or establish that a capture is lossless. The caller records compiler
and binary provenance separately, embedding the temporary preparation manifest
in the benchmark's existing profiler provenance artifact.
"""

import argparse
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import tempfile


REVISION = "247df8fe0fa259ddb5e671bfe3121728e0d6119d"
REPOSITORY = "https://github.com/mstange/samply"
PERF_EVENT = "samply/src/linux/perf_event.rs"
PROFILER = "samply/src/linux/profiler.rs"
EXPECTED_SHA256 = {
    "Cargo.lock": "f8b0bb1a555ef6346e8858e553adc99596221038604933d123bab19d5dca7f2e",
    PERF_EVENT: "3d192c673ecf8aab4872168562616bdc37e38ef1249026b100ef8ea6d28fc142",
    PROFILER: "bf9430d2c02e5d3906c1d19e087d2e027ff5967e85ff881d0cebe2885cd11320",
}
COUNT_BEFORE = b"        const STACK_COUNT_PER_BUFFER: u32 = 32;\n"
COUNT_AFTER = b"        const STACK_COUNT_PER_BUFFER: u32 = 512;\n"
ALLOCATION_ANCHOR = b"        let size = (page_size * page_count) as u64;\n"
ALLOCATION_SUMMARY = (
    "Samply perf ring allocation: pid={pid} cpu={cpu} data_bytes={size} "
    "stack_bytes={stack_size} frequency={frequency}"
)
ALLOCATION_AFTER = ALLOCATION_ANCHOR + (
    '        eprintln!(\n'
    f'            "{ALLOCATION_SUMMARY}"\n'
    '        );\n'
).encode()
LOSS_BEFORE = (
    b"    if total_lost_events > 0 {\n"
    b'        eprintln!("Lost {total_lost_events} events.");\n'
    b"    }\n"
)
LOSS_SUMMARY = "Samply perf loss summary: lost_events={total_lost_events}"
LOSS_AFTER = f'    eprintln!("{LOSS_SUMMARY}");\n'.encode() + LOSS_BEFORE


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def git_output(checkout, *args):
    return subprocess.run(
        ["git", "-C", str(checkout), *args], check=True,
        capture_output=True, text=True,
    ).stdout.strip()


def verify_checkout(checkout):
    if Path(git_output(checkout, "rev-parse", "--show-toplevel")).resolve() != checkout:
        raise ValueError("checkout must be the Git repository root")
    revision = git_output(checkout, "rev-parse", "--verify", "HEAD")
    if revision != REVISION:
        raise ValueError(f"expected upstream HEAD {REVISION}, got {revision}")
    if git_output(checkout, "status", "--porcelain", "--untracked-files=normal"):
        raise ValueError("upstream checkout must be clean before patching")


def replace_once(data, before, after, label):
    count = data.count(before)
    if count != 1:
        raise ValueError(f"{label}: expected exactly one patch anchor, found {count}")
    return data.replace(before, after, 1)


def patch_sources(originals):
    perf = replace_once(originals[PERF_EVENT], COUNT_BEFORE, COUNT_AFTER, "ring size")
    perf = replace_once(perf, ALLOCATION_ANCHOR, ALLOCATION_AFTER, "allocation log")
    profiler = replace_once(originals[PROFILER], LOSS_BEFORE, LOSS_AFTER, "loss summary")
    return {PERF_EVENT: perf, PROFILER: profiler}


def stage_file(path, data, mode):
    """Write beside the destination so each replacement uses one filesystem."""
    fd, name = tempfile.mkstemp(prefix=f".{path.name}.samply-", dir=path.parent)
    staged = Path(name)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fchmod(stream.fileno(), mode)
            os.fsync(stream.fileno())
    except BaseException:
        staged.unlink(missing_ok=True)
        raise
    return staged


def install(checkout, manifest, originals, patched, modes, manifest_bytes):
    """Reserve output exclusively; restore source files on ordinary failures.

    A process or machine crash can interrupt a multi-file update. An absent or
    incomplete manifest is never evidence of a completed preparation; discard
    that disposable checkout and start again.
    """
    staged = {}
    backups = {}
    installed = []
    reserved = False
    try:
        # Reservation happens before changing any source, including when another
        # process creates the output after the preflight existence check.
        with manifest.open("xb") as output:
            reserved = True
            for relative, data in patched.items():
                path = checkout / relative
                backups[relative] = stage_file(path, originals[relative], modes[relative])
                staged[relative] = stage_file(path, data, modes[relative])
            for relative, temporary in staged.items():
                os.replace(temporary, checkout / relative)
                installed.append(relative)
            output.write(manifest_bytes)
            output.flush()
            os.fsync(output.fileno())
    except BaseException:
        try:
            for relative in reversed(installed):
                os.replace(backups[relative], checkout / relative)
        finally:
            if reserved:
                manifest.unlink(missing_ok=True)
        raise
    finally:
        for temporary in [*staged.values(), *backups.values()]:
            temporary.unlink(missing_ok=True)


def prepare(checkout, manifest):
    checkout = Path(checkout).resolve(strict=True)
    requested_manifest = Path(manifest).absolute()
    manifest = requested_manifest.parent.resolve(strict=True) / requested_manifest.name
    if os.path.lexists(manifest):
        raise ValueError(f"manifest already exists: {manifest}")
    if manifest.is_relative_to(checkout):
        raise ValueError("manifest must be outside the disposable upstream checkout")
    verify_checkout(checkout)
    originals = {}
    modes = {}
    for relative, expected in EXPECTED_SHA256.items():
        path = checkout / relative
        if path.resolve(strict=True) != path or not stat.S_ISREG(path.lstat().st_mode):
            raise ValueError(f"source must be a regular file without symlinks: {relative}")
        data = path.read_bytes()
        actual = sha256(data)
        if actual != expected:
            raise ValueError(f"upstream SHA256 mismatch for {relative}: {actual}")
        originals[relative] = data
        modes[relative] = stat.S_IMODE(path.stat().st_mode)
    # Validate every anchor and construct both replacements before any writes.
    patched = patch_sources(originals)
    receipt = {
        "schema_version": 1,
        "mode": "samply-buffered",
        "diagnostic_only": True,
        "repository": REPOSITORY,
        "revision": REVISION,
        "checkout": str(checkout),
        "patcher_sha256": sha256(Path(__file__).resolve().read_bytes()),
        "cargo_lock": {"path": "Cargo.lock", "sha256": sha256(originals["Cargo.lock"])},
        "files": [
            {"path": relative, "upstream_sha256": sha256(originals[relative]),
             "patched_sha256": sha256(data), "patch_count": 2 if relative == PERF_EVENT else 1}
            for relative, data in patched.items()
        ],
        "settings": {
            "stack_count_per_buffer": {"upstream": 32, "patched": 512},
            "ring_multiplier": 16,
            "loss_summary": LOSS_SUMMARY,
            "allocation_summary": ALLOCATION_SUMMARY,
        },
    }
    manifest_bytes = (json.dumps(receipt, indent=2, sort_keys=True) + "\n").encode()
    install(checkout, manifest, originals, patched, modes, manifest_bytes)
    return receipt


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=["prepare"])
    parser.add_argument("checkout", type=Path)
    parser.add_argument("manifest", type=Path)
    args = parser.parse_args()
    try:
        prepare(args.checkout, args.manifest)
    except (OSError, ValueError, subprocess.CalledProcessError) as error:
        parser.exit(1, f"Samply preparation failed: {error}\n")
    print(f"Prepared diagnostic Samply {REVISION}; manifest: {args.manifest}")


if __name__ == "__main__":
    main()
