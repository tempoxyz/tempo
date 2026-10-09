#!/usr/bin/env python3
"""Build or install the pinned, verified Genesis–T10 worker beside Tempo."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
PIN = json.loads((ROOT / "bin/tempo/history.json").read_text())


def run(*args, cwd=None):
    return subprocess.check_output(args, cwd=cwd, text=True).strip()


def digest(path):
    checksum = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            checksum.update(chunk)
    return checksum.hexdigest()


def require(condition, message):
    if not condition:
        raise ValueError(message)


def verify(package, target, profile):
    files = {"era.json", "build-info.json", "verification.json", "tempo-eras.json",
             f"eras/tempo-{PIN['era']}"}
    checksums = {}
    for line in (package / "SHA256SUMS").read_text().splitlines():
        checksum, name = line.split("  ", 1)
        require(name in files and name not in checksums and re.fullmatch(r"[0-9a-f]{64}", checksum),
                f"Unexpected checksum entry: {line}")
        path = package / name
        require(not path.is_symlink() and path.resolve().is_relative_to(package.resolve())
                and digest(path) == checksum, f"Checksum mismatch: {name}")
        checksums[name] = checksum
    require(checksums.keys() == files, "Package checksum manifest is incomplete")
    require(checksums["era.json"] == PIN["era_sha256"], "Package has different frozen era metadata")
    info = json.loads((package / "build-info.json").read_text())
    expected = {"history_revision": PIN["revision"], "upstream_revision": PIN["upstream_revision"],
                "target": target, "profile": profile, "features": [PIN["era"]]}
    require(all(info.get(key) == value for key, value in expected.items()),
            f"Package provenance does not match the pin, host or profile: {info}")
    catalog = json.loads((package / "tempo-eras.json").read_text())
    require(catalog == json.loads((ROOT / "bin/tempo/eras.json").read_text()),
            "Package catalog does not match the embedded era catalog")
    era = json.loads((package / "era.json").read_text())
    verification = json.loads((package / "verification.json").read_text())
    names = [chain["name"] for chain in era["chains"]] + ["synthetic_t10", "synthetic_t11"]
    require(verification.keys() == set(names), "Package smoke verification is incomplete")
    for name, chain in zip(names, catalog["chains"] + [catalog["chains"][0]] * 2):
        expected = {"chain_id": chain["chain_id"], "genesis_hash": chain["genesis_hash"],
                    "protocol_version": era["worker_protocol_version"],
                    "calls_and_traces": "rejected" if name == "synthetic_t11" else "passed",
                    "unsupported_fork": "T11" if name == "synthetic_t11" else None}
        require(verification[name] == expected, f"Package smoke verification failed: {name}")
    worker = package / f"eras/tempo-{PIN['era']}"
    require(os.access(worker, os.X_OK), "Frozen worker is not executable")
    version = run(str(worker), "--version")
    require(version == info["binary_version"].strip() and PIN["revision"] in version
            and PIN["era"].replace("-", "_") in version, "Frozen worker provenance mismatch")
    return checksums


def install(package, output, checksums):
    metadata = Path("history") / PIN["era"]
    paths = {name: metadata / name if "/" not in name and name != "tempo-eras.json"
             else Path(name) for name in checksums}
    output.mkdir(parents=True, exist_ok=True)
    for name, relative in paths.items():
        path = output / relative
        require(not path.is_symlink() and path.resolve().is_relative_to(output.resolve()),
                f"Refusing to install through symlink: {path}")
        require(not path.exists() or digest(path) == checksums[name],
                f"Remove the previous history bundle before replacing {path}")
    manifest = "".join(f"{checksum}  {paths[name]}\n" for name, checksum in sorted(checksums.items()))
    manifest_path = output / metadata / "SHA256SUMS"
    require(not manifest_path.is_symlink(), f"Refusing to replace symlink: {manifest_path}")
    require(not manifest_path.exists() or manifest_path.read_text() == manifest,
            f"Remove the previous history bundle before replacing {manifest_path}")
    with tempfile.TemporaryDirectory(prefix=".history-", dir=output) as temporary:
        stage = Path(temporary)
        for name, relative in paths.items():
            path = output / relative
            if not path.exists():
                staged = stage / relative
                staged.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(package / name, staged)
                path.parent.mkdir(parents=True, exist_ok=True)
                staged.replace(path)
        manifest_path.write_text(manifest)
    worker = f"eras/tempo-{PIN['era']}"
    shutil.copymode(package / worker, output / worker)
    print(f"Verified history {PIN['revision']} installed in {output}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    inputs = parser.add_mutually_exclusive_group()
    inputs.add_argument("--source", type=Path, help="clean checkout at the pinned revision")
    inputs.add_argument("--package", type=Path, help="existing extracted, verified worker package")
    parser.add_argument("--output", type=Path, required=True, help="directory containing the active tempo binary")
    parser.add_argument("--profile", choices=["dev", "release", "maxperf", "profiling"], default="release")
    args = parser.parse_args()
    profile = "release" if args.profile == "profiling" else args.profile
    target = re.search(r"^host: (.+)$", run("rustc", "-vV"), re.MULTILINE).group(1)
    environment = {key: value for key, value in os.environ.items() if not key.startswith("VERGEN_GIT_")}
    environment.update(CARGO_TARGET_DIR=str(Path(
        os.environ.get("CARGO_TARGET_DIR", ROOT / "target")).resolve()),
        VERGEN_GIT_SHA=PIN["revision"], VERGEN_GIT_SHA_SHORT=PIN["revision"][:7], VERGEN_GIT_DIRTY="false")
    with tempfile.TemporaryDirectory(prefix="tempo-history-") as temporary:
        package = args.package
        if package is None:
            source = args.source
            if source is None:
                source = Path(temporary) / "source"
                subprocess.run(["git", "init", str(source)], check=True)
                subprocess.run(["git", "fetch", "--depth=1", PIN["repository"], PIN["revision"]],
                               cwd=source, check=True)
                subprocess.run(["git", "checkout", "--detach", "FETCH_HEAD"], cwd=source, check=True)
            source = source.resolve()
            require(run("git", "rev-parse", "HEAD", cwd=source) == PIN["revision"],
                    "Frozen source checkout is not at the pinned revision")
            require(not run("git", "status", "--porcelain", cwd=source), "Frozen source checkout is dirty")
            name = f"tempo-{PIN['era']}-v{PIN['version']}-{target}-{profile}"
            package = source / "dist" / name / name
            if not package.exists():
                subprocess.run([sys.executable, str(source / "history/package.py"), "--profile", profile],
                               cwd=source, env=environment, check=True)
        install(package.resolve(), args.output.resolve(), verify(package, target, profile))


if __name__ == "__main__":
    try:
        main()
    except (ValueError, OSError, subprocess.CalledProcessError) as error:
        raise SystemExit(str(error)) from error
