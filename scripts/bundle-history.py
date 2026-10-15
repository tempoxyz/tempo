#!/usr/bin/env python3
"""Build, verify, and install the frozen Genesis–T10 worker beside Tempo."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import socket
import subprocess
import tempfile
import time
import tomllib
import urllib.error
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
CRATE = ROOT / "bin/tempo-metabinary/eras/genesis-t10"
CATALOG = json.loads((ROOT / "bin/tempo/eras.json").read_text())
MANIFEST = tomllib.loads((CRATE / "Cargo.toml").read_text())["package"]
ERA = MANIFEST["metadata"]["era"]
BINARY = MANIFEST["name"]
WORKER = f"eras/{BINARY}"
METADATA = Path("history") / ERA["name"]
# Built-in chains served by the frozen worker, with their genesis files in the frozen source.
CHAINS = {"mainnet": "presto.json", "moderato": "moderato.json"}
# Synthetic chains activating the maximum supported fork, then its successor, at genesis.
SYNTHETIC = {f"synthetic_{ERA['maximum_hardfork'].lower()}": None,
             f"synthetic_{ERA['successor_hardfork'].lower()}": ERA["successor_hardfork"]}


def run(*args, env=None):
    return subprocess.run(args, cwd=ROOT, env=env, check=True, text=True,
                          stdout=subprocess.PIPE).stdout.strip()


def digest(path):
    checksum = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            checksum.update(chunk)
    return checksum.hexdigest()


def require(condition, message):
    if not condition:
        raise ValueError(message)


def write_json(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2) + "\n")


def source_revision():
    lock = tomllib.loads((CRATE / "Cargo.lock").read_text())
    [source] = {package["source"] for package in lock["package"] if package["name"] == "tempo"}
    return source.rsplit("#", 1)[1]


def rpc(port, method, params):
    payload = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).encode()
    request = urllib.request.Request(f"http://127.0.0.1:{port}", payload,
                                     {"Content-Type": "application/json"})
    with urllib.request.urlopen(request, timeout=2) as response:
        return json.load(response)


def result(port, method, params):
    response = rpc(port, method, params)
    if "error" in response:
        raise RuntimeError(f"{method}: {response['error']}")
    return response["result"]


def smoke(binary, chain, fixture, unsupported_fork=None):
    """Serve fresh storage read-only and check identity, calls, and traces."""
    datadir = fixture / "data"
    # Build environments may export collector settings (e.g. gRPC-only OTLP) for their own tracing.
    environment = {key: value for key, value in os.environ.items() if not key.startswith("OTEL_")}
    with (fixture / "worker.log").open("w+") as log:
        def output():
            log.seek(0)
            return log.read()[-4000:]

        init = subprocess.run([str(binary), "init", "--chain", str(chain), "--datadir", str(datadir)],
                              cwd=ROOT, env=environment, stdout=log, stderr=log, timeout=120)
        require(init.returncode == 0, f"worker init exited with {init.returncode}: {output()}")
        with socket.socket() as listener:
            listener.bind(("127.0.0.1", 0))
            port = listener.getsockname()[1]
        worker = subprocess.Popen([str(binary), "rpc-only", "--chain", str(chain),
                                   "--datadir", str(datadir), "--port", str(port)],
                                  cwd=ROOT, env=environment, stdout=log, stderr=log)
        try:
            deadline = time.monotonic() + 120
            while True:
                require(worker.poll() is None, f"worker exited: {output()}")
                try:
                    info = result(port, "tempo_executionInfo", [])
                    break
                except (OSError, urllib.error.URLError):
                    require(time.monotonic() < deadline, "worker startup timed out")
                    time.sleep(0.1)
            require(info["processId"] == worker.pid and info["readOnly"]
                    and info["protocolVersion"] == ERA["worker_protocol_version"],
                    f"wrong worker identity: {info}")
            block = result(port, "eth_getBlockByNumber", ["0x0", False])
            require(block["hash"].lower() == info["genesisHash"].lower(),
                    "worker genesis identity disagrees with stored genesis")
            call = {"to": "0x0000000000000000000000000000000000000000",
                    "gas": "0x4c4b40", "gasPrice": "0x0"}
            for method, params in [("eth_call", [call, "0x0"]),
                                   ("debug_traceCall", [call, "0x0", {"tracer": "callTracer"}])]:
                response = rpc(port, method, params)
                if unsupported_fork:
                    require("error" in response
                            and f"does not support {unsupported_fork}" in str(response["error"]),
                            f"{method} did not reject {unsupported_fork}: {response}")
                else:
                    require("error" not in response
                            and (method != "eth_call" or response["result"] == "0x"),
                            f"unexpected {method} result: {response}")
            return {"chain_id": info["chainId"], "genesis_hash": info["genesisHash"],
                    "protocol_version": info["protocolVersion"],
                    "calls_and_traces": "rejected" if unsupported_fork else "passed",
                    "unsupported_fork": unsupported_fork}
        finally:
            if worker.poll() is None:
                worker.terminate()
            try:
                worker.wait(timeout=10)
            except subprocess.TimeoutExpired:
                worker.kill()
                worker.wait(timeout=10)


def verify_catalog(verification):
    """The embedded catalog must route exactly the verified chains to this worker."""
    require({chain["chain_id"] for chain in CATALOG["chains"]}
            == {verification[name]["chain_id"] for name in CHAINS},
            "Embedded era catalog does not match the verified chains")
    for chain in CATALOG["chains"]:
        [frozen] = chain["eras"]
        require(frozen["until"] == ERA["successor_hardfork"] and frozen["binary"] == WORKER,
                f"Embedded era catalog disagrees with the frozen {chain['chain_id']} schedule")


def build(stage, profile, target):
    """Build the frozen crate and smoke-test the executable in the installed layout."""
    revision = source_revision()
    environment = {key: value for key, value in os.environ.items() if not key.startswith("VERGEN_GIT_")}
    environment.update(
        # Separate from live artifacts; the frozen workspace pins its own dependencies and profiles.
        CARGO_TARGET_DIR=str(Path(os.environ.get("CARGO_TARGET_DIR", ROOT / "target")).resolve()
                             / "history"),
        VERGEN_GIT_SHA=revision, VERGEN_GIT_SHA_SHORT=revision[:7], VERGEN_GIT_DIRTY="false")
    manifest = str(CRATE / "Cargo.toml")
    run("cargo", "build", "--locked", "--manifest-path", manifest, "--bin", BINARY,
        "--profile", profile, env=environment)
    metadata = json.loads(run("cargo", "metadata", "--locked", "--format-version", "1",
                              "--manifest-path", manifest, env=environment))
    [chainspec] = [package for package in metadata["packages"] if package["name"] == "tempo-chainspec"]
    genesis_dir = Path(chainspec["manifest_path"]).parent / "src/genesis"
    built = Path(metadata["target_directory"]) / ("debug" if profile == "dev" else profile) / BINARY

    binary = stage / WORKER
    binary.parent.mkdir(parents=True)
    shutil.copy2(built, binary)
    version = run(str(binary), "--version")
    require(revision in version and ERA["name"].replace("-", "_") in version,
            f"Frozen worker provenance or feature missing: {version}")

    verification = {}
    maximum = int(ERA["maximum_hardfork"].removeprefix("T"))
    with tempfile.TemporaryDirectory(prefix="tempo-history-smoke-") as fixtures:
        for name in CHAINS:
            fixture = Path(fixtures) / name
            fixture.mkdir()
            verification[name] = smoke(binary, name, fixture)
        genesis = json.loads((genesis_dir / CHAINS["mainnet"]).read_text())
        for key in genesis["config"]:
            fork = re.fullmatch(r"t(\d+)[a-z]*Time", key)
            if fork:
                genesis["config"][key] = 0 if int(fork.group(1)) <= maximum else 100
        for name, unsupported_fork in SYNTHETIC.items():
            if unsupported_fork:
                genesis["config"][f"{unsupported_fork.lower()}Time"] = 0
            fixture = Path(fixtures) / name
            write_json(fixture / "genesis.json", genesis)
            verification[name] = smoke(binary, fixture / "genesis.json", fixture, unsupported_fork)
    verify_catalog(verification)

    write_json(stage / "tempo-eras.json", CATALOG)
    write_json(stage / METADATA / "verification.json", verification)
    write_json(stage / METADATA / "build-info.json", {
        "era": ERA["name"], "version": MANIFEST["version"], "source_revision": revision,
        "target": target, "profile": profile, "binary_version": version,
        "rustc": run("rustc", "-vV"), "cargo": run("cargo", "--version"),
        "cargo_lock_sha256": digest(CRATE / "Cargo.lock")})
    checksums = {str(path.relative_to(stage)): digest(path)
                 for path in sorted(stage.rglob("*")) if path.is_file()}
    (stage / METADATA / "SHA256SUMS").write_text(
        "".join(f"{checksum}  {name}\n" for name, checksum in checksums.items()))


def verify(package, profile, target):
    """Check an installed or extracted bundle against this checkout, host, and profile."""
    files = {WORKER, "tempo-eras.json", str(METADATA / "build-info.json"),
             str(METADATA / "verification.json")}
    checksums = {}
    for line in (package / METADATA / "SHA256SUMS").read_text().splitlines():
        checksum, name = line.split("  ", 1)
        require(name in files and name not in checksums and re.fullmatch(r"[0-9a-f]{64}", checksum),
                f"Unexpected checksum entry: {line}")
        path = package / name
        require(not path.is_symlink() and path.resolve().is_relative_to(package.resolve())
                and digest(path) == checksum, f"Checksum mismatch: {name}")
        checksums[name] = checksum
    require(checksums.keys() == files, "Bundle checksum manifest is incomplete")
    info = json.loads((package / METADATA / "build-info.json").read_text())
    expected = {"era": ERA["name"], "version": MANIFEST["version"],
                "source_revision": source_revision(), "target": target, "profile": profile,
                "cargo_lock_sha256": digest(CRATE / "Cargo.lock")}
    require(all(info.get(key) == value for key, value in expected.items()),
            f"Bundle provenance does not match this checkout, host or profile: {info}")
    require(json.loads((package / "tempo-eras.json").read_text()) == CATALOG,
            "Bundle catalog does not match the embedded era catalog")
    verification = json.loads((package / METADATA / "verification.json").read_text())
    expected = {**dict.fromkeys(CHAINS), **SYNTHETIC}
    require(verification.keys() == expected.keys()
            and all(checked["protocol_version"] == ERA["worker_protocol_version"]
                    and checked["unsupported_fork"] == expected[name]
                    and checked["calls_and_traces"] == ("rejected" if expected[name] else "passed")
                    for name, checked in verification.items()),
            "Bundle smoke verification is incomplete")
    worker = package / WORKER
    require(os.access(worker, os.X_OK), "Frozen worker is not executable")
    require(run(str(worker), "--version") == info["binary_version"], "Frozen worker provenance mismatch")


def install(package, output):
    """Copy a verified bundle without replacing different existing files."""
    names = [line.split("  ", 1)[1]
             for line in (package / METADATA / "SHA256SUMS").read_text().splitlines()]
    names.append(str(METADATA / "SHA256SUMS"))
    output.mkdir(parents=True, exist_ok=True)
    for name in names:
        path = output / name
        require(not path.is_symlink() and path.resolve().is_relative_to(output.resolve()),
                f"Refusing to install through symlink: {path}")
        require(not path.exists() or digest(path) == digest(package / name),
                f"Remove the previous history bundle before replacing {path}")
    with tempfile.TemporaryDirectory(prefix=".history-", dir=output) as temporary:
        for name in names:
            path = output / name
            if not path.exists():
                staged = Path(temporary) / name
                staged.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(package / name, staged)
                path.parent.mkdir(parents=True, exist_ok=True)
                staged.replace(path)
    print(f"Verified {BINARY} {MANIFEST['version']} ({source_revision()}) installed in {output}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--package", type=Path,
                        help="existing bundle directory (a previous --output or extracted release)")
    parser.add_argument("--output", type=Path, required=True,
                        help="directory containing the active tempo binary")
    parser.add_argument("--profile", choices=["dev", "release", "profiling", "maxperf", "reproducible"],
                        default="release")
    args = parser.parse_args()
    target = re.search(r"^host: (.+)$", run("rustc", "-vV"), re.MULTILINE).group(1)
    with tempfile.TemporaryDirectory(prefix="tempo-history-") as temporary:
        package = args.package
        if package is None:
            package = Path(temporary) / "bundle"
            build(package, args.profile, target)
        package = package.resolve()
        verify(package, args.profile, target)
        install(package, args.output.resolve())


if __name__ == "__main__":
    try:
        main()
    except (ValueError, OSError, subprocess.CalledProcessError) as error:
        raise SystemExit(str(error)) from error
