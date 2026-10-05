#!/usr/bin/env python3
"""Opt-in official-host empty-clock controls. Never runs a node or txgen.

The EVM test has a different dev-dependency graph from the node. Matching source,
Rust, profile, CPU flags and allocator makes it a clock-floor control only, not
an executor benchmark or a guaranteed upper bound on instrumentation overhead.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import selectors
import shutil
import signal
import subprocess
import time

RUSTFLAGS = "-C target-cpu=native -C force-frame-pointers=yes"
TEST = "evm::tests::consumed_candidate_disposal_clock_calibration"
BUILD_SECONDS = 3600
BUILD_BYTES = 64 * 1024**2
SAMPLE_SECONDS = 30
SAMPLE_BYTES = 1024**2
DISK_FLOOR = 1024**3
MEM_AVAILABLE_FLOOR = 4 * 1024**3
CPU_SETS = {"a": "0-7,16-23", "b": "8-15,24-31"}
SOURCES = (
    "Cargo.toml", "Cargo.lock", ".cargo/config.toml", "bin/tempo/Cargo.toml",
    "bin/tempo/src/main.rs", "crates/evm/Cargo.toml", "crates/evm/src/lib.rs",
    "crates/evm/src/evm.rs",
)
STOP = None


def require(ok, message):
    if not ok:
        raise ValueError(message)


def sha(path):
    with Path(path).open("rb") as source:
        return hashlib.file_digest(source, "sha256").hexdigest()


def reference(path):
    path = Path(path).resolve(strict=True)
    return {"path": str(path), "sha256": sha(path), "bytes": path.stat().st_size}


def save(path, value):
    with Path(path).open("x") as out:
        json.dump(value, out, indent=2, allow_nan=False)
        out.write("\n")


def read(path):
    require(Path(path).stat().st_size <= 1024**2, "oversized manifest")
    return json.loads(Path(path).read_text())


def command(argv, cwd=None):
    return subprocess.check_output(argv, cwd=cwd, text=True, timeout=15).strip()


def environment():
    forbidden = ("CARGO_PROFILE_", "CARGO_TARGET_")
    exact = {"CARGO_ENCODED_RUSTFLAGS", "CARGO_BUILD_RUSTFLAGS",
             "RUSTC_WRAPPER", "RUSTC_WORKSPACE_WRAPPER", "LD_PRELOAD",
             "MALLOC_CONF", "_RJEM_MALLOC_CONF"}
    for name, value in os.environ.items():
        if value and (name in exact or name.startswith(forbidden)):
            raise ValueError("unsupported inherited build/allocator override: " + name)
    require(os.environ.get("CARGO_INCREMENTAL") == "0", "CARGO_INCREMENTAL must be pinned to 0")
    rustc = command(["rustc", "-vV"])
    require("release: 1.98.1\n" in rustc + "\n", "default Rust must be 1.98.1")
    pinned = command(["rustc", "+1.98.1", "-vV"])
    require(rustc == pinned, "default and pinned Rust differ")
    require(shutil.which("taskset") is not None, "taskset is required")
    return {"rustc": rustc, "cargo": command(["cargo", "+1.98.1", "-V"]),
            "rustflags": RUSTFLAGS, "cargo_incremental": "0",
            "cpu_affinity": sorted(os.sched_getaffinity(0)),
            "kernel": os.uname().release, "machine": os.uname().machine}


def cpu_set(value):
    out = set()
    for item in value.split(","):
        ends = [int(part) for part in item.split("-")]
        require(len(ends) in (1, 2), "invalid affinity")
        lo, hi = ends[0], ends[-1]
        require(0 <= lo <= hi < 4096, "invalid affinity range")
        out.update(range(lo, hi + 1))
    return out


def assert_idle(proc_root=Path("/proc")):
    # Refuse calibration while a node, workload sender or compiler is still live.
    # Do not print command lines: other processes may contain credentials.
    forbidden = {"tempo", "bench", "txgen-tempo", "cargo", "rustc", "rust-lld", "cc1plus"}
    active = []
    for entry in proc_root.iterdir():
        if not entry.name.isdigit() or int(entry.name) == os.getpid():
            continue
        try:
            argv = (entry / "cmdline").read_bytes().split(b"\0")
            if not argv[0]:
                continue
            name = os.fsdecode(argv[0]).rsplit("/", 1)[-1]
            if name in forbidden:
                active.append({"pid": int(entry.name), "program": name})
        except FileNotFoundError:
            continue
    require(not active, "calibration overlaps live node/workload/compiler: " + str(active))


def free_memory():
    for line in Path("/proc/meminfo").read_text().splitlines():
        if line.startswith("MemAvailable:"):
            return int(line.split()[1]) * 1024
    raise ValueError("MemAvailable is unavailable")


def send_signal(proc, sig):
    try:
        os.killpg(proc.pid, sig)
    except ProcessLookupError:
        pass


def run_bounded(argv, cwd, env, log, seconds, cap):
    """Drain a pipe into a capped file; terminate on the first failed bound."""
    require(STOP is None, "interrupted before process launch")
    require(shutil.disk_usage(log.parent).free >= DISK_FLOOR, "disk reserve before process")
    started = time.time_ns()
    began = time.monotonic()
    reason, stopped = None, None
    retained, observed = 0, 0
    minimum_disk = shutil.disk_usage(log.parent).free
    minimum_memory = free_memory()
    require(minimum_memory >= MEM_AVAILABLE_FLOOR, "memory reserve before process")
    with log.open("xb") as sink:
        proc = subprocess.Popen(argv, cwd=cwd, env=env, stdout=subprocess.PIPE,
                                stderr=subprocess.STDOUT, start_new_session=True)
        selector = selectors.DefaultSelector()
        try:
            selector.register(proc.stdout, selectors.EVENT_READ)
            eof = False
            while proc.poll() is None or not eof:
                for key, _ in selector.select(0.1):
                    chunk = os.read(key.fileobj.fileno(), 65536)
                    if not chunk:
                        selector.unregister(key.fileobj)
                        eof = True
                        continue
                    observed += len(chunk)
                    keep = chunk[:max(0, cap - retained)]
                    sink.write(keep)
                    retained += len(keep)
                disk = shutil.disk_usage(log.parent).free
                memory = free_memory()
                minimum_disk = min(minimum_disk, disk)
                minimum_memory = min(minimum_memory, memory)
                cause = ("interrupted" if STOP else "log_limit" if observed > cap else
                         "wall_limit" if time.monotonic() - began >= seconds else
                         "disk_floor" if disk < DISK_FLOOR else
                         "memory_floor" if memory < MEM_AVAILABLE_FLOOR else None)
                if cause and reason is None:
                    reason, stopped = cause, time.monotonic()
                    send_signal(proc, signal.SIGTERM)
                if stopped is not None and time.monotonic() - stopped >= 2:
                    send_signal(proc, signal.SIGKILL)
                    # An inherited pipe in an escaped process must not keep us waiting.
                    if proc.poll() is not None:
                        break
            proc.wait(timeout=5)
        except BaseException:
            # Losing the output pipe or resource probe must not leave work alive.
            send_signal(proc, signal.SIGKILL)
            proc.wait(timeout=5)
            raise
        finally:
            selector.close()
            proc.stdout.close()
    return {"argv": argv, "pid": proc.pid, "started_unix_ns": started,
            "finished_unix_ns": time.time_ns(), "exit_code": proc.returncode,
            "stop_reason": reason, "log": reference(log), "observed_output_bytes": observed,
            "minimum_disk_free_bytes": minimum_disk, "minimum_mem_available_bytes": minimum_memory,
            "wall_bound_seconds": seconds, "retained_log_bound_bytes": cap}


def check_config(path):
    cfg = read(path)
    require(cfg["schema"] == 1 and cfg["profile"] == "profiling", "wrong calibration config/profile")
    require(cfg["cpus"] == CPU_SETS, "validator affinity changed")
    require(cfg["rustflags"] == RUSTFLAGS and cfg["no_default_features"] is True,
            "node build flags changed")
    require(cfg["cargo_incremental"] == "0", "node incremental setting changed")
    manifest = read(cfg["build_manifest"])
    require(manifest["shared_binary"] is True and len(manifest["arms"]) == 2,
            "diagnostic requires one shared node binary")
    require({arm["side"] for arm in manifest["arms"]} == {"baseline", "feature"}, "wrong arms")
    for arm in manifest["arms"]:
        require(arm["resolved_ref"] == cfg["source_commit"] and arm["profile"] == "profiling"
                and arm["rustflags"] == RUSTFLAGS and arm["no_default_features"] is True,
                "node artifact build provenance differs")
        require(set(arm["features"].split(",")) == {"jemalloc", "asm-keccak", "keccak-cache-global", "otlp"},
                "unexpected node feature set")
        require(Path(arm["path"]).resolve() == Path(cfg["node_binary"]).resolve()
                and sha(arm["path"]) == arm["sha256"], "node binary changed")
    require(manifest["arms"][0]["sha256"] == manifest["arms"][1]["sha256"], "node hashes differ")
    worktree = Path(cfg["worktree"]).resolve(strict=True)
    require(command(["git", "rev-parse", "HEAD"], worktree) == cfg["source_commit"], "source HEAD changed")
    require(not command(["git", "status", "--porcelain", "--untracked-files=no"], worktree), "dirty tracked source")
    return cfg, worktree


def source_hashes(worktree):
    return {name: sha(worktree / name) for name in SOURCES}


def compile_clock(config_path):
    cfg, worktree = check_config(config_path)
    system = environment()
    assert_idle()
    out = Path(cfg["output"]).resolve()
    out.mkdir()  # Existing evidence means this attempt must not be repeated.
    hashes = source_hashes(worktree)
    require("#[global_allocator]" in (worktree / "crates/evm/src/lib.rs").read_text()
            and "reth_cli_util::allocator::Allocator" in (worktree / "crates/evm/src/lib.rs").read_text(),
            "EVM test allocator has not been integrated")
    require(TEST.rsplit("::", 1)[-1] in (worktree / "crates/evm/src/evm.rs").read_text(),
            "clock calibration test has not been integrated")
    env = dict(os.environ, RUSTFLAGS=RUSTFLAGS, CARGO_INCREMENTAL="0")
    argv = ["cargo", "+1.98.1", "test", "--locked", "--profile", "profiling", "--jobs", "4",
            "-p", "tempo-evm", "--lib", "--no-run", "--message-format=json-render-diagnostics",
            "--features", "alloy-primitives/asm-keccak,alloy-primitives/keccak-cache-global,reth-cli-util/jemalloc"]
    pending = {"schema": 1, "status": "building", "config": reference(config_path),
               "node_build_manifest": reference(cfg["build_manifest"]), "sources": hashes,
               "source_commit": cfg["source_commit"], "adapter": reference(__file__),
               "system": system, "command": argv,
               "environment_set": {"RUSTFLAGS": RUSTFLAGS, "CARGO_INCREMENTAL": "0"},
               "limits": {"build_wall_seconds": BUILD_SECONDS, "build_log_bytes": BUILD_BYTES,
                          "sample_wall_seconds": SAMPLE_SECONDS, "sample_log_bytes": SAMPLE_BYTES,
                          "disk_floor_bytes": DISK_FLOOR, "mem_available_floor_bytes": MEM_AVAILABLE_FLOOR},
               "scope": "Empty-clock floor only; EVM test dev-dependency graph differs from node."}
    save(out / "build-start.json", pending)
    result = run_bounded(argv, worktree, env, out / "build.log", BUILD_SECONDS, BUILD_BYTES)
    final = dict(pending, process=result, status="inconclusive")
    try:
        require(result["exit_code"] == 0 and result["stop_reason"] is None, "calibration build failed")
        require(source_hashes(worktree) == hashes, "source/lock changed during calibration build")
        artifacts = []
        for line in (out / "build.log").read_text().splitlines():
            try:
                row = json.loads(line)
            except json.JSONDecodeError:
                continue
            if row.get("reason") == "compiler-artifact" and row.get("executable"):
                if row["target"]["name"] == "tempo_evm" and row["profile"]["test"]:
                    artifacts.append(row)
        require(len(artifacts) == 1, "missing/ambiguous EVM calibration artifact")
        artifact = artifacts[0]
        require(str(artifact["profile"]["opt_level"]) == "3"
                and artifact["profile"]["debug_assertions"] is False, "calibration is not optimized")
        final.update(status="built", artifact=artifact, binary=reference(artifact["executable"]),
                     sources_unchanged=True)
    except (ValueError, KeyError, OSError) as error:
        final["error"] = str(error)
    save(out / "build.json", final)
    require(final["status"] == "built", final.get("error", "build failed"))


def parse_clock(path):
    raw = Path(path).read_bytes()
    require(len(raw) <= SAMPLE_BYTES and raw.endswith(b"\n"), "oversized/truncated clock output")
    values, summaries = {}, []
    for line in raw.decode().splitlines():
        prefix = "consumed_candidate_disposal_clock "
        if prefix in line:
            lead, body = line.split(prefix, 1)
            require(not lead or lead == "test " + TEST + " ... ", "unexpected clock prefix")
            match = re.fullmatch(r"kind=(reuse|fallback) samples=16384 p50_ns=(\d+) p99_ns=(\d+) max_ns=(\d+)", body)
            require(match is not None and match[1] not in values, "malformed/duplicate clock path")
            p50, p99, maximum = map(int, match.groups()[1:])
            require(0 <= p50 <= p99 <= maximum < 2**64, "clock quantile bounds")
            values[match[1]] = {"samples": 16384, "p50_ns": p50, "p99_ns": p99, "max_ns": maximum}
        elif line.startswith("test result: "):
            summaries.append(line)
        else:
            require(not line or line in ("running 1 test", "ok", "test " + TEST + " ... ok"),
                    "unexpected clock process output")
    require(list(values) == ["reuse", "fallback"], "missing/reordered clock paths")
    require(len(summaries) == 1 and re.fullmatch(
        r"test result: ok\. 1 passed; 0 failed; 0 ignored; 0 measured; \d+ filtered out; finished in [0-9.]+s",
        summaries[0]), "clock process did not execute exactly one successful test")
    return values


def sample(config_path, phase, boundary):
    require(re.fullmatch(r"(baseline|feature)-[1-3]", phase), "invalid phase")
    require(boundary in ("pre", "post"), "invalid boundary")
    cfg, worktree = check_config(config_path)
    environment()
    assert_idle()
    out = Path(cfg["output"]).resolve()
    build = read(out / "build.json")
    require(build["status"] == "built" and build["config"] == reference(config_path), "unbound clock build")
    require(source_hashes(worktree) == build["sources"], "clock sources changed")
    require(reference(build["binary"]["path"]) == build["binary"], "clock binary changed")
    attempt = out / (phase + "-" + boundary)
    attempt.mkdir()  # A failed or partial sample is evidence, never a retry slot.
    if boundary == "post":
        require(read(out / (phase + "-pre") / "result.json")["status"] == "passed", "missing pre calibration")
    save(attempt / "start.json", {"phase": phase, "boundary": boundary, "at_unix_ns": time.time_ns(),
                                 "config": reference(config_path), "build": reference(out / "build.json")})
    records = []
    status, error = "passed", None
    try:
        for role, cpus in CPU_SETS.items():
            require(cpu_set(cpus) <= os.sched_getaffinity(0), "validator CPUs unavailable to calibration")
            assert_idle()
            argv = ["taskset", "--cpu-list", cpus, build["binary"]["path"], TEST,
                    "--ignored", "--exact", "--nocapture", "--test-threads=1"]
            record = run_bounded(argv, worktree, dict(os.environ), attempt / (role + ".log"),
                                 SAMPLE_SECONDS, SAMPLE_BYTES)
            record.update(role=role, cpus=cpus, binary=build["binary"])
            save(attempt / (role + "-process.json"), record)
            records.append(record)
            require(record["exit_code"] == 0 and record["stop_reason"] is None, "clock process failed")
            record["clock"] = parse_clock(attempt / (role + ".log"))
        require(source_hashes(worktree) == build["sources"], "sources changed during calibration")
        require(reference(build["binary"]["path"]) == build["binary"], "clock binary changed during calibration")
        assert_idle()
    except (ValueError, OSError, KeyError) as failure:
        status, error = "inconclusive", str(failure)
    save(attempt / "result.json", {"status": status, "error": error, "phase": phase, "boundary": boundary,
                                   "finished_unix_ns": time.time_ns(), "processes": records,
                                   "config": reference(config_path), "build": reference(out / "build.json")})
    require(status == "passed", error or "calibration failed")


def interrupted(signum, _frame):
    global STOP
    STOP = signum


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("environment")
    build = commands.add_parser("build")
    build.add_argument("--config", required=True, type=Path)
    samples = commands.add_parser("sample")
    samples.add_argument("--config", required=True, type=Path)
    samples.add_argument("--phase", required=True)
    samples.add_argument("--boundary", required=True, choices=("pre", "post"))
    args = parser.parse_args()
    signal.signal(signal.SIGTERM, interrupted)
    signal.signal(signal.SIGINT, interrupted)
    try:
        if args.command == "environment":
            environment()
        elif args.command == "build":
            compile_clock(args.config.resolve(strict=True))
        else:
            sample(args.config.resolve(strict=True), args.phase, args.boundary)
    except (ValueError, OSError, KeyError, subprocess.SubprocessError) as error:
        print(json.dumps({"status": "inconclusive", "reason": str(error)}))
        return 1
    print(json.dumps({"status": "passed", "operation": args.command}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
