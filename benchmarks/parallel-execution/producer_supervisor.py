#!/usr/bin/env python3
"""Source-only prototype: one stock-txgen producer diagnostic, no setup or publication.

CLI: producer_supervisor.py --config BOUND.json --output-dir NEW_ATTEMPT_DIRECTORY
The workflow supplies source/build/setup/host evidence. This program verifies the
local file bindings; it cannot attest that a host is idle or an RPC is a real node.
"""

from __future__ import annotations

import argparse
import dataclasses
import hashlib
import json
import os
from pathlib import Path
import re
import resource
import selectors
import shutil
import signal
import subprocess
import sys
import time
from typing import Any


TXGEN_COMMIT = "8ca73369c4b42ffffaf40066bbde8673141049c1"
PRESET_COMMIT = "d85219193b7e523c020f60a109f049dc9fa98e60"
RPC = "http://127.0.0.1:8545"
CONTROLS = {
    "duration_seconds": 60, "seed": 99, "signing_workers": 2,
    "deferred_signing": False, "gas_weighted_mix": True, "accounts": 1000,
    "token_count": 4, "bloat_gib": 100, "hardfork": "T14",
    "gas_weights": {"public_transfer": 80, "public_mint": 5, "mpp_open_only": 15},
}
TX_START = "starting transaction generation: output=stdout count=None duration=Some(60s) signing_workers=2"
WORK_START = "starting workload generation: count=None duration=Some(60s) signing_workers=2"
GAS_ITEMS = [('Template("public_transfer")', 80), ('Template("public_mint")', 5),
             ('Sequence("mpp_open_only")', 15)]
HEX64 = re.compile(r"[0-9a-f]{64}\Z")
HEX40 = re.compile(r"[0-9a-f]{40}\Z")
ALLOWED_ENV = {"PATH", "HOME", "TMPDIR", "LC_ALL", "TXGEN_ACCOUNTS",
               "TXGEN_TIP20_TOKENS", "TXGEN_EXISTING_RECIPIENTS_START",
               "TXGEN_EXISTING_RECIPIENTS_END"}


class Invalid(ValueError):
    pass


@dataclasses.dataclass(frozen=True)
class Limits:
    # No configuration or CLI overrides. Private test injection does not change argv.
    timeout_ns: int = 180_000_000_000
    term_grace_ns: int = 5_000_000_000
    kill_reap_ns: int = 5_000_000_000
    stderr_bytes: int = 16 * 1024 * 1024
    consumer_bytes: int = 4096
    minimum_workload_ns: int = 60_000_000_000
    free_reserve_bytes: int = 1024 * 1024 * 1024
    disk_check_ns: int = 1_000_000_000


PRODUCTION_LIMITS = Limits()


def require(value: Any, message: str) -> None:
    if not value:
        raise Invalid(message)


def digest(path: Path) -> str:
    value = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            value.update(block)
    return value.hexdigest()


def read_json(path: Path) -> dict[str, Any]:
    require(path.stat().st_size <= 2 * 1024 * 1024, f"oversized JSON: {path}")
    def unique(pairs):
        result = {}
        for key, value in pairs:
            require(key not in result, f"duplicate JSON key: {key}")
            result[key] = value
        return result
    value = json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=unique)
    require(isinstance(value, dict), f"JSON must be an object: {path}")
    require("UNBOUND" not in json.dumps(value).upper(), f"UNBOUND evidence: {path}")
    return value


def verify_file(binding: dict[str, Any], records: list[dict[str, str]], *,
                max_bytes: int = 16 * 1024 * 1024) -> Path:
    require(isinstance(binding, dict), "file binding must be an object")
    path = Path(binding.get("path", ""))
    require(path.is_absolute(), "file binding must use an absolute path")
    require(path.is_file() and not path.is_symlink(), f"not a regular non-symlink file: {path}")
    require(path.stat().st_size <= max_bytes, f"oversized bound evidence: {path}")
    expected = binding.get("sha256", "")
    require(isinstance(expected, str) and HEX64.fullmatch(expected), f"unbound hash: {path}")
    require(digest(path) == expected, f"file hash mismatch: {path}")
    records.append({"path": str(path), "sha256": expected})
    return path


def verify_elf(path: Path) -> None:
    require(os.access(path, os.X_OK), f"binary is not executable: {path}")
    with path.open("rb") as stream:
        require(stream.read(4) == b"\x7fELF", f"binary is not an ELF: {path}")


def manifest(binding: dict[str, Any], records: list[dict[str, str]], status: str) -> dict[str, Any]:
    value = read_json(verify_file(binding, records))
    require(value.get("schema_version") == 1 and value.get("status") == status,
            f"manifest requires schema_version=1/status={status}")
    return value


def validate_config(path: Path) -> tuple[dict[str, Any], list[dict[str, str]]]:
    """No subprocesses, network access, setup, or runtime authority checks here."""
    config = read_json(path)
    require(config.get("schema_version") == 1, "config requires schema_version=1")
    require(re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}", config.get("attempt_id", "")),
            "invalid attempt_id")
    require(config.get("controls") == CONTROLS, "incompatible diagnostic controls")
    require(config.get("publication") == {"e2e_series": False, "slack": False},
            "diagnostic cannot publish e2e series or Slack")
    require(config.get("rpc_url") == RPC, "requires normal live local node A RPC address")
    records = [{"path": str(path), "sha256": digest(path)}]
    bindings = config["bindings"]
    build = manifest(bindings["txgen_build"], records, "verified")
    require(build.get("source_commit") == TXGEN_COMMIT and build.get("source_clean") is True,
            "requires clean stock txgen8ca build evidence")
    verify_file(build["cargo_lock"], records)
    verify_file(build["build_evidence"], records)
    info = build["build"]
    require(info.get("profile") == "release" and info.get("features") == "default",
            "requires official optimized release/default-feature txgen build")
    for name in ("cargo", "rustc", "target", "build_id"):
        require(isinstance(info.get(name), str) and info[name].strip(), f"missing build {name}")
    for name in ("rustflags", "cargo_encoded_rustflags"):
        require(isinstance(info.get(name), str), f"missing effective build {name}")
    verify_file(info["cargo_config_evidence"], records)
    producer = verify_file(build["binary"], records, max_bytes=512 * 1024 * 1024)
    verify_elf(producer)

    wc = manifest(bindings["wc_provenance"], records, "verified")
    require(wc.get("implementation") == "GNU coreutils wc", "requires GNU wc")
    version = verify_file(wc["version_evidence"], records).read_text(encoding="utf-8")
    require(version.startswith("wc (GNU coreutils) "), "missing bound GNU wc version evidence")
    consumer = verify_file(wc["binary"], records, max_bytes=512 * 1024 * 1024)
    verify_elf(consumer)

    bundle = manifest(bindings["spec_bundle"], records, "verified")
    require(bundle.get("preset") == "public-mix" and bundle.get("source_commit") == PRESET_COMMIT,
            "requires pinned official public-mix spec bundle")
    require(bundle.get("gas_weights") == CONTROLS["gas_weights"], "incompatible gas weights")
    spec = verify_file(bundle["entry"], records)
    require(3 <= len(bundle.get("dependencies", [])) <= 16,
            "retain a bounded bundle including mpp and both ABI dependencies")
    for dependency in bundle["dependencies"]:
        verify_file(dependency, records)
    environment = config["environment"]
    require(isinstance(environment, dict) and set(environment) <= ALLOWED_ENV,
            "unreviewed runtime environment override")
    require(all(isinstance(k, str) and isinstance(v, str) and "\x00" not in v
                for k, v in environment.items()), "invalid environment value")
    require(environment.get("LC_ALL") == "C" and environment.get("TXGEN_ACCOUNTS") == "1000",
            "requires LC_ALL=C and TXGEN_ACCOUNTS=1000")
    require(environment.get("PATH"), "explicit PATH is required")
    spec_env = {k: v for k, v in environment.items() if k.startswith("TXGEN_")}
    require(spec_env == bundle.get("environment"), "spec environment differs from bound bundle")
    require(set(spec_env) == {"TXGEN_ACCOUNTS", "TXGEN_TIP20_TOKENS",
                              "TXGEN_EXISTING_RECIPIENTS_START", "TXGEN_EXISTING_RECIPIENTS_END"},
            "incomplete public-mix environment")
    tokens = json.loads(spec_env["TXGEN_TIP20_TOKENS"])
    require(tokens == [f"0x20c000000000000000000000{i:016x}" for i in range(4)],
            "requires the four official TIP-20 token addresses")
    require(int(spec_env["TXGEN_EXISTING_RECIPIENTS_START"]) == 10000 and
            int(spec_env["TXGEN_EXISTING_RECIPIENTS_END"]) > 10000, "invalid existing recipient range")

    setup = manifest(bindings["setup_confirmation"], records, "confirmed")
    require(setup.get("chain_id") == 1337 and setup.get("rpc_url") == RPC and
            setup.get("spec_bundle_sha256") == bindings["spec_bundle"]["sha256"],
            "setup evidence does not bind this chain/RPC/spec")
    setup_path = verify_file(setup["setup_state"], records)
    verify_file(setup["receipt_evidence"], records)
    # These are workflow attestations retained by hash, not independent live checks.
    context = manifest(bindings["workflow_context"], records, "verified")
    require(re.fullmatch(r"[0-9]+", str(context.get("run_id", ""))), "missing workflow run identity")
    require(HEX40.fullmatch(context.get("workflow_sha", "")), "missing exact workflow source")
    require(context.get("attempt_id") == config["attempt_id"], "workflow attempt identity differs")
    for name in ("host_evidence", "node_evidence", "measurement_exclusivity_evidence"):
        verify_file(context[name], records)
    require(context.get("responsibility") == "workflow_verified_before_launch",
            "workflow must own host/node/exclusivity qualification")

    expected = [str(producer), "generate", "-s", str(spec), "--duration", "60s", "--seed", "99",
                "--rpc", RPC, "--gas-weighted-mix", "--setup-state-in", str(setup_path)]
    require(config.get("producer_argv") == expected,
            "producer argv must be exact stock duration-only/full-signing command")
    require(config.get("consumer_argv") == [str(consumer), "-l", "-c"],
            "consumer argv must be exact bound GNU wc -l -c")
    return config, records


def duration_ns(value: str) -> int:
    # Rust Duration Debug emits seconds or one subsecond unit, not HH:MM:SS.
    match = re.fullmatch(r"([0-9]+)(?:\.([0-9]+))?(s|ms|µs|ns)", value)
    require(match is not None, f"unknown Rust duration: {value!r}")
    whole, fraction, unit = match.groups()
    scale = {"s": 1_000_000_000, "ms": 1_000_000, "µs": 1000, "ns": 1}[unit]
    fraction = fraction or ""
    denominator = 10 ** len(fraction)
    numerator = (int(whole) * denominator + int(fraction or 0)) * scale
    require(numerator % denominator == 0, "duration has finer than nanosecond precision")
    return numerator // denominator


def qualify(stderr: bytes, stdout: bytes, producer_elapsed_ns: int, pipeline_elapsed_ns: int,
            limits: Limits) -> dict[str, Any]:
    """Parse complete retained bytes; callers separately require clean child exits."""
    text = stderr.decode("utf-8", errors="strict")
    require(text.endswith("\n"), "producer stderr lacks terminal newline")
    lines = text.splitlines()
    require(lines.count(TX_START) == 1 and lines.count(WORK_START) == 1,
            "missing/duplicate/incompatible producer or workload start marker")
    require(not re.search(r"(?i)broken.?pipe|\b(?:error|failed|panic|panicked)\b", text),
            "producer stderr contains failure evidence")
    # Unknown startup/completion variants must not be hidden beside the valid marker.
    require(sum(line.startswith("starting transaction generation:") for line in lines) == 1 and
            sum(line.startswith("starting workload generation:") for line in lines) == 1,
            "extra startup markers")
    work = [(i, re.fullmatch(r"workload generation completed: prepared=([0-9]+) elapsed=(\S+)", line))
            for i, line in enumerate(lines) if line.startswith("workload generation completed:")]
    outer = [(i, re.fullmatch(r"transaction generation completed: elapsed=(\S+)", line))
             for i, line in enumerate(lines) if line.startswith("transaction generation completed:")]
    require(len(work) == 1 and work[0][1] is not None and len(outer) == 1 and outer[0][1] is not None,
            "missing/duplicate/malformed final completion markers (including swallowed BrokenPipe)")
    work_i, work_match = work[0]
    outer_i, outer_match = outer[0]
    start_i = lines.index(WORK_START)
    require(lines.index(TX_START) < start_i < work_i < outer_i == len(lines) - 1,
            "invalid completion marker ordering or trailing producer output")
    prefetch_start = [i for i, line in enumerate(lines) if line == "starting nonce prefetch"]
    prefetch_done = [i for i, line in enumerate(lines)
                     if re.fullmatch(r"nonce prefetch completed: elapsed=\S+", line)]
    require(len(prefetch_start) == len(prefetch_done) == 1 and
            lines.index(TX_START) < prefetch_start[0] < prefetch_done[0] < start_i,
            "missing or misplaced nonce prefetch evidence")
    prefetch_elapsed = duration_ns(lines[prefetch_done[0]].split("elapsed=", 1)[1])
    samples = []
    for i, line in enumerate(lines):
        if line.startswith("gas sample:"):
            match = re.fullmatch(r"gas sample: item=(.+) block_gas=([0-9]+) target_weight=([0-9]+)", line)
            require(match is not None and int(match.group(2)) > 0, "invalid gas sample")
            samples.append((i, match.group(1), int(match.group(2)), int(match.group(3))))
    initial = [s for s in samples if prefetch_done[0] < s[0] < start_i]
    periodic = [s for s in samples if start_i < s[0] < work_i]
    require(len(initial) == 3 and len(periodic) >= 3 and len(periodic) % 3 == 0 and
            len(initial) + len(periodic) == len(samples), "missing/incomplete initial or periodic calibration")
    for group in (initial, periodic):
        for index, sample in enumerate(group):
            require((sample[1], sample[3]) == GAS_ITEMS[index % 3], "calibration order/item/weight differs")
    count = int(work_match.group(1))
    elapsed = duration_ns(work_match.group(2))
    outer_elapsed = duration_ns(outer_match.group(1))
    require(limits.minimum_workload_ns <= elapsed <= outer_elapsed <= producer_elapsed_ns <= pipeline_elapsed_ns,
            "logged and monotonic elapsed bounds do not close")
    require(pipeline_elapsed_ns <= limits.timeout_ns, "final pipeline observation exceeds absolute timeout")
    require(prefetch_elapsed <= outer_elapsed, "nonce prefetch elapsed exceeds whole generation")
    counts = re.fullmatch(rb"\s*([0-9]+)\s+([0-9]+)\s*\n", stdout)
    require(counts is not None, "malformed GNU wc totals")
    delivered, byte_count = map(int, counts.groups())
    require(delivered == count and count > 0 and byte_count >= count,
            "wc output count and final prepared count do not close")
    rate = count * 1_000_000_000 / elapsed
    conservative_rate = count * 1_000_000_000 / pipeline_elapsed_ns
    # flush() completes writes into the pipe, not wc's EOF. Without source clock
    # anchors, the full pipeline is a conservative upper bound on the workload's
    # drain-inclusive elapsed; initial calibration makes that bound deliberately loose.
    numerator = count * 1_000_000_000
    decision = ("headroom_observed" if numerator >= 55_000 * pipeline_elapsed_ns else
                "below_target_supply" if numerator < 50_000 * elapsed else
                "marginal_supply" if numerator >= 50_000 * pipeline_elapsed_ns and numerator < 55_000 * elapsed else
                "inconclusive_rate_bracket")
    return {"decision": decision, "completed_output_count": count, "output_bytes": byte_count,
            "workload_elapsed_ns": elapsed, "logged_generation_elapsed_ns": outer_elapsed,
            "nonce_prefetch_elapsed_ns": prefetch_elapsed,
            "producer_elapsed_upper_bound_ns": producer_elapsed_ns,
            "pipeline_elapsed_upper_bound_ns": pipeline_elapsed_ns,
            "producer_handoff_output_per_second": rate,
            "whole_pipeline_output_per_second": conservative_rate,
            "drain_inclusive_rate_bracket": {"lower": conservative_rate, "upper": rate},
            "extra_drain_elapsed_upper_bound_ns": pipeline_elapsed_ns - elapsed,
            "drain_bound_limit": "Also contains process startup/nonce prefetch/initial calibration and exit observation delay; not pure consumer tail.",
            "initial_calibration_rounds": 1, "periodic_calibration_rounds": len(periodic) // 3,
            "gas_samples": [{"source_line": s[0] + 1, "item": s[1], "block_gas": s[2],
                             "target_weight": s[3]} for s in samples]}


def write_new_json(path: Path, value: Any) -> None:
    with path.open("x", encoding="utf-8") as stream:
        json.dump(value, stream, indent=2, sort_keys=True)
        stream.write("\n")


def group_alive(pgid: int) -> bool:
    try:
        os.killpg(pgid, 0)
        return True
    except ProcessLookupError:
        return False


def signal_group(pgid: int, sig: int) -> None:
    try:
        os.killpg(pgid, sig)
    except ProcessLookupError:
        pass


def process_owner(pid: int, role: str) -> dict[str, Any]:
    """Retain Linux PID-reuse guards for the workflow's independent finalizer."""
    raw = Path(f"/proc/{pid}/stat").read_text()
    fields = raw.rsplit(") ", 1)[1].split()
    return {"pid": pid, "pgid": int(fields[2]), "sid": int(fields[3]),
            "start_ticks": int(fields[19]), "role": role,
            "boot_id": Path("/proc/sys/kernel/random/boot_id").read_text().strip(),
            "recorded_monotonic_ns": time.monotonic_ns()}


def read_proc_evidence(pid: int, name: str) -> str:
    require(name in ("status", "limits", "cgroup"), "unreviewed proc evidence")
    with Path(f"/proc/{pid}/{name}").open("rb") as stream:
        raw = stream.read(16 * 1024 + 1)
    require(len(raw) <= 16 * 1024, "proc evidence size bound")
    return raw.decode("utf-8", errors="strict")


def identity_fields(status: str) -> dict[str, list[int]]:
    output = {}
    for line in status.splitlines():
        key, _, value = line.partition(":")
        if key in ("Uid", "Gid", "Groups"):
            require(key not in output, "duplicate proc identity field")
            require(all(x.isdecimal() for x in value.split()), "invalid proc identity")
            output[key] = [int(x) for x in value.split()]
    require(set(output) == {"Uid", "Gid", "Groups"}, "missing proc identity")
    require(len(output["Uid"]) == len(output["Gid"]) == 4, "incomplete proc credentials")
    output["Groups"].sort()
    return output


def resource_snapshot(pid: int) -> dict[str, Any]:
    """One launch observation, never periodic sampling or an atomic snapshot claim."""
    before = time.monotonic_ns()
    identity = identity_fields(read_proc_evidence(pid, "status"))
    affinity = sorted(os.sched_getaffinity(pid))
    require(affinity, "empty process affinity")
    nofile = list(resource.prlimit(pid, resource.RLIMIT_NOFILE))
    limits = read_proc_evidence(pid, "limits")
    require("Max open files" in limits, "missing proc NOFILE limit")
    cgroup = read_proc_evidence(pid, "cgroup")
    require(any(line.startswith("0::/") for line in cgroup.splitlines()), "cgroup v2 evidence required")
    return {"pid": pid, "before_monotonic_ns": before, "after_monotonic_ns": time.monotonic_ns(),
            "credentials": identity, "affinity": affinity, "rlimit_nofile": nofile,
            "limits_text": limits, "cgroup_text": cgroup,
            "observation": "launch_only_multi_read_not_atomic"}


def verify_inherited_resources(parent: dict[str, Any], child: dict[str, Any]) -> None:
    for field in ("credentials", "affinity", "rlimit_nofile", "cgroup_text"):
        require(child[field] == parent[field], f"child {field} differs from supervisor")


class OwnedGroup:
    """Retain the waitable leader until no further group signal can be issued.

    WNOWAIT leaves an exited leader as our zombie child, reserving its numeric
    PID/PGID. Never poll()/wait() the Popen elsewhere. A missing waitable child
    invalidates ownership rather than authorizing killpg of a recycled number.
    """
    def __init__(self, process: subprocess.Popen):
        self.process = process
        self.exit_info = None
        self.ownership_lost = False
        self.signals_closed = False
        self.reaped = False

    def observe(self) -> None:
        if self.reaped or self.ownership_lost:
            return
        try:
            status = os.waitid(os.P_PID, self.process.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT)
        except ChildProcessError as error:
            self.ownership_lost = True
            raise Invalid("direct-child ownership lost; refusing numeric process-group signals") from error
        if status is not None and self.exit_info is None:
            require(status.si_code in (os.CLD_EXITED, os.CLD_KILLED, os.CLD_DUMPED),
                    "unexpected waitid exit status")
            code = status.si_status if status.si_code == os.CLD_EXITED else -status.si_status
            self.exit_info = {"exit_observed_returncode": code,
                              "exit_observed_monotonic_ns": time.monotonic_ns()}

    def send(self, sig: int) -> None:
        require(not self.signals_closed and not self.reaped and not self.ownership_lost,
                "group signaling is closed or leader ownership is lost")
        self.observe()  # Verifies waitability without reaping even a completed leader.
        signal_group(self.process.pid, sig)

    def close_signals(self) -> None:
        self.signals_closed = True

    def reap(self) -> dict[str, Any] | None:
        require(self.signals_closed, "must close group signaling before releasing leader PID")
        if self.reaped or self.ownership_lost:
            return None
        try:
            pid, status, usage = os.wait4(self.process.pid, os.WNOHANG)
        except ChildProcessError as error:
            self.ownership_lost = True
            raise Invalid("direct-child ownership lost at final reap") from error
        if not pid:
            return None
        self.process.returncode = os.waitstatus_to_exitcode(status)
        self.reaped = True
        return {"returncode": self.process.returncode, "reaped_monotonic_ns": time.monotonic_ns(),
                "user_seconds": usage.ru_utime, "system_seconds": usage.ru_stime,
                "maxrss_kib": usage.ru_maxrss}


def live_group_members(groups: dict[str, OwnedGroup]) -> list[dict[str, Any]]:
    """Endpoint/cleanup scan only, while leaders are still reserved; never timed polling.

    Only our WNOWAIT-confirmed exited leaders may be disregarded. A descendant
    with a zombie-looking group leader may still have live threads, so unknown
    members stay unresolved until they disappear. We do not reap other parents'
    children. The workflow remains responsible for its node scopes.
    """
    require(all(not group.signals_closed and not group.reaped for group in groups.values()),
            "cannot inspect numeric groups after releasing ownership")
    require(not any(group.ownership_lost for group in groups.values()), "group ownership was lost")
    ids = {group.process.pid for group in groups.values()}
    confirmed_exited = {group.process.pid for group in groups.values() if group.exit_info is not None}
    members = []
    for path in Path("/proc").iterdir():
        if not path.name.isdigit():
            continue
        try:
            fields = (path / "stat").read_text().rsplit(") ", 1)[1].split()
        except (FileNotFoundError, ProcessLookupError):
            continue
        if int(fields[2]) in ids and int(path.name) not in confirmed_exited:
            members.append({"pid": int(path.name), "pgid": int(fields[2]), "sid": int(fields[3]),
                            "state": fields[0], "start_ticks": int(fields[19])})
    return members


def commit_result(output: Path, result: dict[str, Any], pending: list[int], old_handlers: dict) -> None:
    """Publish one final result after handling signals observed during serialization.

    After restoring CLI dispositions, a new termination must fail the outer
    process/lifecycle gate. The workflow must require helper exit 0 and a
    noncancelled run, not merely a JSON result found on disk.
    """
    staging = output / "result.pending.json"
    try:
        write_new_json(staging, result)
    finally:
        for sig, previous in old_handlers.items():
            signal.signal(sig, previous)
    # No supervisor handler remains to append after this check. CLI termination
    # after this point is handled by the restored dispositions and outer exit gate.
    if pending:
        result["received_signals"] = pending.copy()
        result["status"] = "invalid"
        result["decision"] = None
        if "external signal received" not in result["errors"]:
            result["errors"].append("external signal received")
        with staging.open("w", encoding="utf-8") as stream:
            json.dump(result, stream, indent=2, sort_keys=True)
            stream.write("\n")
    os.link(staging, output / "result.json")  # Atomic publish, refuses an existing result.
    staging.unlink()


def run(config_path: Path, output: Path, *, _limits: Limits = PRODUCTION_LIMITS) -> dict[str, Any]:
    """Create one immutable attempt. Private limits are solely a fake-process test seam."""
    require(os.name == "posix" and all(hasattr(os, name) for name in ("wait4", "waitid", "WNOWAIT")),
            "Linux wait4/waitid(WNOWAIT) is required")
    require(output.is_absolute() and output.parent.is_dir(), "attempt parent must already exist")
    output.mkdir(mode=0o700)  # Deliberately fails if the attempt exists; no retry/overwrite.
    limits = _limits
    result: dict[str, Any] = {
        "schema_version": 1, "status": "invalid", "decision": None, "errors": [],
        "scope": "producer_output_with_live_calibration; no accepted-TPS or CPU-cause claim",
        "test_limits": limits != PRODUCTION_LIMITS, "limits": dataclasses.asdict(limits),
        "local_file_bindings_verified": False,
        "workflow_responsibilities_independently_verified": False,
        "workflow_responsibilities": ["host role/source binding", "live node/setup qualification",
                                      "no overlapping task-owned measurement"],
        "processes": {}, "received_signals": [], "signals_sent": [],
        "stream_eof_observed_ns": {}, "marker_observations": [],
        "disk_observations": [],
    }
    children: dict[str, subprocess.Popen] = {}
    groups: dict[str, OwnedGroup] = {}
    bindings: list[dict[str, str]] = []
    streams: dict[str, Any] = {}
    files: dict[str, Any] = {}
    byte_counts: dict[str, int] = {}
    selector = selectors.DefaultSelector()
    old_handlers = {}
    termination_at = None
    kill_at = None
    start = None
    signal_pending: list[int] = []
    marker_tail = b""
    last_disk_check = None
    remaining_group_members = None

    def handler(signum, _frame):
        # Idempotent shutdown; repeated signals are evidence, never a reentrant finalizer.
        if len(signal_pending) < 16:
            signal_pending.append(signum)

    def observe() -> None:
        for role, group in groups.items():
            try:
                group.observe()
                if group.exit_info is not None:
                    result["processes"][role].update(group.exit_info)
            except Invalid as error:
                if str(error) not in result["errors"]:
                    result["errors"].append(str(error))

    def send_groups(sig: int, now: int) -> None:
        for role, group in groups.items():
            try:
                group.send(sig)
                result["signals_sent"].append({"role": role, "signal": signal.Signals(sig).name[3:],
                                                "monotonic_ns": now})
            except (Invalid, OSError) as error:
                result["errors"].append(f"{role} signal refused: {error}")

    def begin_termination(reason: str, now: int) -> None:
        nonlocal termination_at
        if reason not in result["errors"]:
            result["errors"].append(reason)
        if termination_at is None:
            termination_at = now
            send_groups(signal.SIGTERM, now)

    def close_safely(stream) -> None:
        if stream is not None and not stream.closed:
            try:
                stream.close()
            except OSError as error:
                result["errors"].append(f"stream close/flush failed: {error}")

    def disk_observation() -> int:
        nonlocal last_disk_check
        before = time.monotonic_ns()
        free = shutil.disk_usage(output).free
        last_disk_check = time.monotonic_ns()
        result["disk_observations"].append({"before_monotonic_ns": before,
                                             "after_monotonic_ns": last_disk_check,
                                             "free_bytes": free})
        result["minimum_observed_free_bytes"] = min(
            result.get("minimum_observed_free_bytes", free), free)
        return free

    try:
        for sig in (signal.SIGINT, signal.SIGTERM):
            old_handlers[sig] = signal.signal(sig, handler)
        require(old_handlers[signal.SIGTERM] == signal.SIG_DFL and
                old_handlers[signal.SIGINT] in (signal.SIG_DFL, signal.default_int_handler),
                "requires normal CLI termination dispositions for the final process-exit gate")
        supervisor_resources = resource_snapshot(os.getpid())
        result["supervisor_resources"] = supervisor_resources
        write_new_json(output / "supervisor-owner.json", {
            **process_owner(os.getpid(), "supervisor"), "resources": supervisor_resources,
        })
        config, bindings = validate_config(config_path.resolve())
        require(disk_observation() >= limits.free_reserve_bytes + limits.stderr_bytes + 4 * 1024 * 1024,
                "insufficient disk reserve for complete bounded evidence")
        result.update(attempt_id=config["attempt_id"], local_file_bindings_verified=True,
                      config_sha256=digest(config_path), bindings=bindings,
                      producer_argv=config["producer_argv"], consumer_argv=config["consumer_argv"])
        write_new_json(output / "config.json", config)
        write_new_json(output / "attempt.json", {
            "attempt_id": config["attempt_id"], "config_sha256": result["config_sha256"],
            "helper_sha256": digest(Path(__file__).resolve()), "bindings": bindings,
            "clock_bracket": {"monotonic_ns": time.monotonic_ns(), "realtime_ns": time.time_ns()},
            "workflow_responsibilities_independently_verified": False,
        })
        require(not signal_pending, "signal received before child launch")
        start = time.monotonic_ns()
        producer = subprocess.Popen(config["producer_argv"], stdin=subprocess.DEVNULL,
                                    stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                    env=config["environment"], start_new_session=True, close_fds=True)
        children["producer"] = producer
        groups["producer"] = OwnedGroup(producer)
        result["processes"]["producer"] = {"pid": producer.pid, "pgid": producer.pid,
                                            "launched_monotonic_ns": start}
        owner = process_owner(producer.pid, "producer")
        owner["resources"] = resource_snapshot(producer.pid)
        verify_inherited_resources(supervisor_resources, owner["resources"])
        result["processes"]["producer"]["resources"] = owner["resources"]
        require(owner["pgid"] == owner["sid"] == producer.pid, "producer session isolation failed")
        write_new_json(output / "producer-owner.json", {
            **owner, "attempt_id": config["attempt_id"], "config_sha256": result["config_sha256"],
            "argv": config["producer_argv"], "launched_monotonic_ns": start,
        })
        try:
            consumer_start = time.monotonic_ns()
            consumer = subprocess.Popen(config["consumer_argv"], stdin=producer.stdout,
                                        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                        env=config["environment"], start_new_session=True, close_fds=True)
            children["consumer"] = consumer
            groups["consumer"] = OwnedGroup(consumer)
            result["processes"]["consumer"] = {"pid": consumer.pid, "pgid": consumer.pid,
                                                "launched_monotonic_ns": consumer_start}
            owner = process_owner(consumer.pid, "consumer")
            owner["resources"] = resource_snapshot(consumer.pid)
            verify_inherited_resources(supervisor_resources, owner["resources"])
            result["processes"]["consumer"]["resources"] = owner["resources"]
            require(owner["pgid"] == owner["sid"] == consumer.pid, "consumer session isolation failed")
            write_new_json(output / "consumer-owner.json", {
                **owner, "attempt_id": config["attempt_id"], "config_sha256": result["config_sha256"],
                "argv": config["consumer_argv"], "launched_monotonic_ns": consumer_start,
            })
        finally:
            producer.stdout.close()  # Parent never reads or retains signed workload bytes.
        streams = {"producer.stderr": producer.stderr, "consumer.stdout": consumer.stdout,
                   "consumer.stderr": consumer.stderr}
        for name, stream in streams.items():
            files[name] = (output / name).open("xb")
            byte_counts[name] = 0
            os.set_blocking(stream.fileno(), False)
            selector.register(stream, selectors.EVENT_READ, name)

        while True:
            now = time.monotonic_ns()
            observe()
            if signal_pending:
                begin_termination("external signal received", now)
            if now - start >= limits.timeout_ns:
                begin_termination("absolute pipeline timeout", now)
            if now - last_disk_check >= limits.disk_check_ns:
                if disk_observation() < limits.free_reserve_bytes:
                    begin_termination("free disk fell below reserve", time.monotonic_ns())
            if any(group.exit_info is not None and group.exit_info["exit_observed_returncode"] != 0
                   for group in groups.values()):
                begin_termination("child exited unsuccessfully", now)
            if any(group.ownership_lost for group in groups.values()):
                begin_termination("direct-child ownership lost", now)
            if termination_at is not None and kill_at is None and now - termination_at >= limits.term_grace_ns:
                kill_at = now
                send_groups(signal.SIGKILL, now)
            all_exited = all(group.exit_info is not None for group in groups.values())
            if all_exited and not any(group.ownership_lost for group in groups.values()):
                remaining_group_members = live_group_members(groups)
                if not remaining_group_members and not selector.get_map():
                    break
                if remaining_group_members and termination_at is None:
                    begin_termination("descendants outlived direct children", now)
            if kill_at is not None and now - kill_at >= limits.kill_reap_ns:
                result["errors"].append("cleanup deadline exceeded after SIGKILL")
                break
            for key, _events in selector.select(0.05):
                data = os.read(key.fd, 64 * 1024)
                if not data:
                    result["stream_eof_observed_ns"][key.data] = time.monotonic_ns()
                    selector.unregister(key.fileobj)
                    key.fileobj.close()
                    continue
                name = key.data
                cap = limits.stderr_bytes if name == "producer.stderr" else limits.consumer_bytes
                remaining = max(0, cap - byte_counts[name])
                files[name].write(data[:remaining])
                byte_counts[name] += len(data)
                if name == "producer.stderr":
                    marker_lines = (marker_tail + data[:remaining]).split(b"\n")
                    marker_tail = marker_lines.pop()[-4096:]
                    for line in marker_lines:
                        for prefix in (b"starting transaction generation:", b"starting workload generation:",
                                       b"workload generation completed:", b"transaction generation completed:"):
                            if line.startswith(prefix) and len(result["marker_observations"]) < 16:
                                result["marker_observations"].append({
                                    "kind": prefix.decode().rstrip(":"),
                                    "observed_monotonic_ns": time.monotonic_ns(),
                                })
                                break
                if len(data) > remaining:
                    begin_termination(f"{name} evidence cap exceeded", time.monotonic_ns())
            # No sampler/profiler or periodic RPC probes run alongside the producer.
    except (Exception, KeyboardInterrupt) as error:
        result["errors"].append(f"{type(error).__name__}: {error}")
    finally:
        # This also covers partial spawn/registration/disk failures. Always close parent
        # descriptors, signal owned sessions, and attempt to reap both direct children.
        result["evidence_reached_eof"] = bool(streams) and not selector.get_map()
        for stream in streams.values():
            close_safely(stream)
        selector.close()
        for child in children.values():
            for stream in (child.stdin, child.stdout, child.stderr):
                close_safely(stream)
        for stream in files.values():
            close_safely(stream)
        observe()
        try:
            remaining_group_members = live_group_members(groups) if groups else []
        except (Invalid, OSError) as error:
            result["errors"].append(f"final group scan failed: {error}")
            remaining_group_members = None
        if groups and (remaining_group_members is None or remaining_group_members or
                       any(group.exit_info is None for group in groups.values())):
            now = time.monotonic_ns()
            begin_termination("finalizer found live children or descendants", now)
            deadline = (termination_at if termination_at is not None else now) + limits.term_grace_ns
            final_deadline = deadline + limits.kill_reap_ns
            while time.monotonic_ns() < final_deadline:
                observe()
                if all(group.exit_info is not None for group in groups.values()):
                    try:
                        remaining_group_members = live_group_members(groups)
                    except (Invalid, OSError) as error:
                        remaining_group_members = None
                    if remaining_group_members == []:
                        break
                if time.monotonic_ns() >= deadline and kill_at is None:
                    kill_at = time.monotonic_ns()
                    send_groups(signal.SIGKILL, kill_at)
                time.sleep(0.01)
            observe()
        # One-way boundary: no code may signal or inspect these numeric groups
        # after releasing leaders. Close *all* guards before the first wait4.
        for group in groups.values():
            group.close_signals()
        for role, group in groups.items():
            try:
                reaped = group.reap()
                if reaped is not None:
                    result["processes"][role].update(reaped)
            except Invalid as error:
                result["errors"].append(f"final reap failed: {error}")
            result["processes"][role]["ownership_lost"] = group.ownership_lost
        result["received_signals"] = signal_pending.copy()
        result["remaining_group_members_before_reap"] = remaining_group_members
        result["cleanup_complete"] = remaining_group_members == [] and all(
            group.reaped and not group.ownership_lost for group in groups.values())
        if not result["cleanup_complete"]:
            result["errors"].append("owned child/session still live; workflow cleanup required")

    result["evidence_byte_counts"] = byte_counts
    if result["local_file_bindings_verified"]:
        try:
            require(disk_observation() >= limits.free_reserve_bytes, "free disk below reserve after cleanup")
        except Exception as error:
            result["errors"].append(f"post-capture disk reserve: {type(error).__name__}: {error}")
    # Recheck every supplied input after cleanup. Do not silently bless mutable setup/spec/ELF.
    if bindings:
        try:
            for binding in bindings:
                require(digest(Path(binding["path"])) == binding["sha256"],
                        f"bound evidence changed: {binding['path']}")
        except Exception as error:
            result["errors"].append(f"post-capture binding: {type(error).__name__}: {error}")
    if not result["errors"]:
        try:
            require(set(children) == {"producer", "consumer"}, "both children must have launched")
            require(all(child.returncode == 0 for child in children.values()), "nonzero child status")
            require(result["evidence_reached_eof"], "evidence streams did not reach EOF")
            require((output / "consumer.stderr").stat().st_size == 0, "GNU wc emitted stderr")
            producer_end = result["processes"]["producer"]["exit_observed_monotonic_ns"]
            consumer_end = result["processes"]["consumer"]["exit_observed_monotonic_ns"]
            result["accounting"] = qualify((output / "producer.stderr").read_bytes(),
                                            (output / "consumer.stdout").read_bytes(),
                                            producer_end - start, max(producer_end, consumer_end) - start,
                                            limits)
            result["status"] = "valid_output_measurement"
            result["decision"] = result["accounting"]["decision"]
            completions = [m["observed_monotonic_ns"] for m in result["marker_observations"]
                           if m["kind"] == "workload generation completed"]
            if len(completions) == 1:
                result["accounting"]["consumer_eof_minus_workload_marker_observation_ns"] = (
                    result["stream_eof_observed_ns"]["consumer.stdout"] - completions[0])
        except Exception as error:
            result["errors"].append(f"qualification: {type(error).__name__}: {error}")
    result["limits_of_interpretation"] = [
        "Average completed producer output with periodic live calibration and a finite counting consumer.",
        "One-time launch resource reads include actual NOFILE, credentials, affinity and cgroup; no atomic or unchanged-throughout-run claim.",
        "No uninterrupted delivery, real-node acceptance, state/receipt correctness, or CPU stage attribution.",
        "Workflow-supplied host/node/exclusivity attestations are retained by hash, not independently verified here.",
        "WNOWAIT exit observations are upper bounds on child exit; final reap is later, after group signaling closes.",
        "Pipe EOF/marker timestamps are parent observations; signed differences may reflect read ordering, not exact child tail latency.",
        "Free space is observed once per second and at endpoints; other writers can change space between checks.",
        "Below-target output does not isolate signing, preparation, calibration, pipe pressure or host scheduling.",
    ]
    if limits != PRODUCTION_LIMITS:
        result["limits_of_interpretation"].append("Private synthetic-test limits: not a real diagnostic result.")
    # Keep signal handling active during bounded qualification and binding rechecks too.
    result["received_signals"] = signal_pending.copy()
    if signal_pending:
        result["status"] = "invalid"
        result["decision"] = None
        if "external signal received" not in result["errors"]:
            result["errors"].append("external signal received")
    result["finished_realtime_ns"] = time.time_ns()
    result["outer_lifecycle_gate"] = "Require helper exit0 and noncancelled workflow as well as valid JSON; post-handler-restoration termination cannot be qualified from JSON alone."
    commit_result(output, result, signal_pending, old_handlers)
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()
    try:
        result = run(args.config, args.output_dir)
    except (Exception, KeyboardInterrupt) as error:
        print(f"producer supervisor refused: {type(error).__name__}: {error}", file=sys.stderr)
        return 2
    print(json.dumps({"status": result["status"], "decision": result["decision"],
                      "result": str(args.output_dir / "result.json")}))
    return 0 if result["status"] == "valid_output_measurement" else 1


if __name__ == "__main__":
    raise SystemExit(main())
