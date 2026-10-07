#!/usr/bin/env python3
"""Bounded Linux scheduler evidence capture. Does not establish block coverage.

Only the named Engine/builder TIDs are recorded; builder tasks can also execute on
Tokio threads. Keep raw perf.data and validate physical scope coverage separately.
"""
import argparse
import contextlib
import hashlib
import json
import math
import os
from pathlib import Path
import re
import resource
import shutil
import signal
import subprocess
import sys
import time

MIB = 1024 * 1024
FILE_LIMIT = 128 * MIB
EVENTS = ("sched_switch", "sched_wakeup", "sched_wakeup_new")
NAMES = ("engine", "payload-builder")
MAX_RING_EVENTS = len(EVENTS) + 1  # perf also creates a dummy metadata event.
SELF = str(Path(__file__).resolve())


class TraceError(Exception):
    pass


def require(ok, message):
    if not ok:
        raise TraceError(message)


def sha256(path):
    digest = hashlib.sha256()
    with open(path, "rb") as stream:
        for chunk in iter(lambda: stream.read(MIB), b""):
            digest.update(chunk)
    return digest.hexdigest()


def save(path, value):
    Path(path).write_text(json.dumps(value, indent=2) + "\n")


def clocks():
    before = time.monotonic_ns()
    realtime = time.time_ns()
    return {"monotonic_before_ns": before, "realtime_ns": realtime,
            "monotonic_after_ns": time.monotonic_ns()}


def cpu_set(text):
    cpus = set()
    for item in text.strip().split(","):
        require(re.fullmatch(r"\d+(?:-\d+)?", item), "invalid online CPU list")
        endpoints = [int(x) for x in item.split("-")]
        low, high = endpoints[0], endpoints[-1]
        require(0 <= low <= high < 65536, "invalid CPU range")
        cpus.update(range(low, high + 1))
    require(cpus, "no online CPUs")
    return sorted(cpus)


def ring_budget(cpus, page_size):
    # Allow separate data+metadata rings for all tracepoints AND perf's dummy event.
    maximum_pages = (512 * MIB // (len(cpus) * MAX_RING_EVENTS * page_size)) - 1
    require(maximum_pages >= 1, "CPU count exceeds scheduler ring budget")
    pages = 1 << int(math.log2(min(maximum_pages, 8 * MIB // page_size)))
    return {"pages_per_ring": pages, "page_size": page_size,
            "worst_case_bytes": len(cpus) * MAX_RING_EVENTS * (pages + 1) * page_size,
            "assumption": "at most four rings per CPU: three tracepoints plus dummy metadata; no AUX"}


def option(argv, name):
    values = []
    for i, arg in enumerate(argv):
        if arg == name:
            require(i + 1 < len(argv) and not argv[i + 1].startswith("--"), f"missing {name}")
            values.append(argv[i + 1])
        elif arg.startswith(name + "="):
            values.append(arg.split("=", 1)[1])
    require(len(values) == 1, f"expected exactly one {name}")
    return values[0]


def task_identity(directory):
    stat = (directory / "stat").read_text()
    fields = stat[stat.rfind(")") + 2:].split()
    require(len(fields) >= 20, "short /proc stat")
    status = (directory / "status").read_text()
    tgid = re.search(r"^Tgid:\s*(\d+)$", status, re.M)
    require(tgid, "missing task TGID")
    return {"tid": int(directory.name), "tgid": int(tgid[1]),
            "starttime_ticks": int(fields[19]), "comm": (directory / "comm").read_text().strip(),
            "cgroup": (directory / "cgroup").read_text()}


def snapshot(binary, datadirs, proc=Path("/proc")):
    binary = Path(binary).resolve(strict=True)
    expected = {role: str(Path(path).resolve()) for role, path in datadirs.items()}
    require(len(set(expected.values())) == 2, "node data directories must differ")
    matches = {role: [] for role in expected}
    for directory in proc.iterdir():
        if not directory.name.isdecimal():
            continue
        try:
            exe = os.readlink(directory / "exe")
            if exe != str(binary):
                continue
            argv = (directory / "cmdline").read_bytes().rstrip(b"\0").decode().split("\0")
            if "node" not in argv:
                continue
            datadir = option(argv, "--datadir")
            base = Path(os.readlink(directory / "cwd"))
            datadir = str((base / datadir).resolve())
            for role, target in expected.items():
                if target != datadir:
                    continue
                identity = task_identity(directory)
                tasks = [task_identity(t) for t in (directory / "task").iterdir() if t.name.isdecimal()]
                named = {name: [t for t in tasks if t["comm"] == name] for name in NAMES}
                require(all(len(v) == 1 for v in named.values()), f"{role}: ambiguous/missing named threads")
                require(all(t["tgid"] == int(directory.name) for t in tasks), "task TGID mismatch")
                matches[role].append({"pid": int(directory.name), "identity": identity,
                    "exe": exe, "exe_sha256": sha256(directory / "exe"), "argv": argv,
                    "datadir": datadir, "pid_namespace": os.readlink(directory / "ns/pid"),
                    "named": {k: v[0] for k, v in named.items()}, "tasks": tasks})
        except FileNotFoundError:
            # A racing process/thread exit cannot produce an accepted match.
            continue
    require(all(len(v) == 1 for v in matches.values()), "expected exactly one live Tempo per data directory")
    result = {k: v[0] for k, v in matches.items()}
    require(result["a"]["pid"] != result["b"]["pid"], "same process matched both nodes")
    digest = sha256(binary)
    require(all(n["exe_sha256"] == digest for n in result.values()), "live binary differs from supplied file")
    return {"clock": clocks(), "binary": str(binary), "binary_sha256": digest, "nodes": result}


def stable(before, after):
    require(before["binary_sha256"] == after["binary_sha256"], "binary changed during capture")
    for role in ("a", "b"):
        a, b = before["nodes"][role], after["nodes"][role]
        for key in ("pid", "identity", "exe", "exe_sha256", "argv", "datadir", "pid_namespace", "named"):
            require(a[key] == b[key], f"{role}: process/thread identity changed: {key}")


def selected_tids(snapshot_value):
    tids = sorted(t["tid"] for node in snapshot_value["nodes"].values() for t in node["named"].values())
    require(len(tids) == len(set(tids)) == 4, "expected four distinct named TIDs")
    return tids


def perf_command(perf, output, tids, pages, seconds):
    require(tids and all(type(t) is int and t > 0 for t in tids), "invalid selected TIDs")
    cmd = [perf, "record", "-a", "-R", "-T", "--sample-cpu", "-k", "mono", "-c", "1",
           "-m", str(pages), "--no-buildid", "--no-buildid-cache", "--synth", "no",
           "--timestamp-boundary", "--max-size", "120M", "-o", str(output)]
    for event in EVENTS:
        fields = ("prev_pid", "next_pid") if event == "sched_switch" else ("pid",)
        expression = " || ".join(f"{field} == {tid}" for field in fields for tid in tids)
        cmd.extend(["-e", "sched:" + event, "--filter", "(" + expression + ")"])
    return cmd + ["--", "/bin/sleep", str(seconds)]


def checked_output(argv, timeout=8):
    result = subprocess.run(argv, capture_output=True, timeout=timeout, check=False)
    require(len(result.stdout) + len(result.stderr) <= 2 * MIB, "unexpectedly large tool output")
    return result


def perf_candidates():
    # Ubuntu's wrapper can exist while its exact kernel package is absent.
    # Use an installed tool from the same kernel series; the probe below still
    # checks its options and the running kernel's actual tracepoint schemas.
    series = ".".join(os.uname().release.split(".")[:2])
    installed = sorted(Path("/usr/lib/linux-tools").glob(series + ".*/perf"), reverse=True)
    return list(dict.fromkeys(p for p in [shutil.which("perf"), *map(str, installed)] if p))


def probe():
    result = {"ok": False, "kernel": list(os.uname()), "events": {}, "perf_help": {},
              "scope": "Read-only preflight; does not open perf events or prove recording permission"}
    try:
        attempts = result["perf_selection"] = []
        perf = None
        for candidate in perf_candidates():
            try:
                response = checked_output([candidate, "version"])
                attempts.append({"path": candidate, "returncode": response.returncode,
                                 "version": (response.stdout + response.stderr).decode(errors="replace")})
            except (OSError, subprocess.SubprocessError) as error:
                attempts.append({"path": candidate, "error": str(error)})
                continue
            if response.returncode == 0:
                perf = candidate
                break
        require(perf, "no working installed perf; see perf_selection")
        result.update(perf_path=perf, perf_entry_sha256=sha256(perf))
        for key, argv in (("perf_version", [perf, "version"]),
                          ("perf_build_options", [perf, "version", "--build-options"])):
            response = checked_output(argv)
            result[key] = (response.stdout + response.stderr).decode(errors="replace")
            require(response.returncode == 0, f"{key} failed")
        required = {"record": ["--all-cpus", "--raw-samples", "--timestamp", "--sample-cpu", "--clockid",
            "--count", "--mmap-pages", "--no-buildid", "--no-buildid-cache", "--synth",
            "--timestamp-boundary", "--max-size", "--event", "--filter"],
            "script": ["--ns", "--show-lost-events", "--dump-raw-trace", "--header-only", "--fields"]}
        for mode, options in required.items():
            response = checked_output([perf, mode, "-h"])
            text = (response.stdout + response.stderr).decode(errors="replace")
            result["perf_help"][mode] = text
            for opt in options:
                require(re.search(r"(?m)^\s*(?:-\w,\s*)?" + re.escape(opt) + r"(?=[\s=\[]|$)", text),
                        f"perf {mode} missing {opt}")
        for event in EVENTS:
            directory = next((Path(root) / "events/sched" / event for root in
                ("/sys/kernel/tracing", "/sys/kernel/debug/tracing")
                if (Path(root) / "events/sched" / event / "format").is_file()), None)
            require(directory is not None, f"missing tracefs format for {event}")
            text = (directory / "format").read_text()
            result["events"][event] = {"path": str(directory), "id": int((directory / "id").read_text()), "format": text}
            fields = ("prev_pid", "next_pid", "prev_state") if event == "sched_switch" else ("pid", "target_cpu")
            require(all(re.search(r"field:[^;]*\b" + f + r";", text) for f in fields), f"bad {event} schema")
        online = cpu_set(Path("/sys/devices/system/cpu/online").read_text())
        result.update(online_cpus=online, rings=ring_budget(online, os.sysconf("SC_PAGE_SIZE")), ok=True)
    except (TraceError, OSError, ValueError, subprocess.SubprocessError) as error:
        result["error"] = str(error)
    return result


@contextlib.contextmanager
def cancellation():
    def interrupted(signum, _frame):
        raise TraceError(f"cancelled by signal {signum}")
    previous = {s: signal.signal(s, interrupted) for s in (signal.SIGINT, signal.SIGTERM)}
    try:
        yield
    finally:
        for s, handler in previous.items():
            signal.signal(s, handler)


@contextlib.contextmanager
def cleanup_signals():
    # Repeated cancellation cannot interrupt the bounded reap already in progress.
    previous = {s: signal.signal(s, signal.SIG_IGN) for s in (signal.SIGINT, signal.SIGTERM)}
    try:
        yield
    finally:
        for s, handler in previous.items(): signal.signal(s, handler)


def stop_owned(child):
    if child.poll() is not None:
        return
    # Child was always created with start_new_session. Only this owned group.
    for sig, wait in ((signal.SIGINT, 3), (signal.SIGKILL, 2)):
        try:
            os.killpg(child.pid, sig)
        except ProcessLookupError:
            pass
        try:
            child.wait(timeout=wait)
            return
        except subprocess.TimeoutExpired:
            continue
    raise TraceError("owned subprocess did not exit")


def capped_child():
    resource.setrlimit(resource.RLIMIT_FSIZE, (FILE_LIMIT, FILE_LIMIT))


def run_owned(argv, stdout, stderr, timeout, stop=None, inspect=None):
    """Own and reap a process session. Used by privileged worker for perf only."""
    child = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=stdout, stderr=stderr,
                             start_new_session=True, preexec_fn=capped_child)
    start = time.monotonic()
    try:
        while child.poll() is None:
            require(not (stop and stop.exists()), "cancelled by stop sentinel")
            require(time.monotonic() - start < timeout, "owned command exceeded deadline")
            if inspect:
                inspect(child)
            time.sleep(0.05)
        return child.returncode
    finally:
        with cleanup_signals():
            stop_owned(child)


def privileged(args, timeout=15):
    result = checked_output(["sudo", "-n", sys.executable, SELF, *args], timeout)
    require(result.returncode == 0, result.stderr.decode(errors="replace")[-2000:] or "privileged read failed")
    return json.loads(result.stdout)


def recorder_worker(config_path):
    config = json.loads(Path(config_path).read_text())
    output = Path(config["output"])
    result = {"ok": False, "clock_before": clocks(), "command": config["command"]}
    seen_executables = {}
    def inspect(child):
        try:
            exe = os.readlink(f"/proc/{child.pid}/exe")
            if exe not in seen_executables:
                with open(f"/proc/{child.pid}/exe", "rb") as stream:
                    elf = stream.read(4) == b"\x7fELF"
                seen_executables[exe] = {"sha256": sha256(f"/proc/{child.pid}/exe"), "elf": elf}
        except FileNotFoundError:
            pass
    try:
        with cancellation(), open(output / "record.stdout", "wb") as stdout, open(output / "record.stderr", "wb") as stderr:
            code = run_owned(config["command"], stdout, stderr, config["seconds"] + 5,
                             output / "stop", inspect)
        require(code == 0, f"perf record exit {code}")
        require(time.monotonic_ns() - result["clock_before"]["monotonic_after_ns"] >= config["seconds"] * 1e9,
                "perf terminated before requested capture duration")
        require(any(v["elf"] for v in seen_executables.values()), "actual recorder ELF was not observed")
        result["ok"] = True
    except (TraceError, OSError) as error:
        result["error"] = str(error)
    finally:
        result.update(clock_after=clocks(), observed_recorder_executables=seen_executables)
        save(output / "record-result.json", result)
        # Only files created by this worker, so the ordinary caller can archive them.
        for name in ("record.stdout", "record.stderr", "record-result.json", "perf.data"):
            path = output / name
            if path.exists():
                path.chmod(0o644)
    return 0 if result["ok"] else 1


def decode_worker(config_path):
    config = json.loads(Path(config_path).read_text()); output = Path(config["output"])
    perf = config["command"][0]; result = {"ok": False}
    commands = [("header", ["--header-only"]),
        ("events", ["--ns", "--show-lost-events", "-F", "trace:comm,pid,tid,cpu,time,event,trace"]),
        ("raw", ["-D"])]
    try:
        with cancellation():
            for name, options in commands:
                with open(output / (name + ".txt"), "wb") as stdout, open(output / (name + ".stderr"), "wb") as stderr:
                    code = run_owned([perf, "script", "-i", str(output / "perf.data"), *options], stdout, stderr, 8, output / "stop")
                require(code == 0, f"perf decode {name} exit {code}")
        result["ok"] = True
    except (TraceError, OSError) as error:
        result["error"] = str(error)
    finally:
        save(output / "decode-result.json", result)
        for name, _ in commands:
            for suffix in ("txt", "stderr"):
                path = output / f"{name}.{suffix}"
                if path.exists(): path.chmod(0o644)
        (output / "decode-result.json").chmod(0o644)
    return 0 if result["ok"] else 1


def loss_evidence(output):
    findings = []
    for name in ("record.stderr", "events.txt", "events.stderr", "raw.txt", "raw.stderr"):
        with open(output / name, errors="replace") as stream:
            for number, line in enumerate(stream, 1):
                if re.search(r"PERF_RECORD_(?:LOST(?:_SAMPLES)?|THROTTLE|UNTHROTTLE)\b|\blost\s+[1-9]\d*\s+(?:events|samples)|\b(?:out of order|size limit reached|failed|truncated)\b", line, re.I):
                    findings.append({"file": name, "line": number, "text": line.strip()[:1000]})
    return findings


def capture(args):
    output = Path(args.output).resolve()
    output.mkdir(parents=True, exist_ok=True)
    require(not any(p.name != "stop" for p in output.iterdir()), "capture output must be empty")
    manifest = {"ok": False, "clock_requested": clocks(), "scope": "Named-thread evidence only; no complete builder/Engine scope coverage or performance claim",
        "exact_accounting_qualified": False, "capture_duration_qualified": False}
    try:
        with cancellation():
            deadline = time.monotonic() + 90
            def remaining(limit):
                require(not (output / "stop").exists(), "cancelled by stop sentinel")
                require(time.monotonic() < deadline, "capture helper deadline")
                return min(limit, deadline - time.monotonic())
            end_delay = time.monotonic() + args.delay
            while time.monotonic() < end_delay:
                remaining(1); time.sleep(min(0.1, end_delay - time.monotonic()))
            preflight = privileged(["_probe"], remaining(12)); save(output / "preflight.json", preflight)
            require(preflight["ok"], preflight.get("error", "preflight failed"))
            snapshot_args = ["_snapshot", "--binary", args.binary, "--datadir-a", args.datadir_a, "--datadir-b", args.datadir_b]
            before = privileged(snapshot_args, remaining(12)); save(output / "threads-before.json", before)
            command = perf_command(preflight["perf_path"], output / "perf.data", selected_tids(before), preflight["rings"]["pages_per_ring"], args.seconds)
            config = {"output": str(output), "seconds": args.seconds, "command": command}
            save(output / "record-config.json", config)
            # The privileged supervisor has its own deadline/finally cleanup. The
            # stop sentinel also survives a killed ordinary helper or sudo proxy.
            with open(output / "worker.stderr", "wb") as stderr:
                worker = subprocess.Popen(["sudo", "-n", sys.executable, SELF, "_record", str(output / "record-config.json")],
                    stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=stderr)
            try:
                while worker.poll() is None:
                    remaining(1); time.sleep(0.1)
                require(worker.returncode == 0, "recorder failed; see record-result.json / worker.stderr")
            finally:
                if worker.poll() is None:
                    with cleanup_signals():
                        (output / "stop").touch()
                        worker.wait(timeout=args.seconds + 10)
            require((output / "perf.data").stat().st_size < FILE_LIMIT, "raw perf file reached hard cap")
            after = privileged(snapshot_args, remaining(12)); save(output / "threads-after.json", after)
            stable(before, after)
            require(cpu_set(Path('/sys/devices/system/cpu/online').read_text()) == preflight['online_cpus'], 'online CPUs changed')
            result = checked_output(["sudo", "-n", sys.executable, SELF, "_decode", str(output / "record-config.json")], remaining(26))
            require(result.returncode == 0, "decoder failed; see decode-result.json")
            findings = loss_evidence(output); save(output / "loss-evidence.json", findings)
            require(not findings, "loss/throttle/limit/decoder anomaly; exact scheduler accounting unavailable")
            require((output / "events.txt").stat().st_size > 0, "empty decoded scheduler trace")
            manifest.update(ok=True, selected_tids=selected_tids(before), raw_bytes=(output / "perf.data").stat().st_size,
                decode_accounting_ready=False,
                loss_scope="No known loss/throttle/error lines in retained decode; raw READ-format loss counters and timeline completeness still require qualified analysis",
                state_scope="Decoded trace text may display symbolic prev_state; original numeric fields remain in perf.data with tracepoint formats")
    except (TraceError, OSError, ValueError, subprocess.SubprocessError) as error:
        (output / "stop").touch()
        manifest["error"] = str(error)
    finally:
        manifest["clock_finished"] = clocks(); save(output / "manifest.json", manifest)
    return 0 if manifest["ok"] else 1


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="mode", required=True)
    preflight = commands.add_parser("preflight"); preflight.add_argument("--output", required=True)
    record = commands.add_parser("capture")
    record.add_argument("--output", required=True)
    for name in ("binary", "datadir-a", "datadir-b"): record.add_argument("--" + name, required=True)
    record.add_argument("--delay", type=float, default=20); record.add_argument("--seconds", type=float, default=15)
    commands.add_parser("_probe")
    snap = commands.add_parser("_snapshot")
    for name in ("binary", "datadir-a", "datadir-b"): snap.add_argument("--" + name, required=True)
    for name in ("_record", "_decode"): commands.add_parser(name).add_argument("config")
    args = parser.parse_args()
    try:
        if args.mode == "preflight":
            result = {"ok": False}
            try: result.update(privileged(["_probe"], 15))
            except (TraceError, OSError, subprocess.SubprocessError) as error: result["error"] = str(error)
            save(args.output, result); return 0 if result["ok"] else 1
        if args.mode == "_probe": print(json.dumps(probe())); return 0
        if args.mode == "_snapshot": print(json.dumps(snapshot(args.binary, {"a": args.datadir_a, "b": args.datadir_b}))); return 0
        if args.mode == "_record": return recorder_worker(args.config)
        if args.mode == "_decode": return decode_worker(args.config)
        require(math.isfinite(args.delay) and 0 <= args.delay <= 30, "delay must be 0..30 seconds")
        require(math.isfinite(args.seconds) and 1 <= args.seconds <= 15, "capture must be 1..15 seconds")
        return capture(args)
    except (TraceError, OSError, ValueError, subprocess.SubprocessError) as error:
        print(str(error), file=sys.stderr); return 1


if __name__ == "__main__":
    sys.exit(main())
