"""Opt-in synthetic scheduler diagnostic; never attach to an existing process."""
import argparse
import collections
import json
import re
import resource
import subprocess
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).parent
KINDS = {0: "register", 1: "switch_out", 2: "switch_in", 3: "wakeup", 4: "exit", 5: "migration"}
EXPECTED_THREADS = {1, 2, 3}


def decode(stdout, stderr, returncode, origin, *, expected_threads=EXPECTED_THREADS, cutoff_ns=None):
    """Reject uncertain capture integrity without echoing private tool output."""
    if returncode:
        raise ValueError("capture tool failed")
    if stderr.strip():
        raise ValueError("capture tool reported a diagnostic; capture rejected")
    records, cutoffs, counts = [], [], []
    for line in stdout.splitlines():
        if not line.strip():
            continue
        event = re.fullmatch(r"E,([0-9]+),([0-9]+),([0-9]+),([0-9]+)", line)
        cutoff = re.fullmatch(r"C,([0-9]+)", line)
        total = re.fullmatch(r"@emitted: ([0-9]+)", line)
        if event:
            ts, ordinal, kind, state = map(int, event.groups())
            if not 0 < ordinal <= 8192 or (expected_threads is not None and ordinal not in expected_threads) or kind not in KINDS:
                raise ValueError("unexpected ordinal/event")
            if (kind != 1 and state != 0) or state > 256:
                raise ValueError("unexpected scheduler state")
            records.append({"ts": ts - origin, "thread": ordinal, "kind": KINDS[kind], "state_bits": state})
        elif cutoff:
            cutoffs.append(int(cutoff[1]) - origin)
        elif total:
            counts.append(int(total[1]))
        else:
            raise ValueError("unexpected tool output")
    if cutoff_ns is not None:
        if cutoffs:
            raise ValueError("unexpected private cutoff marker")
        cutoffs = [cutoff_ns]
    # bpftrace 0.20.2 emits a second zero-valued aggregate after END clears it.
    # BEGIN contributes one to the count so an empty/lost footer cannot pass.
    if len(cutoffs) != 1 or counts not in ([len(records) + 1], [len(records) + 1, 0]):
        raise ValueError("missing boundary/footer or event loss")
    if cutoffs[0] <= 0 or any(r["ts"] < 0 for r in records):
        raise ValueError("clock mismatch")
    records.sort(key=lambda r: r["ts"])
    registered, exited = set(), set()
    events = collections.defaultdict(list)
    for record in records:
        ordinal = record["thread"]
        if record["kind"] == "register":
            if ordinal in registered:
                raise ValueError("ordinal reused")
            registered.add(ordinal)
        elif ordinal not in registered or ordinal in exited:
            raise ValueError("registration/exit gap")
        if record["kind"] == "exit":
            exited.add(ordinal)
        events[ordinal].append(record)
    if not registered or (expected_threads is not None and registered != expected_threads) or exited != registered:
        raise ValueError("registration/exit coverage incomplete")
    cutoff = cutoffs[0]
    intervals = []
    unknown = open_intervals = unmatched_wakeups = 0

    def interval(thread, start, end, kind):
        # Keep even the endpoint strictly before cutoff; discard sub-nanosecond
        # empty results, never extrapolate an unclosed interval.
        low, high = max(0, start), min(cutoff - 1, end)
        if low < high:
            intervals.append({"thread": thread, "start": low, "end": high, "kind": kind,
                              "right_censored": end >= cutoff})

    for thread, rows in events.items():
        out = wake = running = None
        for record in rows:
            kind, ts = record["kind"], record["ts"]
            if kind == "register":
                running = ts
            elif kind == "switch_out":
                if out is not None:
                    raise ValueError("missing switch-in")
                if running is not None:
                    interval(thread, running, ts, "scheduled_on_cpu")
                out, running, wake = record, None, None
            elif kind == "wakeup":
                if out is not None and wake is None:
                    wake = ts
                else:
                    unmatched_wakeups += int(ts < cutoff)
            elif kind == "switch_in":
                if out is None:
                    raise ValueError("missing switch-out")
                # Preflight verifies the exact format: 0x100 denotes preempt/R+.
                if out["state_bits"] in (0, 256):
                    interval(thread, out["ts"], ts, "runnable_off_cpu")
                elif wake is not None:
                    interval(thread, out["ts"], wake, "blocked_before_wakeup")
                    interval(thread, wake, ts, "runnable_after_wakeup")
                else:
                    interval(thread, out["ts"], ts, "off_cpu_unsplit")
                    unknown += int(out["ts"] < cutoff)
                out, wake, running = None, None, ts
            elif kind == "exit":
                if running is not None:
                    interval(thread, running, ts, "scheduled_on_cpu")
                if out is not None:
                    open_intervals += int(out["ts"] < cutoff)
                running = out = None
        if out is not None:
            open_intervals += int(out["ts"] < cutoff)
    kept = [r for r in records if r["ts"] < cutoff]
    return {
        "schema": 1, "scope": "synthetic registered windows only", "process": 1,
        "clock": "monotonic_relative_ns", "cutoff_ns": cutoff,
        "records": kept, "intervals": intervals,
        "quality": {
            "event_loss_detected": False, "registered_threads": len(registered),
            "all_registered_threads_exited": True, "unclassified_off_cpu_intervals": unknown,
            "unclosed_intervals_excluded": open_intervals, "unmatched_wakeups": unmatched_wakeups,
            "at_or_post_cutoff_records_pruned": len(records) - len(kept),
        },
        "registered_window_edges_complete": unknown == 0 and open_intervals == 0 and unmatched_wakeups == 0,
    }


def run_private(command, timeout=30):
    """Only validated derived output may be persisted; raw stdout/stderr stay in memory."""
    try:
        result = subprocess.run(command, capture_output=True, text=True, timeout=timeout)
    except (OSError, subprocess.TimeoutExpired):
        raise ValueError("diagnostic command unavailable or timed out") from None
    return result


def checked(command):
    result = run_private(command)
    if result.returncode:
        raise ValueError("diagnostic prerequisite failed")
    return result.stdout


def preflight():
    checked(["sudo", "-n", "true"])
    checked(["sudo", "-n", "test", "-r", "/sys/kernel/btf/vmlinux"])
    actual = checked(["sudo", "-n", "cat", "/sys/kernel/tracing/events/sched/sched_switch/format"])
    expected = (ROOT / "switch-format.txt").read_text().strip()
    if next((line for line in actual.splitlines() if line.startswith("print fmt:")), "") != expected:
        raise ValueError("unsupported scheduler state encoding")
    for name in ("sched_wakeup", "sched_process_exit", "sched_migrate_task"):
        checked(["sudo", "-n", "test", "-r", f"/sys/kernel/tracing/events/sched/{name}/format"])
    compiled = run_private(["sudo", "-n", "bpftrace", "-d", "-e",
                            'BEGIN { printf("%llu", nsecs(monotonic)); exit(); }'])
    # Compiler evidence is local, without assuming bare nsecs has the right clock.
    if compiled.returncode or "inttoptr (i64 5 to ptr)" not in compiled.stdout + compiled.stderr:
        raise ValueError("monotonic BPF clock could not be verified")


def verify_marker(binary, name):
    # A full optimized validator disassembly can be enormous. Scan it without
    # retaining or printing addresses, and stop as soon as a real call is found.
    try:
        process = subprocess.Popen(["objdump", "-d", str(binary)], stdout=subprocess.PIPE,
                                   stderr=subprocess.DEVNULL, text=True)
    except OSError:
        raise ValueError("release marker verification unavailable") from None
    found = False
    deadline = time.monotonic() + 120
    pattern = re.compile(r"\b(?:call\w*|bl)\s+[^\n]*<" + re.escape(name) + r">")
    try:
        for line in process.stdout:
            if pattern.search(line):
                found = True
                break
            if time.monotonic() > deadline:
                break
    finally:
        process.stdout.close()
        if process.poll() is None:
            process.terminate()
        process.wait()
    if not found:
        raise ValueError("release registration marker call did not survive")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True, help="new sanitized synthetic JSON file")
    args = parser.parse_args()
    # Prevent incidental native mappings in a core dump. Never accept arbitrary PID/binary input.
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    try:
        if args.output.exists():
            raise ValueError("output already exists")
        preflight()
        with tempfile.TemporaryDirectory(prefix="lifecycle-scheduler-") as directory:
            binary = Path(directory) / "synthetic"
            checked(["gcc", "-O3", "-flto", "-fno-ipa-cp-clone", "-pthread", str(ROOT / "synthetic.c"), "-o", str(binary)])
            verify_marker(binary, "lifecycle_thread_register")
            rust_binary = Path(directory) / "rust-marker"
            checked(["rustc", "--edition=2024", "-C", "opt-level=3", "-C", "lto=fat",
                     str(ROOT / "marker.rs"), "-o", str(rust_binary)])
            verify_marker(rust_binary, "reth_lifecycle_thread_register")
            program = Path(directory) / "scheduler.bt"
            program.write_text((ROOT / "scheduler.bt.in").read_text().replace("__BINARY__", str(binary)))
            origin = time.monotonic_ns()
            result = run_private(["sudo", "-n", "bpftrace", "-q", "-k", "-c", str(binary), str(program)])
            capture = decode(result.stdout, result.stderr, result.returncode, origin)
        if not capture["quality"]["at_or_post_cutoff_records_pruned"]:
            raise ValueError("synthetic post-cutoff exercise missing")
        with args.output.open("x") as output:
            json.dump(capture, output, indent=2)
            output.write("\n")
        print(json.dumps({"valid": True, "records": len(capture["records"]),
                          "intervals": len(capture["intervals"]), "quality": capture["quality"]}))
        return 0
    except ValueError as error:
        print(json.dumps({"valid": False, "reason": str(error)}))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
