#!/usr/bin/env python3
"""No tracing/root required: synthetic /proc and real owned child cleanup tests."""
import contextlib
import importlib.util
import io
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location("scheduler_trace", Path(__file__).with_name("scheduler_trace.py"))
trace = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(trace)


class SchedulerTraceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.proc = self.root / "proc"; self.proc.mkdir()
        self.binary = self.root / "tempo"; self.binary.write_bytes(b"fake executable")
        self.datadirs = {"a": str(self.root / "a"), "b": str(self.root / "b")}

    def task(self, directory, tgid, name, start=50):
        directory.mkdir(parents=True, exist_ok=True)
        # A comm with spaces/parentheses must not move stat field22.
        directory.joinpath("stat").write_text(f"{directory.name} ({name}) S " + " ".join(["0"] * 18 + [str(start)]))
        directory.joinpath("status").write_text(f"Tgid:\t{tgid}\n")
        directory.joinpath("comm").write_text(name + "\n")
        directory.joinpath("cgroup").write_text(f"0::/tempo-{tgid}.scope\n")

    def process(self, pid, role, duplicate_engine=False, equals=False):
        directory = self.proc / str(pid)
        self.task(directory, pid, "tempo (node)")
        directory.joinpath("exe").symlink_to(self.binary)
        directory.joinpath("cwd").symlink_to(self.root)
        directory.joinpath("ns").mkdir(); directory.joinpath("ns/pid").symlink_to("pid:[1234]")
        argv = [str(self.binary), "node", "--datadir=" + self.datadirs[role]] if equals else [str(self.binary), "node", "--datadir", self.datadirs[role]]
        directory.joinpath("cmdline").write_bytes(b"\0".join(x.encode() for x in argv) + b"\0")
        for i, name in enumerate(["engine", "payload-builder", "tokio-runtime-worker"] + (["engine"] if duplicate_engine else []), 1):
            self.task(directory / "task" / str(pid + i), pid, name)
        return directory

    def two_nodes(self):
        self.process(100, "a"); self.process(200, "b", equals=True)
        return trace.snapshot(self.binary, self.datadirs, self.proc)

    def test_exact_process_identity_and_uncovered_tokio_threads(self):
        before = self.two_nodes()
        self.assertEqual(trace.selected_tids(before), [101, 102, 201, 202])
        self.assertEqual(before["nodes"]["a"]["identity"]["starttime_ticks"], 50)
        self.assertEqual(len(before["nodes"]["a"]["tasks"]), 3)
        trace.stable(before, trace.snapshot(self.binary, self.datadirs, self.proc))

    def test_duplicate_process_or_thread_is_rejected(self):
        self.two_nodes(); self.process(300, "a")
        with self.assertRaisesRegex(trace.TraceError, "exactly one live"):
            trace.snapshot(self.binary, self.datadirs, self.proc)
        with tempfile.TemporaryDirectory() as temporary:
            # Reuse a fresh proc root without deleting unrelated paths.
            self.proc = Path(temporary)
            self.process(100, "a", duplicate_engine=True); self.process(200, "b")
            with self.assertRaisesRegex(trace.TraceError, "ambiguous/missing"):
                trace.snapshot(self.binary, self.datadirs, self.proc)

    def test_replaced_named_tid_or_binary_rejected(self):
        before = self.two_nodes()
        path = self.proc / "100/task/101"
        self.task(path, 100, "engine", start=51)
        with self.assertRaisesRegex(trace.TraceError, "identity changed"):
            trace.stable(before, trace.snapshot(self.binary, self.datadirs, self.proc))
        self.binary.write_bytes(b"replacement")
        with self.assertRaisesRegex(trace.TraceError, "binary changed"):
            trace.stable(before, trace.snapshot(self.binary, self.datadirs, self.proc))

    def test_duplicate_datadir_option_rejected(self):
        for argv in (["--datadir", "a", "--datadir=b"], ["--datadir"], ["--datadir", "--other"]):
            with self.assertRaises(trace.TraceError): trace.option(argv, "--datadir")

    def test_filters_are_target_fields_on_all_cpus(self):
        command = trace.perf_command("/perf", "/out", [101, 202], 64, 15)
        self.assertIn("-a", command)
        for forbidden in ("--pid", "--tid", "-C", "--cpu", "--call-graph", "--overwrite"):
            self.assertNotIn(forbidden, command)
        filters = [command[i + 1] for i, arg in enumerate(command) if arg == "--filter"]
        self.assertEqual(filters[0], "(prev_pid == 101 || prev_pid == 202 || next_pid == 101 || next_pid == 202)")
        self.assertEqual(filters[1:], ["(pid == 101 || pid == 202)"] * 2)
        self.assertEqual(command[-3:], ["--", "/bin/sleep", "15"])

    def test_budget_counts_tracepoint_and_dummy_rings_per_cpu(self):
        for count in (1, 32, 192, 4096):
            budget = trace.ring_budget(list(range(count)), 4096)
            self.assertLessEqual(budget["worst_case_bytes"], 512 * trace.MIB)
            pages = budget["pages_per_ring"]
            self.assertEqual(pages & (pages - 1), 0)
            self.assertEqual(budget["worst_case_bytes"], count * 4 * (pages + 1) * 4096)
        self.assertEqual(trace.cpu_set("0-2,5,8-9\n"), [0, 1, 2, 5, 8, 9])
        for text in ("", "4-1", "0,thing"):
            with self.assertRaises(trace.TraceError): trace.cpu_set(text)

    def test_loss_types_throttle_and_error_evidence(self):
        names = ("record.stderr", "events.txt", "events.stderr", "raw.txt", "raw.stderr")
        for name in names: (self.root / name).write_text("")
        (self.root / "raw.txt").write_text("PERF_RECORD_LOST\nPERF_RECORD_LOST_SAMPLES\nPERF_RECORD_THROTTLE\nPERF_RECORD_UNTHROTTLE\n")
        (self.root / "record.stderr").write_text("Lost 3 events.\n")
        self.assertEqual(len(trace.loss_evidence(self.root)), 5)
        (self.root / "raw.txt").write_text("normal trace\n")
        (self.root / "record.stderr").write_text("Lost 0 events.\n")
        self.assertEqual(trace.loss_evidence(self.root), [])

    def test_owned_timeout_reaps_only_its_process_group(self):
        unrelated = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(20)"])
        self.addCleanup(lambda: unrelated.poll() is None and (unrelated.kill(), unrelated.wait()))
        observed = []
        def inspect(child): observed.append(child.pid)
        with open(os.devnull, "wb") as sink:
            with self.assertRaisesRegex(trace.TraceError, "deadline"):
                trace.run_owned([sys.executable, "-c", "import time; time.sleep(20)"], sink, sink, 0.1, inspect=inspect)
        self.assertTrue(observed)
        with self.assertRaises(ProcessLookupError): os.kill(observed[0], 0)
        self.assertIsNone(unrelated.poll())

    def test_stop_sentinel_and_error_cleanup(self):
        stop = self.root / "stop"; stop.touch()
        with open(os.devnull, "wb") as sink:
            with self.assertRaisesRegex(trace.TraceError, "stop sentinel"):
                trace.run_owned([sys.executable, "-c", "import time; time.sleep(20)"], sink, sink, 2, stop)
            def broken(_): raise ValueError("fixture error")
            with self.assertRaisesRegex(ValueError, "fixture error"):
                trace.run_owned([sys.executable, "-c", "import time; time.sleep(20)"], sink, sink, 2, inspect=broken)

    def test_capture_cancellation_during_delay_never_invokes_sudo(self):
        self.root.joinpath("output").mkdir(); self.root.joinpath("output/stop").touch()
        args = type("Args", (), dict(output=str(self.root / "output"), delay=20, seconds=15))()
        with patch.object(trace, "privileged", side_effect=AssertionError("must not invoke")):
            self.assertEqual(trace.capture(args), 1)
        self.assertIn("stop sentinel", json.loads((self.root / "output/manifest.json").read_text())["error"])

    def wait_file(self, path, process):
        deadline = time.monotonic() + 3
        while not path.exists() and time.monotonic() < deadline:
            self.assertIsNone(process.poll())
            time.sleep(0.01)
        self.assertTrue(path.exists())

    def test_recorder_sentinel_stops_running_child_and_preserves_failure(self):
        directory = self.root / "record"; directory.mkdir()
        pid_path = directory / "fake-perf.pid"
        program = "import os,time; from pathlib import Path; Path(%r).write_text(str(os.getpid())); time.sleep(30)" % str(pid_path)
        config = directory / "config.json"
        trace.save(config, {"output": str(directory), "seconds": 1,
                            "command": [sys.executable, "-c", program]})
        worker = subprocess.Popen([sys.executable, trace.SELF, "_record", str(config)],
                                  stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        try:
            self.wait_file(pid_path, worker)
            child_pid = int(pid_path.read_text())
            (directory / "stop").touch()
            self.assertEqual(worker.wait(timeout=6), 1)
            with self.assertRaises(ProcessLookupError): os.kill(child_pid, 0)
            result = json.loads((directory / "record-result.json").read_text())
            self.assertFalse(result["ok"])
            self.assertIn("stop sentinel", result["error"])
        finally:
            if worker.poll() is None: worker.kill(); worker.wait()

    def test_repeated_signals_cannot_interrupt_recorder_reap(self):
        directory = self.root / "signals"; directory.mkdir()
        pid_path = directory / "child.pid"
        program = ("import os,signal,time; from pathlib import Path; "
                   "signal.signal(signal.SIGINT, signal.SIG_IGN); "
                   "Path(%r).write_text(str(os.getpid())); time.sleep(30)") % str(pid_path)
        config = directory / "config.json"
        trace.save(config, {"output": str(directory), "seconds": 1,
                            "command": [sys.executable, "-c", program]})
        worker = subprocess.Popen([sys.executable, trace.SELF, "_record", str(config)],
                                  stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        try:
            self.wait_file(pid_path, worker); child_pid = int(pid_path.read_text())
            worker.send_signal(signal.SIGTERM)
            time.sleep(0.1)
            worker.send_signal(signal.SIGTERM)
            self.assertEqual(worker.wait(timeout=5), 1)
            with self.assertRaises(ProcessLookupError): os.kill(child_pid, 0)
            self.assertIn("cancelled by signal", json.loads((directory / "record-result.json").read_text())["error"])
        finally:
            if worker.poll() is None: worker.kill(); worker.wait()

    def test_decode_sentinel_stops_running_decoder(self):
        directory = self.root / "decode"; directory.mkdir()
        fake = directory / "fake-perf"
        fake.write_text("#!" + sys.executable + "\nimport os,time\nfrom pathlib import Path\nPath(__file__ + '.pid').write_text(str(os.getpid()))\ntime.sleep(30)\n")
        fake.chmod(0o755)
        config = directory / "config.json"
        trace.save(config, {"output": str(directory), "command": [str(fake)]})
        worker = subprocess.Popen([sys.executable, trace.SELF, "_decode", str(config)],
                                  stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        try:
            pid_path = Path(str(fake) + ".pid"); self.wait_file(pid_path, worker)
            child_pid = int(pid_path.read_text()); (directory / "stop").touch()
            self.assertEqual(worker.wait(timeout=6), 1)
            with self.assertRaises(ProcessLookupError): os.kill(child_pid, 0)
            result = json.loads((directory / "decode-result.json").read_text())
            self.assertFalse(result["ok"])
            self.assertIn("stop sentinel", result["error"])
        finally:
            if worker.poll() is None: worker.kill(); worker.wait()

    def test_file_cap_is_inherited_by_child(self):
        output = self.root / "limited"
        with patch.object(trace, "FILE_LIMIT", 4096), open(output, "wb") as stdout, open(os.devnull, "wb") as stderr:
            code = trace.run_owned([sys.executable, "-c", "import os; os.write(1, b'x' * 100000); os.write(1, b'x')"], stdout, stderr, 2)
        self.assertNotEqual(code, 0)
        self.assertLessEqual(output.stat().st_size, 4096)

    def test_probe_preserves_version_when_help_missing(self):
        def fake(argv, **_):
            text = "perf version fake\n" if "version" in argv else "no supported flags\n"
            return subprocess.CompletedProcess(argv, 0, text.encode(), b"")
        with patch.object(trace.shutil, "which", return_value=str(self.binary)), patch.object(trace, "checked_output", side_effect=fake):
            result = trace.probe()
        self.assertFalse(result["ok"])
        self.assertIn("perf version fake", result["perf_version"])
        self.assertIn("perf_build_options", result)
        self.assertIn("missing --all-cpus", result["error"])

    def test_preflight_failure_preserves_manifest(self):
        output = self.root / "preflight.json"
        with patch.object(sys, "argv", ["scheduler_trace", "preflight", "--output", str(output)]), patch.object(trace, "privileged", side_effect=trace.TraceError("missing tracefs")):
            self.assertEqual(trace.main(), 1)
        self.assertEqual(json.loads(output.read_text()), {"ok": False, "error": "missing tracefs"})


if __name__ == "__main__": unittest.main()
