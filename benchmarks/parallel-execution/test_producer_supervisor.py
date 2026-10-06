"""Fake-process tests only. Prepared but NOT executed by the source-authoring agent.

Run from this directory: python3 -m unittest -v test_producer_supervisor
Private short limits and a patched ELF-magic check permit text fakes. Hash,
manifest, exact argv, direct pipe, process groups, log parsing and cleanup remain
real. These tests do not execute txgen, wc, a node, a benchmark or any network.
"""

from __future__ import annotations

import copy
import dataclasses
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import threading
import time
from types import SimpleNamespace
import unittest
from unittest import mock

import producer_supervisor as sup


FAST = dataclasses.replace(sup.PRODUCTION_LIMITS, timeout_ns=1_500_000_000,
                           term_grace_ns=150_000_000, kill_reap_ns=500_000_000,
                           minimum_workload_ns=1_000_000, free_reserve_bytes=0,
                           disk_check_ns=20_000_000)


def gas_round() -> list[str]:
    return [
        'gas sample: item=Template("public_transfer") block_gas=62000 target_weight=80',
        'gas sample: item=Template("public_mint") block_gas=44000 target_weight=5',
        'gas sample: item=Sequence("mpp_open_only") block_gas=168000 target_weight=15',
    ]


def successful_log(count: int = 3, elapsed: str = "10ms", total: str = "20ms") -> bytes:
    return ("\n".join([
        sup.TX_START, "starting nonce prefetch", "nonce prefetch completed: elapsed=1ms",
        *gas_round(), sup.WORK_START, *gas_round(),
        f"workload generation completed: prepared={count} elapsed={elapsed}",
        f"transaction generation completed: elapsed={total}",
    ]) + "\n").encode()


class Fixture:
    """A complete supplied-provenance fixture; no external executable is consulted."""
    def __init__(self, root: Path, producer_mode="complete", consumer_mode="count"):
        self.root = root
        self.started = root / "producer-started.json"
        self.consumer_started = root / "consumer-started.json"
        self.producer = root / "txgen-tempo-fake"
        self.consumer = root / "wc-fake"
        log = successful_log().decode()
        if producer_mode == "bad-count":
            log = log.replace("prepared=3", "prepared=4")
        if producer_mode == "missing-calibration":
            before, after = log.split(sup.WORK_START + "\n")
            after = after.replace("\n".join(gas_round()) + "\n", "")
            log = before + sup.WORK_START + "\n" + after
        # Fixed behavior is in the hashed executable, not an unreviewed env override.
        self.producer.write_text(f"""#!{sys.executable}
import json, os, signal, sys, time
mode = {producer_mode!r}
if mode in ('hang', 'flood'):
    signal.signal(signal.SIGTERM, signal.SIG_IGN)
    signal.signal(signal.SIGINT, signal.SIG_IGN)
with open({str(self.started)!r}, 'x') as stream:
    json.dump({{'pid': os.getpid(), 'argv': sys.argv[1:]}}, stream)
if mode == 'hang':
    while True:
        time.sleep(0.01)
if mode == 'flood':
    while True:
        os.write(2, b'x' * 4096)
if mode == 'swallowed-broken-pipe':
    prefix = {successful_log().decode().split('workload generation completed:')[0]!r}
    os.write(2, prefix.encode())
    time.sleep(0.03)
    try:
        for _ in range(16):
            os.write(1, b'x' * 65536)
    except BrokenPipeError:
        pass
    os.write(2, b'transaction generation completed: elapsed=20ms\\n')
    raise SystemExit(0)
time.sleep(0.03)
os.write(1, b'{{"phase":"workload","raw":"0x01"}}\\n' * 3)
os.write(2, {log.encode()!r})
""")
        self.consumer.write_text(f"""#!{sys.executable}
import json, os, signal, sys
mode = {consumer_mode!r}
if mode == 'ignore-signals':
    signal.signal(signal.SIGTERM, signal.SIG_IGN)
    signal.signal(signal.SIGINT, signal.SIG_IGN)
with open({str(self.consumer_started)!r}, 'x') as stream:
    json.dump({{'pid': os.getpid(), 'argv': sys.argv[1:]}}, stream)
if mode == 'early-exit':
    raise SystemExit(0)
count = 0
size = 0
while True:
    data = os.read(0, 65536)
    if not data:
        break
    count += data.count(b'\\n')
    size += len(data)
if mode == 'wrong-total':
    count += 1
os.write(1, f'{{count}} {{size}}\\n'.encode())
""")
        self.producer.chmod(0o700)
        self.consumer.chmod(0o700)
        self.environment = {
            "PATH": "/usr/bin:/bin", "LC_ALL": "C", "TXGEN_ACCOUNTS": "1000",
            "TXGEN_TIP20_TOKENS": json.dumps([
                "0x20c0000000000000000000000000000000000000",
                "0x20c0000000000000000000000000000000000001",
                "0x20c0000000000000000000000000000000000002",
                "0x20c0000000000000000000000000000000000003",
            ]),
            "TXGEN_EXISTING_RECIPIENTS_START": "10000",
            "TXGEN_EXISTING_RECIPIENTS_END": "900000",
        }
        spec = self.file("public-mix.yml", "source-bound fake public spec\n")
        deps = [self.file(name, name + "\n") for name in ("mpp.yml", "tip20.abi.json", "mpp.abi.json")]
        bundle = self.json_file("spec-bundle.json", {
            "schema_version": 1, "status": "verified", "source_commit": sup.PRESET_COMMIT,
            "preset": "public-mix", "entry": spec, "dependencies": deps,
            "gas_weights": sup.CONTROLS["gas_weights"],
            "environment": {k: v for k, v in self.environment.items() if k.startswith("TXGEN_")},
        })
        setup_state = self.file("setup.json", '{"bindings":{}}\n')
        setup = self.json_file("setup-confirmation.json", {
            "schema_version": 1, "status": "confirmed", "chain_id": 1337, "rpc_url": sup.RPC,
            "spec_bundle_sha256": bundle["sha256"], "setup_state": setup_state,
            "receipt_evidence": self.file("setup-confirmed.txt", "synthetic setup evidence\n"),
        })
        build = self.json_file("txgen-build.json", {
            "schema_version": 1, "status": "verified", "source_commit": sup.TXGEN_COMMIT,
            "source_clean": True, "binary": self.binding(self.producer),
            "cargo_lock": self.file("Cargo.lock", "synthetic lock\n"),
            "build_evidence": self.file("build.log", "synthetic build evidence\n"),
            "build": {"profile": "release", "features": "default", "cargo": "cargo fixture",
                      "rustc": "rustc fixture", "target": "x86_64-unknown-linux-gnu",
                      "build_id": "0123456789abcdef", "rustflags": "", "cargo_encoded_rustflags": "",
                      "cargo_config_evidence": self.file("cargo-config.json", '{}\n')},
        })
        wc = self.json_file("wc-provenance.json", {
            "schema_version": 1, "status": "verified", "implementation": "GNU coreutils wc",
            "binary": self.binding(self.consumer),
            "version_evidence": self.file("wc-version.txt", "wc (GNU coreutils) fixture\n"),
        })
        context = self.json_file("workflow-context.json", {
            "schema_version": 1, "status": "verified", "run_id": "123",
            "workflow_sha": "a" * 40, "attempt_id": "fake-attempt",
            "responsibility": "workflow_verified_before_launch",
            "host_evidence": self.file("host.json", '{"fixture":true}\n'),
            "node_evidence": self.file("nodes.json", '{"fixture":true}\n'),
            "measurement_exclusivity_evidence": self.file("exclusivity.json", '{"fixture":true}\n'),
        })
        self.config = {
            "schema_version": 1, "attempt_id": "fake-attempt", "controls": copy.deepcopy(sup.CONTROLS),
            "publication": {"e2e_series": False, "slack": False}, "rpc_url": sup.RPC,
            "bindings": {"txgen_build": build, "wc_provenance": wc, "spec_bundle": bundle,
                         "setup_confirmation": setup, "workflow_context": context},
            "producer_argv": [str(self.producer), "generate", "-s", spec["path"], "--duration", "60s",
                              "--seed", "99", "--rpc", sup.RPC, "--gas-weighted-mix",
                              "--setup-state-in", setup_state["path"]],
            "consumer_argv": [str(self.consumer), "-l", "-c"], "environment": self.environment,
        }
        self.config_path = root / "config.json"
        self.save_config()

    @staticmethod
    def binding(path):
        return {"path": str(path), "sha256": sup.digest(path)}

    def file(self, name, content):
        path = self.root / name
        path.write_text(content)
        return self.binding(path)

    def json_file(self, name, data):
        return self.file(name, json.dumps(data))

    def save_config(self):
        self.config_path.write_text(json.dumps(self.config))


class ParserTests(unittest.TestCase):
    def test_duration_units_and_exact_precision(self):
        for value, expected in [("60s", 60_000_000_000), ("60.125s", 60_125_000_000),
                                ("1.5ms", 1_500_000), ("1.001µs", 1001), ("7ns", 7)]:
            self.assertEqual(sup.duration_ns(value), expected)
        for value in ("NaN", "-1s", "1e2s", "1.1ns", "00:01", "1us"):
            with self.assertRaises(sup.Invalid):
                sup.duration_ns(value)

    def test_production_thresholds_are_distinct_from_invalidity(self):
        for count, decision in [(2_999_940, "below_target_supply"),
                                (3_100_000, "marginal_supply"),
                                (3_410_000, "headroom_observed"),
                                (3_000_000, "inconclusive_rate_bracket"),
                                (3_300_000, "inconclusive_rate_bracket")]:
            result = sup.qualify(successful_log(count, "60s", "61s"),
                                 f"{count} {count * 100}\n".encode(),
                                 62_000_000_000, 62_000_000_000, sup.PRODUCTION_LIMITS)
            self.assertEqual(result["decision"], decision)
            self.assertEqual(result["periodic_calibration_rounds"], 1)
            self.assertLessEqual(result["drain_inclusive_rate_bracket"]["lower"],
                                 result["drain_inclusive_rate_bracket"]["upper"])

    def test_rejects_broken_pipe_style_missing_workload_completion(self):
        log = successful_log().decode()
        log = "\n".join(line for line in log.splitlines()
                        if not line.startswith("workload generation completed:")) + "\n"
        with self.assertRaisesRegex(sup.Invalid, "completion"):
            sup.qualify(log.encode(), b"3 100\n", 100_000_000, 100_000_000, FAST)

    def test_wrong_order_weight_or_partial_calibration_fails(self):
        logs = [
            successful_log().replace(b"target_weight=80", b"target_weight=79", 1),
            successful_log().replace(gas_round()[0].encode() + b"\n", b"", 1),
            successful_log().replace(b"block_gas=62000", b"block_gas=0", 1),
        ]
        for log in logs:
            with self.subTest(log=log), self.assertRaises(sup.Invalid):
                sup.qualify(log, b"3 100\n", 100_000_000, 100_000_000, FAST)

    def test_monotonic_outer_bounds_and_production_minimum(self):
        for log, wall in [(successful_log(3, "60s", "59s"), 62_000_000_000),
                          (successful_log(3, "60s", "61s"), 60_500_000_000),
                          (successful_log(3, "59s", "60s"), 62_000_000_000)]:
            with self.assertRaisesRegex(sup.Invalid, "elapsed"):
                sup.qualify(log, b"3 100\n", wall, wall, sup.PRODUCTION_LIMITS)

    def test_final_observation_crossing_deadline_is_invalid(self):
        with self.assertRaisesRegex(sup.Invalid, "absolute timeout"):
            sup.qualify(successful_log(3, "60s", "61s"), b"3 100\n",
                        180_000_000_001, 180_000_000_001, sup.PRODUCTION_LIMITS)

    def test_elapsed_equal_to_deadline_passes_final_bound(self):
        result = sup.qualify(successful_log(3, "60s", "61s"), b"3 100\n",
                             180_000_000_000, 180_000_000_000, sup.PRODUCTION_LIMITS)
        self.assertEqual(result["decision"], "below_target_supply")

    def test_duplicate_completion_wrong_startup_and_trailing_failure(self):
        logs = [successful_log() + b"panic: after completion\n",
                successful_log().replace(sup.WORK_START.encode(),
                                         (sup.WORK_START + "\n" + sup.WORK_START).encode()),
                successful_log().replace(b"signing_workers=2", b"signing_workers=3", 1)]
        for log in logs:
            with self.assertRaises(sup.Invalid):
                sup.qualify(log, b"3 100\n", 100_000_000, 100_000_000, FAST)


class OwnershipAndCommitTests(unittest.TestCase):
    def test_waitid_reserves_leader_and_recycled_group_cannot_be_signaled(self):
        state = {"recycled": False}
        sent = []
        child = SimpleNamespace(pid=424242, returncode=None)
        guard = sup.OwnedGroup(child)
        status = SimpleNamespace(si_code=os.CLD_EXITED, si_status=0)
        usage = SimpleNamespace(ru_utime=0.0, ru_stime=0.0, ru_maxrss=1)
        def wait4(pid, flags):
            self.assertTrue(guard.signals_closed)
            state["recycled"] = True  # Kernel may reuse this number immediately now.
            return pid, 0, usage
        def killpg(pgid, sig):
            sent.append((pgid, sig, state["recycled"]))
        with mock.patch.object(sup.os, "waitid", return_value=status) as observe, \
                mock.patch.object(sup.os, "wait4", side_effect=wait4) as release, \
                mock.patch.object(sup.os, "killpg", side_effect=killpg):
            guard.observe()
            self.assertIsNone(child.returncode)
            release.assert_not_called()
            self.assertTrue(observe.call_args.args[2] & os.WNOWAIT)
            guard.send(signal.SIGTERM)
            guard.close_signals()
            guard.reap()
            with self.assertRaisesRegex(sup.Invalid, "closed"):
                guard.send(signal.SIGKILL)
        self.assertEqual(sent, [(424242, signal.SIGTERM, False)])
        self.assertTrue(guard.reaped)

    def test_external_reap_loses_ownership_and_never_signals_numeric_group(self):
        guard = sup.OwnedGroup(SimpleNamespace(pid=424242, returncode=None))
        with mock.patch.object(sup.os, "waitid", side_effect=ChildProcessError), \
                mock.patch.object(sup.os, "killpg") as signal_group:
            with self.assertRaisesRegex(sup.Invalid, "ownership lost"):
                guard.send(signal.SIGKILL)
        signal_group.assert_not_called()
        self.assertTrue(guard.ownership_lost)

    def test_signal_during_result_serialization_publishes_invalid(self):
        with tempfile.TemporaryDirectory(prefix="producer-commit-test-") as folder:
            output = Path(folder)
            pending = []
            previous = signal.signal(signal.SIGTERM, lambda signum, frame: pending.append(signum))
            result = {"status": "valid_output_measurement", "decision": "headroom_observed",
                      "received_signals": [], "errors": []}
            real_writer = sup.write_new_json
            def serialize_then_signal(path, value):
                real_writer(path, value)
                os.kill(os.getpid(), signal.SIGTERM)
            try:
                with mock.patch.object(sup, "write_new_json", side_effect=serialize_then_signal):
                    sup.commit_result(output, result, pending, {signal.SIGTERM: previous})
                saved = json.loads((output / "result.json").read_text())
                self.assertEqual(saved["status"], "invalid")
                self.assertIsNone(saved["decision"])
                self.assertEqual(saved["received_signals"], [signal.SIGTERM])
                self.assertFalse((output / "result.pending.json").exists())
                self.assertEqual(signal.getsignal(signal.SIGTERM), previous)
            finally:
                signal.signal(signal.SIGTERM, previous)


@unittest.skipUnless(os.name == "posix" and hasattr(os, "wait4"), "requires POSIX process groups")

class ResourceTests(unittest.TestCase):
    def test_proc_identity_requires_exact_fields_and_keeps_saved_ids(self):
        parsed = sup.identity_fields("Uid: 1 2 3 4\nGid: 5 6 7 8\nGroups: 8 2\n")
        self.assertEqual(parsed, {"Uid": [1, 2, 3, 4], "Gid": [5, 6, 7, 8], "Groups": [2, 8]})
        for bad in ("Uid: 1 2 3 4\n", "Uid: 1 2 3\nGid: 1 2 3 4\nGroups:\n",
                    "Uid: 1 2 3 4\nGid: 1 2 3 4\nGroups: bad\n",
                    "Uid: 1 2 3 4\nUid: 1 2 3 4\nGid: 1 2 3 4\nGroups:\n"):
            with self.subTest(bad=bad), self.assertRaises(sup.Invalid):
                sup.identity_fields(bad)

    def test_resource_gate_rejects_limit_affinity_identity_or_scope_change(self):
        parent = {"credentials": {"Uid": [1000] * 4, "Gid": [1000] * 4, "Groups": [1000]},
                  "affinity": [0, 1], "rlimit_nofile": [1048576, 1048576], "cgroup_text": "0::/owned\n"}
        sup.verify_inherited_resources(parent, copy.deepcopy(parent))
        for field, replacement in (("credentials", {}), ("affinity", [1]),
                                   ("rlimit_nofile", [1024, 1048576]), ("cgroup_text", "0::/other\n")):
            child = copy.deepcopy(parent); child[field] = replacement
            with self.subTest(field=field), self.assertRaises(sup.Invalid):
                sup.verify_inherited_resources(parent, child)

    def test_resource_read_denial_is_not_a_missing_field_default(self):
        with mock.patch.object(sup, "read_proc_evidence", side_effect=PermissionError("denied")):
            with self.assertRaises(PermissionError):
                sup.resource_snapshot(123)


class ProcessTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="producer-supervisor-test-")
        self.root = Path(self.temp.name)

    def tearDown(self):
        self.temp.cleanup()

    def capture(self, fixture, limits=FAST):
        # The only artifact-verifier shortcut: tests use text executables instead of ELFs.
        # SHA256, manifest schemas, provenance retention and exact argv are not bypassed.
        with mock.patch.object(sup, "verify_elf"):
            return sup.run(fixture.config_path, self.root / "attempt", _limits=limits)

    def assert_reaped(self, result):
        self.assertTrue(result["cleanup_complete"], result)
        for info in result["processes"].values():
            self.assertIn("returncode", info)
            with self.assertRaises(ChildProcessError):
                os.waitpid(info["pid"], os.WNOHANG)
            self.assertFalse(sup.group_alive(info["pgid"]))

    def test_completed_direct_pipe_counting_and_below_target_status(self):
        fixture = Fixture(self.root)
        result = self.capture(fixture)
        self.assertEqual(result["status"], "valid_output_measurement", result)
        self.assertEqual(result["decision"], "below_target_supply")
        self.assertEqual(result["accounting"]["completed_output_count"], 3)
        self.assertTrue(result["test_limits"])
        self.assertFalse(result["workflow_responsibilities_independently_verified"])
        self.assert_reaped(result)
        self.assertEqual(json.loads(fixture.started.read_text())["argv"], fixture.config["producer_argv"][1:])
        self.assertEqual(json.loads(fixture.consumer_started.read_text())["argv"], ["-l", "-c"])
        retained = {p.name for p in (self.root / "attempt").iterdir()}
        self.assertEqual(retained, {"config.json", "attempt.json", "result.json", "producer.stderr",
                                    "consumer.stdout", "consumer.stderr", "supervisor-owner.json",
                                    "producer-owner.json", "consumer-owner.json"})
        for role in ("producer", "consumer"):
            owner = json.loads((self.root / "attempt" / f"{role}-owner.json").read_text())
            self.assertEqual(owner["pid"], result["processes"][role]["pid"])
            self.assertEqual(owner["pid"], owner["pgid"])
            self.assertEqual(owner["pid"], owner["sid"])
            self.assertGreater(owner["start_ticks"], 0)
        self.assertNotIn('"phase":"workload"', (self.root / "attempt" / "producer.stderr").read_text())

    def test_output_attempt_cannot_be_reused(self):
        fixture = Fixture(self.root)
        self.capture(fixture)
        before = (self.root / "attempt" / "result.json").read_bytes()
        with self.assertRaises(FileExistsError):
            self.capture(fixture)
        self.assertEqual(before, (self.root / "attempt" / "result.json").read_bytes())

    def test_swallowed_broken_pipe_zero_exit_is_invalid(self):
        fixture = Fixture(self.root, "swallowed-broken-pipe", "early-exit")
        result = self.capture(fixture)
        self.assertEqual(result["status"], "invalid", result)
        self.assertIsNone(result["decision"])
        self.assertEqual(result["processes"]["producer"]["returncode"], 0)
        self.assertTrue(any("completion" in e for e in result["errors"]), result)
        self.assert_reaped(result)

    def test_bad_count_and_missing_periodic_calibration_are_invalid(self):
        for index, mode in enumerate(("bad-count", "missing-calibration")):
            with self.subTest(mode=mode):
                root = self.root / str(index)
                root.mkdir()
                fixture = Fixture(root, mode)
                with mock.patch.object(sup, "verify_elf"):
                    result = sup.run(fixture.config_path, root / "attempt", _limits=FAST)
                self.assertEqual(result["status"], "invalid", result)
                self.assertIsNone(result["decision"])
                self.assert_reaped(result)

    def test_absolute_timeout_escalates_and_reaps(self):
        fixture = Fixture(self.root, "hang", "ignore-signals")
        limits = dataclasses.replace(FAST, timeout_ns=150_000_000)
        started = time.monotonic()
        result = self.capture(fixture, limits)
        self.assertLess(time.monotonic() - started, 3)
        self.assertEqual(result["status"], "invalid", result)
        self.assertIn("absolute pipeline timeout", result["errors"])
        self.assertIn("KILL", [x["signal"] for x in result["signals_sent"]])
        self.assertEqual(result["processes"]["producer"]["returncode"], -signal.SIGKILL)
        self.assert_reaped(result)

    def test_capture_never_signals_after_releasing_any_target_leader(self):
        fixture = Fixture(self.root, "hang", "ignore-signals")
        released = set()
        signal_events = []
        real_wait4 = os.wait4
        real_killpg = os.killpg
        def wait4(pid, flags):
            result = real_wait4(pid, flags)
            if result[0]:
                released.add(pid)
            return result
        def killpg(pgid, sig):
            if sig:
                self.assertNotIn(pgid, released, "would signal a potentially recycled group")
                signal_events.append((pgid, sig))
            return real_killpg(pgid, sig)
        with mock.patch.object(sup.os, "wait4", side_effect=wait4), \
                mock.patch.object(sup.os, "killpg", side_effect=killpg):
            result = self.capture(fixture, dataclasses.replace(FAST, timeout_ns=150_000_000))
        self.assertEqual(result["status"], "invalid", result)
        self.assertEqual(released, {info["pid"] for info in result["processes"].values()})
        self.assertTrue(signal_events)
        self.assert_reaped(result)

    def test_stderr_cap_fails_without_unbounded_retention(self):
        fixture = Fixture(self.root, "flood")
        limits = dataclasses.replace(FAST, stderr_bytes=4096)
        result = self.capture(fixture, limits)
        self.assertEqual(result["status"], "invalid", result)
        self.assertIn("producer.stderr evidence cap exceeded", result["errors"])
        self.assertEqual((self.root / "attempt" / "producer.stderr").stat().st_size, 4096)
        self.assertGreater(result["evidence_byte_counts"]["producer.stderr"], 4096)
        self.assert_reaped(result)

    def test_runtime_disk_floor_aborts_and_retains_minimum(self):
        fixture = Fixture(self.root, "hang", "ignore-signals")
        limits = dataclasses.replace(FAST, free_reserve_bytes=1024)
        calls = []
        def usage(_path):
            calls.append(True)
            return mock.Mock(free=100 * 1024 * 1024 if len(calls) == 1 else 1000)
        with mock.patch.object(sup.shutil, "disk_usage", side_effect=usage):
            result = self.capture(fixture, limits)
        self.assertEqual(result["status"], "invalid", result)
        self.assertIn("free disk fell below reserve", result["errors"])
        self.assertEqual(result["minimum_observed_free_bytes"], 1000)
        self.assertGreaterEqual(len(result["disk_observations"]), 2)
        self.assert_reaped(result)

    def test_repeated_signals_do_not_interrupt_cleanup(self):
        fixture = Fixture(self.root, "hang", "ignore-signals")
        errors = []
        def interrupt():
            deadline = time.monotonic() + 1
            while not fixture.consumer_started.exists() and time.monotonic() < deadline:
                time.sleep(0.005)
            if not fixture.consumer_started.exists():
                errors.append("consumer did not start")
                return
            os.kill(os.getpid(), signal.SIGTERM)
            time.sleep(0.01)
            os.kill(os.getpid(), signal.SIGINT)
        sender = threading.Thread(target=interrupt)
        previous_term = signal.getsignal(signal.SIGTERM)
        previous_int = signal.getsignal(signal.SIGINT)
        sender.start()
        try:
            result = self.capture(fixture)
        finally:
            sender.join(timeout=2)
        self.assertFalse(sender.is_alive())
        self.assertFalse(errors)
        self.assertEqual(result["status"], "invalid", result)
        self.assertEqual(result["received_signals"], [signal.SIGTERM, signal.SIGINT])
        self.assertEqual(signal.getsignal(signal.SIGTERM), previous_term)
        self.assertEqual(signal.getsignal(signal.SIGINT), previous_int)
        self.assertEqual(sum(x["signal"] == "TERM" for x in result["signals_sent"]), 2)
        self.assert_reaped(result)

    def test_consumer_launch_failure_cleans_up_already_started_producer(self):
        fixture = Fixture(self.root, "hang")
        real_popen = subprocess.Popen
        launched = []
        def launch(*args, **kwargs):
            if launched:
                raise OSError("injected consumer spawn failure")
            child = real_popen(*args, **kwargs)
            launched.append(child)
            return child
        with mock.patch.object(sup.subprocess, "Popen", side_effect=launch):
            result = self.capture(fixture)
        self.assertEqual(result["status"], "invalid", result)
        self.assertTrue(any("consumer spawn failure" in e for e in result["errors"]))
        self.assertEqual(set(result["processes"]), {"producer"})
        self.assert_reaped(result)

    def test_unbound_and_incompatible_arguments_never_launch(self):
        fixture = Fixture(self.root)
        original = copy.deepcopy(fixture.config)
        cases = [
            lambda c: c.update(attempt_id="UNBOUND"),
            lambda c: c["producer_argv"].extend(["-n", "3000000"]),
            lambda c: c["producer_argv"].extend(["--signing-workers", "8"]),
            lambda c: c["producer_argv"].append("--defer-signing"),
            lambda c: c["consumer_argv"].append("/tmp/input"),
            lambda c: c["environment"].update(LD_PRELOAD="/tmp/probe.so"),
            lambda c: c["publication"].update(slack=True),
        ]
        for index, mutate in enumerate(cases):
            fixture.config = copy.deepcopy(original)
            mutate(fixture.config)
            fixture.save_config()
            with self.subTest(index=index), mock.patch.object(sup, "verify_elf"), \
                    mock.patch.object(sup.subprocess, "Popen") as spawn:
                result = sup.run(fixture.config_path, self.root / f"refused-{index}", _limits=FAST)
            spawn.assert_not_called()
            self.assertEqual(result["status"], "invalid", result)
            self.assertFalse(result["processes"])

    def test_real_elf_gate_rejects_text_fixture_without_launch(self):
        fixture = Fixture(self.root)
        with mock.patch.object(sup.subprocess, "Popen") as spawn:
            result = sup.run(fixture.config_path, self.root / "attempt", _limits=FAST)
        spawn.assert_not_called()
        self.assertTrue(any("not an ELF" in e for e in result["errors"]), result)

    def test_changed_binding_refuses_launch(self):
        fixture = Fixture(self.root)
        fixture.producer.write_text(fixture.producer.read_text() + "\n# changed\n")
        with mock.patch.object(sup, "verify_elf"), mock.patch.object(sup.subprocess, "Popen") as spawn:
            result = sup.run(fixture.config_path, self.root / "attempt", _limits=FAST)
        spawn.assert_not_called()
        self.assertTrue(any("hash mismatch" in e for e in result["errors"]), result)


if __name__ == "__main__":
    unittest.main()
