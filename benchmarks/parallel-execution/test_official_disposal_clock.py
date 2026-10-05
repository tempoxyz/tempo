"""Pure fixtures and mocked processes: never launch Cargo, nodes or calibration."""
import contextlib
import json
from pathlib import Path
import tempfile
import types
import unittest
from unittest import mock

import official_disposal_clock as clock


def valid_log():
    return ("running 1 test\n" + "test " + clock.TEST + " ... "
            "consumed_candidate_disposal_clock kind=reuse samples=16384 p50_ns=10 p99_ns=12 max_ns=30\n"
            "consumed_candidate_disposal_clock kind=fallback samples=16384 p50_ns=10 p99_ns=13 max_ns=31\n"
            "ok\ntest result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 236 filtered out; finished in 0.01s\n")


class ClockOutputTests(unittest.TestCase):
    def parse(self, text):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "clock.log"
            path.write_text(text)
            return clock.parse_clock(path)

    def test_complete_two_path_single_test(self):
        self.assertEqual(self.parse(valid_log())["fallback"]["p99_ns"], 13)

    def test_missing_duplicate_failed_and_truncated_output_refused(self):
        text = valid_log()
        for altered in [text.replace("kind=fallback", "kind=reuse"),
                        text.replace("1 passed; 0 failed", "0 passed; 1 failed"),
                        text.replace("samples=16384", "samples=2"), text.rstrip(),
                        text + "unexpected runtime warning\n",
                        text.replace("p99_ns=12", "p99_ns=9")]:
            with self.subTest(altered=altered[-120:]):
                with self.assertRaises(ValueError):
                    self.parse(altered)

    def test_zero_selected_tests_are_not_a_calibration(self):
        with self.assertRaises(ValueError):
            self.parse("running 0 tests\ntest result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 239 filtered out; finished in 0.00s\n")


class PreflightTests(unittest.TestCase):
    def test_inherited_profile_or_allocator_override_refused_before_commands(self):
        for name in ["CARGO_PROFILE_PROFILING_OPT_LEVEL", "RUSTC_WRAPPER", "LD_PRELOAD", "MALLOC_CONF"]:
            with mock.patch.dict(clock.os.environ, {name: "override"}, clear=True), mock.patch.object(clock, "command") as command:
                with self.assertRaises(ValueError):
                    clock.environment()
                command.assert_not_called()

    def test_wrong_default_rust_refused(self):
        with mock.patch.dict(clock.os.environ, {}, clear=True), mock.patch.object(clock, "command", return_value="rustc 1.99.0\nrelease: 1.99.0"):
            with self.assertRaises(ValueError):
                clock.environment()

    def test_live_node_or_workload_refused_without_command_line_disclosure(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for index, program in enumerate(["tempo", "bench", "txgen-tempo", "rustc"], 100000):
                path = root / str(index)
                path.mkdir()
                (path / "cmdline").write_bytes(("/bin/" + program).encode() + b"\0secret-not-for-output\0")
            with self.assertRaises(ValueError) as raised:
                clock.assert_idle(root)
            self.assertNotIn("secret-not-for-output", str(raised.exception))


class BoundedProcessTests(unittest.TestCase):
    def test_log_overflow_retains_cap_and_stops_once(self):
        with tempfile.TemporaryDirectory() as directory, tempfile.TemporaryFile() as pipe:
            log = Path(directory) / "process.log"
            proc = mock.Mock(pid=123456, stdout=pipe, returncode=0)
            ended = False
            chunks = iter([b"x" * 25, b""])

            def receive(_fd, _size):
                nonlocal ended
                value = next(chunks)
                if not value:
                    ended = True
                return value

            proc.poll.side_effect = lambda: 0 if ended else None
            selector = mock.Mock()
            selector.select.return_value = [(types.SimpleNamespace(fileobj=pipe), None)]
            with mock.patch.object(clock.subprocess, "Popen", return_value=proc) as launch, \
                    mock.patch.object(clock.selectors, "DefaultSelector", return_value=selector), \
                    mock.patch.object(clock.os, "read", side_effect=receive), \
                    mock.patch.object(clock.shutil, "disk_usage", return_value=types.SimpleNamespace(free=2 * clock.DISK_FLOOR)), \
                    mock.patch.object(clock, "free_memory", return_value=2 * clock.MEM_AVAILABLE_FLOOR), \
                    mock.patch.object(clock, "send_signal") as stop:
                result = clock.run_bounded(["never-executed"], directory, {}, log, 30, 16)
            self.assertEqual(log.stat().st_size, 16)
            self.assertEqual(result["observed_output_bytes"], 25)
            self.assertEqual(result["stop_reason"], "log_limit")
            self.assertEqual(launch.call_count, 1)
            stop.assert_called_once_with(proc, clock.signal.SIGTERM)

    def test_interrupt_before_start_never_launches_process(self):
        with mock.patch.object(clock, "STOP", 2), mock.patch.object(clock.subprocess, "Popen") as launch:
            with self.assertRaises(ValueError):
                clock.run_bounded([], Path("/"), {}, Path("/unopened"), 30, 1)
            launch.assert_not_called()

    def test_low_memory_never_launches_process(self):
        with tempfile.TemporaryDirectory() as directory, \
                mock.patch.object(clock.shutil, "disk_usage", return_value=types.SimpleNamespace(free=2 * clock.DISK_FLOOR)), \
                mock.patch.object(clock, "free_memory", return_value=clock.MEM_AVAILABLE_FLOOR - 1), \
                mock.patch.object(clock.subprocess, "Popen") as launch:
            with self.assertRaises(ValueError):
                clock.run_bounded([], Path(directory), {}, Path(directory) / "unopened", 30, 1)
            launch.assert_not_called()

    def test_pipe_failure_kills_process_and_closes_resources(self):
        with tempfile.TemporaryDirectory() as directory, tempfile.TemporaryFile() as pipe:
            proc = mock.Mock(pid=123456, stdout=pipe)
            proc.poll.return_value = None
            selector = mock.Mock()
            selector.select.side_effect = OSError("fixture pipe failure")
            with mock.patch.object(clock.subprocess, "Popen", return_value=proc), \
                    mock.patch.object(clock.selectors, "DefaultSelector", return_value=selector), \
                    mock.patch.object(clock.shutil, "disk_usage", return_value=types.SimpleNamespace(free=2 * clock.DISK_FLOOR)), \
                    mock.patch.object(clock, "free_memory", return_value=2 * clock.MEM_AVAILABLE_FLOOR), \
                    mock.patch.object(clock, "send_signal") as stop:
                with self.assertRaises(OSError):
                    clock.run_bounded([], directory, {}, Path(directory) / "process.log", 30, 16)
            stop.assert_called_once_with(proc, clock.signal.SIGKILL)
            proc.wait.assert_called_once_with(timeout=5)
            selector.close.assert_called_once()
            self.assertTrue(pipe.closed)


class BuildTests(unittest.TestCase):
    def fixture(self, root):
        config_path = root / "config.json"
        config_path.write_text("{}\n")
        manifest = root / "node-build.json"
        manifest.write_text("{}\n")
        evm = root / "crates/evm/src"
        evm.mkdir(parents=True)
        (evm / "lib.rs").write_text("#[global_allocator]\nreth_cli_util::allocator::Allocator")
        (evm / "evm.rs").write_text(clock.TEST)
        binary = root / "test-binary"
        binary.write_bytes(b"not executable; never launched")
        cfg = {"output": str(root / "output"), "build_manifest": str(manifest), "source_commit": "f" * 40}
        artifact = {"reason": "compiler-artifact", "executable": str(binary),
                    "target": {"name": "tempo_evm"},
                    "profile": {"test": True, "opt_level": "3", "debug_assertions": False}}
        return config_path, cfg, artifact

    def run_fixture(self, root, rows, cfg, config_path):
        def process(argv, cwd, env, log, seconds, cap):
            log.write_text("\n".join(json.dumps(row) for row in rows) + "\n")
            self.assertEqual(seconds, 3600)
            self.assertEqual(env["RUSTFLAGS"], clock.RUSTFLAGS)
            return {"argv": argv, "exit_code": 0, "stop_reason": None, "log": clock.reference(log)}
        with mock.patch.object(clock, "check_config", return_value=(cfg, root)), \
                mock.patch.object(clock, "environment", return_value={}), \
                mock.patch.object(clock, "assert_idle"), \
                mock.patch.object(clock, "source_hashes", return_value={}), \
                mock.patch.object(clock, "run_bounded", side_effect=process):
            clock.compile_clock(config_path)

    def test_single_optimized_artifact_is_bound_to_binary(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path, cfg, artifact = self.fixture(root)
            self.run_fixture(root, [artifact], cfg, path)
            result = clock.read(root / "output/build.json")
            self.assertEqual(result["status"], "built")
            self.assertEqual(result["binary"], clock.reference(artifact["executable"]))
            self.assertEqual(result["command"][1], "+1.98.1")

    def test_missing_duplicate_and_unoptimized_artifacts_remain_inconclusive(self):
        for mode in ["missing", "duplicate", "unoptimized"]:
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                path, cfg, artifact = self.fixture(root)
                rows = [] if mode == "missing" else [artifact, artifact] if mode == "duplicate" else [artifact]
                if mode == "unoptimized":
                    artifact["profile"]["opt_level"] = "0"
                with self.assertRaises(ValueError):
                    self.run_fixture(root, rows, cfg, path)
                self.assertEqual(clock.read(root / "output/build.json")["status"], "inconclusive")


class SampleTests(unittest.TestCase):
    def fixture(self, root):
        config_path = root / "config.json"
        config_path.write_text("{}\n")
        out = root / "output"
        out.mkdir()
        binary = root / "test-binary"
        binary.write_bytes(b"not executable; never launched")
        cfg = {"output": str(out)}
        clock.save(out / "build.json", {"status": "built", "config": clock.reference(config_path),
                                        "sources": {}, "binary": clock.reference(binary)})
        return config_path, cfg, out, binary

    def patches(self, config, root):
        stack = contextlib.ExitStack()
        stack.enter_context(mock.patch.object(clock, "check_config", return_value=(config, root)))
        stack.enter_context(mock.patch.object(clock, "environment", return_value={}))
        stack.enter_context(mock.patch.object(clock, "assert_idle"))
        stack.enter_context(mock.patch.object(clock, "source_hashes", return_value={}))
        stack.enter_context(mock.patch.object(clock.os, "sched_getaffinity", return_value=set(range(32))))
        return stack

    @staticmethod
    def process(argv, cwd, env, log, seconds, cap):
        log.write_text(valid_log())
        return {"argv": argv, "exit_code": 0, "stop_reason": None, "log": clock.reference(log)}

    def test_two_validator_affinities_and_no_repeat_slot(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path, cfg, out, binary = self.fixture(root)
            with self.patches(cfg, root), mock.patch.object(clock, "run_bounded", side_effect=self.process) as run:
                clock.sample(path, "feature-1", "pre")
                self.assertEqual(run.call_count, 2)
                self.assertEqual([call.args[0][2] for call in run.call_args_list], list(clock.CPU_SETS.values()))
                with self.assertRaises(FileExistsError):
                    clock.sample(path, "feature-1", "pre")
                self.assertEqual(run.call_count, 2)
            self.assertEqual(clock.read(out / "feature-1-pre/result.json")["status"], "passed")

    def test_failed_first_role_prevents_second_role_and_retains_failure(self):
        def failed(*args):
            row = self.process(*args)
            row["exit_code"] = 1
            return row
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path, cfg, out, _ = self.fixture(root)
            with self.patches(cfg, root), mock.patch.object(clock, "run_bounded", side_effect=failed) as run:
                with self.assertRaises(ValueError):
                    clock.sample(path, "feature-1", "pre")
                self.assertEqual(run.call_count, 1)
            self.assertEqual(clock.read(out / "feature-1-pre/result.json")["status"], "inconclusive")
            self.assertTrue((out / "feature-1-pre/a-process.json").is_file())

    def test_changed_binary_and_missing_prevent_post_launch(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path, cfg, _, binary = self.fixture(root)
            with self.patches(cfg, root), mock.patch.object(clock, "run_bounded") as run:
                with self.assertRaises(FileNotFoundError):
                    clock.sample(path, "feature-1", "post")
                binary.write_bytes(b"changed")
                with self.assertRaises(ValueError):
                    clock.sample(path, "feature-2", "pre")
                run.assert_not_called()


if __name__ == "__main__":
    unittest.main()
