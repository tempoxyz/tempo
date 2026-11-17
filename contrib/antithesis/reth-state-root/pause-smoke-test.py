#!/usr/bin/env python3
"""Pause an in-flight block in one offline container, then verify SIGKILL recovery.

Uses only an already-built local image (and optionally local binaries); never builds/pulls.
Requires Linux Docker with permission to signal its container's host PID. A missed in-flight
window fails as invalid, not as a pass. The server's configured timeout is not overridden.
"""

import argparse
import hashlib
import json
import math
import os
from pathlib import Path
import shutil
import signal
import socket
import subprocess
import tempfile
import threading
import time
import uuid


PROOFS = {"eth_getMultiProof proofs verify against the model's state root",
          "Proofs rebuilt from the execution witness verify against the model's state root"}


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def assertions(path):
    require(path.exists(), f"missing SDK output: {path}")
    hits = [json.loads(line).get("antithesis_assert", {}) for line in path.read_text().splitlines()]
    require(not any(a.get("hit") and a.get("condition") is False and a.get("assert_type") != "sometimes"
                    for a in hits), f"SDK assertion failed: {path}")
    return {a.get("message") for a in hits if a.get("hit") and a.get("condition") is True}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--image", required=True, help="already-built local workload/runtime image")
    parser.add_argument("--binary-dir", type=Path, help="directory containing both workload binaries")
    parser.add_argument("--output-dir", type=Path, help="new directory for logs and evidence")
    parser.add_argument("--pause-seconds", type=float, default=87.5)
    args = parser.parse_args()
    require(math.isfinite(args.pause_seconds) and args.pause_seconds > 0, "pause must be finite and positive")
    output = args.output_dir.resolve() if args.output_dir else Path(tempfile.mkdtemp(prefix="reth-pause-"))
    if args.output_dir:
        output.mkdir(parents=True, exist_ok=False)
    print(f"Evidence: {output}", flush=True)
    name = "reth-pause-" + uuid.uuid4().hex
    wait = max(900, args.pause_seconds + 120)
    start = time.monotonic()
    lock = threading.Lock()

    def record(event, **fields):
        with lock, (output / "events.jsonl").open("a") as log:
            log.write(json.dumps({"elapsed": time.monotonic() - start, "event": event, **fields}) + "\n")

    def execute(argv, check=True, timeout=30):
        result = subprocess.run(argv, capture_output=True, text=True, timeout=timeout)
        record("command", argv=argv, code=result.returncode, stdout=result.stdout, stderr=result.stderr)
        require(not check or result.returncode == 0, f"command failed: {argv!r}; see events.jsonl")
        return result

    image = execute(["docker", "image", "inspect", "-f", "{{.Id}}", args.image]).stdout.strip()
    (output / "image-id.txt").write_text(image + "\n")
    mounts = []
    if args.binary_dir:
        hashes = {}
        for binary in ["reth-state-root-antithesis", "reth-state-root-commands"]:
            path = (args.binary_dir / binary).resolve()
            require(path.is_file() and os.access(path, os.X_OK), f"missing executable: {path}")
            with path.open("rb") as source:
                hashes[binary] = hashlib.file_digest(source, "sha256").hexdigest()
            mounts += ["-v", f"{path}:/usr/local/bin/{binary}:ro"]
        (output / "binary-hashes.json").write_text(json.dumps(hashes, indent=2))
    with tempfile.TemporaryDirectory(prefix="reth-pause-run-") as directory:
        run = Path(directory)
        stopped, done = threading.Event(), threading.Event()
        outcome = {}
        logproc = None

        def request(method, expected, timeout=wait):
            with socket.socket(socket.AF_UNIX) as connection:
                connection.settimeout(timeout)
                connection.connect(str(run / "trie.sock"))
                connection.sendall(json.dumps({"method": method}).encode() + b"\n")
                connection.shutdown(socket.SHUT_WR)
                with connection.makefile("rb") as reader:
                    line = reader.readline()
                    require(reader.read(1) == b"", f"multiple responses to {method}")
            require(line.endswith(b"\n"), f"incomplete {method} response: {line!r}")
            response = json.loads(line)
            record("response", method=method, response=response)
            require(response.get("result") == expected, f"unexpected {method} response: {response}")
            return response

        def ready():
            deadline = time.monotonic() + 90
            while time.monotonic() < deadline:
                try:
                    return request("state_summary", "summary", timeout=2)
                except (FileNotFoundError, ConnectionRefusedError, socket.timeout):
                    time.sleep(0.1)
            raise RuntimeError("server socket not ready within 90 seconds")

        def checks(label, head):
            require(request("flush", "flushed")["head"] == head, "flush head differs")
            summary = request("state_summary", "summary")
            require(summary["head"] == summary["db_tip"] == summary["state_tip"] == head, "frontiers differ")
            require([r["number"] for r in summary["roots"]] == list(range(head + 1)), "missing model roots")
            root = request("check_root", "root")
            require(root == {"result": "root", **summary["roots"][-1]}, "tip root differs")
            sdk = f"{label}.sdk.jsonl"
            reply = execute(["docker", "exec", "-e", f"ANTITHESIS_SDK_LOCAL_OUTPUT=/work/{sdk}",
                             name, "reth-state-root-commands", "finally_recovered"], timeout=wait)
            events = [json.loads(line) for line in reply.stdout.splitlines() if line.startswith("{")]
            require(not any(e.get("server") == "unavailable" or "rejected" in e for e in events), "checks skipped")
            require(PROOFS | {"Trie workload completes without errors"} <= assertions(run / sdk), "missing proof checks")
            require(any(e.get("root") == summary["roots"][-1] for e in events), "proof command checked wrong root")
            (output / f"{label}.json").write_text(json.dumps(summary, indent=2))
            return summary

        try:
            execute(["docker", "create", "--pull=never", "--name", name, "--network", "none",
                     "--user", f"{os.getuid()}:{os.getgid()}", "-v", f"{run}:/work", *mounts,
                     "-e", "ANTITHESIS_TRIE_SOCKET=/work/trie.sock", "-e", "RUST_BACKTRACE=1",
                     "-e", "ANTITHESIS_SDK_LOCAL_OUTPUT=/work/server.sdk.jsonl",
                     "--entrypoint", "/usr/local/bin/reth-state-root-antithesis", image,
                     "serve", '{"datadir":"/work/state","updates":4096}'])
            execute(["docker", "start", name])
            pid = int(execute(["docker", "inspect", "-f", "{{.State.Pid}}", name]).stdout)
            require(pid > 1, "invalid container host PID")
            logproc = subprocess.Popen(["docker", "logs", "-f", name], stdout=subprocess.PIPE,
                                       stderr=subprocess.STDOUT, text=True, bufsize=1)

            def logs():
                with (output / "container.log").open("w") as log:
                    for line in logproc.stdout:
                        log.write(line)
                        log.flush()
                        if "hint_coverage" in line and not stopped.is_set():
                            try:
                                time.sleep(0.001)  # Same in-flight window as the local reproducer.
                                os.kill(pid, signal.SIGSTOP)
                                record("sigstop", pid=pid, hint=line.strip(), build_done=done.is_set())
                            except Exception as error:
                                outcome["stop_error"] = repr(error)
                            finally:
                                stopped.set()

            threading.Thread(target=logs, daemon=True).start()
            require(ready()["head"] == 0, "test requires fresh state")

            def build():
                try:
                    outcome["block"] = request("build_block", "block")
                except Exception as error:
                    outcome["build_error"] = repr(error)
                    record("build_error", error=repr(error))
                finally:
                    done.set()

            threading.Thread(target=build, daemon=True).start()
            require(stopped.wait(90), "INVALID: no in-flight hint_coverage within 90 seconds")
            require("stop_error" not in outcome and not done.is_set(), f"INVALID: missed stop window: {outcome}")
            execute(["docker", "pause", name])
            state = json.loads(execute(["docker", "inspect", "-f", "{{json .State}}", name]).stdout)
            record("pause_confirmed", state=state, build_done=done.is_set(), seconds=args.pause_seconds)
            require(state["Paused"] and state["Running"] and not done.is_set(), "INVALID: build completed before pause")
            os.kill(pid, signal.SIGCONT)  # Clear SIGSTOP while the Docker cgroup remains frozen.
            time.sleep(args.pause_seconds)
            execute(["docker", "unpause", name])
            require(done.wait(wait), "build did not finish after unpause")
            require("build_error" not in outcome and outcome["block"]["number"] == 1, f"build failed: {outcome}")
            before = checks("after-pause", 1)
            require(outcome["block"]["root"] == before["roots"][-1]["root"], "build root changed")
            execute(["docker", "kill", "--signal", "SIGKILL", name])
            state = json.loads(execute(["docker", "inspect", "-f", "{{json .State}}", name]).stdout)
            require(not state["Running"] and state["ExitCode"] == 137, f"not a SIGKILL exit: {state}")
            execute(["docker", "start", name])
            after = ready()
            for field in ["head", "db_tip", "state_tip", "roots"]:
                require(after[field] == before[field], f"recovery changed {field}")
            checks("after-restart", 1)
            require(request("build_block", "block")["number"] == 2, "restart did not advance exactly once")
            progress = checks("after-progress", 2)
            require(progress["roots"][:len(before["roots"])] == before["roots"], "progress changed historical roots")
            execute(["docker", "stop", "--time", "10", name])
            require("Trie workload recovers persisted blocks after restart" in assertions(run / "server.sdk.jsonl"),
                    "missing server recovery assertion")
            for path in run.glob("*.sdk.jsonl"):
                assertions(path)
            record("pass", pause_seconds=args.pause_seconds, head=2)
            print("PASS: in-flight pause, proofs, persistence, SIGKILL/restart and progress")
        finally:
            # Every cleanup command targets only this test's unique container.
            try:
                execute(["docker", "unpause", name], check=False)
                execute(["docker", "kill", "--signal", "SIGCONT", name], check=False)
                logs = execute(["docker", "logs", name], check=False)
                (output / "container-final.log").write_text(logs.stdout + logs.stderr)
            finally:
                cleanup = execute(["docker", "rm", "-f", name], check=False)
                if logproc:
                    try:
                        logproc.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        logproc.kill()
                        logproc.wait(timeout=5)
                for path in run.glob("*.sdk.jsonl"):
                    shutil.copy2(path, output / path.name)
                require(cleanup.returncode == 0, "container cleanup failed; see events.jsonl")


if __name__ == "__main__":
    main()
