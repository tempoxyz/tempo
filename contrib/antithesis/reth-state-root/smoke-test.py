#!/usr/bin/env python3
"""Test a built image's flushed-state SIGKILL recovery (requires Compose 2.24.4+)."""

import argparse
import hashlib
import json
from pathlib import Path
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import uuid


PROOF_MESSAGES = {
    "eth_getMultiProof proofs verify against the model's state root",
    "Proofs rebuilt from the execution witness verify against the model's state root",
}
SERVICE = "reth-state-root"


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def assertions(path):
    require(path.exists(), f"missing SDK output: {path}")
    events = [json.loads(line).get("antithesis_assert", {}) for line in path.read_text().splitlines()]
    hits = [event for event in events if event.get("hit")]
    failures = [event for event in hits if event.get("condition") is False
                and event.get("assert_type") != "sometimes"]
    require(not failures, f"failed SDK assertions in {path}: {failures}")
    return {event["message"] for event in hits if event.get("condition") is True}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--image", required=True, help="already built workload image (never built/pulled)")
    parser.add_argument("--output-dir", type=Path, help="new directory for logs and evidence")
    parser.add_argument("--binary-dir", type=Path, help="bind local binaries and test commands into a runtime image")
    args = parser.parse_args()
    output = args.output_dir.resolve() if args.output_dir else Path(tempfile.mkdtemp(prefix="reth-smoke-"))
    if args.output_dir:
        output.mkdir(parents=True, exist_ok=False)
    print(f"Evidence: {output}", flush=True)
    project = "reth-smoke-" + uuid.uuid4().hex[:12]
    base = Path(__file__).resolve().parent / "docker-compose.yaml"
    with tempfile.TemporaryDirectory(prefix="reth-run-") as directory:
        run = Path(directory)
        mounts = ""
        if args.binary_dir:
            binary_dir = args.binary_dir.resolve()
            for name in ["reth-state-root-antithesis", "reth-state-root-commands"]:
                require((binary_dir / name).is_file(), f"missing local binary: {binary_dir / name}")
            hashes = {}
            for name in ["reth-state-root-antithesis", "reth-state-root-commands"]:
                with (binary_dir / name).open("rb") as binary:
                    hashes[name] = hashlib.file_digest(binary, "sha256").hexdigest()
            (output / "binary-hashes.json").write_text(json.dumps(hashes, indent=2))
            sources = [(binary_dir / name, f"/usr/local/bin/{name}") for name in
                       ["reth-state-root-antithesis", "reth-state-root-commands"]]
            sources.append((base.parent / "test", "/opt/antithesis/test"))
            mounts = "".join("      - " + json.dumps({"type": "bind", "source": str(source),
                            "target": target, "read_only": True}) + "\n" for source, target in sources)
        override = output / "compose.override.yaml"
        override.write_text(f'''services:
  {SERVICE}:
    image: {json.dumps(args.image)}
    container_name: {project}-node
    entrypoint: ["/usr/local/bin/reth-state-root-antithesis"]
    environment:
      ANTITHESIS_SDK_LOCAL_OUTPUT: /run/server.sdk.jsonl
    volumes:
      - type: bind
        source: {json.dumps(str(run))}
        target: /run
{mounts}    networks: !override [default]
networks: !override
  default: {{}}
''')
        compose = ["docker", "compose", "-p", project, "-f", str(base), "-f", str(override)]

        def execute(arguments, check=True):
            result = subprocess.run(arguments, capture_output=True, text=True, timeout=180)
            with (output / "commands.log").open("a") as log:
                log.write(f"$ {arguments!r}\n{result.stdout}{result.stderr}\nexit={result.returncode}\n")
            require(not check or result.returncode == 0, f"command failed: {arguments!r}; see commands.log")
            return result

        def request(method, expected, **fields):
            with socket.socket(socket.AF_UNIX) as connection:
                connection.settimeout(60)
                connection.connect(str(run / "antithesis-trie.sock"))
                connection.sendall(json.dumps({"method": method, **fields}).encode() + b"\n")
                with connection.makefile("rb") as reader:
                    line = reader.readline()
            require(line.endswith(b"\n"), f"incomplete {method} response: {line!r}")
            response = json.loads(line)
            require(response.get("result") == expected, f"unexpected {method} response: {response}")
            return response

        def ready():
            deadline = time.monotonic() + 120
            while time.monotonic() < deadline:
                try:
                    return request("state_summary", "summary")
                except PermissionError:
                    execute(compose + ["exec", "-T", SERVICE, "chmod", "a+rw", "/run/antithesis-trie.sock"])
                except (FileNotFoundError, ConnectionRefusedError):
                    time.sleep(0.25)
            raise RuntimeError("server socket did not become ready within 120 seconds")

        def flushed():
            reply = request("flush", "flushed")
            summary = request("state_summary", "summary")
            head = summary["head"]
            require(head == reply["head"] == summary["db_tip"] == summary["state_tip"], "flush frontiers differ")
            require([root["number"] for root in summary["roots"]] == list(range(head + 1)), "missing model roots")
            return summary

        def advance(count):
            summary = request("state_summary", "summary")
            address = "0x" + "12" * 20
            writes = [{"kind": "account", "address": address, "balance": "0x7b"},
                      {"kind": "storage", "address": address, "slot": "0x1", "value": "0x2"}]
            queued = request("submit_writes", "queued", round=summary["round"], writes=writes, collider=summary["collider"])
            require(queued["pending"] == len(writes), "driver writes were not queued")
            for number in range(summary["head"] + 1, summary["head"] + count + 1):
                block = request("build_block", "block")
                require(block["number"] == number, "block production did not advance exactly once")
            result = flushed()
            require(result["head"] == summary["head"] + count, "head did not advance")
            require(result["roots"][:len(summary["roots"])] == summary["roots"], "historical roots changed")
            return result

        def checks(label, summary):
            root = request("check_root", "root")
            require(root["number"] == summary["head"] and root["root"] == summary["roots"][-1]["root"], "tip root changed")
            for command in ["anytime_root", "parallel_driver_proofs", "finally_recovered"]:
                name = f"{label}-{command}"
                reply = execute(compose + ["exec", "-T", "-e", f"ANTITHESIS_SDK_LOCAL_OUTPUT=/run/{name}.sdk.jsonl",
                                           SERVICE, f"/opt/antithesis/test/v1/reth_state_root/{command}"])
                events = [json.loads(line) for line in reply.stdout.splitlines() if line.startswith("{")]
                require(not any(event.get("server") == "unavailable" or "rejected" in event for event in events),
                        f"{command} skipped its checks")
                hits = assertions(run / f"{name}.sdk.jsonl")
                require("Trie workload completes without errors" in hits, f"{command} never completed")
                if command != "anytime_root":
                    require(PROOF_MESSAGES <= hits, f"{command} did not verify proofs AND witnesses")
                if command != "parallel_driver_proofs":
                    require(any(event.get("root") == {"number": root["number"], "root": root["root"]}
                                for event in events), f"{command} did not check the expected root")
                if command == "finally_recovered":
                    require(any(event.get("flushed", {}).get("head") == summary["head"] for event in events),
                            "finally_recovered did not flush the expected head")

        try:
            execute(compose + ["up", "-d", "--no-build", "--pull", "never"])
            container = execute(compose + ["ps", "-q", SERVICE]).stdout.strip()
            require(bool(container), "Compose returned no container ID")
            (output / "image-id.txt").write_text(execute(["docker", "inspect", "-f", "{{.Image}}", container]).stdout)
            require(ready()["head"] == 0, "smoke volume was not fresh")
            before = advance(12)
            for cycle in range(2):
                require(before["head"] > 0, "recovery test needs a nonzero head")
                (output / f"cycle-{cycle}-before.json").write_text(json.dumps(before, indent=2))
                checks(f"{cycle}-before", before)
                execute(compose + ["kill", "-s", "SIGKILL", SERVICE])
                state = json.loads(execute(["docker", "inspect", "-f", "{{json .State}}", container]).stdout)
                require(not state["Running"] and state["ExitCode"] == 137, f"not a SIGKILL exit: {state}")
                execute(compose + ["start", SERVICE])
                after = ready()
                require(execute(compose + ["ps", "-q", SERVICE]).stdout.strip() == container, "container was replaced")
                for field in ["head", "db_tip", "state_tip", "roots"]:
                    require(after[field] == before[field], f"recovery changed {field}: {before[field]} -> {after[field]}")
                (output / f"cycle-{cycle}-after.json").write_text(json.dumps(after, indent=2))
                checks(f"{cycle}-after", after)
                before = advance(3)
                checks(f"{cycle}-progress", before)
            execute(compose + ["stop", "--timeout", "10"])
            for path in run.glob("*.sdk.jsonl"):
                assertions(path)
            require("Trie workload recovers persisted blocks after restart" in assertions(run / "server.sdk.jsonl"),
                    "server SDK did not confirm nonzero persisted-state recovery")
            print(f"PASS: two SIGKILL/restart cycles; progressed to head {before['head']}")
        finally:
            failed = sys.exc_info()[0] is not None
            try:
                logs = execute(compose + ["logs", "--no-color"], check=False)
                (output / "container.log").write_text(logs.stdout + logs.stderr)
            finally:
                cleanup = execute(compose + ["down", "--volumes", "--timeout", "10"], check=False)
                for path in run.glob("*.sdk.jsonl"):
                    shutil.copy2(path, output / path.name)
                require(failed or cleanup.returncode == 0, "smoke project cleanup failed; see commands.log")


if __name__ == "__main__":
    main()
