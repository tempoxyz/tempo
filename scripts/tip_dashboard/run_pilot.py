#!/usr/bin/env python3
"""Run isolated Rust witnesses and bind assertion markers to real test outcomes."""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import time
import uuid

import report


def execute(command, cwd, timeout):
    """Never use a shell; kill the whole admitted process group on timeout."""
    import signal
    proc = subprocess.Popen(command, cwd=cwd, stdout=subprocess.PIPE,
                            stderr=subprocess.STDOUT, text=True,
                            env={**os.environ, "CARGO_TERM_COLOR": "never"},
                            start_new_session=True)
    try:
        output, _ = proc.communicate(timeout=timeout)
        return proc.returncode, output, False
    except subprocess.TimeoutExpired:
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        output, _ = proc.communicate()
        return proc.returncode, output, True


def parse_attempt(output, test, exit_code, timed_out=False):
    """Bind completed markers to an independently completed test attempt."""
    short_name = test.rsplit("::", 1)[-1]
    markers, errors = [], []
    for line in output.splitlines():
        if "TIP_EVIDENCE " not in line:
            continue
        payload = line.split("TIP_EVIDENCE ", 1)[1].strip()
        try:
            marker = json.loads(payload)
        except (ValueError, TypeError):
            errors.append("malformed assertion marker")
            continue
        if not isinstance(marker, dict) or set(marker) != {"requirement", "case", "test", "fork"}:
            errors.append("invalid assertion marker fields")
            continue
        if any(not isinstance(v, str) or not v for v in marker.values()):
            errors.append("empty or non-string assertion identity")
            continue
        if marker["test"] not in (test, short_name):
            errors.append("marker belongs to another test")
            continue
        marker["test"] = test
        markers.append(marker)
    completed = re.search(r"test result: ok\. 1 passed; 0 failed; 0 ignored;", output) is not None
    passed = exit_code == 0 and not timed_out and completed and not errors
    return {
        "id": str(uuid.uuid4()), "test": test, "full_test": test,
        "outcome": "passed" if passed else "failed", "exit_code": exit_code,
        "timed_out": timed_out, "markers": markers, "errors": errors,
        "completed_tests": 1 if completed else 0,
    }


def write_json(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = path.with_suffix(path.suffix + ".tmp")
    temp.write_text(json.dumps(value, indent=2) + "\n")
    temp.replace(path)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", default=".", type=Path)
    parser.add_argument("--output", default="output/tip-dashboard/evidence.json", type=Path)
    parser.add_argument("--timeout", type=int, default=1800, help="Total compilation and execution seconds")
    parser.add_argument("--jobs", type=int, default=4)
    parser.add_argument("--package", default="tempo-precompiles")
    parser.add_argument("--filter", default="spec_dashboard")
    args = parser.parse_args(argv)
    repo = args.repo.resolve()
    output = args.output.resolve()
    deadline = time.monotonic() + args.timeout
    envelope = {"schema_version": 1, "runner": {"name": "tip-pilot", "version": "1"},
                "provenance": {"kind": "ci" if os.environ.get("GITHUB_ACTIONS") else "local",
                               "run_url": None}, "attempts": [], "errors": [],
                "started_at": datetime.now(timezone.utc).isoformat()}
    if os.environ.get("GITHUB_RUN_ID") and os.environ.get("GITHUB_REPOSITORY"):
        envelope["provenance"]["run_url"] = (
            "https://github.com/" + os.environ["GITHUB_REPOSITORY"] +
            "/actions/runs/" + os.environ["GITHUB_RUN_ID"] +
            "/attempts/" + os.environ.get("GITHUB_RUN_ATTEMPT", "1"))
    log_parts = []
    try:
        if args.timeout <= 0 or args.jobs <= 0:
            raise ValueError("timeout and jobs must be positive")
        context = report.evidence_context(repo, "WORKTREE")
        envelope.update(context)
        build = ["cargo", "test", "--locked", "-p", args.package, "--features", "test-utils", "--lib", "--no-run",
                 "--message-format=json", "-j", str(args.jobs)]
        code, stdout, timed_out = execute(build, repo, max(1, deadline - time.monotonic()))
        log_parts.append(stdout)
        envelope["build"] = {"command": build, "exit_code": code, "timed_out": timed_out}
        if code or timed_out:
            raise RuntimeError("pilot build failed or timed out; see execution.log")
        binaries = set()
        for line in stdout.splitlines():
            try:
                item = json.loads(line)
            except ValueError:
                continue
            if item.get("reason") == "compiler-artifact" and item.get("profile", {}).get("test"):
                target = item.get("target", {})
                if item.get("executable") and "lib" in target.get("kind", []):
                    binaries.add(item["executable"])
        discovered = []
        for binary in sorted(binaries):
            code, listed, timed_out = execute([binary, "--list", "--ignored", args.filter], repo,
                                              max(1, deadline - time.monotonic()))
            if code or timed_out:
                raise RuntimeError("could not discover ignored pilot tests")
            for line in listed.splitlines():
                if line.endswith(": test"):
                    discovered.append((binary, line[:-6]))
        if not discovered:
            raise RuntimeError("no ignored pilot tests discovered in the selected revision")
        for index, (binary, name) in enumerate(discovered):
            code, stdout, timed_out = execute(
                [binary, "--exact", name, "--ignored", "--nocapture", "--test-threads=1"],
                repo, max(1, deadline - time.monotonic()))
            log_parts.append(stdout)
            attempt = parse_attempt(stdout, name, code, timed_out)
            attempt["sequence"] = index
            envelope["attempts"].append(attempt)
        if context != report.evidence_context(repo, "WORKTREE"):
            raise RuntimeError("source or collector changed while the pilot was running; evidence is stale")
    except Exception as error:
        envelope["errors"].append(str(error))
        # An envelope with no accepted attempts is deliberately not passing evidence.
        for attempt in envelope["attempts"]:
            attempt["outcome"] = "failed"
            attempt.setdefault("errors", []).append("collection context invalidated")
    envelope["finished_at"] = datetime.now(timezone.utc).isoformat()
    output.parent.mkdir(parents=True, exist_ok=True)
    output.with_name("execution.log").write_text("\n".join(log_parts))
    write_json(output, envelope)
    clean = bool(envelope["attempts"]) and not envelope["errors"] and all(
        a["outcome"] == "passed" for a in envelope["attempts"])
    print(f"Pilot {'passed' if clean else 'incomplete/failed'}: {output}")
    for error in envelope["errors"]:
        print(error, file=sys.stderr)
    return 0 if clean else 1


if __name__ == "__main__":
    raise SystemExit(main())
