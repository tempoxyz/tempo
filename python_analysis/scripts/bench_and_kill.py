#!/usr/bin/env python3
"""
Run the tempo max-TPS bench workload, shut down the node, and optionally analyze logs.

Python port of the legacy bench_and_kill.sh helper so the benchmark pipeline can stay in Python.
"""

from __future__ import annotations

import argparse
import os
import signal
import subprocess
import sys
import threading
import time
from pathlib import Path
from urllib.error import URLError
from urllib.request import Request, urlopen

# Resolve repository root from scripts/ directory.
REPO_ROOT = Path(__file__).resolve().parents[2]
ANALYZE_SCRIPT = REPO_ROOT / "analyze_log.py"
RPC_URL = "http://localhost:8545"


DEFAULT_LOG_PATH = os.environ.get(
    "TEMPO_LOG_FILE",
    str(Path(__file__).resolve().parents[1] / "logs" / "debug.log"),
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run tempo bench workload and stop the node.")
    parser.add_argument(
        "--log",
        default=DEFAULT_LOG_PATH,
        help="Path to debug log produced by the tempo node (default: logs/debug.log or TEMPO_LOG_FILE env)",
    )
    parser.add_argument(
        "--json-output",
        dest="json_output",
        help="Write summary metrics JSON to the given path",
    )
    parser.add_argument(
        "--label",
        help="Label to include in the metrics JSON",
    )
    parser.add_argument(
        "--quiet",
        action="store_true",
        help="Suppress verbose analysis output",
    )
    parser.add_argument(
        "--skip-analysis",
        action="store_true",
        help="Skip the log analysis step (use when orchestrator handles it)",
    )
    parser.add_argument(
        "--duration-seconds",
        type=int,
        default=60,
        help="Duration to run tempo-bench before stopping (default: 60 seconds)",
    )
    return parser.parse_args()


def wait_for_tempo(rpc_url: str, timeout_seconds: int = 120) -> None:
    print("Waiting for tempo HTTP endpoint...")
    payload = b'{"jsonrpc":"2.0","method":"eth_blockNumber","params":[],"id":1}'
    headers = {"Content-Type": "application/json"}
    request = Request(rpc_url, data=payload, headers=headers)

    deadline = time.time() + timeout_seconds
    while time.time() < deadline:
        try:
            with urlopen(request, timeout=2) as response:  # nosec - local URL
                if response.status == 200:
                    print("Tempo HTTP endpoint is ready.")
                    return
        except URLError:
            pass
        time.sleep(1)

    raise RuntimeError(f"Tempo HTTP endpoint at {rpc_url} did not become ready in time.")


def run_tempo_bench(duration_seconds: int, log_dir: Path) -> None:
    print("Step 1: Running tempo-bench with max-tps...")
    cmd = [
        "cargo",
        "run",
        "--bin",
        "tempo-bench",
        "run-max-tps",
        "--duration",
        str(duration_seconds),
        "--tps",
        "20000",
        "--target-urls",
        RPC_URL,
        "--disable-thread-pinning",
        "true",
        "--chain-id",
        "1337",
    ]
    process = subprocess.Popen(
        cmd,
        cwd=REPO_ROOT,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1,
    )

    bench_cli_log = log_dir / "bench.log"

    def stream_output() -> None:
        if not process.stdout:
            return
        prefix = "tempo bench: "
        with bench_cli_log.open("a") as log_handle:
            for line in process.stdout:
                sys.stdout.write(prefix + line)
                sys.stdout.flush()
                log_handle.write(prefix + line)
                log_handle.flush()

    stream_thread = threading.Thread(target=stream_output, name="tempo-bench-log", daemon=True)
    stream_thread.start()

    # Add buffer time for tempo-bench to finish cleanly after its internal duration expires
    timeout = duration_seconds + 30
    stopped_by_timer = False
    try:
        process.wait(timeout=timeout)
        if process.returncode not in (0, None):
            # Failed before the timer elapsed
            raise subprocess.CalledProcessError(process.returncode, cmd)
        print("tempo-bench completed successfully.")
        return
    except subprocess.TimeoutExpired:
        stopped_by_timer = True
        print(f"tempo-bench still running after {timeout}s timeout, stopping workload...")
        process.send_signal(signal.SIGINT)
        try:
            process.wait(timeout=30)
        except subprocess.TimeoutExpired:
            print("tempo-bench did not exit after SIGINT, killing process.")
            process.kill()
            process.wait()
    finally:
        # Ensure stdout is closed so the streaming thread exits
        if process.stdout:
            try:
                process.stdout.close()
            except Exception:
                pass
        stream_thread.join(timeout=5)

    return_code = process.returncode
    if return_code in (None, 0):
        print("tempo-bench stopped successfully.")
        return

    # Normalise signal-based exits (e.g., 130, -2) when we initiated the stop.
    expected_signals = {
        -signal.SIGINT,
        -signal.SIGTERM,
        -signal.SIGKILL,
        128 + signal.SIGINT,
        128 + signal.SIGTERM,
        128 + signal.SIGKILL,
        256 - signal.SIGINT,
        256 - signal.SIGTERM,
        256 - signal.SIGKILL,
    }
    if stopped_by_timer and return_code in expected_signals:
        print(f"tempo-bench stopped via signal (return code {return_code}).")
        return

    raise subprocess.CalledProcessError(return_code or -1, cmd)


def find_tempo_pids() -> list[int]:
    print("\nStep 2: Finding tempo node process...")
    result = subprocess.run(
        ["pgrep", "-x", "tempo"],
        cwd=REPO_ROOT,
        check=False,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0 or not result.stdout.strip():
        return []
    pids: list[int] = []
    for token in result.stdout.split():
        try:
            pids.append(int(token))
        except ValueError:
            continue
    return pids


def kill_tempo(pids: list[int]) -> None:
    if not pids:
        raise RuntimeError("No tempo process found")

    print(f"Found tempo process IDs: {', '.join(map(str, pids))}")
    print("\nStep 3: Killing tempo node...")
    for pid in pids:
        try:
            os.kill(pid, signal.SIGTERM)
        except ProcessLookupError:
            continue

    for pid in pids:
        try:
            os.waitpid(pid, 0)
        except ChildProcessError:
            pass
        except OSError:
            pass

    print("Tempo process killed successfully")


def analyze_logs(args: argparse.Namespace) -> None:
    if args.skip_analysis:
        print("\nSkipping log analysis step (requested via --skip-analysis).")
        return

    log_path = Path(args.log)
    print(f"\nStep 4: Analyzing logs ({log_path})...")

    analyze_args = [
        sys.executable,
        str(ANALYZE_SCRIPT),
        "--log",
        str(log_path),
    ]

    if args.json_output:
        json_path = Path(args.json_output)
        json_path.parent.mkdir(parents=True, exist_ok=True)
        analyze_args.extend(["--json", str(json_path)])

    if args.label:
        analyze_args.extend(["--label", args.label])

    if args.quiet:
        analyze_args.append("--quiet")

    subprocess.run(analyze_args, cwd=REPO_ROOT, check=True)


def main() -> None:
    args = parse_args()

    log_path = Path(args.log)
    log_path.parent.mkdir(parents=True, exist_ok=True)

    wait_for_tempo(RPC_URL)
    run_tempo_bench(args.duration_seconds, log_path.parent)

    pids = find_tempo_pids()
    if not pids:
        raise SystemExit("No tempo process found")

    kill_tempo(pids)

    analyze_logs(args)


if __name__ == "__main__":
    try:
        main()
    except subprocess.CalledProcessError as err:
        raise SystemExit(err.returncode) from err
