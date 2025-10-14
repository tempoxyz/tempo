#!/usr/bin/env python3
"""Automates Tempo benches for two Reth revisions and prints the metrics comparison."""

from __future__ import annotations

import atexit
import json
import re
import signal
import subprocess
import sys
import threading
import time
from datetime import datetime
from pathlib import Path
from typing import Iterable, Optional, Sequence
from urllib.error import URLError
from urllib.request import Request, urlopen

# Add parent directory to path for importing from lib
sys.path.insert(0, str(Path(__file__).parent.parent))

from lib.log_analysis import (
    strip_ansi_codes,
    parse_timestamp,
    parse_time_to_ms,
    find_block_range,
    compute_statistics,
    build_summary,
    analyze_log,
)

FEATURE_COMMIT = "1619408"
MAIN_COMMIT = "d2070f4de34f523f6097ebc64fa9d63a04878055"
# Navigate to repo root (2 levels up from scripts/)
SCRIPT_DIR = Path(__file__).resolve().parent.parent.parent
TEMPO_BIN = SCRIPT_DIR / "target" / "release" / "tempo"
BENCH_AND_KILL_SCRIPT = Path(__file__).resolve().parent / "bench_and_kill.sh"
LOG_SELECTORS = re.compile(
    r"build_payload|Received block from consensus engine|State root task finished|Block added to canonical chain"
)
BUILD_PAYLOAD_MARKER = re.compile(r"build[_ ]payload", re.IGNORECASE)

# TL;DR workflow:
# 1. Swap the Reth git revision, then cargo update/build to rebuild tempo.
# 2. Start tempo, tee interesting logs into per-run files, and wait for readiness.
# 3. Run the bench workload, kill tempo once the run is done.
# 4. Parse captured logs (only txs > 1), write metrics JSON, print comparison.
tempo_process: Optional[subprocess.Popen[str]] = None
tempo_thread: Optional[threading.Thread] = None
MetricStats = dict[str, object]
MetricsSummary = dict[str, object]


# ---- Log analysis helpers -------------------------------------------------

def print_block_decisions(block_decisions: dict[int, dict[str, object]], block_range: Optional[Sequence[int]]) -> None:
    """Print a summary of which blocks were included/excluded and why."""
    if not block_decisions:
        return

    included_blocks = []
    excluded_blocks = []

    for block_num in sorted(block_decisions.keys()):
        decision = block_decisions[block_num]
        if decision["include"] and (block_range is None or (block_range[0] <= block_num <= block_range[1])):
            included_blocks.append(block_num)
        else:
            excluded_blocks.append((block_num, decision))

    print("\n" + "="*80)
    print("BLOCK FILTERING DECISIONS")
    print("="*80)

    if block_range:
        print(f"Steady-state range: [{block_range[0]} - {block_range[1]}]")
    else:
        print("Steady-state range: None (all blocks analyzed)")

    print(f"\n✓ Included blocks: {len(included_blocks)}")
    if included_blocks and len(included_blocks) <= 20:
        print(f"  Block numbers: {included_blocks}")
    elif included_blocks:
        print(f"  Block range: {included_blocks[0]} to {included_blocks[-1]}")

    # Check for metric consistency
    metric_issues = []
    for block_num in included_blocks:
        decision = block_decisions[block_num]
        missing = []
        if not decision["has_build_time"]:
            missing.append("build_time")
        if not decision["has_payload_to_received_time"]:
            missing.append("payload_to_received")
        if not decision["has_block_added_time"]:
            missing.append("block_added")

        if missing:
            metric_issues.append((block_num, missing))

    if metric_issues:
        print(f"\n  ⚠️  WARNING: {len(metric_issues)} blocks have missing metrics:")
        for block_num, missing in metric_issues[:10]:  # Show first 10
            print(f"      Block {block_num}: missing {', '.join(missing)}")
        if len(metric_issues) > 10:
            print(f"      ... and {len(metric_issues) - 10} more")

    print(f"\n✗ Excluded blocks: {len(excluded_blocks)}")
    if excluded_blocks and len(excluded_blocks) <= 20:
        for block_num, decision in excluded_blocks:
            reason = decision["reason"] or "Unknown"
            tx_count = decision["tx_count"]
            print(f"  Block {block_num}: {reason} (txs={tx_count})")
    elif excluded_blocks:
        # Group by reason
        reason_counts: dict[str, int] = {}
        for _, decision in excluded_blocks:
            reason = decision["reason"] or "Unknown"
            reason_counts[reason] = reason_counts.get(reason, 0) + 1
        for reason, count in reason_counts.items():
            print(f"  {reason}: {count} blocks")

    print("="*80 + "\n")


def parse_log_file_with_decisions(log_file: Path, block_range: Optional[Sequence[int]] = None) -> tuple[list[float], list[float], list[float], list[float], list[float], list[float]]:
    """
    Enhanced version of parse_log_file that tracks block decisions for debugging.
    This is used by the benchmark comparison script to provide detailed feedback.
    """
    build_times: list[float] = []
    execution_times: list[float] = []
    builder_finish_times: list[float] = []
    state_root_task_times: list[float] = []
    block_added_times: list[float] = []
    payload_to_received_times: list[float] = []

    built_payload_times: dict[int, dict[str, object]] = {}
    current_block_context: Optional[dict[str, object]] = None

    # Track block decisions for verification
    block_decisions: dict[int, dict[str, object]] = {}

    with log_file.open("r", encoding="utf-8") as handle:
        for raw_line in handle:
            timestamp = parse_timestamp(raw_line)
            clean_line = strip_ansi_codes(raw_line)

            if BUILD_PAYLOAD_MARKER.search(clean_line):
                parent_match = re.search(r"parent_number\s*=\s*(\d+)", clean_line)
                txs_match = re.search(r"total_transactions\s*=\s*(\d+)", clean_line)
                if parent_match and timestamp:
                    parent_number = int(parent_match.group(1))
                    block_number = parent_number + 1
                    total_transactions = int(txs_match.group(1)) if txs_match else 0
                    include_block = total_transactions > 1 and block_number != 1

                    # Track block decision
                    block_decisions[block_number] = {
                        "tx_count": total_transactions,
                        "include": include_block,
                        "reason": None,
                        "has_build_time": False,
                        "has_payload_to_received_time": False,
                        "has_block_added_time": False,
                    }

                    if include_block or block_number > 1:
                        built_payload_times[block_number] = {"timestamp": timestamp, "include": include_block}

                match = re.search(r"elapsed\s*=\s*([\d.]+(?:ms|µs|s))", clean_line)
                if match and parent_match:
                    block_number = int(parent_match.group(1)) + 1
                    block_info = built_payload_times.get(block_number)
                    in_range = block_range is None or (block_range[0] <= block_number <= block_range[1])

                    if block_number in block_decisions:
                        if not block_info or not block_info["include"]:
                            block_decisions[block_number]["reason"] = "Block #1 or ≤1 tx"
                        elif not in_range:
                            block_decisions[block_number]["reason"] = f"Outside range [{block_range[0]}-{block_range[1]}]" if block_range else None

                    if block_info and block_info["include"] and in_range:
                        time_ms = parse_time_to_ms(match.group(1))
                        if time_ms is not None:
                            build_times.append(time_ms)
                            if block_number in block_decisions:
                                block_decisions[block_number]["has_build_time"] = True

                        # Extract execution_elapsed
                        exec_match = re.search(r"execution_elapsed\s*=\s*([\d.]+(?:ms|µs|s|ns))", clean_line)
                        if exec_match:
                            time_str = exec_match.group(1)
                            # Handle nanoseconds
                            if time_str.endswith("ns"):
                                exec_time_ms = float(time_str[:-2]) / 1_000_000.0
                            else:
                                exec_time_ms = parse_time_to_ms(time_str)
                            if exec_time_ms is not None:
                                execution_times.append(exec_time_ms)

                        # Extract builder_finish_elapsed
                        builder_match = re.search(r"builder_finish_elapsed\s*=\s*([\d.]+(?:ms|µs|s|ns))", clean_line)
                        if builder_match:
                            time_str = builder_match.group(1)
                            # Handle nanoseconds
                            if time_str.endswith("ns"):
                                builder_time_ms = float(time_str[:-2]) / 1_000_000.0
                            else:
                                builder_time_ms = parse_time_to_ms(time_str)
                            if builder_time_ms is not None:
                                builder_finish_times.append(builder_time_ms)

            elif "Received block from consensus engine" in clean_line:
                number_match = re.search(r"number\s*=\s*(\d+)", clean_line)
                if number_match and timestamp:
                    block_number = int(number_match.group(1))
                    block_info = built_payload_times.get(block_number)
                    if block_info:
                        # Set current block context for state root task tracking
                        in_range = block_range is None or (block_range[0] <= block_number <= block_range[1])
                        current_block_context = {
                            "block_number": block_number,
                            "include": block_info["include"],
                            "in_range": in_range
                        }
                        if (
                            block_info["include"]
                            and in_range
                        ):
                            start_time = block_info["timestamp"]
                            elapsed_ms = (timestamp - start_time).total_seconds() * 1000
                            payload_to_received_times.append(elapsed_ms)
                            if block_number in block_decisions:
                                block_decisions[block_number]["has_payload_to_received_time"] = True
                        del built_payload_times[block_number]
                continue

            elif "State root task finished" in clean_line:
                match = re.search(r"elapsed\s*=\s*([\d.]+(?:ms|µs|s))", clean_line)
                if match and current_block_context:
                    if current_block_context["include"] and current_block_context["in_range"]:
                        time_ms = parse_time_to_ms(match.group(1))
                        if time_ms is not None:
                            state_root_task_times.append(time_ms)

            elif "Block added to canonical chain" in clean_line:
                number_match = re.search(r"number\s*=\s*(\d+)", clean_line)
                txs_match = re.search(r"txs\s*=\s*(\d+)", clean_line)
                match = re.search(r"elapsed\s*=\s*([\d.]+(?:ms|µs|s))", clean_line)
                if match and number_match:
                    block_number = int(number_match.group(1))
                    total_transactions = int(txs_match.group(1)) if txs_match else 0
                    # Apply consistent filtering: exclude block #1 and blocks with ≤1 tx
                    if total_transactions <= 1 or block_number == 1:
                        continue
                    if block_range is None or (block_range[0] <= block_number <= block_range[1]):
                        time_ms = parse_time_to_ms(match.group(1))
                        if time_ms is not None:
                            block_added_times.append(time_ms)
                            if block_number in block_decisions:
                                block_decisions[block_number]["has_block_added_time"] = True
                # Clear block context
                current_block_context = None

    # Print block decisions summary
    print_block_decisions(block_decisions, block_range)

    return build_times, execution_times, builder_finish_times, state_root_task_times, payload_to_received_times, block_added_times


def analyze_log_file(log_file: Path, *, label: Optional[str] = None, quiet: bool = True) -> MetricsSummary:
    """
    Analyze a log file with block decision tracking for detailed debugging.
    Uses the enhanced parse_log_file_with_decisions function.
    """
    if not log_file.exists():
        raise FileNotFoundError(f"Log file not found: {log_file}")

    first_block, last_block = find_block_range(log_file)
    block_range = (first_block, last_block) if first_block is not None and last_block is not None else None

    # Use the enhanced version with decision tracking
    build_times, execution_times, builder_finish_times, state_root_task_times, payload_to_received_times, block_added_times = parse_log_file_with_decisions(
        log_file, block_range
    )

    # Build metrics dict compatible with the library's build_summary function
    metrics = {
        "build_times": build_times,
        "execution_times": execution_times,
        "builder_finish_times": builder_finish_times,
        "state_root_task_times": state_root_task_times,
        "payload_to_received_times": payload_to_received_times,
        "block_added_times": block_added_times,
    }

    summary = build_summary(log_file, block_range, metrics, label=label)

    if not quiet:
        print("")
        print(f"Analyzing {log_file}...")
        if block_range:
            start, end = block_range
            print(f"Blocks analyzed: {start} -> {end} ({end - start + 1} blocks)")
        else:
            print("Analyzed entire log (no non-empty steady-state range detected).")
        for metric_name, stats in summary["metrics"].items():
            if not stats:
                print(f"- {metric_name}: no samples")
                continue
            print(f"- {metric_name}: mean={stats['mean']:.3f} ms, median={stats['median']:.3f} ms, count={int(stats['count'])}")

    return summary


def write_metrics(summary: MetricsSummary, metrics_path: Path) -> None:
    metrics_path.write_text(json.dumps(summary, indent=2))


# ---- Benchmark orchestration ---------------------------------------------


def run_command(args: Iterable[str], *, cwd: Path | None = None) -> None:
    """Run a subprocess, streaming output. Raise if it fails."""
    print("")
    print(f"Running command: {' '.join(args)}")
    subprocess.run(args, cwd=cwd, check=True)


def cleanup(*_args: object) -> None:
    """Best-effort cleanup to avoid dangling tempo processes."""
    global tempo_process, tempo_thread

    if tempo_process and tempo_process.poll() is None:
        tempo_process.terminate()
        try:
            tempo_process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            tempo_process.kill()

    if tempo_thread and tempo_thread.is_alive():
        tempo_thread.join(timeout=5)
    tempo_thread = None

    # mirror the shell script's pkill safeguard; ignore failures.
    try:
        subprocess.run(["pkill", "-x", "tempo"], check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except FileNotFoundError:
        pass

    tempo_process = None


atexit.register(cleanup)
signal.signal(signal.SIGINT, cleanup)
signal.signal(signal.SIGTERM, cleanup)


def update_reth_revision(label: str, commit: str) -> None:
    cargo_toml = SCRIPT_DIR / "Cargo.toml"
    print("")
    print(f"=== Switching to {label} commit {commit} ===")

    original = cargo_toml.read_text()
    # More robust pattern that handles variable whitespace
    pattern = r'(git\s*=\s*"https://github\.com/paradigmxyz/reth",\s*rev\s*=\s*")([^"]*)(")'
    updated, count = re.subn(pattern, r"\g<1>" + commit + r"\g<3>", original)

    if count == 0:
        raise RuntimeError(
            "Unable to locate Reth git revision in Cargo.toml. "
            "Expected format: git = \"https://github.com/paradigmxyz/reth\", rev = \"...\""
        )

    # Validate we updated the expected number of reth dependencies (should be 50+)
    if count < 50:
        raise RuntimeError(
            f"Only updated {count} reth dependencies. Expected 50+. "
            "This may indicate an incomplete Cargo.toml or pattern mismatch."
        )

    print(f"Updated {count} reth dependencies from their current revision to {commit[:7]}...")
    cargo_toml.write_text(updated)
    print("")
    print("Updating reth dependency...")
    run_command(["cargo", "update", "-p", "reth"], cwd=SCRIPT_DIR)

    print("")
    print("Building tempo (--release)...")
    run_command(["cargo", "build", "--release"], cwd=SCRIPT_DIR)


def start_tempo_node(log_path: Path, extra_args: Optional[list[str]] = None) -> None:
    global tempo_process, tempo_thread

    if not TEMPO_BIN.exists():
        raise FileNotFoundError(f"tempo binary not found at {TEMPO_BIN}. Did the build succeed?")

    log_path.write_text("")

    args = [
        str(TEMPO_BIN),
        "node",
        "--http",
        "--http.addr",
        "0.0.0.0",
        "--http.port",
        "8545",
        "--http.api",
        "all",
        "--datadir",
        "./data",
        "--dev",
        "--dev.block-time",
        "1s",
        "--chain",
        "genesis.json",
        "--engine.disable-precompile-cache",
        "--builder.gaslimit",
        "3000000000",
        "--builder.max-tasks",
        "8",
        "--builder.deadline",
        "4",
        "--txpool.pending-max-count",
        "10000000000000",
        "--txpool.basefee-max-count",
        "10000000000000",
        "--txpool.queued-max-count",
        "10000000000000",
        "--txpool.pending-max-size",
        "10000",
        "--txpool.basefee-max-size",
        "10000",
        "--txpool.queued-max-size",
        "10000",
        "--txpool.max-new-pending-txs-notifications",
        "10000000",
        "--txpool.max-account-slots",
        "500000",
        "--txpool.max-pending-txns",
        "10000000000000",
        "--txpool.max-new-txns",
        "10000000000000",
        "--txpool.disable-transactions-backup",
        "--txpool.additional-validation-tasks",
        "8",
        "--txpool.minimal-protocol-fee",
        "0",
        "--txpool.minimum-priority-fee",
        "0",
        "--rpc.max-connections",
        "429496729",
        "--rpc.max-request-size",
        "1000000",
        "--rpc.max-response-size",
        "1000000",
        "--max-tx-reqs",
        "1000000",
    ]

    # Add extra arguments if provided
    if extra_args:
        args.extend(extra_args)

    print("")
    print("Starting tempo node...")
    if extra_args:
        print(f"  Extra arguments: {' '.join(extra_args)}")
    tempo_process = subprocess.Popen(
        args,
        cwd=SCRIPT_DIR,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1,
    )

    process = tempo_process

    bench_log_path = log_path.parent / "bench.log"

    def stream_reader(proc: subprocess.Popen[str], destination: Path, bench_log: Path) -> None:
        if not proc.stdout:
            return
        with proc.stdout as stream, destination.open("a") as log_handle, bench_log.open("a") as bench_handle:
            for line in stream:
                clean_line = strip_ansi_codes(line)
                bench_handle.write(clean_line)
                bench_handle.flush()
                if LOG_SELECTORS.search(line):
                    log_handle.write(clean_line)
                    log_handle.flush()

    tempo_thread = threading.Thread(
        target=stream_reader, args=(process, log_path, bench_log_path), name="tempo-log-reader", daemon=True
    )
    tempo_thread.start()

    wait_for_tempo()


def wait_for_tempo() -> None:
    print("Waiting for tempo HTTP endpoint...")
    payload = b'{"jsonrpc":"2.0","method":"eth_blockNumber","params":[],"id":1}'
    headers = {"Content-Type": "application/json"}
    request = Request("http://localhost:8545", data=payload, headers=headers)

    for _ in range(60):
        if tempo_process and tempo_process.poll() is not None:
            raise RuntimeError("Tempo process exited unexpectedly while waiting for readiness.")
        try:
            with urlopen(request, timeout=2) as response:  # nosec: HTTP call to local node
                if response.status == 200:
                    print("Tempo HTTP endpoint is ready.")
                    return
        except URLError:
            pass
        time.sleep(1)

    raise RuntimeError("Tempo HTTP endpoint did not become ready in time.")


def run_bench_cycle(label: str, commit: str, log_path: Path, metrics_path: Path, extra_args: Optional[list[str]] = None) -> MetricsSummary:
    global tempo_process, tempo_thread

    update_reth_revision(label, commit)
    start_tempo_node(log_path, extra_args)

    print("")
    print(f"Running bench_and_kill.sh for {label}...")
    run_command(
        [
            "bash",
            str(BENCH_AND_KILL_SCRIPT),
            "--log",
            str(log_path),
            "--skip-analysis",
        ],
        cwd=SCRIPT_DIR,
    )

    print("")
    print("Waiting for tempo node to exit...")
    if tempo_process:
        tempo_process.wait()
    if tempo_thread and tempo_thread.is_alive():
        tempo_thread.join(timeout=5)
    summary = analyze_log_file(log_path, label=label, quiet=True)
    write_metrics(summary, metrics_path)
    print(f"Bench cycle for {label} complete. Metrics saved to {metrics_path}")
    # Reset globals to avoid leaking state between cycles.
    tempo_process = None
    tempo_thread = None
    return summary


def print_comparison(before_file: Path, after_file: Path) -> None:
    if not before_file.exists() or not after_file.exists():
        print("Comparison skipped: missing metrics files.")
        return

    before = json.loads(before_file.read_text())
    after = json.loads(after_file.read_text())

    # Order for rendering key tempo metrics:
    # - Build Payload Time: proposer payload construction latency (total).
    # - Execution Time: EVM execution phase from built payload.
    # - Payload Finalization: builder finalization phase that merges transitions and may compute the state root synchronously.
    # - State Root Task: explicit state root computation (ranges from µs cache lookups to seconds for actual computation).
    # - Payload Delivery Lag: time from payload build to consensus-engine receipt.
    # - Block Added to Canonical Chain: end-to-end block import confirmation.
    metrics_order = [
        "Build Payload Time",
        "Execution Time",
        "Payload Finalization",
        "State Root Task",
        "Payload Delivery Lag",
        "Block Added to Canonical Chain",
    ]

    stat_labels = [
        ("mean", "Average"),
        ("median", "Median"),
        ("min", "Min"),
        ("max", "Max"),
        ("std_dev", "Std Dev"),
    ]

    def fmt(value: Optional[float]) -> str:
        if value is None:
            return "n/a"
        return f"{value:.3f} ms"

    def fmt_signed(value: Optional[float]) -> str:
        if value is None:
            return "n/a"
        return f"{value:+.3f} ms"

    def fmt_pct(before_val: Optional[float], diff: float) -> str:
        if before_val in (None, 0):
            return "n/a"
        return f"{(diff / before_val) * 100:+.1f}%"

    print("Complete Metrics Comparison")
    print("{:<28} {:<10} {:>14} {:>14} {:>14} {:>10}".format("Metric", "Statistic", "Before", "After", "Abs Diff", "% Change"))

    for metric in metrics_order:
        before_stats = before["metrics"].get(metric)
        after_stats = after["metrics"].get(metric)

        for stat_key, stat_label in stat_labels:
            before_val = before_stats.get(stat_key) if before_stats else None
            after_val = after_stats.get(stat_key) if after_stats else None

            if before_val is None and after_val is None:
                continue

            diff: Optional[float] = None
            if before_val is not None and after_val is not None:
                diff = after_val - before_val

            diff_str = fmt_signed(diff) if diff is not None else "n/a"
            pct_str = fmt_pct(before_val, diff) if diff is not None else "n/a"

            print(
                "{:<28} {:<10} {:>14} {:>14} {:>14} {:>10}".format(
                    metric if stat_label == "Average" else "",
                    stat_label,
                    fmt(before_val),
                    fmt(after_val),
                    diff_str,
                    pct_str,
                )
            )


def main() -> None:
    timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    base_logs_dir = SCRIPT_DIR / "python_analysis" / "logs"
    run_dir = base_logs_dir / timestamp
    run_dir.mkdir(parents=True, exist_ok=True)
    main_log = run_dir / "debug_main.log"
    feature_log = run_dir / "debug_feature.log"
    main_metrics = run_dir / "metrics_main.json"
    feature_metrics = run_dir / "metrics_feature.json"

    # Feature-specific arguments for testing engine worker counts
    feature_args = [
        "--engine.account-worker-count", "32",
        "--engine.storage-worker-count", "32",
    ]

    print("Starting main -> feature bench cycles...")
    run_bench_cycle("main", MAIN_COMMIT, main_log, main_metrics)
    run_bench_cycle("feature", FEATURE_COMMIT, feature_log, feature_metrics, extra_args=feature_args)
    print("")
    print("All bench cycles completed.")
    print("")
    print_comparison(main_metrics, feature_metrics)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nInterrupted.")
        sys.exit(1)
