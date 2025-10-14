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
from statistics import mean, median, stdev
from typing import Iterable, Optional, Sequence
from urllib.error import URLError
from urllib.request import Request, urlopen

FEATURE_COMMIT = "1619408"
MAIN_COMMIT = "d2070f4de34f523f6097ebc64fa9d63a04878055"
SCRIPT_DIR = Path(__file__).resolve().parent
TEMPO_BIN = SCRIPT_DIR / "target" / "release" / "tempo"
LOG_SELECTORS = re.compile(
    r"build_payload|Received block from consensus engine|State root task finished|Block added to canonical chain"
)

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

def parse_time_to_ms(time_str: str) -> Optional[float]:
    """Convert time strings like 1.23ms/300µs/0.1s into milliseconds."""
    match = re.match(r"([\d.]+)(ms|µs|s)", time_str.strip())
    if not match:
        return None

    value, unit = match.groups()
    value = float(value)
    if unit == "ms":
        return value
    if unit == "µs":
        return value / 1000.0
    if unit == "s":
        return value * 1000.0
    return None


ANSI_ESCAPE = re.compile(r"\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])")


def strip_ansi_codes(text: str) -> str:
    return ANSI_ESCAPE.sub("", text)


def parse_timestamp(line: str) -> Optional[datetime]:
    clean_line = strip_ansi_codes(line)
    match = re.match(r"(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d+Z)", clean_line)
    if match:
        return datetime.fromisoformat(match.group(1).replace("Z", "+00:00"))
    return None


def find_block_range(log_file: Path, min_gas: int = 1000) -> tuple[Optional[int], Optional[int]]:
    """Detect a steady-state block range (excluding warm-up/down) based on gas usage."""
    non_empty_blocks: list[int] = []

    with log_file.open("r", encoding="utf-8") as handle:
        for raw_line in handle:
            clean_line = strip_ansi_codes(raw_line)
            if "Block added to canonical chain" not in clean_line:
                continue

            num_match = re.search(r"number\s*=\s*(\d+)", clean_line)
            gas_match = re.search(r"gas_used\s*=\s*([\d.]+)([KMG]?)gas", clean_line)
            txs_match = re.search(r"txs\s*=\s*(\d+)", clean_line)
            if not num_match or not gas_match or not txs_match:
                continue

            total_transactions = int(txs_match.group(1))
            if total_transactions <= 1:
                continue

            block_num = int(num_match.group(1))
            gas_val = float(gas_match.group(1))
            gas_unit = gas_match.group(2)

            if gas_unit == "K":
                gas_used = gas_val * 1_000
            elif gas_unit == "M":
                gas_used = gas_val * 1_000_000
            elif gas_unit == "G":
                gas_used = gas_val * 1_000_000_000
            else:
                gas_used = gas_val

            if gas_used > min_gas:
                non_empty_blocks.append(block_num)

    if len(non_empty_blocks) >= 3:
        return non_empty_blocks[0] + 1, non_empty_blocks[-1] - 1
    if non_empty_blocks:
        return non_empty_blocks[0], non_empty_blocks[-1]
    return None, None


def parse_log_file(log_file: Path, block_range: Optional[Sequence[int]] = None) -> tuple[list[float], list[float], list[float], list[float]]:
    build_times: list[float] = []
    explicit_state_root_times: list[float] = []
    block_added_times: list[float] = []
    payload_to_received_times: list[float] = []

    built_payload_times: dict[int, dict[str, object]] = {}

    with log_file.open("r", encoding="utf-8") as handle:
        for raw_line in handle:
            timestamp = parse_timestamp(raw_line)
            clean_line = strip_ansi_codes(raw_line)

            if "Built payload" in clean_line:
                parent_match = re.search(r"parent_number\s*=\s*(\d+)", clean_line)
                txs_match = re.search(r"total_transactions\s*=\s*(\d+)", clean_line)
                if parent_match and timestamp:
                    parent_number = int(parent_match.group(1))
                    block_number = parent_number + 1
                    total_transactions = int(txs_match.group(1)) if txs_match else 0
                    include_block = total_transactions > 1 and block_number != 1
                    if block_number != 1:
                        built_payload_times[block_number] = {"timestamp": timestamp, "include": include_block}

                match = re.search(r"elapsed\s*=\s*([\d.]+(?:ms|µs|s))", clean_line)
                if match and parent_match:
                    block_number = int(parent_match.group(1)) + 1
                    block_info = built_payload_times.get(block_number)
                    if (
                        block_info
                        and block_info["include"]
                        and (block_range is None or (block_range[0] <= block_number <= block_range[1]))
                    ):
                        time_ms = parse_time_to_ms(match.group(1))
                        if time_ms is not None:
                            build_times.append(time_ms)

            elif "Received block from consensus engine" in clean_line:
                number_match = re.search(r"number\s*=\s*(\d+)", clean_line)
                if number_match and timestamp:
                    block_number = int(number_match.group(1))
                    block_info = built_payload_times.get(block_number)
                    if block_info:
                        if (
                            block_info["include"]
                            and (block_range is None or (block_range[0] <= block_number <= block_range[1]))
                        ):
                            start_time = block_info["timestamp"]
                            elapsed_ms = (timestamp - start_time).total_seconds() * 1000
                            payload_to_received_times.append(elapsed_ms)
                        del built_payload_times[block_number]
                continue

            elif "State root task finished" in clean_line:
                match = re.search(r"elapsed\s*=\s*([\d.]+(?:ms|µs|s))", clean_line)
                if match:
                    time_ms = parse_time_to_ms(match.group(1))
                    if time_ms is not None:
                        explicit_state_root_times.append(time_ms)

            elif "Block added to canonical chain" in clean_line:
                number_match = re.search(r"number\s*=\s*(\d+)", clean_line)
                txs_match = re.search(r"txs\s*=\s*(\d+)", clean_line)
                match = re.search(r"elapsed\s*=\s*([\d.]+(?:ms|µs|s))", clean_line)
                if match and number_match:
                    block_number = int(number_match.group(1))
                    total_transactions = int(txs_match.group(1)) if txs_match else 0
                    if total_transactions <= 1:
                        continue
                    if block_range is None or (block_range[0] <= block_number <= block_range[1]):
                        time_ms = parse_time_to_ms(match.group(1))
                        if time_ms is not None:
                            block_added_times.append(time_ms)

    return build_times, explicit_state_root_times, payload_to_received_times, block_added_times


def compute_statistics(times: list[float]) -> Optional[MetricStats]:
    if not times:
        return None
    values = {
        "count": float(len(times)),
        "mean": mean(times),
        "median": median(times),
        "min": min(times),
        "max": max(times),
        "std_dev": stdev(times) if len(times) > 1 else 0.0,
    }
    # Cast counts back to int when serializing; keep as float for uniform type hints.
    values["count"] = int(values["count"])  # type: ignore[assignment]
    return values  # type: ignore[return-value]


def build_summary(log_file: Path, block_range: Optional[Sequence[int]], build_times: list[float], explicit_state_root_times: list[float], payload_to_received_times: list[float], block_added_times: list[float], label: Optional[str] = None) -> MetricsSummary:
    return {
        "label": label,
        "log_file": str(log_file),
        "block_range": list(block_range) if block_range else None,
        "metrics": {
            "Build Payload Time": compute_statistics(build_times),
            "Payload Delivery Lag": compute_statistics(payload_to_received_times),
            "Explicit State Root Task": compute_statistics(explicit_state_root_times),
            "Block Added to Canonical Chain": compute_statistics(block_added_times),
        },
    }


def analyze_log_file(log_file: Path, *, label: Optional[str] = None, quiet: bool = True) -> MetricsSummary:
    if not log_file.exists():
        raise FileNotFoundError(f"Log file not found: {log_file}")

    first_block, last_block = find_block_range(log_file)
    block_range = (first_block, last_block) if first_block is not None and last_block is not None else None

    build_times, explicit_state_root_times, payload_to_received_times, block_added_times = parse_log_file(
        log_file, block_range
    )

    summary = build_summary(log_file, block_range, build_times, explicit_state_root_times, payload_to_received_times, block_added_times, label=label)

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
    pattern = r'(git = "https://github.com/paradigmxyz/reth", rev = ")([^"]*)(")'
    updated, count = re.subn(pattern, r"\g<1>" + commit + r"\g<3>", original)
    if count == 0:
        raise RuntimeError("Unable to locate Reth git revision in Cargo.toml")
    cargo_toml.write_text(updated)

    print("")
    print("Updating reth dependency...")
    run_command(["cargo", "update", "-p", "reth"], cwd=SCRIPT_DIR)

    print("")
    print("Building tempo (--release)...")
    run_command(["cargo", "build", "--release"], cwd=SCRIPT_DIR)


def start_tempo_node(log_path: Path) -> None:
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

    print("")
    print("Starting tempo node...")
    tempo_process = subprocess.Popen(
        args,
        cwd=SCRIPT_DIR,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1,
    )

    process = tempo_process

    bench_log_path = SCRIPT_DIR / "bench.log"

    def stream_reader(proc: subprocess.Popen[str], destination: Path, bench_log: Path) -> None:
        if not proc.stdout:
            return
        with proc.stdout as stream, destination.open("a") as log_handle, bench_log.open("a") as bench_handle:
            for line in stream:
                sys.stdout.write(line)
                sys.stdout.flush()
                bench_handle.write(line)
                bench_handle.flush()
                if LOG_SELECTORS.search(line):
                    log_handle.write(line)
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


def run_bench_cycle(label: str, commit: str, log_path: Path, metrics_path: Path) -> MetricsSummary:
    global tempo_process, tempo_thread

    update_reth_revision(label, commit)
    start_tempo_node(log_path)

    print("")
    print(f"Running bench_and_kill.sh for {label}...")
    run_command(
        [
            "./bench_and_kill.sh",
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
    # - Build Payload Time: proposer payload construction latency.
    # - Payload Delivery Lag: time from payload build to consensus-engine receipt.
    # - Explicit State Root Task: dedicated state-root worker execution.
    # - Block Added to Canonical Chain: end-to-end block import confirmation.
    metrics_order = [
        "Build Payload Time",
        "Payload Delivery Lag",
        "Explicit State Root Task",
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
    main_log = SCRIPT_DIR / "debug_main.log"
    feature_log = SCRIPT_DIR / "debug_feature.log"
    main_metrics = SCRIPT_DIR / "metrics_main.json"
    feature_metrics = SCRIPT_DIR / "metrics_feature.json"

    print("Starting main -> feature bench cycles...")
    run_bench_cycle("main", MAIN_COMMIT, main_log, main_metrics)
    run_bench_cycle("feature", FEATURE_COMMIT, feature_log, feature_metrics)
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
