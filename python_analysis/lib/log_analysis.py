"""
Core log analysis functions for tempo benchmark logs.
Shared by both the full benchmark pipeline and standalone analysis script.
"""

import re
from datetime import datetime
from pathlib import Path
from statistics import mean, median, stdev
from typing import Optional

ANSI_ESCAPE = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')


def strip_ansi_codes(text: str) -> str:
    """Remove ANSI escape codes from text."""
    return ANSI_ESCAPE.sub("", text)


def parse_timestamp(line: str) -> Optional[datetime]:
    """Extract timestamp from log line."""
    clean_line = strip_ansi_codes(line)
    match = re.match(r"(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d+Z)", clean_line)
    if match:
        return datetime.fromisoformat(match.group(1).replace("Z", "+00:00"))
    return None


def parse_time_to_ms(time_str: str) -> Optional[float]:
    """Parse time strings like '279.248125ms', '9.333µs', '1.44211675s' to milliseconds."""
    if time_str.endswith("ms"):
        return float(time_str[:-2])
    elif time_str.endswith("µs"):
        return float(time_str[:-2]) / 1000.0
    elif time_str.endswith("s"):
        return float(time_str[:-1]) * 1000.0
    elif time_str.endswith("ns"):
        return float(time_str[:-2]) / 1_000_000.0
    return None


def find_block_range(log_file: Path, min_gas: int = 1000) -> tuple[Optional[int], Optional[int]]:
    """
    Detect a steady-state block range based on gas usage and transaction count.
    Returns (first_block, last_block) for blocks with txs > 1 and gas > min_gas.
    """
    non_empty_blocks = []

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

    # Return the full range of blocks with txs > 1
    if non_empty_blocks:
        return non_empty_blocks[0], non_empty_blocks[-1]
    return None, None


def parse_log_file(log_file: Path, block_range: Optional[tuple[int, int]] = None) -> dict:
    """
    Parse log file and extract all timing metrics.

    Args:
        log_file: Path to the log file
        block_range: Optional (first_block, last_block) tuple to filter blocks

    Returns:
        Dict with lists of timing values:
            - build_times: Build Payload Time
            - execution_times: Execution Time (from Built payload)
            - builder_finish_times: Payload Finalization
            - state_root_task_times: State Root Task (explicit task)
            - payload_to_received_times: Payload Delivery Lag
            - block_added_times: Block Added to Canonical Chain
    """
    build_times = []
    execution_times = []
    builder_finish_times = []
    state_root_task_times = []
    block_added_times = []
    payload_to_received_times = []

    built_payload_times = {}
    current_block_context = None

    with log_file.open("r", encoding="utf-8") as handle:
        for raw_line in handle:
            timestamp = parse_timestamp(raw_line)
            clean_line = strip_ansi_codes(raw_line)

            # Parse "Built payload" logs
            if "Built payload" in clean_line:
                parent_match = re.search(r"parent_number\s*=\s*(\d+)", clean_line)
                txs_match = re.search(r"total_transactions\s*=\s*(\d+)", clean_line)

                if parent_match and timestamp:
                    parent_number = int(parent_match.group(1))
                    block_number = parent_number + 1
                    total_transactions = int(txs_match.group(1)) if txs_match else 0
                    include_block = total_transactions > 1 and block_number != 1

                    if include_block:
                        built_payload_times[block_number] = {"timestamp": timestamp, "include": True}

                    # Check if block is in range
                    in_range = block_range is None or (block_range[0] <= block_number <= block_range[1])

                    if include_block and in_range:
                        # Extract total build time
                        elapsed_match = re.search(r"elapsed\s*=\s*([\d.]+(?:ms|µs|s))", clean_line)
                        if elapsed_match:
                            time_ms = parse_time_to_ms(elapsed_match.group(1))
                            if time_ms is not None:
                                build_times.append(time_ms)

                        # Extract execution_elapsed
                        exec_match = re.search(r"execution_elapsed\s*=\s*([\d.]+(?:ms|µs|s|ns))", clean_line)
                        if exec_match:
                            time_ms = parse_time_to_ms(exec_match.group(1))
                            if time_ms is not None:
                                execution_times.append(time_ms)

                        # Extract builder_finish_elapsed
                        builder_match = re.search(r"builder_finish_elapsed\s*=\s*([\d.]+(?:ms|µs|s|ns))", clean_line)
                        if builder_match:
                            time_ms = parse_time_to_ms(builder_match.group(1))
                            if time_ms is not None:
                                builder_finish_times.append(time_ms)

            # Parse "Received block from consensus engine"
            elif "Received block from consensus engine" in clean_line:
                number_match = re.search(r"number\s*=\s*(\d+)", clean_line)
                if number_match and timestamp:
                    block_number = int(number_match.group(1))
                    block_info = built_payload_times.get(block_number)

                    if block_info:
                        in_range = block_range is None or (block_range[0] <= block_number <= block_range[1])
                        current_block_context = {
                            "block_number": block_number,
                            "include": block_info["include"],
                            "in_range": in_range
                        }

                        if block_info["include"] and in_range:
                            # Calculate payload delivery lag
                            start_time = block_info["timestamp"]
                            elapsed_ms = (timestamp - start_time).total_seconds() * 1000
                            payload_to_received_times.append(elapsed_ms)

                        del built_payload_times[block_number]
                    else:
                        current_block_context = None
                continue

            # Parse "State root task finished"
            elif "State root task finished" in clean_line:
                match = re.search(r"elapsed\s*=\s*([\d.]+(?:ms|µs|s))", clean_line)
                if match and current_block_context:
                    if current_block_context["include"] and current_block_context["in_range"]:
                        time_ms = parse_time_to_ms(match.group(1))
                        if time_ms is not None:
                            state_root_task_times.append(time_ms)

            # Parse "Block added to canonical chain"
            elif "Block added to canonical chain" in clean_line:
                current_block_context = None
                number_match = re.search(r"number\s*=\s*(\d+)", clean_line)
                txs_match = re.search(r"txs\s*=\s*(\d+)", clean_line)
                match = re.search(r"elapsed\s*=\s*([\d.]+(?:ms|µs|s))", clean_line)

                if match and number_match:
                    block_number = int(number_match.group(1))
                    total_transactions = int(txs_match.group(1)) if txs_match else 0

                    # Filter: exclude block #1 and blocks with ≤1 tx
                    if total_transactions <= 1 or block_number == 1:
                        continue

                    if block_range is None or (block_range[0] <= block_number <= block_range[1]):
                        time_ms = parse_time_to_ms(match.group(1))
                        if time_ms is not None:
                            block_added_times.append(time_ms)

    return {
        "build_times": build_times,
        "execution_times": execution_times,
        "builder_finish_times": builder_finish_times,
        "state_root_task_times": state_root_task_times,
        "payload_to_received_times": payload_to_received_times,
        "block_added_times": block_added_times,
    }


def compute_statistics(times: list[float]) -> Optional[dict]:
    """Compute statistics for a list of times."""
    if not times:
        return None

    return {
        "count": len(times),
        "mean": mean(times),
        "median": median(times),
        "min": min(times),
        "max": max(times),
        "std_dev": stdev(times) if len(times) > 1 else 0.0,
    }


def build_summary(log_file: Path, block_range: Optional[tuple[int, int]], metrics: dict, label: Optional[str] = None) -> dict:
    """
    Build a metrics summary from parsed log data.

    Args:
        log_file: Path to the log file
        block_range: Optional (first_block, last_block) tuple
        metrics: Dict from parse_log_file() containing timing lists
        label: Optional label for this summary

    Returns:
        Dict with label, log_file, block_range, and computed metrics
    """
    return {
        "label": label or log_file.stem,
        "log_file": str(log_file),
        "block_range": list(block_range) if block_range else None,
        "metrics": {
            "Build Payload Time": compute_statistics(metrics["build_times"]),
            "Execution Time": compute_statistics(metrics["execution_times"]),
            "Payload Finalization": compute_statistics(metrics["builder_finish_times"]),
            "State Root Task": compute_statistics(metrics["state_root_task_times"]),
            "Payload Delivery Lag": compute_statistics(metrics["payload_to_received_times"]),
            "Block Added to Canonical Chain": compute_statistics(metrics["block_added_times"]),
        },
    }


def analyze_log(log_file: Path, label: Optional[str] = None, quiet: bool = False) -> dict:
    """
    Analyze a single log file and return metrics summary.

    Args:
        log_file: Path to the log file
        label: Optional label for this log
        quiet: If True, don't print progress messages

    Returns:
        Dict with metrics summary
    """
    if not quiet:
        print(f"\nAnalyzing: {log_file}")
        print("=" * 80)

    if not log_file.exists():
        raise FileNotFoundError(f"Log file not found: {log_file}")

    # Find steady-state block range
    first_block, last_block = find_block_range(log_file)
    block_range = (first_block, last_block) if first_block and last_block else None

    if not quiet:
        if block_range:
            print(f"Block range: {block_range[0]} -> {block_range[1]} ({block_range[1] - block_range[0] + 1} blocks)")
        else:
            print("Block range: entire log")

    # Parse metrics
    metrics = parse_log_file(log_file, block_range)

    # Build summary
    summary = build_summary(log_file, block_range, metrics, label)

    # Print summary
    if not quiet:
        print("\nMetrics:")
        for metric_name, stats in summary["metrics"].items():
            if not stats:
                print(f"  {metric_name}: no data")
                continue
            print(f"  {metric_name}: mean={stats['mean']:.3f} ms, median={stats['median']:.3f} ms, count={stats['count']}")

    return summary
