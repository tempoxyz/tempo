#!/usr/bin/env python3
"""
Test script to validate new metric parsing logic.
Tests extraction of execution_elapsed and builder_finish_elapsed from Built payload logs.
"""

import re
from pathlib import Path
from statistics import mean, median, stdev
from typing import Optional

ANSI_ESCAPE = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')


def strip_ansi_codes(text: str) -> str:
    return ANSI_ESCAPE.sub("", text)


def parse_time_to_ms(time_str: str) -> Optional[float]:
    """Parse time strings like '279.248125ms', '9.333µs', '1.44211675s' to milliseconds."""
    if time_str.endswith("ms"):
        return float(time_str[:-2])
    elif time_str.endswith("µs"):
        return float(time_str[:-2]) / 1000.0
    elif time_str.endswith("s"):
        return float(time_str[:-1]) * 1000.0
    return None


def find_block_range(log_file: Path, min_gas: int = 1000) -> tuple[Optional[int], Optional[int]]:
    """Detect a steady-state block range (excluding warm-up/down) based on gas usage."""
    non_empty_blocks = []

    with log_file.open("r", encoding="utf-8") as handle:
        for line in handle:
            clean = strip_ansi_codes(line)
            if "Block added to canonical chain" not in clean:
                continue

            num_match = re.search(r"number\s*=\s*(\d+)", clean)
            gas_match = re.search(r"gas_used\s*=\s*([\d.]+)([KMG]?)gas", clean)
            txs_match = re.search(r"txs\s*=\s*(\d+)", clean)

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
    # Do NOT skip first/last blocks with +1/-1 adjustment
    if non_empty_blocks:
        return non_empty_blocks[0], non_empty_blocks[-1]
    return None, None


def parse_new_metrics(log_file: Path, block_range: Optional[tuple[int, int]] = None):
    """Parse new metrics: execution_elapsed and builder_finish_elapsed from Built payload."""

    build_times = []
    execution_times = []
    builder_finish_times = []
    payload_to_received_times = []
    block_added_times = []
    old_state_root_times = []  # For comparison with old metric

    built_payload_timestamps = {}
    current_block_context = None

    with log_file.open("r", encoding="utf-8") as handle:
        for line in handle:
            from datetime import datetime
            clean = strip_ansi_codes(line)

            # Parse timestamp
            timestamp = None
            match = re.match(r"(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d+Z)", clean)
            if match:
                timestamp = datetime.fromisoformat(match.group(1).replace('Z', '+00:00'))

            # Parse "Built payload" logs
            if "Built payload" in clean:
                parent_match = re.search(r"parent_number\s*=\s*(\d+)", clean)
                txs_match = re.search(r"total_transactions\s*=\s*(\d+)", clean)

                if parent_match and timestamp:
                    parent_number = int(parent_match.group(1))
                    block_number = parent_number + 1
                    total_txs = int(txs_match.group(1)) if txs_match else 0

                    # Filter: txs > 1 and block_number != 1
                    include_block = total_txs > 1 and block_number != 1

                    if include_block:
                        built_payload_timestamps[block_number] = {
                            "timestamp": timestamp,
                            "include": True
                        }

                    # Check if block is in range
                    in_range = block_range is None or (block_range[0] <= block_number <= block_range[1])

                    if include_block and in_range:
                        # Extract total build time
                        elapsed_match = re.search(r"elapsed\s*=\s*([\d.]+(?:ms|µs|s))", clean)
                        if elapsed_match:
                            time_ms = parse_time_to_ms(elapsed_match.group(1))
                            if time_ms is not None:
                                build_times.append(time_ms)

                        # Extract execution_elapsed
                        exec_match = re.search(r"execution_elapsed\s*=\s*([\d.]+(?:ms|µs|s|ns))", clean)
                        if exec_match:
                            time_str = exec_match.group(1)
                            # Handle nanoseconds
                            if time_str.endswith("ns"):
                                time_ms = float(time_str[:-2]) / 1_000_000.0
                            else:
                                time_ms = parse_time_to_ms(time_str)
                            if time_ms is not None:
                                execution_times.append(time_ms)

                        # Extract builder_finish_elapsed
                        builder_match = re.search(r"builder_finish_elapsed\s*=\s*([\d.]+(?:ms|µs|s|ns))", clean)
                        if builder_match:
                            time_str = builder_match.group(1)
                            # Handle nanoseconds
                            if time_str.endswith("ns"):
                                time_ms = float(time_str[:-2]) / 1_000_000.0
                            else:
                                time_ms = parse_time_to_ms(time_str)
                            if time_ms is not None:
                                builder_finish_times.append(time_ms)

            # Parse "Received block from consensus engine"
            elif "Received block from consensus engine" in clean:
                number_match = re.search(r"number\s*=\s*(\d+)", clean)
                if number_match and timestamp:
                    block_number = int(number_match.group(1))
                    block_info = built_payload_timestamps.get(block_number)

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

                        del built_payload_timestamps[block_number]

            # Parse OLD "State root task finished" (for comparison)
            elif "State root task finished" in clean:
                if current_block_context and current_block_context["include"] and current_block_context["in_range"]:
                    match = re.search(r"elapsed\s*=\s*([\d.]+(?:ms|µs|s))", clean)
                    if match:
                        time_ms = parse_time_to_ms(match.group(1))
                        if time_ms is not None:
                            old_state_root_times.append(time_ms)

            # Parse "Block added to canonical chain"
            elif "Block added to canonical chain" in clean:
                number_match = re.search(r"number\s*=\s*(\d+)", clean)
                txs_match = re.search(r"txs\s*=\s*(\d+)", clean)
                elapsed_match = re.search(r"elapsed\s*=\s*([\d.]+(?:ms|µs|s))", clean)

                if elapsed_match and number_match:
                    block_number = int(number_match.group(1))
                    total_txs = int(txs_match.group(1)) if txs_match else 0

                    # Filter: txs > 1 and block_number != 1
                    if total_txs > 1 and block_number != 1:
                        in_range = block_range is None or (block_range[0] <= block_number <= block_range[1])
                        if in_range:
                            time_ms = parse_time_to_ms(elapsed_match.group(1))
                            if time_ms is not None:
                                block_added_times.append(time_ms)

                # Clear block context
                current_block_context = None

    return {
        "build_times": build_times,
        "execution_times": execution_times,
        "builder_finish_times": builder_finish_times,
        "payload_to_received_times": payload_to_received_times,
        "block_added_times": block_added_times,
        "old_state_root_times": old_state_root_times,
    }


def compute_stats(times: list[float]) -> dict:
    """Compute statistics for a list of times."""
    if not times:
        return {"count": 0}

    return {
        "count": len(times),
        "mean": mean(times),
        "median": median(times),
        "min": min(times),
        "max": max(times),
        "std_dev": stdev(times) if len(times) > 1 else 0.0,
    }


def print_stats(name: str, stats: dict) -> None:
    """Print statistics in a readable format."""
    if stats["count"] == 0:
        print(f"  {name}: No data")
        return

    print(f"  {name}:")
    print(f"    Count:   {stats['count']}")
    print(f"    Mean:    {stats['mean']:.3f} ms")
    print(f"    Median:  {stats['median']:.3f} ms")
    print(f"    Min:     {stats['min']:.3f} ms")
    print(f"    Max:     {stats['max']:.3f} ms")
    print(f"    StdDev:  {stats['std_dev']:.3f} ms")


def main():
    script_dir = Path(__file__).parent

    for log_name in ["debug_main.log", "debug_feature.log"]:
        log_file = script_dir / log_name

        if not log_file.exists():
            print(f"\nSkipping {log_name} (not found)")
            continue

        print(f"\n{'='*80}")
        print(f"Analyzing: {log_name}")
        print(f"{'='*80}")

        # Find block range (last 1%)
        first_block, last_block = find_block_range(log_file)
        block_range = (first_block, last_block) if first_block and last_block else None

        if block_range:
            print(f"Block range: {block_range[0]} -> {block_range[1]} ({block_range[1] - block_range[0] + 1} blocks)")
        else:
            print("Block range: entire log")

        # Parse metrics
        metrics = parse_new_metrics(log_file, block_range)

        print("\n--- NEW METRICS (from Built payload) ---")
        print_stats("Build Payload Time", compute_stats(metrics["build_times"]))
        print_stats("Execution Time", compute_stats(metrics["execution_times"]))
        print_stats("Builder Finish Time", compute_stats(metrics["builder_finish_times"]))

        print("\n--- OTHER METRICS ---")
        print_stats("Payload Delivery Lag", compute_stats(metrics["payload_to_received_times"]))
        print_stats("Block Added to Canonical Chain", compute_stats(metrics["block_added_times"]))

        print("\n--- OLD METRIC (for comparison) ---")
        print_stats("OLD: Explicit State Root Task (9µs - WRONG!)", compute_stats(metrics["old_state_root_times"]))

        print("\n" + "="*80)
        print("COMPARISON:")
        exec_stats = compute_stats(metrics["execution_times"])
        builder_stats = compute_stats(metrics["builder_finish_times"])
        old_stats = compute_stats(metrics["old_state_root_times"])

        if exec_stats["count"] > 0 and old_stats["count"] > 0:
            print(f"  Execution Time mean:       {exec_stats['mean']:.3f} ms")
            print(f"  Builder Finish Time mean:  {builder_stats['mean']:.3f} ms")
            print(f"  OLD State Root Time mean:  {old_stats['mean']:.6f} ms  <-- THIS IS WRONG!")
            print(f"\n  The OLD metric is {exec_stats['mean'] / old_stats['mean']:.0f}x smaller than Execution Time!")
            print(f"  The OLD metric is {builder_stats['mean'] / old_stats['mean']:.0f}x smaller than Builder Finish Time!")
        print("="*80)


if __name__ == "__main__":
    main()
