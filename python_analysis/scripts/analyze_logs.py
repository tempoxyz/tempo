#!/usr/bin/env python3
"""
Standalone log analysis script for tempo benchmark logs.
Extracts and compares performance metrics from debug logs.

Usage:
    python3 analyze_logs.py <log_file>                    # Analyze single log
    python3 analyze_logs.py <main_log> <feature_log>      # Compare two logs
    python3 analyze_logs.py <log_file> --save <output>    # Save metrics to JSON
"""

import json
import sys
from pathlib import Path
from typing import Optional

# Add parent directory to path to import lib
sys.path.insert(0, str(Path(__file__).parent.parent))

from lib.log_analysis import analyze_log


def compare_logs(before_summary: dict, after_summary: dict) -> None:
    """Print comparison between two log summaries."""
    print("\n" + "=" * 80)
    print("COMPARISON")
    print("=" * 80)

    before_label = before_summary.get("label", "Before")
    after_label = after_summary.get("label", "After")

    print(f"{before_label} vs {after_label}\n")

    metrics_order = [
        "Build Payload Time",
        "Execution Time",
        "Builder Finish Time",
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

    print("{:<28} {:<10} {:>14} {:>14} {:>14} {:>10}".format(
        "Metric", "Statistic", "Before", "After", "Abs Diff", "% Change"
    ))
    print("-" * 90)

    for metric in metrics_order:
        before_stats = before_summary["metrics"].get(metric)
        after_stats = after_summary["metrics"].get(metric)

        for stat_key, stat_label in stat_labels:
            before_val = before_stats.get(stat_key) if before_stats else None
            after_val = after_stats.get(stat_key) if after_stats else None

            if before_val is None and after_val is None:
                continue

            diff = None
            if before_val is not None and after_val is not None:
                diff = after_val - before_val

            diff_str = fmt_signed(diff) if diff is not None else "n/a"
            pct_str = fmt_pct(before_val, diff) if diff is not None else "n/a"

            print("{:<28} {:<10} {:>14} {:>14} {:>14} {:>10}".format(
                metric if stat_label == "Average" else "",
                stat_label,
                fmt(before_val),
                fmt(after_val),
                diff_str,
                pct_str,
            ))


def main():
    """Main entry point."""
    if len(sys.argv) < 2:
        print("Usage:")
        print(f"  {sys.argv[0]} <log_file>                    # Analyze single log")
        print(f"  {sys.argv[0]} <main_log> <feature_log>      # Compare two logs")
        print(f"  {sys.argv[0]} <log_file> --save <output>    # Save metrics to JSON")
        sys.exit(1)

    log1_path = Path(sys.argv[1])

    # Analyze first log
    summary1 = analyze_log(log1_path, label=log1_path.stem)

    # Check if we should save to JSON
    if len(sys.argv) == 4 and sys.argv[2] == "--save":
        output_path = Path(sys.argv[3])
        output_path.write_text(json.dumps(summary1, indent=2))
        print(f"\nSaved metrics to: {output_path}")

    # Check if we have a second log to compare
    elif len(sys.argv) >= 3 and sys.argv[2] != "--save":
        log2_path = Path(sys.argv[2])
        summary2 = analyze_log(log2_path, label=log2_path.stem)

        # Compare the two
        compare_logs(summary1, summary2)

        # Optionally save both
        if len(sys.argv) >= 5 and sys.argv[3] == "--save":
            output1 = Path(sys.argv[4])
            output2 = Path(f"{output1.stem}_2{output1.suffix}")
            output1.write_text(json.dumps(summary1, indent=2))
            output2.write_text(json.dumps(summary2, indent=2))
            print(f"\nSaved metrics to: {output1} and {output2}")


if __name__ == "__main__":
    main()
