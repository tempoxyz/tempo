#!/usr/bin/env python3
"""Analyze tempo debug logs and emit summary statistics (standalone CLI wrapper)."""

from __future__ import annotations

import argparse
from pathlib import Path

from reth_bench_compare import analyze_log_file, write_metrics


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Analyze tempo debug logs for benchmark metrics.")
    parser.add_argument("--log", type=Path, default=Path(__file__).parent / "debug.log", help="Path to the log file to analyze.")
    parser.add_argument("--json", type=Path, help="Optional path to write summary statistics as JSON.")
    parser.add_argument("--label", help="Optional label to include in the JSON summary.")
    parser.add_argument("--quiet", action="store_true", help="Suppress detailed textual output.")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    summary = analyze_log_file(args.log, label=args.label, quiet=args.quiet)
    if args.json:
        args.json.parent.mkdir(parents=True, exist_ok=True)
        write_metrics(summary, args.json)


if __name__ == "__main__":
    main()
