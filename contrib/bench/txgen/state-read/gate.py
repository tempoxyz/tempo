#!/usr/bin/env python3
"""Worst-case state-read gate.

Reads a bench-e2e-multi-region results directory produced with a state-read-*
preset and reports how long validators took to execute loaded blocks in the
feature phase. Validators run blocks of up to --serial-txs transactions one
after another, so the gate projects each such block to a full serial block
(execution time x serial-txs / txs) before comparing p99 with --threshold-ms
(default: 500, about one block time). Blocks with more transactions run in
parallel and count as measured. Exits 1 under --enforce when p99 exceeds the
threshold or a run has fewer than --min-blocks loaded blocks.
"""

import argparse
import datetime as dt
import glob
import os
import re
import sys

BLOCK = re.compile(
    r"(\d{4}-\d\d-\d\dT\S+?Z).*Block added to canonical chain.*?txs=(\d+) "
    r"gas_used=([\d.]+)([KMG])gas.*?elapsed=([\d.]+)(ns|µs|ms|s)\b"
)
PHASE = re.compile(r"\| (feature-\d+) \| (\S+Z) \| \d+ \| (\S+Z) \| \d+ \| (\S+Z) \|")
GAS = {"K": 1e3, "M": 1e6, "G": 1e9}
SECS = {"ns": 1e-9, "µs": 1e-6, "ms": 1e-3, "s": 1.0}


def ts(value):
    value = value.rstrip("Z")
    if "." in value:
        head, frac = value.split(".", 1)
        value = f"{head}.{frac[:6]}"
    return dt.datetime.fromisoformat(value).replace(tzinfo=dt.timezone.utc)


def feature_windows(results):
    try:
        summary = open(os.path.join(results, "summary.md"), encoding="utf-8").read()
    except OSError:
        return []
    return [(ts(m.group(2)), ts(m.group(4))) for m in PHASE.finditer(summary)]


def samples(results, windows):
    out = []
    for path in glob.glob(os.path.join(results, "cloud-artifacts", "*", "validator-*", "tempo-node.log")):
        with open(path, encoding="utf-8", errors="ignore") as log:
            for line in log:
                m = BLOCK.search(line)
                if not m:
                    continue
                when, txs, gas, unit, elapsed, eunit = m.groups()
                gas = float(gas) * GAS[unit]
                secs = float(elapsed) * SECS[eunit]
                # Skip empty blocks and the proposer's own (near-zero) insert of a block it built.
                if gas < 9e6 or secs < 2e-3:
                    continue
                if not any(a <= ts(when) <= b for a, b in windows):
                    continue
                out.append((int(txs), gas, secs * 1000))
    return out


def pct(values, q):
    values = sorted(values)
    return values[min(len(values) - 1, int(q * len(values)))]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("results", nargs="+", help="bench results directories")
    parser.add_argument("--threshold-ms", type=float, default=500.0)
    parser.add_argument("--serial-txs", type=int, default=4, help="largest block size validators execute serially")
    parser.add_argument("--min-blocks", type=int, default=30, help="loaded blocks a run needs to be conclusive")
    parser.add_argument("--enforce", action="store_true")
    args = parser.parse_args()

    lines = ["## State-read gate", "", f"Threshold: p99 worst-case block execution <= {args.threshold_ms:.0f} ms "
             f"(blocks of <= {args.serial_txs} txs projected to {args.serial_txs} serial txs)", ""]
    lines += ["| Run | Blocks | Txs/block p50 | Exec p50 | Worst-case p99 | Worst-case max | Mgas/s p50 | Result |", "|---|---|---|---|---|---|---|---|"]
    failed = False
    for results in args.results:
        name = os.path.basename(os.path.normpath(results))
        windows = feature_windows(results)
        if not windows:
            # Without the feature phase window the result would mix in baseline blocks.
            lines.append(f"| {name} | - | - | - | - | - | - | no feature phase in summary.md |")
            failed = True
            continue
        rows = samples(results, windows)
        if not rows:
            lines.append(f"| {name} | 0 | - | - | - | - | - | no loaded blocks |")
            failed = True
            continue
        execs = [r[2] for r in rows]
        worst = [r[2] * args.serial_txs / r[0] if 0 < r[0] <= args.serial_txs else r[2] for r in rows]
        p99 = pct(worst, 0.99)
        if len(rows) < args.min_blocks:
            result, ok = f"inconclusive (< {args.min_blocks} blocks)", False
        else:
            ok = p99 <= args.threshold_ms
            result = "pass" if ok else "over threshold"
        failed |= not ok
        lines.append(
            f"| {name} | {len(rows)} | {pct([r[0] for r in rows], 0.5)} | {pct(execs, 0.5):.0f} ms "
            f"| {p99:.0f} ms | {max(worst):.0f} ms | {pct([r[1] / r[2] / 1e3 for r in rows], 0.5):.0f} | {result} |"
        )
    if failed and not args.enforce:
        lines += ["", "Report only: run with enforce to fail on this result."]
    report = "\n".join(lines) + "\n"
    print(report)
    summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary:
        with open(summary, "a", encoding="utf-8") as fh:
            fh.write(report)
    return 1 if failed and args.enforce else 0


if __name__ == "__main__":
    sys.exit(main())
