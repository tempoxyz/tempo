#!/usr/bin/env python3
"""Worst-case state-read gate.

Reads a bench-e2e-multi-region results directory produced with a state-read-*
preset and reports how long validators took to execute loaded blocks in the
feature phase. Exits 1 when --enforce is set and the p99 block execution time
exceeds --threshold-ms (default: 500, about one block time).
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
                if windows and not any(a <= ts(when) <= b for a, b in windows):
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
    parser.add_argument("--enforce", action="store_true")
    args = parser.parse_args()

    lines = ["## State-read gate", "", f"Threshold: p99 block execution <= {args.threshold_ms:.0f} ms", ""]
    lines += ["| Run | Blocks | Gas/block p50 | Exec p50 | Exec p99 | Exec max | Mgas/s p50 | Result |", "|---|---|---|---|---|---|---|---|"]
    failed = False
    for results in args.results:
        rows = samples(results, feature_windows(results))
        name = os.path.basename(os.path.normpath(results))
        if not rows:
            lines.append(f"| {name} | 0 | - | - | - | - | - | no loaded blocks |")
            failed = True
            continue
        execs = [r[2] for r in rows]
        p99 = pct(execs, 0.99)
        ok = p99 <= args.threshold_ms
        failed |= not ok
        lines.append(
            f"| {name} | {len(rows)} | {pct([r[1] for r in rows], 0.5) / 1e6:.0f}M | {pct(execs, 0.5):.0f} ms "
            f"| {p99:.0f} ms | {max(execs):.0f} ms | {pct([r[1] / r[2] / 1e3 for r in rows], 0.5):.0f} "
            f"| {'pass' if ok else 'over threshold'} |"
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
