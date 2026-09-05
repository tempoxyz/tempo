"""Read-only validity gate for ordinary successful-workload gas studies.

A pass checks report consistency, not workload semantics, saturation, or pricing.
Run with uv run python contrib/bench/gas-study-audit.py RESULTS_DIRECTORY.
"""

import argparse
import json
from pathlib import Path


def count(value):
    return type(value) is int and value >= 0


def audit(directory):
    directory = Path(directory)
    summary = json.loads((directory / "summary.json").read_text())
    issues = []
    runs = []
    pairs = summary["config"].get("run_pairs")
    if not count(pairs) or pairs == 0:
        issues.append("comparison requires a positive integer run_pairs")
        pairs = 0
    expected = {
        f"{side}-{index}"
        for side in ("baseline", "feature")
        for index in range(1, pairs + 1)
    }
    rows = summary.get("per_run", [])
    labels = [row["label"] for row in rows]
    if len(labels) != len(set(labels)):
        issues.append("duplicate summary run labels")
    if set(labels) != expected:
        issues.append("summary run set does not match requested comparison pairs")
    for label in sorted(expected):
        problems = []
        path = directory / f"report-{label}.json"
        if not path.is_file():
            runs.append({"label": label, "issues": ["missing raw report"]})
            continue
        raw = json.loads(path.read_text())
        blocks = raw.get("blocks", [])
        numbers = [block.get("number") for block in blocks]
        valid_numbers = all(count(n) for n in numbers)
        if not valid_numbers or numbers != sorted(set(numbers)):
            problems.append("block numbers are invalid, duplicated, or out of order")
        elif numbers and numbers != list(range(numbers[0], numbers[-1] + 1)):
            problems.append("block range has gaps")
        complete = all(
            all(count(block.get(key)) for key in ("tx_count", "ok_count", "err_count", "gas_used"))
            and block["ok_count"] + block["err_count"] == block["tx_count"]
            for block in blocks
        )
        if not complete:
            problems.append("raw receipt outcomes are absent or inconsistent")
        totals = {
            key: sum(block[key] for block in blocks) if complete else None
            for key in ("tx_count", "ok_count", "err_count", "gas_used")
        }
        if not blocks or totals["ok_count"] == 0:
            problems.append("no successful included transactions")
        if totals["err_count"]:
            problems.append("reverted transactions in ordinary successful-workload run")
        if not count(raw.get("failed")) or raw["failed"] != 0:
            problems.append("submission failures are present or unknown")
        row = next((row for row in rows if row["label"] == label), None)
        if row is None:
            problems.append("missing retained summary row")
        elif complete:
            warmup = row.get("summary_warmup_blocks")
            if not count(warmup) or warmup > len(blocks):
                problems.append("invalid summary warmup window")
            else:
                retained = blocks[warmup:]
                mappings = {"total_tx": "tx_count", "ok": "ok_count", "err": "err_count", "total_gas": "gas_used"}
                if row.get("blocks") != len(retained) or any(
                    row.get(target) != sum(block[source] for block in retained)
                    for target, source in mappings.items()
                ):
                    problems.append("retained summary does not reconcile with raw blocks")
                if not retained or sum(block["ok_count"] for block in retained) == 0:
                    problems.append("no successful transactions after warmup")
                if row.get("receipt_outcomes_complete") is not True:
                    problems.append("summary receipt outcomes are not complete")
        runs.append({"label": label, "raw_totals": totals, "submission_failed": raw.get("failed"), "issues": problems})
    return {
        "benchmark_id": summary.get("benchmark_id"),
        "ordinary_workload_data_valid": not issues and all(not run["issues"] for run in runs),
        "pricing_ready": False,
        "limitations": "Consistency only. Requires separate output validation, workload inclusion attribution, saturation checks, matched hardware/state/forks, repeated runs, and gas attribution before pricing inference.",
        "issues": issues,
        "runs": runs,
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path)
    args = parser.parse_args()
    result = audit(args.directory)
    print(json.dumps(result, indent=2))
    raise SystemExit(0 if result["ordinary_workload_data_valid"] else 1)
