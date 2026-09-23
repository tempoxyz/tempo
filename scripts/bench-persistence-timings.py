#!/usr/bin/env python3
"""Summarize instrumented persistence/ execution logs exported from VictoriaLogs.

Run with uv run scripts/bench-persistence-timings.py logs.json --output report.json.
Input may be one JSON array or newline-delimited JSON. Export the structured fields,
not only _msg. Use a bounded benchmark_id query covering every measured phase.
"""

import argparse
from collections import defaultdict
import json
from pathlib import Path
import statistics


def phase(row):
    return tuple(str(row.get(k, "")) for k in ("benchmark_id", "benchmark_run", "runner_role"))


def batch(row):
    return phase(row) + tuple(str(row[k]) for k in ("last_block_number", "state_block_number"))


def ratio(numerator, denominator):
    return numerator / denominator if denominator else None


def mean(values):
    return statistics.fmean(values) if values else None


def analyze(rows):
    # Event identity preserves legitimate same-time events on distinct nodes/threads.
    rows = list({json.dumps(row, sort_keys=True): row for row in rows}.values())
    completed = {batch(r): r for r in rows if r.get("message") == "Persistence batch complete"}
    writes = {batch(r): r for r in rows if r.get("message") == "Persistence batch writes"}
    accepted = completed.keys() & writes.keys()
    phases = defaultdict(lambda: defaultdict(list))
    for row in rows:
        phases[phase(row)][row.get("message", "")].append(row)
    result = []
    for key, events in sorted(phases.items()):
        if not key[1].startswith(("baseline-", "feature-")):
            continue
        keys = [k for k in accepted if k[:3] == key]
        if not keys:
            continue
        blocks = sum(int(writes[k]["block_count"]) for k in keys)
        transactions = sum(int(writes[k]["transaction_count"]) for k in keys)
        state_blocks = sum(int(writes[k]["state_trie_block_count"]) for k in keys)
        write_seconds = sum(float(writes[k]["elapsed_seconds"]) for k in keys)
        complete_seconds = sum(float(completed[k]["elapsed_seconds"]) for k in keys)
        commit_seconds = sum(float(completed[k]["commit_seconds"]) for k in keys)
        tables = defaultdict(lambda: {"operations": 0, "operation_seconds": 0.0, "observations": 0})
        for row in events["Persistence table operations"]:
            if batch(row) in accepted:
                table = tables[row["table"]]
                table["operations"] += int(row["operations"])
                table["operation_seconds"] += int(row["operation_nanos"]) / 1e9
                table["observations"] += 1
        for table in tables.values():
            table["operation_ms_per_batch"] = table["operation_seconds"] * 1000 / len(keys)
            table["operation_us_per_persisted_transaction"] = ratio(table["operation_seconds"] * 1e6, transactions)
        tasks = defaultdict(list)
        intervals = defaultdict(list)
        parallel_batches = {batch(r) for r in events["Persistence worker preparation"]}
        for row in events["Persistence table task"]:
            if batch(row) not in accepted:
                continue
            duration = float(row["elapsed_seconds"])
            tasks[(row["table"], str(row["shard"]))].append(duration)
            if batch(row) in parallel_batches:
                start = float(row["start_offset_seconds"])
                intervals[batch(row)].extend([(start, 1), (start + duration, -1)])
        concurrency = []
        for points in intervals.values():
            active = peak = 0
            for _, delta in sorted(points):
                active += delta
                peak = max(peak, active)
            concurrency.append(peak)
        validator = events["Executed block"] + events["Executed block via BAL path"]
        builder = events["Built payload"]
        result.append({
            "benchmark_id": key[0], "phase": key[1], "node": key[2],
            "completed_batches": len(keys), "persisted_blocks": blocks,
            "persisted_transactions": transactions, "state_trie_blocks": state_blocks,
            "save_blocks_seconds": write_seconds, "complete_persistence_seconds": complete_seconds,
            "save_blocks_ms_per_block": ratio(write_seconds * 1000, blocks),
            "complete_persistence_ms_per_block": ratio(complete_seconds * 1000, blocks),
            "complete_persistence_us_per_transaction": ratio(complete_seconds * 1e6, transactions),
            "persistence_service_blocks_per_second": ratio(blocks, complete_seconds),
            "persistence_service_transactions_per_second": ratio(transactions, complete_seconds),
            "mean_commit_ms_per_batch": commit_seconds * 1000 / len(keys),
            "mean_save_blocks_ms_per_batch": write_seconds * 1000 / len(keys),
            "mean_validator_execution_ms": mean([float(r["execution_seconds"]) * 1000 for r in validator if "execution_seconds" in r]),
            "validator_execution_samples": sum("execution_seconds" in r for r in validator),
            "mean_builder_ms": mean([float(r["build_seconds"]) * 1000 for r in builder if "build_seconds" in r]),
            "mean_builder_transaction_execution_ms": mean([float(r["transaction_execution_seconds"]) * 1000 for r in builder if "transaction_execution_seconds" in r]),
            "builder_samples": sum("build_seconds" in r for r in builder),
            "mean_peak_overlapping_table_tasks": mean(concurrency),
            "mean_child_commit_ms_per_batch": sum(float(r["elapsed_seconds"]) * 1000 for r in events["Persistence child transaction commits"] if batch(r) in accepted) / len(keys),
            "tables": dict(sorted(tables.items())),
            "table_tasks": [{"table": table, "shard": shard, "samples": len(values),
                             "mean_wall_ms": mean(values) * 1000, "max_wall_ms": max(values) * 1000}
                            for (table, shard), values in sorted(tasks.items())],
        })
    return {"phases": result, "unmatched_write_batches": len(writes.keys() - completed.keys()),
            "unmatched_completed_batches": len(completed.keys() - writes.keys()),
            "notes": [
                "Ratios use sums of durations/counts, not averages of batch ratios.",
                "Operation time includes seeks and writes; it excludes work outside database calls. Logical sharded tables sum operations across shards.",
                "Table-task wall times include waits and loop work. Overlap is wall-time overlap, not proof of simultaneous CPU execution.",
                "Only batches with write and completion events contribute persistence/table statistics. Unmatched batches are reported separately.",
                "Block-data and state-trie frontiers can advance separately. State-trie block counts are provided explicitly.",
                "Execution means describe attempts recorded in the exported phase; speculative/repeated execution is not deduplicated into canonical blocks.",
                "Persistence service throughput measures work while persistence is busy; it is not network TPS. Compare block production intervals from summary.json separately.",
                "Absent table events mean no observed timed operations, not an independently measured zero.",
            ]}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("logs", type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    raw = args.logs.read_text()
    rows = json.loads(raw) if raw.lstrip().startswith("[") else [json.loads(line) for line in raw.splitlines() if line.strip()]
    report = analyze(rows)
    if not report["phases"]:
        raise SystemExit("No matched instrumented persistence batches; check export coverage and node instrumentation.")
    args.output.write_text(json.dumps(report, indent=2) + "\n")
    print(f"Wrote {len(report['phases'])} node/phase summaries to {args.output}")


if __name__ == "__main__":
    main()
