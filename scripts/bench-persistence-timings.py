#!/usr/bin/env python3
"""Report normal persistence metrics from a Prometheus query_range JSON matrix."""
import argparse
from collections import defaultdict
import json
from pathlib import Path

P = "reth_consensus_engine_persistence_"
T = "reth_storage_providers_database_table_write_seconds"


def ratio(a, b):
    return a / b if a is not None and b else None


def delta(series):
    points = [(float(t), float(v)) for t, v in series["values"]]
    if len(points) < 2:
        raise ValueError("Need at least two scrapes per series")
    if any(b[1] < a[1] for a, b in zip(points, points[1:])):
        raise ValueError("Counter reset inside phase; split export at restart")
    return points[-1][1] - points[0][1], points[0][0], points[-1][0]


def analyze(document):
    data = document.get("data", document)
    if data.get("resultType") != "matrix":
        raise ValueError("Expected Prometheus query_range matrix")
    phases = defaultdict(dict)
    for series in data["result"]:
        labels = series["metric"]
        name = labels["__name__"]
        if not name.endswith(("_sum", "_count", "_total")):
            continue
        identity = tuple(sorted((k, v) for k, v in labels.items()
                                if k not in ("__name__", "table", "shard", "quantile")))
        key = (name, labels.get("table", ""), labels.get("shard", ""))
        if key in phases[identity]:
            raise ValueError("Duplicate metric series")
        phases[identity][key] = delta(series)
    result = []
    for identity, values in sorted(phases.items()):
        def value(name):
            item = values.get((name, "", ""))
            return item[0] if item else None

        def mean(name, scale=1000):
            total = value(name + "_sum")
            return ratio(total * scale if total is not None else None, value(name + "_count"))

        blocks = value(P + "persisted_blocks_total")
        busy = value(P + "save_blocks_duration_seconds_sum")
        if blocks is None or busy is None:
            continue
        txs = value(P + "persisted_transactions_total")
        tables = []
        for (name, table, shard), (seconds, first, last) in sorted(values.items()):
            if name != T + "_sum":
                continue
            count = values.get((T + "_count", table, shard))
            tables.append({"table": table, "shard": shard,
                           "samples": count[0] if count else None,
                           "mean_task_ms": ratio(seconds * 1000, count[0] if count else None),
                           "task_ms_per_persisted_block": ratio(seconds * 1000, blocks),
                           "first_scrape": first, "last_scrape": last})
        result.append({
            "labels": dict(identity), "persisted_blocks": blocks, "persisted_transactions": txs,
            "state_trie_blocks": value(P + "persisted_state_trie_blocks_total"),
            "complete_persistence_ms_per_block": ratio(busy * 1000, blocks),
            "complete_persistence_us_per_transaction": ratio(busy * 1e6, txs),
            "persistence_service_blocks_per_second": ratio(blocks, busy),
            "persistence_service_transactions_per_second": ratio(txs, busy),
            "mean_persistence_batch_ms": mean(P + "save_blocks_duration_seconds"),
            "mean_commit_ms": mean(P + "commit_duration_seconds"),
            "mean_validator_execution_ms": mean("reth_sync_execution_execution_histogram"),
            "mean_payload_build_ms": mean("reth_tempo_payload_builder_payload_build_duration_seconds"),
            "mean_produced_block_interval_ms": mean("reth_tempo_payload_builder_block_time_millis", 1),
            "tables": tables,
            "scrape_start_min": min(v[1] for v in values.values()),
            "scrape_start_max": max(v[1] for v in values.values()),
            "scrape_end_min": min(v[2] for v in values.values()),
            "scrape_end_max": max(v[2] for v in values.values()),
        })
    return {"phases": result}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("metrics", type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    report = analyze(json.loads(args.metrics.read_text()))
    if not report["phases"]:
        raise SystemExit("No persistence counters found; check export and phase bounds")
    args.output.write_text(json.dumps(report, indent=2) + "\n")


if __name__ == "__main__":
    main()
