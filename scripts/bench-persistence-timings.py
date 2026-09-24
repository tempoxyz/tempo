#!/usr/bin/env python3
"""Report normal persistence metrics from a Prometheus query_range JSON matrix."""
import argparse
from collections import defaultdict
import json
from pathlib import Path

P = "reth_consensus_engine_persistence_"
T = "reth_storage_providers_database_table_write_seconds"
TABLE_METRICS = {
    T: "mdbx",
    "reth_storage_providers_static_file_segment_write_seconds": "static_file",
    "reth_storage_providers_rocksdb_table_write_seconds": "rocksdb",
}


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
        if "quantile" in labels or not (
            name.endswith(("_sum", "_count")) or name in {
                P + "persisted_blocks_total", P + "persisted_transactions_total",
                P + "persisted_state_trie_blocks_total",
            }
        ):
            continue
        identity = tuple(sorted((k, v) for k, v in labels.items()
                                if k not in ("__name__", "table", "segment", "shard", "quantile")))
        key = (name, labels.get("table", labels.get("segment", "")), labels.get("shard", ""))
        if key in phases[identity]:
            raise ValueError("Duplicate metric series")
        delta(series)  # Reject resets before clipping to the shared interval.
        phases[identity][key] = series
    result = []
    for identity, raw in sorted(phases.items()):
        common_start = max(float(v["values"][0][0]) for v in raw.values())
        common_end = min(float(v["values"][-1][0]) for v in raw.values())
        values = {
            key: delta({"values": [(t, v) for t, v in series["values"]
                                  if common_start <= float(t) <= common_end]})
            for key, series in raw.items()
        }
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
            metric = name.removesuffix("_sum")
            if not name.endswith("_sum") or metric not in TABLE_METRICS:
                continue
            count = values.get((metric + "_count", table, shard))
            tables.append({"backend": TABLE_METRICS[metric], "table": table, "shard": shard,
                           "samples": count[0] if count else None,
                           "mean_task_ms": ratio(seconds * 1000, count[0] if count else None),
                           "task_ms_per_persisted_block": ratio(seconds * 1000, blocks),
                           "first_scrape": first, "last_scrape": last})
        result.append({
            "labels": dict(identity), "persisted_blocks": blocks, "persisted_transactions": txs,
            "compared_start": common_start, "compared_end": common_end,
            "state_trie_blocks": value(P + "persisted_state_trie_blocks_total"),
            "complete_persistence_ms_per_block": ratio(busy * 1000, blocks),
            "complete_persistence_us_per_transaction": ratio(busy * 1e6, txs),
            "persistence_service_blocks_per_second": ratio(blocks, busy),
            "persistence_service_transactions_per_second": ratio(txs, busy),
            "mean_persistence_batch_ms": mean(P + "save_blocks_duration_seconds"),
            "mean_commit_ms": mean(P + "commit_duration_seconds"),
            "mean_worker_preparation_ms": mean("reth_storage_providers_database_persistence_worker_preparation_seconds"),
            "mean_child_commit_ms": mean("reth_storage_providers_database_persistence_child_commit_seconds"),
            "mean_save_blocks_ms": mean("reth_storage_providers_database_save_blocks_total"),
            "mean_mdbx_writes_ms": mean("reth_storage_providers_database_save_blocks_mdbx"),
            "mean_static_file_writes_ms": mean("reth_storage_providers_database_save_blocks_sf"),
            "mean_rocksdb_writes_ms": mean("reth_storage_providers_database_save_blocks_rocksdb"),
            "mean_validator_execution_ms": mean("reth_sync_execution_execution_histogram"),
            "mean_new_payload_processing_ms": mean("reth_sync_block_validation_total_duration"),
            "mean_state_root_wait_ms": mean("reth_sync_block_validation_state_root_histogram"),
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
