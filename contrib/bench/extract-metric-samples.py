#!/usr/bin/env python3
"""Extract the benchmark metric samples needed by tempo.nu summaries.

The txgen samples sidecar can contain millions of full Prometheus samples. The
summary only needs a small fixed allowlist, so this script streams NDJSON (plain
or gzip), parses only matching metric-name lines, and emits compact JSON for
Nushell to consume.
"""

from __future__ import annotations

import gzip
import json
import math
import sys
from pathlib import Path
from typing import BinaryIO, Iterator, Optional

SUMMARY_METRICS = {
    "reth_tempo_payload_builder_payload_build_duration_seconds",
    "reth_tempo_payload_builder_payload_finalization_duration_seconds",
    "reth_tempo_payload_builder_total_normal_included_transaction_execution_duration_seconds",
    "reth_tempo_payload_builder_total_normal_invalid_transaction_execution_duration_seconds",
    "reth_tempo_payload_builder_invalid_pool_transaction_execution_attempts",
    "reth_tempo_payload_builder_pool_transactions_skipped_total",
    "reth_tempo_payload_builder_normal_transaction_fill_overhead_duration_seconds",
    "reth_tempo_payload_builder_normal_transaction_fill_idle_duration_seconds",
    "reth_consensus_engine_beacon_new_payload_latency",
    "reth_tempo_payload_builder_gas_per_second_last",
    "reth_consensus_engine_beacon_new_payload_gas_per_second_last",
}
SUMMARY_METRICS_BYTES = {name.encode() for name in SUMMARY_METRICS}
ALLOWED_QUANTILES = {"", "0.5", "0.9", "0.99"}
NAME_MARKER = b'"name":"'


def open_samples(path: Path) -> BinaryIO:
    if path.suffix == ".gz":
        return gzip.open(path, "rb")
    return path.open("rb")


def fast_metric_name(line: bytes) -> Optional[bytes]:
    """Return the metric name without parsing JSON, when possible.

    txgen writes samples with `name` first, but searching for the marker keeps
    this tolerant of field-order changes. Metric names do not contain escaped
    quotes, so a byte scan is enough for the prefilter.
    """

    start = line.find(NAME_MARKER)
    if start < 0:
        return None
    start += len(NAME_MARKER)
    end = line.find(b'"', start)
    if end < 0:
        return None
    return line[start:end]


def iter_summary_samples(path: Path) -> Iterator[dict]:
    with open_samples(path) as samples:
        for line in samples:
            if not line.strip():
                continue

            name_bytes = fast_metric_name(line)
            if name_bytes not in SUMMARY_METRICS_BYTES:
                continue

            sample = json.loads(line)
            name = sample.get("name")
            if name not in SUMMARY_METRICS:
                continue

            labels = sample.get("labels") or {}
            quantile = labels.get("quantile", "")
            if quantile not in ALLOWED_QUANTILES:
                continue

            value = sample.get("value")
            if not isinstance(value, (int, float)) or not math.isfinite(value):
                continue

            summary_labels = {}
            if quantile:
                summary_labels["quantile"] = quantile
            reason = labels.get("reason")
            if reason is not None:
                summary_labels["reason"] = reason

            yield {"name": name, "labels": summary_labels, "value": value}


def write_json_array(samples: Iterator[dict]) -> None:
    sys.stdout.write("[")
    first = True
    for sample in samples:
        if not first:
            sys.stdout.write(",")
        first = False
        sys.stdout.write(json.dumps(sample, separators=(",", ":")))
    sys.stdout.write("]\n")


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: extract-metric-samples.py <samples.ndjson[.gz]>", file=sys.stderr)
        return 2

    path = Path(sys.argv[1])
    if not path.exists():
        print(f"samples file not found: {path}", file=sys.stderr)
        return 1

    write_json_array(iter_summary_samples(path))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
