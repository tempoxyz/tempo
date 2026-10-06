#!/usr/bin/env python3
"""Analyze nonce diagnostics in an extracted bench-e2e artifact (stdlib only).

Usage: python3 contrib/bench/analyze-expiring-nonces.py RESULTS_DIRECTORY

Use the same first-five-block exclusion as the repository summary. Counter deltas
span the first/last scrapes inside that window. Quantiles are rolling exporter
quantiles: report their median/maximum across scrapes, never pool them as if they
were raw observations. Hot operations sample 1/1024 calls; estimated totals are
weighted, their latency distributions are unweighted. Nested timers overlap.
Slow-log intervals include operations >=10ms (sampled for hot operations). Their
union is an observed overlap with block gaps, not a causal explanation of gaps.
"""
import collections
import datetime
import gzip
import json
import math
import pathlib
import statistics
import sys

SAMPLED = {"check", "membership_lookup", "insert_updates", "index_insert",
           "bucket_cow", "commitment_update", "bucket_append", "recover_signer"}


def union_ms(intervals):
    total, previous = 0.0, -math.inf
    for start, end in sorted(intervals):
        total += max(0.0, end - max(start, previous))
        previous = max(previous, end)
    return total


def analyze(root, label):
    blocks = json.loads((root / f"report-{label}.json").read_text())["blocks"][5:]
    start, end = blocks[0]["timestamp_ms"], blocks[-1]["timestamp_ms"]
    series = collections.defaultdict(list)
    path = root / f"report-{label}.samples.ndjson.gz"
    with gzip.open(path, "rb") as source:
        for line in source:
            if b"tempo_expiring_nonce" not in line:
                continue
            row = json.loads(line)
            value = row["value"]
            if not start <= row["unix_ms"] <= end or not isinstance(value, (int, float)) or not math.isfinite(value):
                continue
            labels = row["labels"]
            key = (row["name"].removeprefix("reth_tempo_expiring_nonce_"),
                   labels["node"], labels.get("operation", labels.get("event")), labels.get("quantile"))
            series[key].append(value)

    def delta(name, node, operation):
        values = series.get((name, node, operation, None), [])
        if any(b < a for a, b in zip(values, values[1:])):
            raise ValueError(f"counter reset: {label}/{node}/{operation}/{name}")
        return values[-1] - values[0] if values else 0

    operations, events = [], []
    for name, node, operation, quantile in sorted(series, key=str):
        if name == "events_total":
            events.append(dict(node=node, event=operation, count=delta(name, node, operation)))
        if name != "duration_seconds_sum":
            continue
        count = delta("duration_seconds_count", node, operation)
        seconds = delta(name, node, operation)
        quantiles = {}
        for (metric, n, op, q), values in series.items():
            if metric == "duration_seconds" and n == node and op == operation:
                quantiles[q] = dict(median_over_scrapes_us=statistics.median(values) * 1e6,
                                    max_over_scrapes_us=max(values) * 1e6)
        operations.append(dict(node=node, operation=operation, observations=count,
                               estimated_calls=delta("operations_total", node, operation),
                               mean_us=seconds / count * 1e6 if count else None,
                               estimated_total_seconds=seconds * (1024 if operation in SAMPLED else 1),
                               rolling_quantiles=quantiles))

    intervals, slow, expiry = [], collections.defaultdict(list), []
    for path in sorted(root.glob(f"logs-{label}-*/dev/reth.log")):
        node = path.parts[-3].rsplit("-", 1)[-1]
        with path.open() as source:
            for line in source:
                if '"target":"tempo::expiring_nonces"' not in line:
                    continue
                row = json.loads(line)
                finish = datetime.datetime.fromisoformat(row["timestamp"]).timestamp() * 1000
                if not start <= finish <= end:
                    continue
                fields = row["fields"]
                if fields["message"] == "Expiring nonce expiry batch":
                    expiry.append(dict(node=node, finish_ms=finish, **fields))
                if fields["message"] != "Slow expiring nonce operation":
                    continue
                elapsed, operation = fields["elapsed_ms"], fields["operation"]
                slow[node, operation].append(elapsed)
                intervals.append((finish - elapsed, finish, node, operation))
    gaps = []
    for block in blocks:
        duration = block["block_time_ms"]
        if duration < 2000:
            continue
        finish = block["timestamp_ms"]
        begin = finish - duration
        overlapping = [(max(a, begin), min(b, finish), n, op) for a, b, n, op in intervals if a < finish and b > begin]
        gaps.append(dict(block=block["number"], start_ms=begin, end_ms=finish,
                         gap_ms=duration, slow_nonce_overlap_ms=union_ms((a, b) for a, b, _, _ in overlapping),
                         operations=sorted({op for _, _, _, op in overlapping})))
    return dict(run=label, start_ms=start, end_ms=end, events=events, operations=operations,
                slow_operations=[dict(node=n, operation=op, count=len(v), max_ms=max(v), total_ms=sum(v))
                                 for (n, op), v in sorted(slow.items())],
                slow_expiry_batches=expiry, gaps=gaps)


if __name__ == "__main__":
    root = pathlib.Path(sys.argv[1])
    runs = [p.name.removeprefix("report-").removesuffix(".samples.ndjson.gz")
            for p in sorted(root.glob("report-feature-*.samples.ndjson.gz"))]
    if not runs:
        raise SystemExit("No feature metric sidecars found; pass the extracted artifact's run directory")
    print(json.dumps([analyze(root, label) for label in runs], indent=2))
