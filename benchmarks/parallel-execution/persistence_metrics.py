#!/usr/bin/env python3
"""Bounded local persistence counters before/after a benchmark pipeline.

These snapshots include setup and pipeline drainage. Histogram sums/counts are
cumulative; last-value gauges can miss cycles. Backend timers overlap and are
wall time, not CPU time. Nothing here establishes a throughput improvement.
"""

import argparse
import datetime
import hashlib
import json
import math
from pathlib import Path
import re
import signal
import urllib.request

MAX_BODY = 8 * 1024**2
MAX_OUTPUT = 256 * 1024
PREFIX = "reth_storage_providers_database_"
STAGES = (
    "save_blocks_total", "save_blocks_mdbx", "save_blocks_sf", "save_blocks_rocksdb",
    "save_blocks_insert_block", "save_blocks_write_state", "save_blocks_write_hashed_state",
    "save_blocks_write_trie_updates", "save_blocks_update_history_indices",
    "save_blocks_update_pipeline_stages", "save_blocks_batch_size",
    "save_blocks_commit_mdbx", "save_blocks_commit_sf", "save_blocks_commit_rocksdb",
)
NAMES = {PREFIX + stage + suffix for stage in STAGES for suffix in ("_sum", "_count", "_last")}
NAMES |= {PREFIX + "insert_transaction_hash_numbers" + suffix for suffix in ("_sum", "_count")}
NAMES |= {"reth_consensus_engine_beacon_" + stage + suffix
          for stage in ("persistence_duration", "backpressure_stall_duration")
          for suffix in ("_sum", "_count")}
NAMES.add("reth_consensus_engine_beacon_backpressure_active")
SAMPLE = re.compile(r"([a-zA-Z_:][a-zA-Z_0-9:]*)(\{[^\n]*\})?\s+([^\s]+)(?:\s+([0-9]+))?")


def now():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def selected_samples(body):
    if len(body) > MAX_BODY:
        raise ValueError("metrics response exceeds 8 MiB")
    if body and not body.endswith(b"\n"):
        raise ValueError("incomplete metrics response")
    samples, seen = [], set()
    for line in body.decode("utf-8").splitlines():
        if not line or line.startswith("#"):
            continue
        name = re.split(r"[\s{]", line, maxsplit=1)[0]
        if name not in NAMES:
            continue
        match = SAMPLE.fullmatch(line)
        if match is None or len(line) > 4096:
            raise ValueError("malformed persistence metric")
        name, labels, value, timestamp = match.groups()
        number = float(value)
        if not math.isfinite(number) or number < 0:
            raise ValueError("invalid persistence metric value")
        if name.endswith("_count") and not number.is_integer():
            raise ValueError("nonintegral histogram count")
        identity = (name, labels)
        if identity in seen:
            raise ValueError("duplicate persistence metric")
        seen.add(identity)
        samples.append({"name": name, "labels": labels, "value": value,
                        "timestamp": timestamp, "raw_line": line})
        if len(samples) > 128:
            raise ValueError("too many persistence series")
    if not samples:
        raise ValueError("no persistence metrics found")
    return samples


def snapshot(role, url):
    started = now()
    request = urllib.request.Request(url, headers={"Accept-Encoding": "identity"})
    with urllib.request.urlopen(request, timeout=5) as response:
        if response.status != 200 or response.geturl() != url:
            raise ValueError("unexpected metrics response or redirect")
        if response.headers.get("Content-Encoding", "identity") != "identity":
            raise ValueError("unexpected compressed metrics response")
        body = response.read(MAX_BODY + 1)
    return {"role": role, "url": url, "started_at": started, "finished_at": now(),
            "response_bytes": len(body), "response_sha256": hashlib.sha256(body).hexdigest(),
            "samples": selected_samples(body)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--phase", required=True)
    parser.add_argument("--boundary", choices=("pre", "post"), required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if not re.fullmatch(r"(?:baseline|feature)-[1-9][0-9]*", args.phase):
        parser.error("invalid phase")
    result = {"phase": args.phase, "boundary": args.boundary, "started_at": now(),
              "status": "passed", "nodes": [], "errors": [], "scope": __doc__}
    # Bound the entire pair, including slow responses; no sampler survives this process.
    def deadline(_signum, _frame):
        raise TimeoutError("metrics snapshot deadline")
    signal.signal(signal.SIGALRM, deadline)
    signal.alarm(12)
    try:
        for role, port in (("a", 9001), ("b", 9101)):
            result["nodes"].append(snapshot(role, f"http://127.0.0.1:{port}/metrics"))
    except Exception as error:
        result["status"] = "failed"
        result["errors"].append(str(error)[:1000])
    finally:
        signal.alarm(0)
    result["finished_at"] = now()
    encoded = json.dumps(result, indent=2, allow_nan=False) + "\n"
    if len(encoded.encode()) > MAX_OUTPUT:
        raise ValueError("snapshot exceeds 256 KiB")
    with args.output.open("x") as output:
        output.write(encoded)
    print(f"Persistence metrics {args.phase}/{args.boundary}: {result['status']}")
    return 0 if result["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
