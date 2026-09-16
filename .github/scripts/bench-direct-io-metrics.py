#!/usr/bin/env python3
"""Reduce this experiment's immutable artifact to storage and pressure evidence."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile
import zipfile

ARTIFACT_ID = 10445430036
RUN_ID = 35087336997
PREFIXES = (
    "reth_storage_providers_database_save_blocks",
    "reth_consensus_engine_persistence_save_blocks",
    "reth_database_transaction_commit_",
    "node_memory_", "node_pressure_", "node_vmstat_",
    "process_resident_memory", "process_cpu_seconds", "jemalloc",
)


def main():
    api = f"repos/tempoxyz/tempo/actions/artifacts/{ARTIFACT_ID}"
    metadata = json.loads(subprocess.check_output(["gh", "api", api], text=True))
    assert metadata["workflow_run"]["id"] == RUN_ID
    assert metadata["name"] == "tempo-bench-results" and not metadata["expired"]
    with tempfile.TemporaryDirectory() as directory:
        archive = Path(directory) / "source.zip"
        with archive.open("wb") as output:
            subprocess.run(["gh", "api", api + "/zip"], stdout=output, check=True, timeout=600)
        assert archive.stat().st_size == metadata["size_in_bytes"]
        with archive.open("rb") as source:
            digest = hashlib.file_digest(source, "sha256").hexdigest()
        assert metadata["digest"] == "sha256:" + digest
        result = {"run_id": RUN_ID, "artifact_id": ARTIFACT_ID, "archive_sha256": digest,
                  "note": "Counter deltas use first/last samples after five warmup blocks. Gauge min/max are sampled observations. Preserve node labels; never sum stacked block-device counters.",
                  "phases": {}}
        with zipfile.ZipFile(archive) as zipped:
            entries = [name for name in zipped.namelist() if name.endswith(".samples.ndjson.gz")]
            assert len(entries) == 6
            for entry in sorted(entries):
                report = json.loads(zipped.read(entry.replace(".samples.ndjson.gz", ".json")))
                blocks = sorted(report["blocks"], key=lambda block: block["timestamp_ms"])
                cutoff = blocks[5]["timestamp_ms"] - blocks[0]["timestamp_ms"]
                samples = Path(directory) / "samples.gz"
                with zipped.open(entry) as source, samples.open("wb") as output:
                    import shutil
                    shutil.copyfileobj(source, output, 1024 * 1024)
                decompress = subprocess.Popen(["gzip", "-dc", str(samples)], stdout=subprocess.PIPE)
                command = ["grep", "-F"]
                for prefix in PREFIXES:
                    command.extend(["-e", prefix])
                filtered = subprocess.Popen(command, stdin=decompress.stdout, stdout=subprocess.PIPE, text=True)
                decompress.stdout.close()
                series = {}
                for line in filtered.stdout:
                    sample = json.loads(line)
                    name, labels = sample["name"], sample["labels"]
                    if "quantile" in labels or name.endswith("_bucket"):
                        continue
                    if sample.get("offset_ms", sample["unix_ms"] - blocks[0]["timestamp_ms"]) < cutoff:
                        continue
                    identity = (name, json.dumps(labels, sort_keys=True))
                    timestamp, value = sample["unix_ms"], sample["value"]
                    if identity not in series:
                        series[identity] = {"name": name, "labels": labels, "first_ms": timestamp,
                                            "last_ms": timestamp, "first": value, "last": value,
                                            "min": value, "max": value, "samples": 0}
                    row = series[identity]
                    if timestamp < row["first_ms"]:
                        row.update(first_ms=timestamp, first=value)
                    if timestamp >= row["last_ms"]:
                        row.update(last_ms=timestamp, last=value)
                    row["min"], row["max"] = min(row["min"], value), max(row["max"], value)
                    row["samples"] += 1
                assert filtered.wait() == 0 and decompress.wait() == 0
                phase = report["metadata"]["benchmark_run"]
                result["phases"][phase] = {"entry": entry, "cutoff_offset_ms": cutoff,
                                             "series": [dict(row, delta=row["last"] - row["first"])
                                                        for _, row in sorted(series.items())]}
                print(phase, "reduced to", len(series), "series", flush=True)
                samples.unlink()
        Path("direct-io-metrics.json").write_text(json.dumps(result, indent=2) + "\n")


if __name__ == "__main__":
    main()
