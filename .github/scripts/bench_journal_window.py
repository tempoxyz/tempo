"""Bounded, read-only journal reduction executed on an existing validator via SSM."""
import collections
import datetime
import hashlib
import json
import re
import subprocess
import sys
import time
import urllib.request

since, until = sys.argv[1:3]
first = datetime.datetime.fromisoformat(since.replace("Z", "+00:00")).timestamp()
last = datetime.datetime.fromisoformat(until.replace("Z", "+00:00")).timestamp()
assert 0 < last - first <= 900
patterns = {
    "built_payload": "Built payload", "canonical": "Block added to canonical chain",
    "canonical_commit": "Canonical chain committed", "slow_block": "Slow block",
    "proposal": "constructed proposal", "budget_cutoff": "stopping pool transaction execution before payload build budget",
    "marshal_estimate": "updated marshal persistence estimate", "proposal_pacing": "sleeping before returning proposal",
    "invalid_block": "Encountered invalid block", "persistence": r"(?i)persist(?:ed|ing|ence).*block|backpressure",
}
fields = re.compile(r'(?<![\w.])([\w.]+)=([^\s]+)')
wanted = {"number", "block.number", "total_transactions", "pool_transactions_yielded", "pool_transactions_included",
          "parallel_transactions_executed", "invalid_pool_transaction_execution_attempts", "gas_used", "block.tx_count",
          "elapsed", "validation_work_duration", "validation_latency_duration", "normal_transaction_fill_elapsed",
          "normal_transaction_fill_idle_elapsed", "sparse_trie_state_root_wait_elapsed", "builder_finish_elapsed",
          "timing.execution_ms", "timing.state_read_ms", "timing.state_hash_ms", "timing.commit_ms", "timing.total_ms",
          "observed_ns_per_byte", "estimated_ns_per_byte", "build_budget", "total_reserved", "marshal_persist"}
units = {"ns": 1e-6, "nsecs": 1e-6, "us": .001, "µs": .001, "µsecs": .001,
         "ms": 1, "msec": 1, "msecs": 1, "s": 1000, "sec": 1000, "secs": 1000}
def duration_ms(value):
    parts = re.findall(r'(\d+(?:\.\d+)?)(nsecs|µsecs|msecs|secs|msec|sec|ns|us|µs|ms|s)\b', value)
    return sum(float(n) * units[u] for n, u in parts) if parts else None

def category(message):
    if "execution task finished" in message:
        match = re.search(r'task_type="(\w+)"', message)
        return "task_" + (match[1] if match else "unknown")
    for name, pattern in patterns.items():
        if re.search(pattern, message):
            return name
    return None

result = {"since": since, "until": until, "journal_lines": 0, "journal_bytes": 0,
          "debug_lines": 0, "categories": {}, "complete": False,
          "notes": ["Journal window may include setup; this is not the final txgen report or a receipt proof.",
                    "Zero DEBUG matches do not establish absence of the corresponding behavior.",
                    "Metric snapshot is cumulative/current at inspection time, not historical window data."]}
proc = subprocess.Popen(["journalctl", "-u", "tempo-node", "--since", since, "--until", until,
                         "--no-pager", "--output=json", "--output-fields=__REALTIME_TIMESTAMP,MESSAGE,PRIORITY"],
                        stdout=subprocess.PIPE, stderr=subprocess.PIPE)
digest = hashlib.sha256()
started = time.monotonic()
try:
    for raw in proc.stdout:
        digest.update(raw)
        result["journal_bytes"] += len(raw)
        result["journal_lines"] += 1
        if result["journal_bytes"] > 64 * 1024 * 1024 or time.monotonic() - started > 35:
            result["limit"] = "64MiB or35seconds"
            break
        entry = json.loads(raw)
        message = entry.get("MESSAGE", "")
        if not isinstance(message, str):
            continue
        if " DEBUG " in message or entry.get("PRIORITY") == "7":
            result["debug_lines"] += 1
        name = category(message)
        if name is None:
            continue
        timestamp = int(entry["__REALTIME_TIMESTAMP"]) / 1000000
        values = {key: value.strip('"') for key, value in fields.findall(message) if key in wanted}
        # Task elapsed uses human units separated by spaces; payload elapsed uses Rust Debug units.
        elapsed = duration_ms(message.rsplit("elapsed=", 1)[-1]) if name.startswith("task_") else duration_ms(values.get("elapsed", ""))
        score = float(values.get("timing.total_ms", 0)) if name == "slow_block" else elapsed or 0
        row = {"unix_ms": round(timestamp * 1000, 3), "fields": values}
        if elapsed is not None:
            row["elapsed_ms"] = round(elapsed, 3)
        group = result["categories"].setdefault(name, {"count": 0, "minutes": {}, "slowest": [], "first": None, "last": None})
        group["count"] += 1
        minute = int((timestamp - first) // 60)
        bucket = group["minutes"].setdefault(minute, {"count": 0, "elapsed_ms_sum": 0, "elapsed_ms_max": 0, "transactions": 0})
        bucket["count"] += 1
        if elapsed is not None:
            bucket["elapsed_ms_sum"] = round(bucket["elapsed_ms_sum"] + elapsed, 3)
            bucket["elapsed_ms_max"] = max(bucket["elapsed_ms_max"], round(elapsed, 3))
        bucket["transactions"] += int(values.get("total_transactions", values.get("block.tx_count", "0")))
        excerpt = {"unix_ms": row["unix_ms"], "line": message[-850:]}
        if group["first"] is None:
            group["first"] = excerpt
        group["last"] = excerpt
        group["slowest"].append((score, row))
        group["slowest"] = sorted(group["slowest"], key=lambda pair: pair[0], reverse=True)[:3]
    else:
        result["complete"] = True
finally:
    if proc.poll() is None:
        proc.terminate()
    proc.wait(timeout=5)
result["journal_returncode"] = proc.returncode
result["journal_stderr"] = proc.stderr.read().decode(errors="replace")[:500]
result["journal_source_sha256"] = digest.hexdigest()
result["snapshot_unix_ms"] = round(time.time() * 1000)
result["service_started"] = subprocess.run(["systemctl", "show", "-p", "ActiveEnterTimestamp", "--value", "tempo-node"], capture_output=True, text=True).stdout.strip()
metric_prefixes = ("reth_consensus_engine_beacon_backpressure_", "reth_consensus_engine_persistence_save_blocks_duration_seconds",
                   "reth_blockchain_tree_canonical_chain_height", "reth_sync_checkpoint", "reth_tempo_payload_builder_block_build_stop_total")
try:
    with urllib.request.urlopen("http://127.0.0.1:9000/metrics", timeout=5) as response:
        text = response.read(8 * 1024 * 1024).decode()
    result["metric_snapshot"] = [line for line in text.splitlines() if line.startswith(metric_prefixes)
                                  and (not line.startswith("reth_sync_checkpoint") or 'stage="Finish"' in line)
                                  and ("quantile=" not in line or 'quantile="0.99"' in line)][:24]
except Exception as error:
    result["metric_snapshot_error"] = str(error)
# SSM stdout is capped at24KB; retain parsed timings/counts before raw excerpts.
encoded = json.dumps(result, separators=(",", ":"))
if len(encoded.encode()) > 22000:
    for group in result["categories"].values():
        group.pop("first", None)
        group.pop("last", None)
    result["excerpts_omitted_for_output_limit"] = True
    encoded = json.dumps(result, separators=(",", ":"))
if len(encoded.encode()) > 22000:
    for group in result["categories"].values():
        group["slowest"] = group["slowest"][:1]
    result["slowest_reduced_for_output_limit"] = True
    encoded = json.dumps(result, separators=(",", ":"))
assert len(encoded.encode()) <= 22000, "Diagnostic output exceeds SSM bound"
print(encoded)
