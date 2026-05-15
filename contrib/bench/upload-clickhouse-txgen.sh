#!/usr/bin/env bash
# Upload native txgen bench results to ClickHouse.
#
# Reads report-*.json files from the results directory and inserts into:
#   - tempo_bench_runs   (one row per run)
#   - tempo_bench_blocks (one row per block per run)
#
# Environment:
#   CLICKHOUSE_URL      - ClickHouse HTTP endpoint (https://host:8443)
#   CLICKHOUSE_USER     - ClickHouse user
#   CLICKHOUSE_PASSWORD - ClickHouse password
#   CLICKHOUSE_DB       - database name (default: "default")
#
# Usage: upload-clickhouse-txgen.sh <results-dir>

set -euo pipefail

RESULTS_DIR="$1"
DB="${CLICKHOUSE_DB:-default}"

if [ -z "${CLICKHOUSE_URL:-}" ] || [ -z "${CLICKHOUSE_USER:-}" ] || [ -z "${CLICKHOUSE_PASSWORD:-}" ]; then
  echo "Skipping ClickHouse upload: CLICKHOUSE_URL, CLICKHOUSE_USER, or CLICKHOUSE_PASSWORD not set"
  exit 0
fi

ch_query() {
  local query="$1"
  if ! curl -sf --user "$CLICKHOUSE_USER:$CLICKHOUSE_PASSWORD" \
    "$CLICKHOUSE_URL/?database=$DB" --data-binary "$query"; then
    echo "  Warning: ClickHouse query failed" >&2
    return 1
  fi
}

echo "Uploading txgen bench results to ClickHouse..."

for label in baseline-1 feature-1 feature-2 baseline-2; do
  REPORT="$RESULTS_DIR/report-$label.json"
  if [ ! -f "$REPORT" ]; then
    echo "  Warning: $REPORT not found, skipping"
    continue
  fi

  echo "  Processing: $label"

  # Generate SQL statements via python (one statement per line, no internal newlines)
  QUERIES=$(REPORT_PATH="$REPORT" BENCH_RUN_LABEL="$label" python3 << 'PYEOF'
import json, uuid, os

report = json.load(open(os.environ["REPORT_PATH"]))
meta = report.get("metadata") or {}
run_stats = report.get("run_stats") or {}

def as_int(value, default=0):
    if value is None or value == "":
        return default
    return int(value)

def as_float(value, default=0.0):
    if value is None or value == "":
        return default
    return float(value)

def normalized_blocks(report):
    normalized = []
    for b in report.get("blocks") or []:
        tx_count = as_int(b.get("tx_count"))
        normalized.append({
            "number": as_int(b.get("number")),
            "timestamp": as_int(b.get("timestamp", b.get("timestamp_ms"))),
            "tx_count": tx_count,
            "ok_count": tx_count,
            "err_count": 0,
            "gas_used": as_int(b.get("gas_used")),
            "latency_ms": b.get("block_time_ms"),
        })
    return normalized

blocks = normalized_blocks(report)

run_id = str(uuid.uuid4())

# Compute aggregates
total_tx = sum(b["tx_count"] for b in blocks)
total_ok = sum(b["ok_count"] for b in blocks)
total_err = sum(b["err_count"] for b in blocks)
total_gas = sum(b["gas_used"] for b in blocks)
total_blocks = len(blocks)

timestamps = [b["timestamp"] for b in blocks]
if len(timestamps) > 1:
    time_span_ms = max(timestamps[-1] - timestamps[0], 1)
    avg_block_time_ms = time_span_ms / (len(timestamps) - 1)
    avg_tps = total_tx / (time_span_ms / 1000.0)
else:
    avg_block_time_ms = 0.0
    avg_tps = 0.0

def esc(s):
    return s.replace("'", "\\'")

sha = esc(meta.get("node_commit_sha") or "")
profile = esc(meta.get("build_profile") or "")
mode = esc(meta.get("mode") or "")

run_label = esc(os.environ.get("BENCH_RUN_LABEL", ""))
pr_number = esc(os.environ.get("BENCH_PR", ""))
baseline_ref = esc(os.environ.get("BENCH_BASELINE_REF", ""))
feature_ref = esc(os.environ.get("BENCH_FEATURE_REF", ""))
triggered_by = esc(os.environ.get("BENCH_ACTOR", ""))
run_type = esc(os.environ.get("BENCH_RUN_TYPE", "manual"))
github_run_id_raw = os.environ.get("GITHUB_RUN_ID", "")
default_run_url = ""
if github_run_id_raw and os.environ.get("GITHUB_SERVER_URL") and os.environ.get("GITHUB_REPOSITORY"):
    default_run_url = f"{os.environ['GITHUB_SERVER_URL']}/{os.environ['GITHUB_REPOSITORY']}/actions/runs/{github_run_id_raw}"
github_run_id = esc(github_run_id_raw)
github_run_url = esc(os.environ.get("BENCH_JOB_URL") or default_run_url)

print(
    f"INSERT INTO tempo_bench_runs (run_id, created_at, chain_id, start_block, end_block, "
    f"target_tps, run_duration_secs, accounts, total_connections, "
    f"total_blocks, total_transactions, total_successful, total_failed, "
    f"total_gas_used, avg_block_time_ms, avg_tps, "
    f"node_commit_sha, build_profile, benchmark_mode, "
    f"run_label, pr_number, baseline_ref, feature_ref, "
    f"triggered_by, run_type, github_run_id, github_run_url) VALUES "
    f"('{run_id}', now64(3), {as_int(meta.get('chain_id'))}, "
    f"{as_int(run_stats.get('start_block'))}, {as_int(run_stats.get('end_block'))}, "
    f"{as_int(meta.get('target_tps'))}, {as_int(meta.get('run_duration_secs'))}, "
    f"{as_int(meta.get('accounts'))}, {as_int(meta.get('total_connections'))}, "
    f"{total_blocks}, {total_tx}, {total_ok}, {total_err}, "
    f"{total_gas}, {avg_block_time_ms}, {avg_tps}, "
    f"'{sha}', '{profile}', '{mode}', "
    f"'{run_label}', '{pr_number}', '{baseline_ref}', '{feature_ref}', "
    f"'{triggered_by}', '{run_type}', '{github_run_id}', '{github_run_url}')"
)

# Blocks insert (batch all blocks in one statement)
if blocks:
    rows = []
    for b in blocks:
        lat = b.get("latency_ms")
        lat_val = lat if lat is not None else 0
        rows.append(
            f"('{run_id}', {b['number']}, {b['timestamp']}, "
            f"{b['tx_count']}, {b['ok_count']}, {b['err_count']}, "
            f"{b['gas_used']}, 0, {lat_val})"
        )
    values = ", ".join(rows)
    print(
        f"INSERT INTO tempo_bench_blocks (run_id, block_number, timestamp_ms, "
        f"tx_count, ok_count, err_count, gas_used, gas_limit, latency_ms) VALUES {values}"
    )
PYEOF
  )

  echo "$QUERIES" | while IFS= read -r query; do
    [ -z "$query" ] && continue
    ch_query "$query"
  done

  echo "  Uploaded: $label"
done

echo "ClickHouse upload complete."
