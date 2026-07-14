#!/usr/bin/env bash
# Insert native execution microbenchmark JSONEachRow data into ClickHouse.
#
# This runner intentionally has no DDL path. Apply the versioned table DDL with
# an administrative account before configuring the benchmark workflow.
#
# Environment:
#   CLICKHOUSE_URL       ClickHouse HTTP endpoint (for example, https://host:8443)
#   CLICKHOUSE_USER      Benchmark user with INSERT and SELECT on the result table
#   CLICKHOUSE_PASSWORD  Benchmark user password
#   CLICKHOUSE_DATABASE  Database name (default: default)
#
# Usage: upload-execution-microbench-results.sh <clickhouse-rows.jsonl>

set -euo pipefail

TABLE="tempo_execution_microbench_results"
ROWS_PATH="${1:-}"
DATABASE="${CLICKHOUSE_DATABASE:-default}"

credential_count=0
[ -n "${CLICKHOUSE_URL:-}" ] && credential_count=$((credential_count + 1))
[ -n "${CLICKHOUSE_USER:-}" ] && credential_count=$((credential_count + 1))
[ -n "${CLICKHOUSE_PASSWORD:-}" ] && credential_count=$((credential_count + 1))
if [ "$credential_count" -eq 0 ]; then
  echo "Skipping ClickHouse upload: CLICKHOUSE_URL, CLICKHOUSE_USER, or CLICKHOUSE_PASSWORD not set"
  exit 0
fi
if [ "$credential_count" -ne 3 ]; then
  echo "error: ClickHouse credentials are partially configured; URL, user, and password are all required" >&2
  exit 1
fi

if [[ "$CLICKHOUSE_URL" == https://* ]]; then
  CURL_PROTOCOL="=https"
elif [[ "$CLICKHOUSE_URL" =~ ^http://(localhost|127\.0\.0\.1|\[::1\])(:[0-9]+)?(/.*)?$ ]]; then
  CURL_PROTOCOL="=http"
else
  echo "error: CLICKHOUSE_URL must use HTTPS; HTTP is allowed only for an explicit loopback address" >&2
  exit 1
fi

if [ -z "$ROWS_PATH" ] || [ ! -f "$ROWS_PATH" ]; then
  echo "error: JSONEachRow input file not found: ${ROWS_PATH:-<missing>}" >&2
  exit 1
fi
if ! [[ "$DATABASE" =~ ^[A-Za-z_][A-Za-z0-9_]*$ ]]; then
  echo "error: CLICKHOUSE_DATABASE is not a valid unquoted database identifier" >&2
  exit 1
fi
if [[ "$CLICKHOUSE_USER" == *$'\n'* || "$CLICKHOUSE_USER" == *$'\r'* || "$CLICKHOUSE_PASSWORD" == *$'\n'* || "$CLICKHOUSE_PASSWORD" == *$'\r'* ]]; then
  echo "error: ClickHouse credentials must not contain line breaks" >&2
  exit 1
fi

# Validate the complete batch before sending any bytes. This catches truncated
# artifacts, duplicate cases, and accidental simulation results locally.
VALIDATION_RESULT="$(env -u CLICKHOUSE_USER -u CLICKHOUSE_PASSWORD python3 - "$ROWS_PATH" <<'PY'
import json
import re
import sys
from pathlib import Path

path = Path(sys.argv[1])
rows = []
for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
    if not line.strip():
        continue
    try:
        row = json.loads(line)
    except json.JSONDecodeError as error:
        raise SystemExit(f"error: invalid JSONEachRow line {line_number}: {error}")
    if not isinstance(row, dict):
        raise SystemExit(f"error: JSONEachRow line {line_number} is not an object")
    rows.append(row)

if not rows:
    raise SystemExit("error: JSONEachRow input contains no results")

run_ids = {row.get("run_id") for row in rows}
if len(run_ids) != 1 or None in run_ids or "" in run_ids:
    raise SystemExit("error: every row must have the same non-empty run_id")
run_id = next(iter(run_ids))
if not re.fullmatch(r"[A-Za-z0-9._:-]+", run_id):
    raise SystemExit("error: run_id contains unsupported characters")
case_ids = [row.get("case_id") for row in rows]
if any(not isinstance(case_id, str) or not case_id for case_id in case_ids):
    raise SystemExit("error: every row must have a non-empty case_id")
if len(case_ids) != len(set(case_ids)):
    raise SystemExit("error: duplicate case_id in JSONEachRow input")
if any(row.get("schema_version") != 1 for row in rows):
    raise SystemExit("error: unsupported JSONEachRow schema_version")
if any(row.get("measurement_mode") != "wall_time" for row in rows):
    raise SystemExit("error: only wall_time measurements may be published")
if any("hostname" in row for row in rows):
    raise SystemExit("error: hostname must not be persisted in benchmark rows")

cpu_sets = {row.get("cpu_set") for row in rows}
if len(cpu_sets) != 1 or None in cpu_sets or "" in cpu_sets:
    raise SystemExit("error: published runs require one non-empty cpu_set")
machine_ids = {row.get("machine_id") for row in rows}
if len(machine_ids) != 1 or None in machine_ids or "" in machine_ids:
    raise SystemExit("error: published runs require one non-empty machine_id")
governor_sets = {row.get("cpu_governors") for row in rows}
if len(governor_sets) != 1 or None in governor_sets or "" in governor_sets:
    raise SystemExit("error: published runs require observed CPU governor metadata")
governors = next(iter(governor_sets)).split(",")
if any(governor != "performance" for governor in governors):
    raise SystemExit("error: every observed CPU governor must be performance")

turbo_values = {row.get("turbo_control_json") for row in rows}
if len(turbo_values) != 1:
    raise SystemExit("error: inconsistent turbo-control metadata")
turbo_json = next(iter(turbo_values))
if turbo_json is not None:
    try:
        turbo = json.loads(turbo_json)
    except (TypeError, json.JSONDecodeError) as error:
        raise SystemExit(f"error: invalid turbo-control metadata: {error}")
    path = turbo.get("path", "")
    value = turbo.get("value")
    if path.endswith("/intel_pstate/no_turbo"):
        expected = "1"
    elif path.endswith("/cpufreq/boost"):
        expected = "0"
    else:
        raise SystemExit(f"error: unknown turbo-control path: {path}")
    if value != expected:
        raise SystemExit(f"error: turbo boost is enabled according to {path}")

print(f"{run_id}\t{len(rows)}")
PY
)"
IFS=$'\t' read -r RUN_ID EXPECTED_COUNT <<< "$VALIDATION_RESULT"
echo "Validated ${EXPECTED_COUNT} result(s) for run ${RUN_ID}"

# Keep credentials out of argv and command output. Curl reads the temporary
# mode-0600 config, and the trap removes it on success or failure.
AUTH_CONFIG="$(mktemp)"
trap 'rm -f "$AUTH_CONFIG"' EXIT
chmod 600 "$AUTH_CONFIG"
escaped_user="${CLICKHOUSE_USER//\\/\\\\}"
escaped_user="${escaped_user//\"/\\\"}"
escaped_password="${CLICKHOUSE_PASSWORD//\\/\\\\}"
escaped_password="${escaped_password//\"/\\\"}"
printf 'user = "%s:%s"\n' "$escaped_user" "$escaped_password" > "$AUTH_CONFIG"
unset CLICKHOUSE_USER CLICKHOUSE_PASSWORD escaped_user escaped_password

endpoint="${CLICKHOUSE_URL%/}/?database=${DATABASE}&date_time_input_format=best_effort&input_format_defaults_for_omitted_fields=1&query=INSERT%20INTO%20${TABLE}%20FORMAT%20JSONEachRow"
curl \
  --config "$AUTH_CONFIG" \
  --proto "$CURL_PROTOCOL" \
  --proto-redir "$CURL_PROTOCOL" \
  --fail-with-body \
  --silent \
  --show-error \
  --data-binary "@$ROWS_PATH" \
  "$endpoint"

observed_count="$(curl \
  --config "$AUTH_CONFIG" \
  --proto "$CURL_PROTOCOL" \
  --proto-redir "$CURL_PROTOCOL" \
  --fail-with-body \
  --silent \
  --show-error \
  --get \
  --data-urlencode "database=$DATABASE" \
  --data-urlencode "param_run_id=$RUN_ID" \
  --data-urlencode "query=SELECT count() FROM $TABLE FINAL WHERE run_id = {run_id:String} FORMAT TabSeparatedRaw" \
  "${CLICKHOUSE_URL%/}/")"
observed_count="${observed_count//[[:space:]]/}"
if ! [[ "$observed_count" =~ ^[0-9]+$ ]]; then
  echo "error: ClickHouse verification returned an invalid count" >&2
  exit 1
fi
if [ "$observed_count" -ne "$EXPECTED_COUNT" ]; then
  echo "error: ClickHouse verification found $observed_count row(s), expected $EXPECTED_COUNT" >&2
  exit 1
fi

echo "Uploaded and verified ${EXPECTED_COUNT} result(s) in ${DATABASE}.${TABLE}"
