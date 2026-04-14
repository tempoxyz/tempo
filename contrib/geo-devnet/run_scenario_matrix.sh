#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
RESULT_ROOT_DEFAULT="$SCRIPT_DIR/.geodevnet/scenario-runs/$(date -u +%Y%m%dT%H%M%SZ)"
RESULT_ROOT="${RESULT_ROOT:-$RESULT_ROOT_DEFAULT}"

RPC_URL="${RPC_URL:-http://172.20.0.10:8545}"
BENCH_BIN="${BENCH_BIN:-$REPO_ROOT/target/release/tempo-bench}"
TPS="${TPS:-1800}"
DURATION="${DURATION:-60}"
ACCOUNTS="${ACCOUNTS:-400}"
MAX_CONCURRENT_REQUESTS="${MAX_CONCURRENT_REQUESTS:-400}"
FROM_MNEMONIC_INDEX_BASE="${FROM_MNEMONIC_INDEX_BASE:-8000}"
MNEMONIC="${MNEMONIC:-test test test test test test test test test test test junk}"
MIN_TOTAL_TRANSACTIONS="${MIN_TOTAL_TRANSACTIONS:-500}"
SNAPSHOT_INTERVAL_SECS="${SNAPSHOT_INTERVAL_SECS:-0.5}"
ANSI_RE='\x1b\[[0-9;]*m'

CONTAINERS=(eu-val-0 eu-val-1 us-val-2 us-val-3)
ANALYSES=(
  "buffer_sent broadcast_received"
  "buffer_sent buffer_resolved"
  "buffer_sent execution_layer"
  "constructed_proposal marshal_wait"
  "constructed_proposal broadcast_received"
  "constructed_proposal execution_layer"
)

if [ "$#" -gt 0 ]; then
  SCENARIOS=("$@")
else
  SCENARIOS=(default initcwnd363 bbr fq_bbr)
fi

require_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "missing required command: $1" >&2
    exit 1
  fi
}

container_pid() {
  docker inspect -f '{{.State.Pid}}' "$1"
}

container_ip() {
  docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$1"
}

wait_for_rpc() {
  python3 - "$RPC_URL" <<'PY'
import json
import sys
import time
import urllib.request

url = sys.argv[1]
payload = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "eth_blockNumber", "params": []}).encode()
for attempt in range(60):
    try:
        req = urllib.request.Request(url, data=payload, headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=2) as response:
            print(response.read().decode())
            sys.exit(0)
    except Exception:
        if attempt == 59:
            raise
        time.sleep(1)
PY
}

current_max_view() {
  python3 - "${CONTAINERS[@]}" <<'PY'
import re
import subprocess
import sys

ansi_re = re.compile(r"\x1b\[[0-9;]*m")
pattern = re.compile(r"view=(\d+).*constructed proposal")
max_view = 0
for container in sys.argv[1:]:
    result = subprocess.run(["docker", "logs", container], capture_output=True, text=True)
    text = ansi_re.sub("", result.stdout + result.stderr)
    for match in pattern.finditer(text):
        max_view = max(max_view, int(match.group(1)))
print(max_view)
PY
}

first_view_at_or_after() {
  local timestamp="$1"
  python3 - "$timestamp" "${CONTAINERS[@]}" <<'PY'
import datetime as dt
import re
import subprocess
import sys

ansi_re = re.compile(r"\x1b\[[0-9;]*m")
proposal_re = re.compile(
    r"(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d+Z).*?view=(\d+).*?constructed proposal"
)
target_ts = dt.datetime.fromisoformat(sys.argv[1].replace("Z", "+00:00"))
first_view = None
for container in sys.argv[2:]:
    result = subprocess.run(["docker", "logs", container], capture_output=True, text=True)
    text = ansi_re.sub("", result.stdout + result.stderr)
    for line in text.splitlines():
        match = proposal_re.search(line)
        if not match:
            continue
        line_ts = dt.datetime.fromisoformat(match.group(1).replace("Z", "+00:00"))
        if line_ts < target_ts:
            continue
        view = int(match.group(2))
        if first_view is None or view < first_view:
            first_view = view
        break
print(first_view or 0)
PY
}

snapshot_static_state() {
  local scenario_dir="$1"
  mkdir -p "$scenario_dir/state"
  for container in "${CONTAINERS[@]}"; do
    local pid
    pid="$(container_pid "$container")"
    {
      echo "container=$container"
      echo "pid=$pid"
      echo "timestamp=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
      echo "congestion_control=$(sudo nsenter -t "$pid" -n sysctl -n net.ipv4.tcp_congestion_control)"
      echo "available_congestion_control=$(sudo nsenter -t "$pid" -n cat /proc/sys/net/ipv4/tcp_available_congestion_control)"
    } >"$scenario_dir/state/$container.sysctl.txt"
    docker exec "$container" ip -4 route show >"$scenario_dir/state/$container.routes.txt"
    docker exec "$container" tc -s qdisc show dev eth0 >"$scenario_dir/state/$container.qdisc.txt"
    docker exec "$container" tc -s class show dev eth0 >"$scenario_dir/state/$container.class.txt"
    sudo nsenter -t "$pid" -n sh -lc 'ss -tinm | grep -A1 9001 || true' >"$scenario_dir/state/$container.ss.pre.txt"
  done
}

start_tcp_snapshots() {
  local scenario_dir="$1"
  SNAPSHOT_PIDS=()
  mkdir -p "$scenario_dir/tcp"
  for container in "${CONTAINERS[@]}"; do
    local output="$scenario_dir/tcp/$container.ss-tinm.log"
    (
      while true; do
        local pid
        pid="$(container_pid "$container")"
        {
          echo "### $(date -u +%Y-%m-%dT%H:%M:%SZ)"
          echo "container=$container"
          echo "pid=$pid"
          echo -n "congestion_control="
          sudo nsenter -t "$pid" -n sysctl -n net.ipv4.tcp_congestion_control || true
          sudo nsenter -t "$pid" -n sh -lc 'ss -tinm | grep -A1 9001 || true'
          echo
        } >>"$output" 2>&1
        sleep "$SNAPSHOT_INTERVAL_SECS"
      done
    ) &
    SNAPSHOT_PIDS+=("$!")
  done
}

stop_tcp_snapshots() {
  if [ "${#SNAPSHOT_PIDS[@]}" -eq 0 ]; then
    return
  fi
  kill "${SNAPSHOT_PIDS[@]}" 2>/dev/null || true
  wait "${SNAPSHOT_PIDS[@]}" 2>/dev/null || true
  SNAPSHOT_PIDS=()
}

apply_qdisc_mode() {
  local container="$1"
  local qdisc_mode="$2"
  docker exec "$container" /usr/local/bin/geodevnet-network apply-qdisc "$qdisc_mode"
}

configure_scenario() {
  local scenario="$1"
  local cc qdisc_mode
  case "$scenario" in
    default|initcwnd363)
      cc="cubic"
      qdisc_mode="legacy"
      ;;
    bbr)
      cc="bbr"
      qdisc_mode="legacy"
      sudo modprobe tcp_bbr >/dev/null 2>&1 || true
      if ! sysctl -n net.ipv4.tcp_available_congestion_control | grep -qw bbr; then
        echo "bbr is not available on this host" >&2
        exit 1
      fi
      ;;
    fq_bbr)
      cc="bbr"
      qdisc_mode="fq"
      sudo modprobe tcp_bbr >/dev/null 2>&1 || true
      sudo modprobe sch_fq >/dev/null 2>&1 || true
      if ! sysctl -n net.ipv4.tcp_available_congestion_control | grep -qw bbr; then
        echo "bbr is not available on this host" >&2
        exit 1
      fi
      ;;
    *)
      echo "unknown scenario: $scenario" >&2
      exit 1
      ;;
  esac

  CURRENT_CONGESTION_CONTROL="$cc"
  CURRENT_QDISC_MODE="$qdisc_mode"

  for container in "${CONTAINERS[@]}"; do
    local pid ip
    pid="$(container_pid "$container")"
    ip="$(container_ip "$container")"
    sudo nsenter -t "$pid" -n sysctl -w "net.ipv4.tcp_congestion_control=$cc" >/dev/null
    apply_qdisc_mode "$container" "$qdisc_mode"
    case "$scenario" in
      initcwnd363)
        docker exec "$container" sh -lc "ip route replace 172.20.0.0/24 dev eth0 proto kernel scope link src $ip initcwnd 363 initrwnd 363"
        docker exec "$container" sh -lc "ip route replace default via 172.20.0.1 dev eth0"
        ;;
      default|bbr|fq_bbr)
        docker exec "$container" sh -lc "ip route replace 172.20.0.0/24 dev eth0 proto kernel scope link src $ip"
        docker exec "$container" sh -lc "ip route replace default via 172.20.0.1 dev eth0"
        ;;
    esac
    docker exec "$container" sh -lc 'ss -K dport = 9001 || true; ss -K sport = 9001 || true' >/dev/null 2>&1 || true
  done

  sleep 8
  wait_for_rpc >/dev/null
}

run_bench() {
  local scenario_dir="$1"
  local mnemonic_index="$2"
  local bench_log="$scenario_dir/bench.log"
  "$BENCH_BIN" run-max-tps \
    --tps "$TPS" \
    --duration "$DURATION" \
    --accounts "$ACCOUNTS" \
    --from-mnemonic-index "$mnemonic_index" \
    -m "$MNEMONIC" \
    --target-urls "$RPC_URL" \
    --max-concurrent-requests "$MAX_CONCURRENT_REQUESTS" \
    --use-standard-nonces \
    --tip20-weight 1.0 \
    --existing-recipients \
    --fd-limit 65536 \
    >"$bench_log" 2>&1
  if [ -f "$REPO_ROOT/report.json" ]; then
    cp "$REPO_ROOT/report.json" "$scenario_dir/report.json"
  fi
}

run_analyses() {
  local scenario_dir="$1"
  local min_view="$2"
  local max_view="${3:-}"
  mkdir -p "$scenario_dir/analysis"
  for combo in "${ANALYSES[@]}"; do
    local sender receiver output
    sender="${combo%% *}"
    receiver="${combo##* }"
    output="$scenario_dir/analysis/${sender}__${receiver}.txt"
    if [ -n "$max_view" ]; then
      python3 "$SCRIPT_DIR/analyze_propagation.py" \
        --min-view "$min_view" \
        --max-view "$max_view" \
        --sender-marker "$sender" \
        --receiver-marker "$receiver" \
        --min-total-transactions "$MIN_TOTAL_TRANSACTIONS" \
        >"$output" 2>&1
    else
      python3 "$SCRIPT_DIR/analyze_propagation.py" \
        --min-view "$min_view" \
        --sender-marker "$sender" \
        --receiver-marker "$receiver" \
        --min-total-transactions "$MIN_TOTAL_TRANSACTIONS" \
        >"$output" 2>&1
    fi
  done
}

write_run_metadata() {
  local scenario_dir="$1"
  local scenario="$2"
  local start_timestamp="$3"
  local mnemonic_index="$4"
  cat >"$scenario_dir/run-metadata.txt" <<EOF
scenario=$scenario
tps=$TPS
duration=$DURATION
accounts=$ACCOUNTS
max_concurrent_requests=$MAX_CONCURRENT_REQUESTS
from_mnemonic_index=$mnemonic_index
min_total_transactions=$MIN_TOTAL_TRANSACTIONS
start_timestamp=$start_timestamp
rpc_url=$RPC_URL
tcp_congestion_control=$CURRENT_CONGESTION_CONTROL
qdisc_mode=$CURRENT_QDISC_MODE
timestamp=$(date -u +%Y-%m-%dT%H:%M:%SZ)
EOF
}

cleanup() {
  stop_tcp_snapshots
}

require_cmd docker
require_cmd python3
require_cmd sudo

trap cleanup EXIT

mkdir -p "$RESULT_ROOT"

printf 'result_root=%s\n' "$RESULT_ROOT"

scenario_index=0
scenario_dirs=()
scenario_timestamps=()
for scenario in "${SCENARIOS[@]}"; do
  scenario_index=$((scenario_index + 1))
  scenario_dir="$RESULT_ROOT/${scenario_index}-${scenario}"
  mkdir -p "$scenario_dir"
  echo "==> scenario: $scenario"
  configure_scenario "$scenario"
  snapshot_static_state "$scenario_dir"
  start_timestamp="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  mnemonic_index="$((FROM_MNEMONIC_INDEX_BASE + (scenario_index - 1) * ACCOUNTS))"
  write_run_metadata "$scenario_dir" "$scenario" "$start_timestamp" "$mnemonic_index"
  start_tcp_snapshots "$scenario_dir"
  run_bench "$scenario_dir" "$mnemonic_index"
  stop_tcp_snapshots
  snapshot_static_state "$scenario_dir/post"
  scenario_dirs+=("$scenario_dir")
  scenario_timestamps+=("$start_timestamp")
done

for i in "${!scenario_dirs[@]}"; do
  start_view="$(first_view_at_or_after "${scenario_timestamps[$i]}")"
  max_view=""
  if [ $((i + 1)) -lt ${#scenario_dirs[@]} ]; then
    next_start_view="$(first_view_at_or_after "${scenario_timestamps[$((i + 1))]}")"
    if [ "$next_start_view" -gt 0 ]; then
      max_view="$((next_start_view - 1))"
    fi
  fi
  run_analyses "${scenario_dirs[$i]}" "$start_view" "$max_view"
done
