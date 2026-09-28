#!/usr/bin/env bash
set -euo pipefail
cd /home/ubuntu/repos/tempo-payments-bloat-pr
exec flock --nonblock /proc/self/fd/9 \
  systemd-run --scope --quiet --collect --unit tempo-bytecode-io-latency-20260927-traced \
  taskset -c 8 /tmp/tempo-bytecode-latency-diagnostic \
  /reth-bench-b/tempo_e2e_100000mb_state_access_isolated_roles_history_paths/db /mnt2 \
  "$PWD/bench-results/bytecode-latency-breakdown-20260927/records-traced-request-id.bin" \
  > bench-results/bytecode-latency-breakdown-20260927/latency-traced.jsonl \
  2> bench-results/bytecode-latency-breakdown-20260927/latency-traced.stderr \
  9< /tmp/tempo-general-state-access-20260922.lock
