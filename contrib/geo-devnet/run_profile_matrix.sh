#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RESULT_ROOT_DEFAULT="$SCRIPT_DIR/.profile-matrix-runs/$(date -u +%Y%m%dT%H%M%SZ)"
RESULT_ROOT="${RESULT_ROOT:-$RESULT_ROOT_DEFAULT}"
ACCOUNTS_PER_RUN="${ACCOUNTS:-400}"
FROM_MNEMONIC_INDEX_BASE="${FROM_MNEMONIC_INDEX_BASE:-24000}"

SCENARIOS=(default initcwnd363 fq_bbr)

if [ "$#" -gt 0 ]; then
  PROFILES=("$@")
else
  PROFILES=(good_cloud normal_peering congested_peak)
fi

require_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "missing required command: $1" >&2
    exit 1
  fi
}

profile_settings() {
  local profile="$1"
  case "$profile" in
    good_cloud)
      PROFILE_RTT_MS=85
      PROFILE_LOSS_PCT=0.005
      ;;
    normal_peering)
      PROFILE_RTT_MS=95
      PROFILE_LOSS_PCT=0.05
      ;;
    congested_peak)
      PROFILE_RTT_MS=125
      PROFILE_LOSS_PCT=0.3
      ;;
    *)
      echo "unknown profile: $profile" >&2
      exit 1
      ;;
  esac
}

teardown_stack() {
  docker compose -p geodevnet -f "$SCRIPT_DIR/.geodevnet/docker-compose.yml" down -v 2>/dev/null || true
  sudo rm -rf "$SCRIPT_DIR/.geodevnet"
}

require_cmd docker
require_cmd sudo

mkdir -p "$RESULT_ROOT"

cat > "$RESULT_ROOT/profiles.tsv" <<EOF
profile	rtt_ms	loss_pct
good_cloud	85	0.005
normal_peering	95	0.05
congested_peak	125	0.3
EOF

printf 'result_root=%s\n' "$RESULT_ROOT"

mnemonic_index_base="$FROM_MNEMONIC_INDEX_BASE"
for profile in "${PROFILES[@]}"; do
  profile_settings "$profile"
  profile_dir="$RESULT_ROOT/$profile"
  mkdir -p "$profile_dir"
  cat > "$profile_dir/profile.txt" <<EOF
profile=$profile
rtt_ms=$PROFILE_RTT_MS
loss_pct=$PROFILE_LOSS_PCT
EOF

  for scenario in "${SCENARIOS[@]}"; do
    echo "==> profile=$profile rtt=${PROFILE_RTT_MS}ms loss=${PROFILE_LOSS_PCT}% scenario=$scenario"
    teardown_stack
    "$SCRIPT_DIR/geo-devnet.sh" 4 "$PROFILE_RTT_MS" "$PROFILE_LOSS_PCT"
    RESULT_ROOT="$profile_dir/$scenario" \
      FROM_MNEMONIC_INDEX_BASE="$mnemonic_index_base" \
      "$SCRIPT_DIR/run_scenario_matrix.sh" "$scenario"
    mnemonic_index_base=$((mnemonic_index_base + ACCOUNTS_PER_RUN))
  done
done
