#!/usr/bin/env bash
#
# Resolves baseline and feature refs for scheduled replay benchmark runs.
#
# The feature ref is the latest successful scheduled docker.yml build. The
# baseline ref is read from per-chain replay state in the charts repo. If the
# nightly Docker build is stale or unchanged, the caller can alert, fail, or
# skip before occupying a benchmark runner.
#
# Usage: bench-replay-scheduled-refs.sh <force> <chains-json>
#   force       - "true" to run even if no new nightly commit is available
#   chains-json - JSON array of chains to consider, e.g. ["mainnet","testnet"]
#
# Outputs (via GITHUB_OUTPUT):
#   baseline-ref
#   baseline-name
#   baseline-refs-json
#   baseline-names-json
#   feature-ref
#   feature-name
#   should-skip
#   is-stale
#   stale-age-hours
#   nightly-created
#   chains-json
set -euo pipefail

FORCE="${1:-false}"
CHAINS_JSON="${2:-${INPUT_CHAINS_JSON:-[\"mainnet\",\"testnet\"]}}"
REPO="${GITHUB_REPOSITORY:-tempoxyz/tempo}"
STATE_REPO="${BENCH_REPLAY_STATE_REPO:-decofe/tempo-bench-charts}"
STATE_FILE_PREFIX="${BENCH_REPLAY_STATE_FILE_PREFIX:-state/replay-nightly}"
LEGACY_STATE_FILE="${BENCH_REPLAY_LEGACY_STATE_FILE:-state/replay-nightly-last-feature-ref}"
STALE_THRESHOLD_HOURS="${BENCH_REPLAY_STALE_THRESHOLD_HOURS:-24}"

AUTH_HEADER=()
if [ -n "${DEREK_TOKEN:-}" ]; then
  AUTH_HEADER=(-H "Authorization: token ${DEREK_TOKEN}")
fi

state_file_for_chain() {
  local chain="$1"
  printf "%s-%s-last-feature-ref" "$STATE_FILE_PREFIX" "$chain"
}

read_state_file() {
  local state_file="$1"
  local state_url="https://raw.githubusercontent.com/${STATE_REPO}/state/${state_file}"
  local raw

  if raw=$(curl -sfL "${AUTH_HEADER[@]}" "$state_url"); then
    echo "$raw" | tr -d "[:space:]"
  fi
}

echo "Force: $FORCE"
echo "Repository: $REPO"
echo "Chains: $CHAINS_JSON"

if ! echo "$CHAINS_JSON" | jq -e 'type == "array" and length > 0 and ([.[] | select(. != "mainnet" and . != "testnet")] | length == 0)' >/dev/null; then
  echo "::error::chains-json must be a non-empty array containing only mainnet and testnet"
  exit 1
fi
mapfile -t SELECTED_CHAINS < <(echo "$CHAINS_JSON" | jq -r ".[]")

# --- Step 1: Query latest successful scheduled docker.yml run ---
echo "::group::Querying latest nightly docker build"
RUNS_JSON=$(gh run list \
  -R "$REPO" \
  --workflow=docker.yml \
  --event=schedule \
  --status=completed \
  --limit 10 \
  --json headSha,createdAt,conclusion)

LATEST=$(echo "$RUNS_JSON" | jq -r '[.[] | select(.conclusion == "success")] | first // empty')
if [ -z "$LATEST" ]; then
  echo "::error::No successful scheduled docker.yml run found in the last 10 runs"
  echo "Runs found: $RUNS_JSON"
  exit 1
fi

FEATURE_REF=$(echo "$LATEST" | jq -r ".headSha")
CREATED_AT=$(echo "$LATEST" | jq -r ".createdAt")
echo "Latest nightly commit: $FEATURE_REF"
echo "Built at: $CREATED_AT"
echo "::endgroup::"

# --- Step 2: Staleness check ---
echo "::group::Checking nightly staleness"
NOW_EPOCH=$(date +%s)
CREATED_EPOCH=$(date -d "$CREATED_AT" +%s 2>/dev/null || \
  date -j -f "%Y-%m-%dT%H:%M:%SZ" "$CREATED_AT" +%s 2>/dev/null || \
  date -j -f "%Y-%m-%dT%T%z" "$CREATED_AT" +%s 2>/dev/null || \
  { echo "::error::Cannot parse date: $CREATED_AT"; exit 1; })

AGE_SECONDS=$(( NOW_EPOCH - CREATED_EPOCH ))
AGE_HOURS=$(( AGE_SECONDS / 3600 ))
IS_STALE="false"

if [ "$AGE_HOURS" -gt "$STALE_THRESHOLD_HOURS" ]; then
  IS_STALE="true"
  echo "::warning::Stale nightly Docker build: ${AGE_HOURS}h old (threshold: ${STALE_THRESHOLD_HOURS}h)"
else
  echo "Nightly Docker build age: ${AGE_HOURS}h"
fi
echo "::endgroup::"

# --- Step 3: Read last successful feature refs from charts repo state branch ---
echo "::group::Reading persisted replay state"
LEGACY_LAST_FEATURE_REF=$(read_state_file "$LEGACY_STATE_FILE")
if [ -n "$LEGACY_LAST_FEATURE_REF" ]; then
  echo "Legacy replay feature ref: $LEGACY_LAST_FEATURE_REF"
else
  echo "No legacy replay state found"
fi
echo "::endgroup::"

# --- Step 4: Determine chain baselines and skip logic ---
echo "::group::Resolving refs"
RUN_CHAINS_JSON="[]"
BASELINE_REFS_JSON="{}"
BASELINE_NAMES_JSON="{}"
SHOULD_SKIP="true"
FIRST_BASELINE_REF=""
FIRST_BASELINE_NAME=""

for CHAIN in "${SELECTED_CHAINS[@]}"; do
  STATE_FILE=$(state_file_for_chain "$CHAIN")
  LAST_FEATURE_REF=$(read_state_file "$STATE_FILE")
  SOURCE="chain state"

  if [ -z "$LAST_FEATURE_REF" ] && [ -n "$LEGACY_LAST_FEATURE_REF" ]; then
    LAST_FEATURE_REF="$LEGACY_LAST_FEATURE_REF"
    SOURCE="legacy shared state"
  fi

  BASELINE_REF="$FEATURE_REF"
  RUN_CHAIN="false"

  if [ "$IS_STALE" = "true" ]; then
    BASELINE_REF="${LAST_FEATURE_REF:-$FEATURE_REF}"
    echo "${CHAIN}: stale nightly detected; workflow will fail before benchmarking"
  elif [ -z "$LAST_FEATURE_REF" ]; then
    BASELINE_REF="$FEATURE_REF"
    RUN_CHAIN="true"
    echo "${CHAIN}: no persisted state; benchmarking nightly against itself to establish replay state"
  elif [ "$LAST_FEATURE_REF" = "$FEATURE_REF" ]; then
    BASELINE_REF="$LAST_FEATURE_REF"
    if [ "$FORCE" = "true" ] || [ "$FORCE" = "--force" ]; then
      RUN_CHAIN="true"
      echo "${CHAIN}: no new nightly commit, but force=true; running anyway"
    else
      echo "${CHAIN}: no new nightly commit since last successful replay; skipping"
    fi
  else
    BASELINE_REF="$LAST_FEATURE_REF"
    RUN_CHAIN="true"
    echo "${CHAIN}: new nightly commit detected (previous ref from ${SOURCE})"
  fi

  BASELINE_NAME="nightly-${BASELINE_REF:0:8}"
  BASELINE_REFS_JSON=$(jq -c --arg chain "$CHAIN" --arg ref "$BASELINE_REF" '. + {($chain): $ref}' <<< "$BASELINE_REFS_JSON")
  BASELINE_NAMES_JSON=$(jq -c --arg chain "$CHAIN" --arg name "$BASELINE_NAME" '. + {($chain): $name}' <<< "$BASELINE_NAMES_JSON")

  if [ -z "$FIRST_BASELINE_REF" ]; then
    FIRST_BASELINE_REF="$BASELINE_REF"
    FIRST_BASELINE_NAME="$BASELINE_NAME"
  fi

  if [ "$RUN_CHAIN" = "true" ]; then
    RUN_CHAINS_JSON=$(jq -c --arg chain "$CHAIN" '. + [$chain]' <<< "$RUN_CHAINS_JSON")
    SHOULD_SKIP="false"
  fi

  echo "${CHAIN}: baseline=${BASELINE_REF}, feature=${FEATURE_REF}, run=${RUN_CHAIN}"
done

if [ "$IS_STALE" = "true" ]; then
  SHOULD_SKIP="false"
fi

FEATURE_NAME="nightly-${FEATURE_REF:0:8}"

echo "Run chains: $RUN_CHAINS_JSON"
echo "Baseline refs: $BASELINE_REFS_JSON"
echo "Feature: $FEATURE_REF"
echo "Skip: $SHOULD_SKIP"
echo "Stale: $IS_STALE"
echo "::endgroup::"

# --- Step 5: Write outputs ---
{
  echo "baseline-ref=$FIRST_BASELINE_REF"
  echo "baseline-name=$FIRST_BASELINE_NAME"
  echo "baseline-refs-json=$BASELINE_REFS_JSON"
  echo "baseline-names-json=$BASELINE_NAMES_JSON"
  echo "feature-ref=$FEATURE_REF"
  echo "feature-name=$FEATURE_NAME"
  echo "should-skip=$SHOULD_SKIP"
  echo "is-stale=$IS_STALE"
  echo "stale-age-hours=$AGE_HOURS"
  echo "nightly-created=$CREATED_AT"
  echo "chains-json=$RUN_CHAINS_JSON"
} >> "$GITHUB_OUTPUT"
