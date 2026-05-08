#!/usr/bin/env bash
#
# Resolves baseline and feature refs for scheduled replay benchmark runs.
#
# The feature ref is the latest successful scheduled docker.yml build. The
# baseline ref is the last successful scheduled replay feature ref persisted in
# the charts repo. If the nightly Docker build is stale or unchanged, the
# caller can alert, fail, or skip before occupying a benchmark runner.
#
# Usage: bench-replay-scheduled-refs.sh <force>
#   force - "true" to run even if no new nightly commit is available
#
# Outputs (via GITHUB_OUTPUT):
#   baseline-ref
#   baseline-name
#   feature-ref
#   feature-name
#   should-skip
#   is-stale
#   stale-age-hours
#   nightly-created
set -euxo pipefail

FORCE="${1:-false}"
REPO="${GITHUB_REPOSITORY:-tempoxyz/tempo}"
STATE_REPO="${BENCH_REPLAY_STATE_REPO:-decofe/tempo-bench-charts}"
STATE_FILE="${BENCH_REPLAY_STATE_FILE:-state/replay-nightly-last-feature-ref}"
STALE_THRESHOLD_HOURS="${BENCH_REPLAY_STALE_THRESHOLD_HOURS:-24}"

echo "Force: $FORCE"
echo "Repository: $REPO"

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

FEATURE_REF=$(echo "$LATEST" | jq -r '.headSha')
CREATED_AT=$(echo "$LATEST" | jq -r '.createdAt')
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

# --- Step 3: Read last successful feature ref from charts repo state branch ---
echo "::group::Reading persisted replay state"
LAST_FEATURE_REF=""
STATE_URL="https://raw.githubusercontent.com/${STATE_REPO}/state/${STATE_FILE}"
if RAW=$(curl -sfL -H "Authorization: token ${DEREK_TOKEN}" "$STATE_URL"); then
  LAST_FEATURE_REF=$(echo "$RAW" | tr -d '[:space:]')
  echo "Previous replay feature ref: $LAST_FEATURE_REF"
else
  echo "No persisted replay state found"
fi
echo "::endgroup::"

# --- Step 4: Determine baseline and skip logic ---
echo "::group::Resolving refs"
SHOULD_SKIP="false"
BASELINE_REF="$FEATURE_REF"

if [ "$IS_STALE" = "true" ]; then
  BASELINE_REF="${LAST_FEATURE_REF:-$FEATURE_REF}"
  echo "Stale nightly detected; workflow will fail before benchmarking"
elif [ -z "$LAST_FEATURE_REF" ]; then
  BASELINE_REF="$FEATURE_REF"
  echo "First run; benchmarking nightly against itself to establish replay state"
elif [ "$LAST_FEATURE_REF" = "$FEATURE_REF" ]; then
  BASELINE_REF="$LAST_FEATURE_REF"
  if [ "$FORCE" = "true" ] || [ "$FORCE" = "--force" ]; then
    echo "No new nightly commit, but force=true; running anyway"
  else
    SHOULD_SKIP="true"
    echo "No new nightly commit since last successful replay; skipping"
  fi
else
  BASELINE_REF="$LAST_FEATURE_REF"
  echo "New nightly commit detected"
fi

BASELINE_NAME="nightly-${BASELINE_REF:0:8}"
FEATURE_NAME="nightly-${FEATURE_REF:0:8}"

echo "Baseline: $BASELINE_REF"
echo "Feature:  $FEATURE_REF"
echo "Skip:     $SHOULD_SKIP"
echo "Stale:    $IS_STALE"
echo "::endgroup::"

# --- Step 5: Write outputs ---
{
  echo "baseline-ref=$BASELINE_REF"
  echo "baseline-name=$BASELINE_NAME"
  echo "feature-ref=$FEATURE_REF"
  echo "feature-name=$FEATURE_NAME"
  echo "should-skip=$SHOULD_SKIP"
  echo "is-stale=$IS_STALE"
  echo "stale-age-hours=$AGE_HOURS"
  echo "nightly-created=$CREATED_AT"
} >> "$GITHUB_OUTPUT"
