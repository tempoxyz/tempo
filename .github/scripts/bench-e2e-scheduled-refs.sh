#!/usr/bin/env bash
#
# Resolves baseline and feature refs for scheduled e2e benchmark runs.
#
# Nightly runs compare the latest successful scheduled docker.yml build against
# the last commit that completed this scheduled e2e workflow successfully.
# Release tag runs compare the pushed v*.*.* tag against the previous v*.*.* tag.
#
# Usage: bench-e2e-scheduled-refs.sh <force>
#   force - "true" to run even if no new nightly commit is available
#
# Outputs (via GITHUB_OUTPUT):
#   baseline-ref
#   baseline-name
#   feature-ref
#   feature-name
#   should-skip
#   run-type
#   actor
#   is-stale
#   stale-age-hours
#   nightly-created
set -euo pipefail

FORCE="${1:-false}"
REPO="${GITHUB_REPOSITORY:-tempoxyz/tempo}"
STATE_REPO="${BENCH_E2E_STATE_REPO:-decofe/tempo-bench-charts}"
STATE_FILE="${BENCH_E2E_STATE_FILE:-state/e2e-nightly-last-feature-ref}"
STALE_THRESHOLD_HOURS="${BENCH_E2E_STALE_THRESHOLD_HOURS:-24}"

echo "Force: $FORCE"
echo "Repository: $REPO"

short_sha() {
  printf "%.8s" "$1"
}

write_outputs() {
  {
    echo "baseline-ref=$BASELINE_REF"
    echo "baseline-name=$BASELINE_NAME"
    echo "feature-ref=$FEATURE_REF"
    echo "feature-name=$FEATURE_NAME"
    echo "should-skip=$SHOULD_SKIP"
    echo "run-type=$RUN_TYPE"
    echo "actor=$ACTOR"
    echo "is-stale=$IS_STALE"
    echo "stale-age-hours=$AGE_HOURS"
    echo "nightly-created=$CREATED_AT"
  } >> "$GITHUB_OUTPUT"
}

SHOULD_SKIP="false"
IS_STALE="false"
AGE_HOURS="0"
CREATED_AT=""

if [ "${GITHUB_REF_TYPE:-}" = "tag" ]; then
  RUN_TYPE="release"
  ACTOR="e2e-release"
  CURRENT_TAG="${GITHUB_REF_NAME:-}"

  if [ -z "$CURRENT_TAG" ]; then
    echo "::error::GITHUB_REF_NAME is not set for tag run"
    exit 1
  fi

  echo "::group::Resolving release tags"
  git fetch --tags --force --quiet --no-recurse-submodules origin

  mapfile -t TAGS < <(git tag --list "v*.*.*" --sort=-v:refname)
  FOUND="false"
  PREVIOUS_TAG=""
  for tag in "${TAGS[@]}"; do
    if [ "$FOUND" = "true" ] && [ "$tag" != "$CURRENT_TAG" ]; then
      PREVIOUS_TAG="$tag"
      break
    fi
    if [ "$tag" = "$CURRENT_TAG" ]; then
      FOUND="true"
    fi
  done

  if [ "$FOUND" != "true" ]; then
    echo "::error::Current tag $CURRENT_TAG was not found in fetched v*.*.* tags"
    exit 1
  fi

  FEATURE_REF="$(git rev-list -n 1 "$CURRENT_TAG")"
  FEATURE_NAME="$CURRENT_TAG"

  if [ -n "$PREVIOUS_TAG" ]; then
    BASELINE_REF="$(git rev-list -n 1 "$PREVIOUS_TAG")"
    BASELINE_NAME="$PREVIOUS_TAG"
  else
    BASELINE_REF="$FEATURE_REF"
    BASELINE_NAME="$CURRENT_TAG"
    echo "No previous release tag found before $CURRENT_TAG; benchmarking release against itself"
  fi

  echo "Baseline: $BASELINE_NAME ($BASELINE_REF)"
  echo "Feature:  $FEATURE_NAME ($FEATURE_REF)"
  echo "::endgroup::"

  write_outputs
  exit 0
fi

RUN_TYPE="nightly"
ACTOR="e2e-nightly"

echo "::group::Querying latest nightly docker build"
RUNS_JSON="$(gh run list \
  -R "$REPO" \
  --workflow=docker.yml \
  --event=schedule \
  --status=completed \
  --limit 10 \
  --json headSha,createdAt,conclusion)"

LATEST="$(echo "$RUNS_JSON" | jq -r '[.[] | select(.conclusion == "success")] | first // empty')"
if [ -z "$LATEST" ]; then
  echo "::error::No successful scheduled docker.yml run found in the last 10 runs"
  echo "Runs found: $RUNS_JSON"
  exit 1
fi

FEATURE_REF="$(echo "$LATEST" | jq -r '.headSha')"
CREATED_AT="$(echo "$LATEST" | jq -r '.createdAt')"
echo "Latest nightly commit: $FEATURE_REF"
echo "Built at: $CREATED_AT"
echo "::endgroup::"

echo "::group::Checking nightly staleness"
NOW_EPOCH="$(date +%s)"
CREATED_EPOCH="$(date -d "$CREATED_AT" +%s 2>/dev/null || \
  date -j -f "%Y-%m-%dT%H:%M:%SZ" "$CREATED_AT" +%s 2>/dev/null || \
  date -j -f "%Y-%m-%dT%T%z" "$CREATED_AT" +%s 2>/dev/null || \
  { echo "::error::Cannot parse date: $CREATED_AT"; exit 1; })"

AGE_SECONDS=$(( NOW_EPOCH - CREATED_EPOCH ))
AGE_HOURS=$(( AGE_SECONDS / 3600 ))

if [ "$AGE_HOURS" -gt "$STALE_THRESHOLD_HOURS" ]; then
  IS_STALE="true"
  echo "::warning::Stale nightly Docker build: ${AGE_HOURS}h old (threshold: ${STALE_THRESHOLD_HOURS}h)"
else
  echo "Nightly Docker build age: ${AGE_HOURS}h"
fi
echo "::endgroup::"

echo "::group::Reading persisted e2e state"
LAST_FEATURE_REF=""
STATE_URL="https://raw.githubusercontent.com/${STATE_REPO}/state/${STATE_FILE}"
if RAW="$(curl -sfL -H "Authorization: token ${DEREK_TOKEN:-}" "$STATE_URL")"; then
  LAST_FEATURE_REF="$(echo "$RAW" | tr -d '[:space:]')"
  echo "Previous e2e feature ref: $LAST_FEATURE_REF"
else
  echo "No persisted e2e state found"
fi
echo "::endgroup::"

echo "::group::Resolving refs"
BASELINE_REF="$FEATURE_REF"

if [ "$IS_STALE" = "true" ]; then
  BASELINE_REF="${LAST_FEATURE_REF:-$FEATURE_REF}"
  echo "Stale nightly detected; workflow will fail before benchmarking"
elif [ -z "$LAST_FEATURE_REF" ]; then
  BASELINE_REF="$FEATURE_REF"
  echo "First run; benchmarking nightly against itself to establish e2e state"
elif [ "$LAST_FEATURE_REF" = "$FEATURE_REF" ]; then
  BASELINE_REF="$LAST_FEATURE_REF"
  if [ "$FORCE" = "true" ] || [ "$FORCE" = "--force" ]; then
    echo "No new nightly commit, but force=true; running anyway"
  else
    SHOULD_SKIP="true"
    echo "No new nightly commit since last successful e2e run; skipping"
  fi
else
  BASELINE_REF="$LAST_FEATURE_REF"
  echo "New nightly commit detected"
fi

BASELINE_NAME="nightly-$(short_sha "$BASELINE_REF")"
FEATURE_NAME="nightly-$(short_sha "$FEATURE_REF")"

echo "Baseline: $BASELINE_REF"
echo "Feature:  $FEATURE_REF"
echo "Skip:     $SHOULD_SKIP"
echo "Stale:    $IS_STALE"
echo "::endgroup::"

write_outputs
