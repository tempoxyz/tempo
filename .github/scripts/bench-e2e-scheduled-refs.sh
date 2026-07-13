#!/usr/bin/env bash
#
# Resolves baseline and feature refs for scheduled e2e benchmark runs.
#
# Nightly runs compare the latest main commit against the last commit that
# completed this scheduled e2e workflow successfully.
# Release tag runs compare the pushed v*.*.* tag against the previous v*.*.* tag.
#
# Usage: bench-e2e-scheduled-refs.sh <force> [state-key]
#   force - "true" to run even if no new main commit is available
#   state-key - filesystem-safe key used to scope persisted nightly state
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
#   state-file
set -euo pipefail

FORCE="${1:-false}"
STATE_KEY="${2:-${BENCH_E2E_STATE_KEY:-${BENCH_E2E_PRESET:-default}}}"
REPO="${GITHUB_REPOSITORY:-tempoxyz/tempo}"
STATE_REPO="${BENCH_E2E_STATE_REPO:-decofe/tempo-bench-charts}"

if [[ ! "$STATE_KEY" =~ ^[A-Za-z0-9_-]+$ ]]; then
  echo "::error::Invalid benchmark state key: $STATE_KEY"
  exit 1
fi

STATE_FILE="${BENCH_E2E_STATE_FILE:-state/e2e-nightly-${STATE_KEY}-last-feature-ref}"

echo "Force: $FORCE"
echo "State key: $STATE_KEY"
echo "Repository: $REPO"
echo "State file: $STATE_FILE"

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
    echo "state-key=$STATE_KEY"
    echo "state-file=$STATE_FILE"
  } >> "$GITHUB_OUTPUT"
}

SHOULD_SKIP="false"
IS_STALE="false"
AGE_HOURS="0"
CREATED_AT=""

if [ -n "${INPUT_REF:-}" ] || [ "${GITHUB_REF_TYPE:-}" = "tag" ]; then
  RUN_TYPE="release"
  ACTOR="e2e-release"

  if [ -n "${INPUT_REF:-}" ]; then
    CURRENT_TAG="$INPUT_REF"
    echo "Using manually provided ref: $CURRENT_TAG"
  else
    CURRENT_TAG="${GITHUB_REF_NAME:-}"
  fi

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

echo "::group::Resolving latest main commit"
git fetch --force --quiet --no-recurse-submodules origin main
FEATURE_REF="$(git rev-parse origin/main)"
CREATED_AT="$(git log -1 --format=%cI "$FEATURE_REF")"
echo "Latest main commit: $FEATURE_REF"
echo "Committed at: $CREATED_AT"
echo "::endgroup::"

echo "::group::Reading persisted e2e state"
LAST_FEATURE_REF=""
STATE_URL="https://raw.githubusercontent.com/${STATE_REPO}/state/${STATE_FILE}"
if RAW="$(curl -sfL -H "Authorization: token ${DEREK_TOKEN:-}" "$STATE_URL")"; then
  LAST_FEATURE_REF="$(echo "$RAW" | tr -d '[:space:]')"
  echo "Previous e2e feature ref for $STATE_KEY: $LAST_FEATURE_REF"
else
  echo "No persisted e2e state found for $STATE_KEY"
fi
echo "::endgroup::"

echo "::group::Resolving refs"
BASELINE_REF="$FEATURE_REF"

if [ -z "$LAST_FEATURE_REF" ]; then
  BASELINE_REF="$FEATURE_REF"
  echo "First run; benchmarking main against itself to establish e2e state"
elif [ "$LAST_FEATURE_REF" = "$FEATURE_REF" ]; then
  BASELINE_REF="$LAST_FEATURE_REF"
  if [ "$FORCE" = "true" ] || [ "$FORCE" = "--force" ]; then
    echo "No new main commit, but force=true; running anyway"
  else
    SHOULD_SKIP="true"
    echo "No new main commit since last successful e2e run; skipping"
  fi
else
  BASELINE_REF="$LAST_FEATURE_REF"
  echo "New main commit detected"
fi

BASELINE_NAME="nightly-$(short_sha "$BASELINE_REF")"
FEATURE_NAME="nightly-$(short_sha "$FEATURE_REF")"

echo "Baseline: $BASELINE_REF"
echo "Feature:  $FEATURE_REF"
echo "Skip:     $SHOULD_SKIP"
echo "Stale:    $IS_STALE"
echo "::endgroup::"

write_outputs
