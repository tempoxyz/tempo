#!/usr/bin/env bash
# Wait until this run's zones-artifacts job has uploaded zones-test-artifacts.
# Fails if the job finishes without it, or after 20 minutes.
set -euo pipefail

: "${GITHUB_REPOSITORY:?}" "${RUN_ID:?}" "${RUN_ATTEMPT:?}"
artifact="zones-test-artifacts"
job="Build Zones test artifacts"

for _ in $(seq 1 120); do
  if [[ -n "$(gh api "repos/$GITHUB_REPOSITORY/actions/runs/$RUN_ID/artifacts?name=$artifact" \
    --jq '.artifacts[] | select(.expired | not) | .id')" ]]; then
    echo "$artifact is available"
    exit 0
  fi
  conclusion="$(gh api "repos/$GITHUB_REPOSITORY/actions/runs/$RUN_ID/attempts/$RUN_ATTEMPT/jobs" \
    --paginate --jq ".jobs[] | select(.name == \"$job\") | .conclusion // empty")"
  if [[ -n "$conclusion" && "$conclusion" != "success" ]]; then
    echo "::error::$job finished with $conclusion without uploading $artifact"
    exit 1
  fi
  sleep 10
done

echo "::error::Timed out waiting for $artifact"
exit 1
