#!/usr/bin/env bash
# Accept immutable artifacts only from a successful run of this workflow/commit.
set -euo pipefail
: "${PREPARED_RUN_ID:?PREPARED_RUN_ID is required}"
: "${SOURCE_SHA:?SOURCE_SHA is required}"
: "${WORKFLOW_PATH:?WORKFLOW_PATH is required}"
: "${GITHUB_REPOSITORY:?GITHUB_REPOSITORY is required}"
: "${GITHUB_OUTPUT:?GITHUB_OUTPUT is required}"
[[ "$PREPARED_RUN_ID" =~ ^[1-9][0-9]*$ ]]
[[ "$SOURCE_SHA" =~ ^[0-9a-f]{40}$ ]]
[[ "$PREPARED_RUN_ID" != "${GITHUB_RUN_ID:-}" ]]
run="$(gh api "repos/$GITHUB_REPOSITORY/actions/runs/$PREPARED_RUN_ID")"
jq -e --arg sha "$SOURCE_SHA" --arg workflow "$WORKFLOW_PATH" \
  --arg repository "$GITHUB_REPOSITORY" '
    .status == "completed" and .conclusion == "success" and
    .head_sha == $sha and .path == $workflow and
    .head_repository.full_name == $repository and
    (.event == "push" or .event == "workflow_dispatch") and
    (.run_attempt | type == "number" and . >= 1)
  ' <<< "$run" >/dev/null
printf 'artifact_run_id=%s\nartifact_attempt=%s\n' \
  "$PREPARED_RUN_ID" "$(jq -r .run_attempt <<< "$run")" >> "$GITHUB_OUTPUT"
