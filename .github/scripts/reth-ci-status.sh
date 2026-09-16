#!/usr/bin/env bash
# Read checks for an immutable commit, including legacy external status contexts.
set -euo pipefail

sha=${1:?commit SHA required}
repo=${GITHUB_REPOSITORY:?repository required}

checks=$(gh api --paginate --slurp "repos/$repo/commits/$sha/check-runs?per_page=100&filter=latest")
statuses=$(gh api --paginate --slurp "repos/$repo/commits/$sha/statuses?per_page=100")

jq -s '
  .[0] as $checks | .[1] as $statuses |
  [$checks[].check_runs[] | {
    name,
    state: (if .status != "completed" then "PENDING"
            elif (.conclusion == "success" or .conclusion == "neutral" or .conclusion == "skipped") then "SUCCESS"
            else "FAILURE" end)
  }] +
  ([$statuses[][]] | group_by(.context) | map(max_by(.id)) | map({
    name: .context,
    state: (.state | ascii_upcase)
  }))
' <(printf '%s\n' "$checks") <(printf '%s\n' "$statuses")
