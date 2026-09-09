#!/usr/bin/env bash
# Read checks from the pushed commit, not a potentially stale PR head/rollup.
set -euo pipefail

head_sha="${1:?expected commit SHA}"
repository="${GITHUB_REPOSITORY:?expected GitHub repository}"
checks=$(gh api --paginate --slurp "repos/$repository/commits/$head_sha/check-runs?per_page=100")
statuses=$(gh api --paginate --slurp "repos/$repository/commits/$head_sha/status?per_page=100")

# Retain both check runs and legacy commit statuses (including external audits).
jq -n --argjson checks "$checks" --argjson statuses "$statuses" '
  [ $checks[].check_runs[] | {
      name,
      state: ((if .status == "completed" then .conclusion else .status end) | ascii_upcase)
    }
  ] + [ $statuses[].statuses[] | {name: .context, state: (.state | ascii_upcase)} ]
'
