#!/usr/bin/env bash
# Read only checks attached to the pushed revision, including external commit statuses.
set -euo pipefail

REPO=${1:?repository required}
SHA=${2:?commit SHA required}
DATA_DIR=$(mktemp -d)
trap 'rm -rf "$DATA_DIR"' EXIT
gh api --paginate --slurp "repos/$REPO/commits/$SHA/check-runs?per_page=100" > "$DATA_DIR/checks.json"
gh api --paginate --slurp "repos/$REPO/commits/$SHA/statuses?per_page=100" > "$DATA_DIR/statuses.json"

jq -n --slurpfile checks "$DATA_DIR/checks.json" --slurpfile statuses "$DATA_DIR/statuses.json" '
  # Prefer the newest attempt for each check/context, including across pages.
  ([$checks[0][].check_runs[]] | group_by(.name) | map(max_by(.id))
    | map({name, state: (if .status != "completed" then "PENDING"
        elif .conclusion == "success" or .conclusion == "neutral" or .conclusion == "skipped" then "SUCCESS"
        else "FAILURE" end)})) as $runs
  | ([$statuses[0][][]] | group_by(.context) | map(max_by(.id))
    | map({name: .context, state: (.state | ascii_upcase)})) as $contexts
  | ($runs + $contexts) as $all
  # An empty/partial response must not pass before the required gates register.
  | ["lint success", "specs success", "test success", "Tempo Network E2E"] as $required
  | ($all + [($required - [$all[].name])[] | {name: ., state: "PENDING"}])
  | map(. + {external: (.name == "Tempo Network E2E" or (.name | startswith("Workflows /")))})
'
