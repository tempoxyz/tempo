#!/usr/bin/env bash
# Tag builds promote a completed preparation for the exact commit, when available.
set -euo pipefail
if [[ -n "${PREPARED_RUN_ID:-}" ]]; then
  bash scripts/validate-prepared-run.sh
  printf 'prepared_run_id=%s\n' "$PREPARED_RUN_ID" >> "$GITHUB_OUTPUT"
  exit 0
fi
[[ "${AUTO_REUSE:-false}" == true ]] || exit 0
workflow="${WORKFLOW_PATH##*/}"
runs="$(gh api --method GET "repos/$GITHUB_REPOSITORY/actions/workflows/$workflow/runs" \
  -f head_sha="$SOURCE_SHA" -f status=success -f per_page=20)"
while read -r run_id; do
  directory="$(mktemp -d)"
  if [[ "$workflow" == release.yml ]]; then
    # Only complete dry runs for this exact release version/profile qualify.
    if ! gh run download "$run_id" --repo "$GITHUB_REPOSITORY" \
      --name release-preparation --dir "$directory"; then
      rm -rf "$directory"
      continue
    fi
    if ! jq -e --arg sha "$SOURCE_SHA" --arg version "$VERSION" --arg profile "$MACOS_PROFILE" \
      '.sha == $sha and .version == $version and .macos_profile == $profile and .dry_run == true' \
      "$directory/manifest.json" >/dev/null; then
      rm -rf "$directory"
      continue
    fi
  else
    # Promotion-only runs have no candidates of their own. Skip those and
    # preparations whose short-lived archives have already expired.
    gh api --paginate "repos/$GITHUB_REPOSITORY/actions/runs/$run_id/artifacts?per_page=100" \
      --jq '.artifacts[] | select(.expired == false) | .name' > "$directory/artifacts"
    if [[ "$(awk '/^docker-(candidate|clean|clean-devnet)-(amd64|arm64)-[0-9]+$/ {n++} END {print n+0}' "$directory/artifacts")" -lt 6 ]]; then
      rm -rf "$directory"
      continue
    fi
  fi
  rm -rf "$directory"
  PREPARED_RUN_ID="$run_id" bash scripts/validate-prepared-run.sh
  printf 'prepared_run_id=%s\n' "$run_id" >> "$GITHUB_OUTPUT"
  echo "Promoting prepared artifacts from run $run_id for $SOURCE_SHA"
  exit 0
done < <(jq -r --arg current "$GITHUB_RUN_ID" \
  '.workflow_runs[] | select((.id | tostring) != $current) | .id' <<< "$runs")
echo 'No completed preparation found; building and independently verifying from source.'
