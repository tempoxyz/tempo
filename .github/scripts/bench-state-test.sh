#!/usr/bin/env bash
set -euo pipefail
scripts="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
scratch=$(mktemp -d)
trap 'rm -rf "$scratch"' EXIT
export STATE_TEST_DIR="$scratch"
export GITHUB_OUTPUT="$scratch/output"
export GITHUB_REPOSITORY=owner/repo
export GITHUB_REF_NAME=main
export GITHUB_REF_TYPE=branch
unset INPUT_REF BENCH_E2E_PRESET BENCH_E2E_STATE_KEY
export STATE_TEST_WORKFLOW=.github/workflows/bench-replay-scheduled.yml
export STATE_TEST_VALUE=""
export STATE_TEST_FAILURE=""
export GH_TOKEN=workflow-test-token
feature=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
previous=bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
export STATE_TEST_DATE
STATE_TEST_DATE=$(date -u +%Y-%m-%dT%H:%M:%SZ)

gh() {
  case "$1" in
    api)
      if [[ "$2" == *'/git/'* ]]; then
        if [[ "$*" == *'.object.type'* ]]; then printf 'commit\n'; else printf '%s\n' bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb; fi
        return
      fi
      [[ "$GH_TOKEN" == workflow-test-token ]] || return 1
      if [[ "$*" == *'--paginate --slurp'* ]]; then
        [[ "$STATE_TEST_FAILURE" != list ]] || return 1
        if [[ -n "${STATE_TEST_ARTIFACTS:-}" ]]; then
          printf '%s\n' "$STATE_TEST_ARTIFACTS"
        elif [[ -z "$STATE_TEST_VALUE" ]]; then
          printf '[{"artifacts":[]}]\n'
        else
          local name="${!#}"
          name="${name#*name=}"
          name="${name%%&*}"
          jq -nc --arg name "$name" '[{artifacts:[{id:10,name:$name,expired:false,
            workflow_run:{id:100,head_branch:"main",repository_id:1,head_repository_id:1}}]}]'
        fi
      elif [[ "$2" == */runs/* ]]; then
        [[ "$STATE_TEST_FAILURE" != run ]] || return 1
        jq -nc --arg conclusion "${STATE_TEST_CONCLUSION:-success}" \
          --arg path "${STATE_TEST_PATH:-$STATE_TEST_WORKFLOW}" \
          --arg event "${STATE_TEST_EVENT:-schedule}" --arg status "${STATE_TEST_STATUS:-completed}" \
          '{path:$path,head_branch:"main",status:$status,conclusion:$conclusion,event:$event}'
      elif [[ "$2" == */zip ]]; then
        [[ "$STATE_TEST_FAILURE" != download ]] || return 1
        printf '%s\n' "$2" >> "$STATE_TEST_DIR/downloads"
        if [[ "$STATE_TEST_FAILURE" == archive ]]; then printf 'invalid zip'; return; fi
        printf '%s\n' "$STATE_TEST_VALUE" > "$STATE_TEST_DIR/feature-ref"
        (cd "$STATE_TEST_DIR" && zip -q - feature-ref)
      else
        return 1
      fi
      ;;
    release) printf '{"tagName":"v1.0.0"}\n' ;;
    run)
      if [[ "$*" == *'--status=in_progress'* ]]; then
        printf '0\n'
      else
        printf '[{"headSha":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","createdAt":"%s","conclusion":"success"}]\n' "$STATE_TEST_DATE"
      fi
      ;;
    *) return 1 ;;
  esac
}
git() {
  case "$*" in
    fetch*) ;;
    'rev-parse origin/main') printf '%s\n' aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa ;;
    'tag --list v*.*.* --sort=-v:refname') printf 'v2.0.0\nv1.0.0\n' ;;
    'rev-list -n 1 v2.0.0') printf '%s\n' aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa ;;
    'rev-list -n 1 v1.0.0') printf '%s\n' bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb ;;
    'rev-parse origin/main~1') printf '%s\n' bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb ;;
    'log -1 --format=%cI '* ) printf '%s\n' "$STATE_TEST_DATE" ;;
    *) return 1 ;;
  esac
}
export -f gh git

[[ -z "$(bash "$scripts/bench-state.sh" owner/repo replay mainnet)" ]]
export STATE_TEST_VALUE="$previous"
[[ "$(bash "$scripts/bench-state.sh" owner/repo replay mainnet)" == "$previous" ]]
export STATE_TEST_VALUE=invalid
if bash "$scripts/bench-state.sh" owner/repo replay mainnet 2>/dev/null; then exit 1; fi
if bash "$scripts/bench-state.sh" owner/repo invalid mainnet 2>/dev/null; then exit 1; fi
export STATE_TEST_VALUE="$previous"
for failure in list run download archive; do
  export STATE_TEST_FAILURE="$failure"
  if bash "$scripts/bench-state.sh" owner/repo replay mainnet 2>/dev/null; then exit 1; fi
done
export STATE_TEST_FAILURE=""
echo 'PASS: missing state, real ZIP restore, SHA validation, and API/archive failures'

# Newer unusable artifacts must not hide the newest usable artifact, even when
# it is on another page. The workflow SHA is deliberately not the feature SHA.
export STATE_TEST_ARTIFACTS
STATE_TEST_ARTIFACTS=$(jq -nc '
  def artifact($id): {id:$id,name:"bench-state-replay-mainnet",expired:false,
    workflow_run:{id:100,head_branch:"main",head_sha:"cccccccccccccccccccccccccccccccccccccccc",
      repository_id:1,head_repository_id:1}};
  [{artifacts:[
    (artifact(90) | .expired=true),
    (artifact(80) | .workflow_run.head_branch="test"),
    (artifact(70) | .workflow_run.head_repository_id=2),
    (artifact(60) | .name="bench-state-replay-testnet")]},
   {artifacts:[artifact(10),artifact(20)]}]')
: > "$scratch/downloads"
[[ "$(bash "$scripts/bench-state.sh" owner/repo replay mainnet)" == "$previous" ]]
[[ "$(cat "$scratch/downloads")" == repos/owner/repo/actions/artifacts/20/zip ]]
export GITHUB_REF_NAME=other-branch
[[ -z "$(bash "$scripts/bench-state.sh" owner/repo replay mainnet)" ]]
export GITHUB_REF_NAME=main
export STATE_TEST_ARTIFACTS='[{"artifacts":[]}]'
[[ -z "$(bash "$scripts/bench-state.sh" owner/repo replay mainnet)" ]]
unset STATE_TEST_ARTIFACTS
for conclusion in failure cancelled skipped; do
  export STATE_TEST_CONCLUSION="$conclusion"
  [[ -z "$(bash "$scripts/bench-state.sh" owner/repo replay mainnet)" ]]
done
unset STATE_TEST_CONCLUSION
export STATE_TEST_STATUS=in_progress
[[ -z "$(bash "$scripts/bench-state.sh" owner/repo replay mainnet)" ]]
unset STATE_TEST_STATUS
export STATE_TEST_PATH=.github/workflows/other.yml
[[ -z "$(bash "$scripts/bench-state.sh" owner/repo replay mainnet)" ]]
unset STATE_TEST_PATH
export STATE_TEST_EVENT=pull_request
[[ -z "$(bash "$scripts/bench-state.sh" owner/repo replay mainnet)" ]]
unset STATE_TEST_EVENT
echo 'PASS: pagination, newest state, expiry, branch/mode/fork/workflow/event isolation, and run outcomes'

for series in replay e2e; do
  export STATE_TEST_WORKFLOW=".github/workflows/bench-$series-scheduled.yml"
  if [[ "$series" == replay ]]; then keys=(mainnet testnet); else keys=(default tip20-existing-any); fi
  for key in "${keys[@]}"; do
    export BENCH_REPLAY_CHAIN="$key"
    resolver="$scripts/bench-$series-scheduled-refs.sh"
    for value in "" "$feature" "$previous"; do
      export STATE_TEST_VALUE="$value"
      : > "$GITHUB_OUTPUT"
      bash "$resolver" false "$key" > "$scratch/log" 2>&1
      if [[ "$value" == "$feature" ]]; then
        grep -q '^should-skip=true$' "$GITHUB_OUTPUT"
      else
        grep -q '^should-skip=false$' "$GITHUB_OUTPUT"
      fi
      baseline="${value:-$feature}"
      grep -q "^baseline-ref=$baseline$" "$GITHUB_OUTPUT"
    done
    export STATE_TEST_VALUE="$feature"
    : > "$GITHUB_OUTPUT"
    bash "$resolver" true "$key" > "$scratch/log" 2>&1
    grep -q '^should-skip=false$' "$GITHUB_OUTPUT"
    export STATE_TEST_FAILURE=list
    if bash "$resolver" false "$key" > "$scratch/log" 2>&1; then exit 1; fi
    export STATE_TEST_FAILURE=""
    echo "PASS: $series $key first run, unchanged/changed commit, force, and API failure"
  done
done

# Release comparisons must never read nightly state, whether triggered by a tag
# or a manual release ref. A state API failure must not affect either path.
export STATE_TEST_FAILURE=list
for release_trigger in tag manual; do
  if [[ "$release_trigger" == tag ]]; then
    export GITHUB_REF_TYPE=tag GITHUB_REF_NAME=v2.0.0
    unset INPUT_REF
  else
    export GITHUB_REF_TYPE=branch GITHUB_REF_NAME=main INPUT_REF=v2.0.0
  fi
  : > "$GITHUB_OUTPUT"
  bash "$scripts/bench-e2e-scheduled-refs.sh" false default > "$scratch/log" 2>&1
  grep -q '^run-type=release$' "$GITHUB_OUTPUT"
  grep -q "^baseline-ref=$previous$" "$GITHUB_OUTPUT"
  grep -q "^feature-ref=$feature$" "$GITHUB_OUTPUT"
done
echo 'PASS: tag/manual releases bypass nightly state'
