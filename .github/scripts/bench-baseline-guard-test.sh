#!/usr/bin/env bash
set -euo pipefail
scripts="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
scratch=$(mktemp -d)
trap 'rm -rf "$scratch"' EXIT
export GITHUB_OUTPUT="$scratch/output"
export GITHUB_REPOSITORY=owner/repo
export BENCH_GUARD_NOW=2000
export old=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
export new=bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
export GENESIS_OLD='{"config":{"t11Time":1000,"t12Time":null}}'
export GENESIS_NEW='{"config":{"t11Time":1000,"t12Time":1500,"t13Time":3000}}'
export COMPARE_STATUS=ahead

gh() {
  case "$*" in
    *"contents/"*"ref=$old"*) printf '%s\n' "$GENESIS_OLD" ;;
    *"contents/"*"ref=$new"*) printf '%s\n' "$GENESIS_NEW" ;;
    *compare/*) printf '%s\n' "$COMPARE_STATUS" ;;
    *) return 1 ;;
  esac
}
export -f gh

run() {
  : > "$GITHUB_OUTPUT"
  BASELINE_REF=$old BASELINE_NAME=nightly-old FEATURE_REF=$new FEATURE_NAME=nightly-new \
    bash "$scripts/bench-baseline-guard.sh" "$@" > /dev/null
}
expect() {
  grep -qxF "$1" "$GITHUB_OUTPUT" || { echo "expected $1 in:"; cat "$GITHUB_OUTPUT"; exit 1; }
}

# A fork the feature activated by now is missing from the baseline.
run fork-schedule genesis.json
expect "baseline-ref=$new"; expect baseline-name=nightly-new; expect rebaselined=true

# Forks scheduled in the future don't count.
GENESIS_OLD='{"config":{"t11Time":1000,"t12Time":1500}}' run fork-schedule genesis.json
expect "baseline-ref=$old"; expect rebaselined=false

# A different activation time for an active fork counts.
GENESIS_OLD='{"config":{"t11Time":1000,"t12Time":1600}}' run fork-schedule genesis.json
expect rebaselined=true

# A baseline containing the commit is kept; one without it is replaced.
run min-commit cccccccccccccccccccccccccccccccccccccccc
expect "baseline-ref=$old"; expect rebaselined=false
COMPARE_STATUS=identical run min-commit cccccccccccccccccccccccccccccccccccccccc
expect rebaselined=false
COMPARE_STATUS=diverged run min-commit cccccccccccccccccccccccccccccccccccccccc
expect "baseline-ref=$new"; expect rebaselined=true

# API failures fail the step.
if GENESIS_NEW='' run fork-schedule genesis.json 2>/dev/null; then echo "expected failure"; exit 1; fi

echo "bench-baseline-guard tests passed"
