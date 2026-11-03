#!/usr/bin/env bash
# Re-baselines a scheduled benchmark whose stored baseline can no longer run.
#
# Nightly state only advances when a run passes, so a baseline that cannot run
# against today's chain or harness fails every night and never moves. This
# swaps such a baseline for the feature, so the run passes and stores a new one.
#
# Usage:
#   bench-baseline-guard.sh fork-schedule <genesis-path>
#     The baseline's genesis must activate every Tempo fork the feature's
#     genesis has activated by now, at the same time. Otherwise a replay
#     baseline rejects the chain's blocks after that fork.
#   bench-baseline-guard.sh min-commit <sha>
#     The baseline must contain <sha>, a harness fix it depends on.
#
# Env: BASELINE_REF, BASELINE_NAME, FEATURE_REF, FEATURE_NAME, GITHUB_REPOSITORY, GH_TOKEN
# Outputs (via GITHUB_OUTPUT): baseline-ref, baseline-name, rebaselined
set -euo pipefail

mode=${1:?expected fork-schedule or min-commit}
arg=${2:?expected a genesis path or commit}
repo=${GITHUB_REPOSITORY:-tempoxyz/tempo}
baseline=${BASELINE_REF:?BASELINE_REF required}
feature=${FEATURE_REF:?FEATURE_REF required}
baseline_name=${BASELINE_NAME:-$baseline}
reason=""

# Prints the Tempo fork activations (tNTime=timestamp) of the genesis at a ref.
genesis_forks() {
  gh api -H 'Accept: application/vnd.github.raw+json' "repos/$repo/contents/$arg?ref=$1" \
    | jq -r '.config | to_entries[] | select(.key | test("^t[0-9]+[a-z]*Time$")) | "\(.key)=\(.value)"'
}

if [[ -n "$baseline" && "$baseline" != "$feature" ]]; then
  case "$mode" in
    fork-schedule)
      now=${BENCH_GUARD_NOW:-$(date +%s)}
      feature_forks=$(genesis_forks "$feature")
      baseline_forks=$(genesis_forks "$baseline")
      [[ -n "$feature_forks" ]] || { echo "No Tempo forks in $arg at $feature" >&2; exit 1; }
      while IFS='=' read -r key value; do
        [[ "$value" =~ ^[0-9]+$ ]] && (( value <= now )) || continue
        if ! grep -qxF "$key=$value" <<<"$baseline_forks"; then
          reason="its $arg lacks $key=$value, which is active now"
          break
        fi
      done <<<"$feature_forks"
      ;;
    min-commit)
      status=$(gh api "repos/$repo/compare/$arg...$baseline" --jq .status)
      case "$status" in
        ahead|identical) ;;
        *) reason="it does not contain $arg" ;;
      esac
      ;;
    *)
      echo "Unknown guard mode: $mode" >&2
      exit 1
      ;;
  esac
fi

rebaselined=false
if [[ -n "$reason" ]]; then
  echo "::warning::Baseline ${baseline:0:8} cannot run: $reason. Benchmarking ${FEATURE_NAME:-$feature} against itself to store a new baseline."
  baseline=$feature
  baseline_name=${FEATURE_NAME:-$feature}
  rebaselined=true
fi
{
  echo "baseline-ref=$baseline"
  echo "baseline-name=$baseline_name"
  echo "rebaselined=$rebaselined"
} >> "$GITHUB_OUTPUT"
