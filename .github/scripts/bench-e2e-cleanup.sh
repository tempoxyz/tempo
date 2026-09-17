#!/usr/bin/env bash
# Run after artifact uploads and reporting, including on failure/cancellation.
set -euo pipefail

workspace=$(realpath -e -- "${GITHUB_WORKSPACE:?}")
runner_temp=$(realpath -e -- "${RUNNER_TEMP:?}")
if [[ "$workspace" == / || ! -d "$workspace/.git" ]]; then
  echo "::error::Refusing cleanup outside the benchmark checkout"
  exit 1
fi

bench_tmp=${BENCH_JOB_TMPDIR:-}
if [[ -n "$bench_tmp" ]]; then
  # Only accept the direct child created by this job's mktemp step, never /tmp.
  if [[ "$bench_tmp" != "$runner_temp"/tempo-bench-e2e.* ||
        "${bench_tmp#"$runner_temp"/}" == */* ||
        "$(realpath -m -- "$bench_tmp")" != "$bench_tmp" ]]; then
    echo "::error::Refusing unexpected benchmark temporary directory: $bench_tmp"
    exit 1
  fi
fi

# Validators/profilers run outside the runner's process tree in these scopes.
# Stop waits for them to exit, including after a failed or cancelled benchmark.
sudo systemctl stop 'tempo-e2e-*.scope'

paths=(.bench-worktrees .bench-tmp target localnet valscope/target tempo-bench-valscope-static)
# Keep results locally when upload failed or was skipped (e.g. cancellation).
if [[ "${BENCH_RESULTS_UPLOADED:-}" == success ]]; then
  paths+=(bench-results)
fi

targets=()
for path in "${paths[@]}"; do
  target="$workspace/$path"
  if [[ "$(realpath -m -- "$target")" != "$target" ]] || mountpoint -q -- "$target"; then
    echo "::error::Refusing symlinked or mounted cleanup target: $target"
    exit 1
  fi
  targets+=("$target")
done
if [[ -n "$bench_tmp" ]]; then
  if mountpoint -q -- "$bench_tmp"; then
    echo "::error::Refusing mounted temporary directory: $bench_tmp"
    exit 1
  fi
  targets+=("$bench_tmp")
fi

echo "Removing benchmark build outputs and temporary files:"
printf '  %s\n' "${targets[@]}"
sudo rm -rf --one-file-system -- "${targets[@]}"
if [[ -n "$bench_tmp" ]]; then
  # Post-job actions still inherit TMPDIR. Leave an empty, runner-owned directory.
  mkdir -m 700 -- "$bench_tmp"
fi
git -C "$workspace" worktree prune
df -h "$workspace"
