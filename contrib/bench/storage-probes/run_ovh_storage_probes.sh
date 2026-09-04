#!/usr/bin/env bash
set -euo pipefail

# This integration only writes probe results and disposable files created by the
# common probe. It never mounts, restores, promotes, or edits a benchmark snapshot.
probe_source_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
: "${RUNNER_TEMP:?GitHub Actions RUNNER_TEMP is required}"
: "${RUNNER_NAME:?GitHub Actions RUNNER_NAME is required}"
: "${GITHUB_RUN_ID:?GitHub Actions GITHUB_RUN_ID is required}"
: "${GITHUB_RUN_ATTEMPT:?GitHub Actions GITHUB_RUN_ATTEMPT is required}"
results_dir="${RUNNER_TEMP}/tempo-storage-results-${GITHUB_RUN_ID}-${GITHUB_RUN_ATTEMPT}"
mkdir -p -- "$results_dir"
printf 'runner=%s\nrun_id=%s\nattempt=%s\n' "$RUNNER_NAME" "$GITHUB_RUN_ID" "$GITHUB_RUN_ATTEMPT" > "$results_dir/runner.txt"

# A runner executes one Actions job at a time. Also reject orphaned workloads;
# this probe must not stop or change any unrelated process.
if pgrep -x 'tempo|txgen-tempo|txgen|bench|reth-bench|fio' > "$results_dir/conflicting-process-ids.txt"; then
    echo 'A validator, load generator, or disk benchmark is already running; refusing to probe.' >&2
    exit 1
fi

for executable in python3 cc timeout findmnt mountpoint stat; do
    command -v "$executable" >/dev/null || {
        printf 'Required executable is missing: %s\n' "$executable" >&2
        exit 1
    }
done
missing_packages=()
if ! command -v fio >/dev/null; then
    missing_packages+=(fio)
fi
if ! command -v nvme >/dev/null; then
    missing_packages+=(nvme-cli)
fi
if ((${#missing_packages[@]})); then
    # Neither package installs a sampling daemon. Controller commands remain
    # read-only; the probe never changes write-cache features or firmware.
    sudo -n env DEBIAN_FRONTEND=noninteractive apt-get update
    sudo -n env DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends --no-upgrade "${missing_packages[@]}"
fi
fio --version > "$results_dir/fio-version.txt"

test "$(findmnt -n -o FSTYPE --target "$RUNNER_TEMP")" = ext4 || {
    printf 'Expected an existing ext4 target: %s\n' "$RUNNER_TEMP" >&2
    exit 1
}
dm_target=""
dm_role=""
for candidate_role in a b; do
    candidate="/reth-bench-$candidate_role"
    if ! mountpoint -q -- "$candidate"; then
        printf '%s is not already mounted\n' "$candidate" >> "$results_dir/era-selection.txt"
        continue
    fi
    if [[ "$(findmnt -n -o FSTYPE --target "$candidate")" != ext4 ]]; then
        printf '%s is not ext4\n' "$candidate" >> "$results_dir/era-selection.txt"
        continue
    fi
    mapping_file="$results_dir/bench-era-$candidate_role-table.txt"
    if ! sudo -n dmsetup table "bench_era_$candidate_role" > "$mapping_file" ||
        ! awk '$3 == "era" { found=1 } END { exit !found }' "$mapping_file"; then
        printf '%s has no existing era mapping\n' "$candidate" >> "$results_dir/era-selection.txt"
        continue
    fi
    dm_target="$candidate"
    dm_role="$candidate_role"
    printf 'Selected %s\n' "$dm_target" >> "$results_dir/era-selection.txt"
    findmnt --json --target "$dm_target" > "$results_dir/dm-era-target-mount.json"
    break
done
if [[ -z "$dm_target" ]]; then
    printf '%s\n' 'No existing ext4 dm-era benchmark mount is available; era probe skipped without changing mounts or snapshots.' > "$results_dir/era-skip.txt"
    cat "$results_dir/era-skip.txt"
fi
findmnt --json --target "$RUNNER_TEMP" > "$results_dir/plain-target-mount.json"
printf '%s\n' \
    'The plain ext4 target and the dm-era target may have different physical backing devices.' \
    'This is a measured comparison of existing mounts, not an isolated dm-era overhead experiment.' \
    > "$results_dir/comparison-limits.txt"

# Keep files uploadable even when a root-owned probe reports an error.
caller_uid=$(id -u)
caller_gid=$(id -g)
restore_result_owner() {
    sudo -n chown -R -- "$caller_uid:$caller_gid" "$results_dir" || true
}
trap restore_result_owner EXIT

if [[ -n "$dm_target" ]]; then
    sudo -n bash "$probe_source_dir/run_storage_probe.sh" \
        --target "$dm_target" --out "$results_dir/dm-era-$dm_role" \
        --label "ovh-dm-era-$dm_role" --size-gib 8 --duration 20
fi
sudo -n bash "$probe_source_dir/run_storage_probe.sh" \
    --target "$RUNNER_TEMP" --out "$results_dir/plain-ext4" \
    --label ovh-plain-ext4 --size-gib 8 --duration 20
