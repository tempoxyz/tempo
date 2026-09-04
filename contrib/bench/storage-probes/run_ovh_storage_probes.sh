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

dm_target=/reth-bench-a
mountpoint -q -- "$dm_target" || {
    echo '/reth-bench-a is not already mounted; no mount or snapshot change will be attempted.' >&2
    exit 1
}
for target in "$dm_target" "$RUNNER_TEMP"; do
    test "$(findmnt -n -o FSTYPE --target "$target")" = ext4 || {
        printf 'Expected an existing ext4 target: %s\n' "$target" >&2
        exit 1
    }
done
sudo -n dmsetup table bench_era_a > "$results_dir/bench-era-a-table.txt"
awk '$3 == "era" { found=1 } END { exit !found }' "$results_dir/bench-era-a-table.txt" || {
    echo 'bench_era_a is not an existing dm-era mapping.' >&2
    exit 1
}
findmnt --json --target "$dm_target" > "$results_dir/dm-era-target-mount.json"
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

sudo -n bash "$probe_source_dir/run_storage_probe.sh" \
    --target "$dm_target" --out "$results_dir/dm-era-a" \
    --label ovh-dm-era-a --size-gib 8 --duration 20
sudo -n bash "$probe_source_dir/run_storage_probe.sh" \
    --target "$RUNNER_TEMP" --out "$results_dir/plain-ext4" \
    --label ovh-plain-ext4 --size-gib 8 --duration 20
