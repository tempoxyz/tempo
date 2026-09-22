#!/usr/bin/env bash
set -euo pipefail
# Re-enter this script as a tiny fake Tempo binary when the helper probes it.
if [[ ${1:-} == --help ]]; then
  echo 'bench-shard-storage'
  exit 0
elif [[ ${1:-} == bench-shard-storage ]]; then
  [[ $2 == --database ]]
  [[ ${TEMPO_BENCH_TEST_FAIL:-0} == 0 ]] || exit 1
  printf '3' > "$3/database.version"
  printf 'converted' > "$3/shard.data"
  printf 'conversion\n' >> "$TEMPO_BENCH_TEST_CALLS"
  exit 0
fi

test_root=$(mktemp -d)
trap 'rm -rf -- "$test_root"' EXIT
script_path=$(realpath -- "${BASH_SOURCE[0]}")
repo_root=$(cd -- "$(dirname -- "$script_path")/../.." && pwd)
helper="$repo_root/scripts/bench-cache-storage-layout.sh"
datadir="$test_root/tempo_e2e_fixture"
export TEMPO_BENCH_TEST_CALLS="$test_root/calls"
mkdir -p "$datadir/db"
printf '2' > "$datadir/db/database.version"
printf 'original-data' > "$datadir/db/data"
bash "$helper" prepare "$script_path" "$datadir" job-key
[[ $(<"$datadir/db/database.version") == 2 ]]
[[ $(<"$datadir/db/data") == original-data ]]
[[ $(<"$datadir/.bench-sharded-storage/db/database.version") == 3 ]]
cp -a "$datadir" "$test_root/virgin"

if bash "$helper" activate "$script_path" "$datadir" wrong-key; then exit 1; fi
[[ $(<"$datadir/db/database.version") == 2 ]]
bash "$helper" activate "$script_path" "$datadir" job-key
[[ $(<"$datadir/db/database.version") == 3 ]]
[[ $(<"$datadir/.bench-unsharded-source/database.version") == 2 ]]
printf 'measured-workload' > "$datadir/db/data"
if bash "$helper" activate "$script_path" "$datadir" job-key; then exit 1; fi

# Simulate restoring the same virgin snapshot for the next baseline and feature.
rm -rf -- "$datadir"
cp -a "$test_root/virgin" "$datadir"
[[ $(<"$datadir/db/database.version") == 2 ]]
[[ $(<"$datadir/.bench-sharded-storage/db/data") == original-data ]]
bash "$helper" activate "$script_path" "$datadir" job-key
[[ $(wc -l < "$TEMPO_BENCH_TEST_CALLS") == 1 ]]
[[ $(<"$datadir/db/data") == original-data ]]

rm -rf -- "$datadir"
cp -a "$test_root/virgin" "$datadir"
printf 'not-owned' > "$datadir/.bench-sharded-storage/owner"
if bash "$helper" prepare "$script_path" "$datadir" next-key; then exit 1; fi
[[ $(<"$datadir/.bench-sharded-storage/owner") == not-owned ]]

rm -rf -- "$datadir"
cp -a "$test_root/virgin" "$datadir"
if TEMPO_BENCH_TEST_FAIL=1 bash "$helper" prepare "$script_path" "$datadir" next-key; then exit 1; fi
[[ $(<"$datadir/db/database.version") == 2 ]]
[[ $(<"$datadir/db/data") == original-data ]]
if bash "$helper" activate "$script_path" "$datadir" next-key; then exit 1; fi
echo 'Storage layout cache tests passed'
