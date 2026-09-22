#!/usr/bin/env bash
# Owns only .bench-sharded-storage inside a disposable tempo_e2e_* datadir.
# Prepare before promoting a pristine snapshot; activate only after restoring it.
set -euo pipefail
[[ $# == 4 ]] || { echo "usage: $0 prepare|activate TEMPO_BINARY NODE_DATADIR CACHE_KEY" >&2; exit 2; }
mode=$1
tempo_binary=$2
bench_datadir=$(realpath -e -- "$3")
cache_key=$4
case "$mode" in prepare|activate) ;; *) echo "invalid cache mode" >&2; exit 2;; esac
[[ ${bench_datadir##*/} == tempo_e2e_* ]] || { echo "cache requires a disposable tempo_e2e_* datadir" >&2; exit 1; }
[[ -n "$cache_key" && -d "$bench_datadir/db" && ! -L "$bench_datadir/db" ]] || exit 1
[[ $(<"$bench_datadir/db/database.version") == 2 ]] || { echo "cache requires the untouched v2 baseline" >&2; exit 1; }
cache="$bench_datadir/.bench-sharded-storage"
owner=tempo-bench-shard-cache-v1
if [[ -e "$cache" || -L "$cache" ]]; then
  [[ ! -L "$cache" && -f "$cache/owner" && $(<"$cache/owner") == "$owner" ]] || {
    echo "refusing to replace an unowned layout cache" >&2; exit 1;
  }
fi

if [[ "$mode" == prepare ]]; then
  # This is an owned disposable cache, never the source database or datadir.
  if [[ -d "$cache" ]]; then rm -rf -- "$cache"; fi
  source_bytes=$(du -s --block-size=1 "$bench_datadir/db" | awk '{print $1}')
  available_bytes=$(df --output=avail --block-size=1 "$bench_datadir" | tail -1 | tr -d ' ')
  required_bytes=$((source_bytes * 2 + 67108864))
  (( available_bytes >= required_bytes )) || {
    echo "insufficient space for an independent converted snapshot: need $required_bytes, available $available_bytes" >&2
    exit 1
  }
  mkdir -- "$cache"
  printf '%s\n' "$owner" > "$cache/owner"
  cp -a --reflink=auto -- "$bench_datadir/db" "$cache/db"
  bash "$(dirname -- "${BASH_SOURCE[0]}")/bench-prepare-storage-layout.sh" "$tempo_binary" "$cache"
  [[ $(<"$cache/db/database.version") == 3 ]] || { echo "cache conversion did not produce schema v3" >&2; exit 1; }
  printf '%s\n' "$cache_key" > "$cache/key"
  echo "Prepared pristine sharded cache for $bench_datadir; baseline db remains v2"
else
  [[ -f "$cache/key" && $(<"$cache/key") == "$cache_key" && -d "$cache/db" && ! -L "$cache/db" ]] || {
    echo "missing or mismatched pristine layout cache" >&2; exit 1;
  }
  [[ $(<"$cache/db/database.version") == 3 ]] || exit 1
  source_backup="$bench_datadir/.bench-unsharded-source"
  [[ ! -e "$source_backup" && ! -L "$source_backup" ]] || { echo "datadir was not freshly restored" >&2; exit 1; }
  mv -T -- "$bench_datadir/db" "$source_backup"
  if ! mv -T -- "$cache/db" "$bench_datadir/db"; then
    mv -T -- "$source_backup" "$bench_datadir/db"
    exit 1
  fi
  echo "Activated pristine sharded database for $bench_datadir"
fi
