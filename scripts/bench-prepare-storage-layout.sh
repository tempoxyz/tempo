#!/usr/bin/env bash
# Run only after stopping nodes and restoring a disposable benchmark snapshot.
# Baseline and candidate start from exactly the same logical state. Conversion is
# outside the measured interval; it preserves all key/value bytes and state roots.
set -euo pipefail
if [[ $# != 2 ]]; then
  echo "usage: $0 TEMPO_BINARY NODE_DATADIR" >&2
  exit 2
fi
tempo_binary=$1
bench_datadir=$2
[[ -f "$bench_datadir/db/database.version" ]] || { echo "missing database.version" >&2; exit 1; }
help_output=$("$tempo_binary" --help)
if [[ "$help_output" == *bench-shard-storage* ]]; then
  "$tempo_binary" bench-shard-storage --database "$bench_datadir/db"
elif [[ $(<"$bench_datadir/db/database.version") != 2 ]]; then
  echo "unsharded baseline requires a restored v2 snapshot" >&2
  exit 1
fi
