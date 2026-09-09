#!/usr/bin/env bash
# Prepare stopped block-zero Tempo datadirs without changing the source snapshots.
set -euo pipefail

usage() {
    cat <<'HELP'
Usage: prepare-account-ext-snapshots.sh OUTPUT_ROOT [SOURCE_ROOT] [TEMPO_BIN]

Copies SOURCE_ROOT/tempo-{a,b} (default: /schelk), adds a deterministic
32-byte value (33 bytes with RLP encoding) to every account extension, rebuilds
the account trie, and writes matching genesis files. Existing output directories
are never replaced.

Without TEMPO_BIN, builds this branch with --profile profiling --features
account-ext. CARGO_TARGET_DIR and CARGO_BUILD_JOBS can control the build.

Source nodes must be stopped. Choose OUTPUT_ROOT outside /schelk to retain
snapshots across schelk recover. This script never recovers or promotes schelk.

Each completed directory contains .bench-meta/genesis-account-ext.json,
account-ext-preparation.log, and account-ext-manifest.json. Restore the whole
directory for a benchmark and pass that genesis file with --chain.
HELP
}

if [[ ${1:-} == --help || ${1:-} == -h ]]; then
    usage
    exit 0
fi
if (( $# < 1 || $# > 3 )); then usage >&2; exit 2; fi

for tool in realpath fuser du df cp python3 sha256sum; do
    command -v "$tool" >/dev/null || { echo "Missing tool: $tool" >&2; exit 1; }
done

repo=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
output=$(realpath -m -- "$1")
source_root=$(realpath -- "${2:-/schelk}")
mkdir -p -- "$output"
for name in tempo-a tempo-b; do
    source_dir="$source_root/$name"
    [[ -f "$source_dir/db/mdbx.dat" && -f "$source_dir/.bench-meta/genesis.json" ]] || {
        echo "Missing database or genesis in $source_dir" >&2; exit 1;
    }
    [[ ! -e "$output/$name" && ! -e "$output/$name.incomplete" ]] || {
        echo "Output already exists for $name" >&2; exit 1;
    }
    case "$output/" in "$source_dir/"*) echo 'Output cannot be inside a source datadir' >&2; exit 1;; esac
    if fuser "$source_dir/db/mdbx.dat" "$source_dir/rocksdb/LOCK" 2>/dev/null; then
        echo "Stop processes using $source_dir before preparing snapshots" >&2; exit 1
    fi
done
required=$(du -scB1 "$source_root/tempo-a" "$source_root/tempo-b" | tail -1 | cut -f1)
available=$(df -B1 --output=avail "$output" | tail -1)
# Leave room for copy-on-write database pages and build artifacts.
if (( available < required + 10 * 1024 * 1024 * 1024 )); then
    echo "Insufficient output space: need at least $((required / 1024**3 + 10)) GiB free" >&2
    exit 1
fi

if (( $# == 3 )); then
    tempo=$(realpath -- "$3")
else
    cd -- "$repo"
    export RUSTFLAGS="${RUSTFLAGS:--C target-cpu=native}"
    cargo build --locked --profile profiling --bin tempo --features account-ext
    tempo=$(realpath -- "${CARGO_TARGET_DIR:-$repo/target}/profiling/tempo")
fi
"$tempo" prepare-account-extensions --help >/dev/null
binary_sha=$(sha256sum "$tempo" | cut -d' ' -f1)

for name in tempo-a tempo-b; do
    source_dir="$source_root/$name"
    destination="$output/$name.incomplete"
    mkdir -- "$destination"
    echo "Copying $source_dir to $destination"
    cp -a --reflink=auto --sparse=always "$source_dir/." "$destination/"
    "$tempo" prepare-account-extensions \
        --datadir "$destination" \
        --chain "$destination/.bench-meta/genesis.json" \
        --output-genesis "$destination/.bench-meta/genesis-account-ext.json" \
        --seed 42 2>&1 | tee "$destination/account-ext-preparation.log"
    python3 - "$destination" "$source_dir" "$binary_sha" <<'PY'
import datetime, hashlib, json, pathlib, sys
out, source, binary_sha = sys.argv[1:]
root = pathlib.Path(out)
genesis = root / '.bench-meta/genesis-account-ext.json'
data = json.loads(genesis.read_text())
manifest = {
    'source': source,
    'reth_commit': '98e6e3118c3fe60526bc68fd313efb8f91a87789',
    'binary_sha256': binary_sha,
    'genesis_sha256': hashlib.sha256(genesis.read_bytes()).hexdigest(),
    'source_genesis_sha256': hashlib.sha256((root / '.bench-meta/genesis.json').read_bytes()).hexdigest(),
    'state_root': data['config']['benchmarkStateRoot'],
    'extension_value_bytes': 32,
    'extension_encoded_bytes': 33,
    'seed': 42,
    'prepared_at': datetime.datetime.now(datetime.timezone.utc).isoformat(),
}
(root / 'account-ext-manifest.json').write_text(json.dumps(manifest, indent=2) + '\n')
PY
    sync -f "$destination"
    mv -- "$destination" "$output/$name"
    echo "Ready: $output/$name (use .bench-meta/genesis-account-ext.json)"
done
