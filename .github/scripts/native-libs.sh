#!/usr/bin/env bash
# Prebuilds the static native libraries behind librocksdb-sys (rocksdb, snappy) and
# tikv-jemalloc-sys so CI builds can link them instead of compiling them.
#
# Their build scripts can't be cached by sccache and run serially (jemalloc's configure, then
# rocksdb's ~250 C++ files), which puts ~1 min in front of every job's reth-provider build.
#
# The libraries are built with exactly the features the job's own build resolves, because
# rocksdb compiled with or without jemalloc, and jemalloc with or without profiling, are not
# interchangeable.
#
# Usage:
#   native-libs.sh spec  <dir> <cargo tree args...>   writes <dir>/crate and prints the cache key
#   native-libs.sh build <dir>                        builds the libraries into <dir>/out
#   native-libs.sh env   <dir>                        exports the overrides to $GITHUB_ENV
set -euo pipefail

TARGET=x86_64-unknown-linux-gnu

# Prints the features `cargo tree` resolves for `$1`, one per line, or nothing if the crate
# is not part of the selection.
resolved_features() {
    local krate=$1
    shift
    cargo tree --locked "$@" --target "$TARGET" -e features -i "$krate" --prefix none 2>/dev/null |
        sed -nE "s/^$krate feature \"([a-z0-9_-]+)\"$/\1/p" | sort -u || true
}

# Prints the locked version of `$1` without build metadata.
locked_version() {
    awk -v name="$1" '$0 == "name = \"" name "\"" { getline; gsub(/"|version = /, ""); print; exit }' Cargo.lock |
        sed 's/+.*//'
}

# Prints a dependency entry for `$1` with the features in `$2`.
dependency() {
    local krate=$1 features=$2 default=false list=""
    for feature in $features; do
        if [[ $feature == default ]]; then
            default=true
        else
            list+="\"$feature\", "
        fi
    done
    echo "$krate = { version = \"=$(locked_version "$krate")\", default-features = $default, features = [${list%, }] }"
}

cmd_spec() {
    local dir=$1
    shift
    local rocksdb jemalloc
    rocksdb=$(resolved_features librocksdb-sys "$@")
    if [[ -z $rocksdb ]]; then
        echo "librocksdb-sys is not part of the selection" >&2
        return 0
    fi
    jemalloc=$(resolved_features tikv-jemalloc-sys "$@")

    mkdir -p "$dir/crate/src"
    : >"$dir/crate/src/lib.rs"
    {
        echo '[package]'
        echo 'name = "native-libs"'
        echo 'version = "0.0.0"'
        echo 'edition = "2024"'
        echo 'publish = false'
        echo
        echo '[dependencies]'
        dependency librocksdb-sys "$rocksdb"
        if [[ -n $jemalloc ]]; then
            dependency tikv-jemalloc-sys "$jemalloc"
        fi
    } >"$dir/crate/Cargo.toml"

    {
        cat "$dir/crate/Cargo.toml"
        cc --version | head -n1
        c++ --version | head -n1
    } | sha256sum | cut -c1-16
}

cmd_build() {
    local dir=$1 target=$1/crate/target
    CARGO_TARGET_DIR=$target cargo build --release --manifest-path "$dir/crate/Cargo.toml"
    mkdir -p "$dir/out"
    cp "$target"/release/build/librocksdb-sys-*/out/{librocksdb.a,libsnappy.a} "$dir/out/"
    if compgen -G "$target/release/build/tikv-jemalloc-sys-*/out/lib/libjemalloc.a" >/dev/null; then
        cp "$target"/release/build/tikv-jemalloc-sys-*/out/lib/libjemalloc.a "$dir/out/"
    fi
    rm -rf "$target"
}

cmd_env() {
    local dir=$1 out=$1/out
    # librocksdb-sys only links the C++ runtime when it compiles rocksdb itself.
    mkdir -p "$dir/bin"
    printf '#!/bin/sh\nexec cc "$@" -lstdc++\n' >"$dir/bin/cc-stdcxx"
    chmod +x "$dir/bin/cc-stdcxx"
    {
        echo "ROCKSDB_LIB_DIR=$out"
        echo "ROCKSDB_STATIC=1"
        echo "SNAPPY_LIB_DIR=$out"
        echo "SNAPPY_STATIC=1"
        echo "CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER=$dir/bin/cc-stdcxx"
        if [[ -f $out/libjemalloc.a ]]; then
            echo "JEMALLOC_OVERRIDE=$out/libjemalloc.a"
        fi
    } >>"$GITHUB_ENV"
}

cmd="cmd_$1"
shift
"$cmd" "$@"
