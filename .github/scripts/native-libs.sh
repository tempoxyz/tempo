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
#   native-libs.sh key <cargo tree args...>        prints the cache key, without running cargo
#   native-libs.sh prepare <dir> <cargo tree args...>  builds the libraries into <dir>/out
#   native-libs.sh env <dir>                       exports the overrides to $GITHUB_ENV
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

# Prints the Cargo.lock entries (name, version, source, checksum) of `$1`.
lock_entries() {
    awk -v name="$1" '$0 == "[[package]]" { p = 0 } $0 == "name = \"" name "\"" { p = 1 }
        p && /^(name|version|source|checksum) = / { print }' Cargo.lock
}

# Succeeds if `$1` is locked exactly once, from crates.io. Patched, git or path sources would
# not match the registry release the prebuilt libraries are built from.
from_registry() {
    [[ $(lock_entries "$1" | grep -c '^source = "registry+https://github.com/rust-lang/crates.io-index"$') == 1 &&
        $(lock_entries "$1" | grep -c '^name = ') == 1 ]]
}

# Prints a "name version checksum" line per registry package in the lockfile `$1`.
locked_packages() {
    awk '/^name = / { n = $3 } /^version = / { v = $3 } /^checksum = / { print n, v, $3 }' "$1" | sort
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

# Writes a crate to <dir>/crate that depends on the native -sys crates with the selection's
# features, locked like the repository. Fails if the selection should build them from source.
write_crate() {
    local dir=$1
    shift
    local rocksdb jemalloc
    rocksdb=$(resolved_features librocksdb-sys "$@")
    if [[ -z $rocksdb ]]; then
        echo "librocksdb-sys is not part of the selection" >&2
        return 1
    fi
    jemalloc=$(resolved_features tikv-jemalloc-sys "$@")
    for krate in librocksdb-sys ${jemalloc:+tikv-jemalloc-sys}; do
        if ! from_registry "$krate"; then
            echo "$krate is not locked to a single crates.io release; building it from source" >&2
            return 1
        fi
    done

    mkdir -p "$dir/crate/src"
    echo "use librocksdb_sys as _;" >"$dir/crate/src/lib.rs"
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
    if [[ -n $jemalloc ]]; then
        echo "use tikv_jemalloc_sys as _;" >>"$dir/crate/src/lib.rs"
    fi

    # Seed the crate with the repository lock: cargo keeps the locked versions of everything the
    # crate still uses (build-time deps like cc and bindgen included) and prunes the rest.
    cp Cargo.lock "$dir/crate/Cargo.lock"
    cargo metadata --format-version 1 --manifest-path "$dir/crate/Cargo.toml" >/dev/null
    local unlocked
    unlocked=$(comm -23 <(locked_packages "$dir/crate/Cargo.lock") <(locked_packages Cargo.lock))
    if [[ -n $unlocked ]]; then
        echo "native-libs resolved packages that Cargo.lock does not pin:" >&2
        echo "$unlocked" >&2
        exit 1
    fi
}

# The resolved features and versions are a function of the manifests, the lockfile and the
# selection, so hashing those keys the cache without running cargo on a hit.
cmd_key() {
    {
        echo "$*"
        cat "$0" Cargo.lock
        git ls-files -z -- '*Cargo.toml' | sort -z | xargs -0 cat
        cc --version | head -n1
        c++ --version | head -n1
    } | sha256sum | cut -c1-16
}

cmd_prepare() {
    local dir=$1
    shift
    mkdir -p "$dir/out"
    if write_crate "$dir" "$@"; then
        build "$dir"
    fi
}

build() {
    local dir=$1 target=$1/crate/target
    # Build script output directories, keyed by crate name.
    local out_dirs
    out_dirs=$(CARGO_TARGET_DIR=$target cargo build --locked --release --manifest-path "$dir/crate/Cargo.toml" \
        --message-format json-render-diagnostics |
        jq -r 'select(.reason == "build-script-executed") | "\(.package_id) \(.out_dir)"')
    out_dir() { awk -v krate="$1" '$1 ~ "[/#]" krate "[@#]" { print $2 }' <<<"$out_dirs"; }

    mkdir -p "$dir/out"
    local rocksdb jemalloc
    rocksdb=$(out_dir librocksdb-sys)
    cp "$rocksdb/librocksdb.a" "$rocksdb/libsnappy.a" "$dir/out/"
    jemalloc=$(out_dir tikv-jemalloc-sys)
    if [[ -n $jemalloc ]]; then
        cp "$jemalloc/lib/libjemalloc.a" "$dir/out/"
    fi
    rm -rf "$target"
}

cmd_env() {
    local dir=$1 out=$1/out
    if [[ ! -f $out/librocksdb.a ]]; then
        return 0
    fi
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
