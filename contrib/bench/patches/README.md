# Benchmark dependency patches

The recorded node and generator binaries include changes outside this repository.
`manifest.json` pins their base revisions and the SHA-256 of each complete patch,
including new files and regression tests. These are experimental benchmark
dependencies, not updates to Tempo's default dependency pins.

- `txgen.patch`: signed native/EIP-2930/EIP-1559 access-list templates, bounded
  storage-key ranges, deferred-signing preservation, and tests. Required for the
  declared read/write presets; the preflight rejects an older generator.
- `reth.patch`: cancellation of abandoned payload resolution, removal of canceled
  queued payloads, RocksDB cache-shard sizing, opt-in mapped-bytecode page prefetch
  with read-only/read-write transaction coverage, and a read-only Finish checkpoint
  diagnostic. The completed measurements use these changes; an unpatched build
  is not the same experimental configuration.

Apply each patch to a dedicated checkout at its manifest revision. From this
Tempo checkout, with `BENCH_RETH` and `BENCH_TXGEN` pointing to those checkouts:

```sh
git -C "$BENCH_RETH" apply --check "$PWD/contrib/bench/patches/reth.patch"
git -C "$BENCH_RETH" apply "$PWD/contrib/bench/patches/reth.patch"
git -C "$BENCH_TXGEN" apply --check "$PWD/contrib/bench/patches/txgen.patch"
git -C "$BENCH_TXGEN" apply "$PWD/contrib/bench/patches/txgen.patch"
python3 contrib/bench/patches/reth-config.py "$BENCH_RETH" > contrib/bench/payload-cancel-patches.toml
cargo build --config contrib/bench/payload-cancel-patches.toml -p tempo --bin tempo --profile profiling --features jemalloc,asm-keccak
cargo build --manifest-path "$BENCH_TXGEN/Cargo.toml" --release -p txgen-tempo --bin txgen-tempo
```

The generated Cargo config contains absolute paths and is ignored. Cargo also
rewrites the local lockfile when path patches are enabled; do not commit that
host-specific resolution. The committed lockfile retains the normal Git pins.
Python 3.11 or newer is required by the config generator. Use the same build
flags, toolchain, node settings, and patched binary for both sides of a comparison;
the archived manifests record the settings used for the reported measurements.
