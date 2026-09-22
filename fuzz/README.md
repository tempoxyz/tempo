# Tempo binary protocol fuzzing

This package exercises canonical decoding and re-encoding for Tempo consensus RLP types and the
strict ABI decoder against the protocol's generated precompile bindings.

Run a bounded local campaign with:

```sh
cargo +nightly install cargo-fuzz
cargo +nightly fuzz run consensus-rlp -- -max_len=1048576 -rss_limit_mb=4096 -timeout=10
cargo +nightly fuzz run strict-abi -- -max_len=1048576 -rss_limit_mb=4096 -timeout=10
```

The build script creates valid seeds in each target's corpus directory. Keep minimized crash inputs
as regression tests in the owning crate; do not commit generated corpora or artifacts.
