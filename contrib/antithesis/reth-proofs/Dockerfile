# Build the proof workload from Tempo's root workspace and lockfile.
FROM rust:1.96-bookworm@sha256:5e2214abe154fe26e39f64488952e5c991eeed1d6d6da7cc8381ae83927f0cfc AS builder
SHELL ["/bin/bash", "-o", "pipefail", "-c"]
RUN apt-get update \
    && apt-get install --no-install-recommends -y clang libclang-dev pkg-config libssl-dev mold \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /work
# The Dockerfile-specific allowlist includes every workspace member manifest.
COPY . ./
# Instrument target code only, not host build scripts/proc macros. Disable LTO (with it the
# crate-local ThinLTO pass over multiple codegen units): it can optimize away compile-time
# coverage. Keep assertions and line tables for Antithesis.
ENV CARGO_PROFILE_ANTITHESIS_DEBUG=line-tables-only \
    CARGO_PROFILE_ANTITHESIS_DEBUG_ASSERTIONS=true \
    CARGO_PROFILE_ANTITHESIS_OVERFLOW_CHECKS=true \
    CARGO_PROFILE_ANTITHESIS_STRIP=false \
    CARGO_PROFILE_ANTITHESIS_LTO=off
# COPY preserves timestamps. Force the local crate fresh when this layer reruns:
# its source may have changed while an earlier cached-target build was running.
# Cargo locks its own registry; a private target cache never waits on a concurrent or cancelled
# build, and each workload keeps its own (their features differ).
RUN --mount=type=cache,target=/usr/local/cargo/registry,sharing=shared \
    --mount=type=cache,target=/usr/local/cargo/git,sharing=shared \
    --mount=type=cache,id=antithesis-reth-proofs-target,target=/work/target,sharing=private \
    touch contrib/antithesis/reth-proofs/src/main.rs \
    && cargo build --locked --timings --profile antithesis -p reth-proofs-antithesis \
      --features reth-proofs-antithesis/fuzz --bin reth-proofs-antithesis \
      --target x86_64-unknown-linux-gnu \
      --config 'target.x86_64-unknown-linux-gnu.rustflags=["-Clink-arg=-fuse-ld=mold","-Cpasses=sancov-module","-Cllvm-args=-sanitizer-coverage-level=3","-Cllvm-args=-sanitizer-coverage-trace-pc-guard","-Cllvm-args=-sanitizer-coverage-pc-table","-Clink-args=-Wl,--build-id"]' \
    && mkdir /out /timings \
    && cp target/cargo-timings/cargo-timing.html /timings/ \
    && cp target/x86_64-unknown-linux-gnu/antithesis/reth-proofs-antithesis /out/ \
    && nm /out/reth-proofs-antithesis | grep ' T antithesis_load_libvoidstar$' \
    && readelf -SW /out/reth-proofs-antithesis | grep __sancov_guards \
    && readelf -SW /out/reth-proofs-antithesis | grep __sancov_pcs \
    && readelf -SW /out/reth-proofs-antithesis | grep .debug_info \
    && readelf -n /out/reth-proofs-antithesis | grep 'Build ID:'

# The cargo --timings report, exported by CI with --target timings.
FROM scratch AS timings
COPY --from=builder /timings/ /

FROM debian:bookworm-slim@sha256:7ff6ba31527b9e336162fa061746c366c4b2032f4d2cff2078bea43f78efe3f8
RUN apt-get update \
    && apt-get install --no-install-recommends -y ca-certificates libssl3 \
    && rm -rf /var/lib/apt/lists/*
COPY --from=builder /out/reth-proofs-antithesis /usr/local/bin/reth-proofs-antithesis
# The instrumentation shim loads Antithesis's injected runtime when available, and
# falls back locally. No separately downloaded libvoidstar is needed with this SDK.
RUN mkdir /symbols && ln -s /usr/local/bin/reth-proofs-antithesis /symbols/reth-proofs-antithesis
ENV RUST_BACKTRACE=full
WORKDIR /work
ENTRYPOINT ["/usr/local/bin/reth-proofs-antithesis"]
