# Real-consensus sibling of zones/Dockerfile: same toolchain, coverage flags and caches, full tempo/fuzz.
FROM rust:1.96-bookworm@sha256:5e2214abe154fe26e39f64488952e5c991eeed1d6d6da7cc8381ae83927f0cfc AS builder

RUN apt-get update \
    && apt-get install --no-install-recommends -y \
    pkg-config \
    libssl-dev \
    build-essential \
    clang \
    libclang-dev \
    mold \
    && rm -rf /var/lib/apt/lists/*

# Match the regular Tempo Docker builders; keep installation cached across source changes.
RUN cargo install sccache --version 0.14.0 --locked

ENV CARGO_INCREMENTAL=0 \
    RUSTC_WRAPPER=sccache \
    SCCACHE_DIR=/sccache

# Release optimizations with debug assertions and symbols, without LTO (including the crate-local
# ThinLTO pass) so Antithesis can symbolize the coverage instrumentation.
ARG RUST_PROFILE=antithesis
# Full DWARF (the profile inherits line tables only), so gdb can print locals, arguments and types.
ARG CARGO_PROFILE_ANTITHESIS_DEBUG=2
# The build context has no Git metadata, so the version SHA comes from the caller.
ARG VERGEN_GIT_SHA=0000000000000000000000000000000000000000
ARG VERGEN_GIT_SHA_SHORT=00000000
# Lower on small machines: parallel LTO links of the four binaries need a lot of memory.
ARG CARGO_BUILD_JOBS=default

WORKDIR /app
COPY . .

# Antithesis coverage instrumentation (https://antithesis.com/docs/reference/sdk/rust/instrumentation/):
# sancov trace-pc-guard edges that the antithesis-coverage feature's shim forwards to the
# platform's libvoidstar (a no-op outside Antithesis), which also lets Antithesis pause threads.
# --target keeps build scripts and proc macros uninstrumented.
ARG COVERAGE_RUSTFLAGS="-Cpasses=sancov-module -Cllvm-args=-sanitizer-coverage-level=3 -Cllvm-args=-sanitizer-coverage-trace-pc-guard -Cllvm-args=-sanitizer-coverage-pc-table -Clink-args=-Wl,--build-id"
# The build platform's architecture (BuildKit sets it), so local arm64 builds stay native.
ARG TARGETARCH

RUN --mount=type=cache,id=antithesis-cluster-registry,target=/usr/local/cargo/registry,sharing=private \
    --mount=type=cache,id=antithesis-cluster-git,target=/usr/local/cargo/git,sharing=private \
    --mount=type=cache,id=antithesis-cluster-sccache,target=/sccache,sharing=private \
    --mount=type=cache,id=antithesis-cluster-target,target=/app/target,sharing=private \
    case "${TARGETARCH}" in arm64) target=aarch64-unknown-linux-gnu ;; *) target=x86_64-unknown-linux-gnu ;; esac \
    && RUSTFLAGS="-C link-arg=-fuse-ld=mold ${COVERAGE_RUSTFLAGS}" \
    cargo build --locked --profile ${RUST_PROFILE} --target "$target" \
        -p tempo -p tempo-xtask --bin tempo --bin tempo-xtask \
        --features tempo/fuzz,tempo/antithesis-coverage,tempo-xtask/antithesis-coverage \
    && mkdir -p /out \
    && cp "target/$target/${RUST_PROFILE}"/tempo "target/$target/${RUST_PROFILE}"/tempo-xtask /out/ \
    && readelf -SW /out/tempo | grep __sancov_guards

FROM debian:bookworm-slim@sha256:7ff6ba31527b9e336162fa061746c366c4b2032f4d2cff2078bea43f78efe3f8
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates curl jq gdb python3 python3-venv \
    && rm -rf /var/lib/apt/lists/*
COPY --from=builder /out/ /usr/local/bin/
COPY --chmod=755 contrib/antithesis/tempo-cluster/scripts/node.sh /opt/tempo-cluster/node.sh
# Fixed addresses are also committed to ValidatorConfigV2 by generate-localnet.
RUN tempo-xtask generate-localnet --output /opt/tempo-cluster/genesis \
    --accounts 64 --seed 42 --chain-id 1337 --epoch-length 20 --unencrypted-signing-keys \
    --gas-limit 500000000 --general-gas-limit 50000000 \
    --validators 10.21.0.11:8000,10.21.0.12:8000,10.21.0.13:8000,10.21.0.14:8000 \
    && mkdir /symbols \
    && ln -s /usr/local/bin/tempo /symbols/tempo \
    && ln -s /usr/local/bin/tempo-xtask /symbols/tempo-xtask
ENV RUST_BACKTRACE=full
ENTRYPOINT ["/opt/tempo-cluster/node.sh"]
