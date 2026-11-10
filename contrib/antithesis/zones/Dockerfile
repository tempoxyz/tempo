# Zone test image: the Tempo L1 node and the zone node built with SDK assertions enabled (the L1
# without the consensus ones, since it runs --dev and never starts consensus), the provisioning
# tools, the scripts docker-compose.yaml runs and the test template.
#
# Build from the repository root (requires the crates/zones/contracts/lib submodules):
#   docker build -f contrib/antithesis/zones/Dockerfile -t tempo-zones-antithesis:latest \
#     --build-arg VERGEN_GIT_SHA="$(git rev-parse HEAD)" .
#   docker build -f contrib/antithesis/zones/Dockerfile --target workload \
#     -t tempo-zones-antithesis-workload:latest \
#     --build-arg VERGEN_GIT_SHA="$(git rev-parse HEAD)" .

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

# Release optimizations with debug assertions and symbols, without LTO and with one codegen
# unit per crate so Antithesis can symbolize the coverage instrumentation.
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
ARG COVERAGE_RUSTFLAGS="-Ccodegen-units=1 -Cpasses=sancov-module -Cllvm-args=-sanitizer-coverage-level=3 -Cllvm-args=-sanitizer-coverage-trace-pc-guard -Cllvm-args=-sanitizer-coverage-pc-table -Clink-args=-Wl,--build-id"
# The build platform's architecture (BuildKit sets it), so local arm64 builds stay native.
ARG TARGETARCH

RUN --mount=type=cache,target=/usr/local/cargo/registry,sharing=locked \
    --mount=type=cache,target=/usr/local/cargo/git,sharing=locked \
    --mount=type=cache,target=/app/target,sharing=locked \
    case "${TARGETARCH}" in arm64) target=aarch64-unknown-linux-gnu ;; *) target=x86_64-unknown-linux-gnu ;; esac \
    && RUSTFLAGS="-C link-arg=-fuse-ld=mold ${COVERAGE_RUSTFLAGS}" \
    cargo build --locked --profile ${RUST_PROFILE} --target "$target" \
        -p tempo -p tempo-zone -p tempo-xtask \
        --bin tempo --bin tempo-zone --bin tempo-xtask --bin tempo-zone-xtask \
        --features tempo/fuzz-execution,tempo-zone/fuzz,tempo/antithesis-coverage,tempo-zone/antithesis-coverage,tempo-xtask/antithesis-coverage \
    && mkdir -p /out \
    && cd "target/$target/${RUST_PROFILE}" \
    && cp tempo tempo-zone tempo-xtask tempo-zone-xtask /out/

FROM debian:bookworm-slim@sha256:7ff6ba31527b9e336162fa061746c366c4b2032f4d2cff2078bea43f78efe3f8 AS solidity
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates curl git \
    && rm -rf /var/lib/apt/lists/*
RUN curl -fsSL https://foundry.paradigm.xyz | bash \
    && /root/.foundry/bin/foundryup --install nightly-fc14f674bd853bc817c308a5202faa5be8df05e7
ENV PATH="/root/.foundry/bin:${PATH}"
WORKDIR /app/crates/zones/contracts
COPY crates/zones/contracts .
RUN forge build --skip test

# Dev-mode L1 genesis with the native ZoneFactory owned by dev account 0, so the provisioner
# can create the zone. Built once so every container starts from the same chain.
FROM builder AS l1-genesis
COPY --from=solidity /app/crates/zones/contracts/out /app/crates/zones/contracts/out
RUN /out/tempo-xtask generate-genesis --output /genesis --accounts 20 --no-dkg-in-genesis \
    && /out/tempo-zone-xtask install-reference-zone-factory \
        --genesis /genesis/genesis.json \
        --owner 0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266 \
        --specs-out /app/crates/zones/contracts/out \
        --output /genesis/l1-genesis.json

FROM debian:bookworm-slim@sha256:7ff6ba31527b9e336162fa061746c366c4b2032f4d2cff2078bea43f78efe3f8 AS runtime

# gdb lets debugging sessions attach to the nodes (gdb -p) or open their core dumps.
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates jq gdb \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /out/ /usr/local/bin/
COPY --from=solidity /root/.foundry/bin/cast /usr/local/bin/cast
COPY --from=solidity /app/crates/zones/contracts/out /app/crates/zones/contracts/out
COPY --from=l1-genesis /genesis/l1-genesis.json /opt/zones/l1-genesis.json
COPY contrib/antithesis/zones/scripts/ /opt/zones/

# Antithesis reads the symbols of instrumented binaries from /symbols; the binaries keep theirs.
RUN mkdir /symbols && for bin in tempo tempo-zone tempo-xtask tempo-zone-xtask; do \
        ln -s /usr/local/bin/$bin /symbols/$bin; \
    done

ENV RUST_BACKTRACE=full
WORKDIR /app

# The workload container's image: the runtime image with the test template in
# /opt/antithesis/test, where the test platform looks for it in the image it is given. Only
# this image has it, so no other container offers test commands. Build it with
# --target workload.
FROM runtime AS workload
COPY --chmod=755 contrib/antithesis/zones/test/ /opt/antithesis/test/

# The default target stays the image the nodes run.
FROM runtime
