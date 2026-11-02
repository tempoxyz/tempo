# Zone test image: the Tempo L1 node, the zone node built with SDK assertions enabled,
# the provisioning tools and the scripts docker-compose.yaml runs.
#
# Build from the repository root (requires the crates/zones/contracts/lib submodules):
#   docker build -f zones/antithesis/Dockerfile -t tempo-zones-antithesis:latest \
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

# Release optimizations with debug assertions and symbols.
ARG RUST_PROFILE=fuzz
# The build context has no Git metadata, so the version SHA comes from the caller.
ARG VERGEN_GIT_SHA=0000000000000000000000000000000000000000
ARG VERGEN_GIT_SHA_SHORT=00000000
# Lower on small machines: parallel LTO links of the four binaries need a lot of memory.
ARG CARGO_BUILD_JOBS=default

WORKDIR /app
COPY . .

RUN --mount=type=cache,target=/usr/local/cargo/registry,sharing=locked \
    --mount=type=cache,target=/usr/local/cargo/git,sharing=locked \
    --mount=type=cache,target=/app/target,sharing=locked \
    RUSTFLAGS="-C link-arg=-fuse-ld=mold" \
    cargo build --locked --profile ${RUST_PROFILE} \
        -p tempo -p tempo-zone -p tempo-xtask \
        --bin tempo --bin tempo-zone --bin tempo-xtask --bin tempo-zone-xtask \
        --features tempo-zone/fuzz \
    && mkdir -p /out \
    && cp target/${RUST_PROFILE}/tempo target/${RUST_PROFILE}/tempo-zone \
        target/${RUST_PROFILE}/tempo-xtask target/${RUST_PROFILE}/tempo-zone-xtask /out/

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

FROM debian:bookworm-slim@sha256:7ff6ba31527b9e336162fa061746c366c4b2032f4d2cff2078bea43f78efe3f8

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates jq \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /out/ /usr/local/bin/
COPY --from=solidity /root/.foundry/bin/cast /usr/local/bin/cast
COPY --from=solidity /app/crates/zones/contracts/out /app/crates/zones/contracts/out
COPY --from=l1-genesis /genesis/l1-genesis.json /opt/zones/l1-genesis.json
COPY zones/antithesis/scripts/ /opt/zones/

ENV RUST_BACKTRACE=full
WORKDIR /app
