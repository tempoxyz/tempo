ARG CHEF_IMAGE=chef

FROM ${CHEF_IMAGE} AS builder

ARG TARGETARCH
ARG CACHE_FAMILY=node

ARG RUST_PROFILE=profiling
ARG VERGEN_GIT_SHA
ARG VERGEN_GIT_SHA_SHORT
ARG EXTRA_RUSTFLAGS=""

COPY . .

# Keep the shared dependency layer, but compile only the requested executable.
FROM builder AS node-builder

RUN --mount=type=cache,target=/usr/local/cargo/registry,sharing=locked,id=zones-${TARGETARCH}-${RUST_PROFILE}-${CACHE_FAMILY}-registry \
    --mount=type=cache,target=/usr/local/cargo/git,sharing=locked,id=zones-${TARGETARCH}-${RUST_PROFILE}-${CACHE_FAMILY}-git \
    --mount=type=cache,target=$SCCACHE_DIR,sharing=locked,id=zones-${TARGETARCH}-${RUST_PROFILE}-${CACHE_FAMILY}-sccache \
    RUSTFLAGS="-C link-arg=-fuse-ld=mold ${EXTRA_RUSTFLAGS}" \
    cargo build --locked --profile ${RUST_PROFILE} \
        --bin tempo-zone --features "jemalloc" \
    && if [ -n "$VERGEN_GIT_SHA" ]; then \
         /app/target/${RUST_PROFILE}/tempo-zone --version | grep -F "$VERGEN_GIT_SHA"; \
       fi

FROM builder AS xtask-builder

RUN --mount=type=cache,target=/usr/local/cargo/registry,sharing=locked,id=zones-${TARGETARCH}-${RUST_PROFILE}-${CACHE_FAMILY}-registry \
    --mount=type=cache,target=/usr/local/cargo/git,sharing=locked,id=zones-${TARGETARCH}-${RUST_PROFILE}-${CACHE_FAMILY}-git \
    --mount=type=cache,target=$SCCACHE_DIR,sharing=locked,id=zones-${TARGETARCH}-${RUST_PROFILE}-${CACHE_FAMILY}-sccache \
    RUSTFLAGS="-C link-arg=-fuse-ld=mold ${EXTRA_RUSTFLAGS}" \
    cargo build --locked --profile ${RUST_PROFILE} \
        --bin tempo-zone-xtask

# Solidity contracts compiled for shared runtimes, routers, and zone genesis artifacts.
# Requires the crates/zones/contracts/lib submodules to be checked out.
FROM debian:bookworm-slim@sha256:7ff6ba31527b9e336162fa061746c366c4b2032f4d2cff2078bea43f78efe3f8 AS solidity
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates curl git \
    && rm -rf /var/lib/apt/lists/*
# This stage lacks Git metadata required by newer Foundry lockfile validation.
RUN curl -fsSL https://foundry.paradigm.xyz | bash \
    && /root/.foundry/bin/foundryup --install nightly-fc14f674bd853bc817c308a5202faa5be8df05e7
ENV PATH="/root/.foundry/bin:${PATH}"
WORKDIR /app/crates/zones/contracts
COPY crates/zones/contracts .
RUN forge build --skip test

FROM debian:bookworm-slim@sha256:7ff6ba31527b9e336162fa061746c366c4b2032f4d2cff2078bea43f78efe3f8 AS base

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /data

# tempo-zone
FROM base AS tempo-zone
ARG RUST_PROFILE=profiling
COPY --from=node-builder /app/target/${RUST_PROFILE}/tempo-zone /usr/local/bin/tempo-zone
ENTRYPOINT ["/usr/local/bin/tempo-zone"]

# tempo-zone-xtask: zone provisioning tooling (create-zone, zone-info, deploy-router).
# Ships the compiled contract artifacts used by provisioning and router deployment.
FROM base AS tempo-zone-xtask
ARG RUST_PROFILE=profiling
RUN apt-get update && apt-get install -y --no-install-recommends \
    jq \
    && rm -rf /var/lib/apt/lists/*
COPY --from=xtask-builder /app/target/${RUST_PROFILE}/tempo-zone-xtask /usr/local/bin/tempo-xtask
COPY --from=solidity /root/.foundry/bin/cast /usr/local/bin/cast
COPY --from=solidity /app/crates/zones/contracts/out /app/crates/zones/contracts/out
WORKDIR /app
ENTRYPOINT ["/usr/local/bin/tempo-xtask"]
