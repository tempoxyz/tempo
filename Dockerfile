ARG CHEF_IMAGE=chef

FROM ${CHEF_IMAGE} AS builder

ARG TARGETARCH
ARG RUST_PROFILE=profiling
ARG VERGEN_GIT_SHA
ARG VERGEN_GIT_SHA_SHORT
ARG EXTRA_RUSTFLAGS=""

COPY . .

# Build ALL binaries in one pass - they share compiled artifacts
RUN --mount=type=cache,target=/usr/local/cargo/registry,sharing=locked,id=cargo-registry-${TARGETARCH} \
    --mount=type=cache,target=/usr/local/cargo/git,sharing=locked,id=cargo-git-${TARGETARCH} \
    --mount=type=cache,target=$SCCACHE_DIR,sharing=locked,id=sccache-${TARGETARCH} \
    RUSTFLAGS="-C link-arg=-fuse-ld=mold ${EXTRA_RUSTFLAGS}" \
    cargo build --profile ${RUST_PROFILE} \
        --bin tempo --features "asm-keccak,jemalloc,otlp" \
        --bin tempo-bench \
        --bin tempo-sidecar \
        --bin tempo-xtask

FROM debian:bookworm-slim AS base

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /data

# tempo
FROM base AS tempo
ARG RUST_PROFILE=profiling
COPY --from=builder /app/target/${RUST_PROFILE}/tempo /usr/local/bin/tempo
ENTRYPOINT ["/usr/local/bin/tempo"]

# tempo-sidecar
FROM base AS tempo-sidecar
ARG RUST_PROFILE=profiling
COPY --from=builder /app/target/${RUST_PROFILE}/tempo-sidecar /usr/local/bin/tempo-sidecar
ENTRYPOINT ["/usr/local/bin/tempo-sidecar"]

# tempo-xtask
FROM base AS tempo-xtask
ARG RUST_PROFILE=profiling
COPY --from=builder /app/target/${RUST_PROFILE}/tempo-xtask /usr/local/bin/tempo-xtask
ENTRYPOINT ["/usr/local/bin/tempo-xtask"]

# tempo-bench (needs nushell)
FROM --platform=$TARGETPLATFORM ghcr.io/nushell/nushell:0.108.0-bookworm AS nushell

FROM base AS tempo-bench
ARG RUST_PROFILE=profiling
COPY --from=nushell /usr/bin/nu /usr/bin/nu
COPY --from=builder /app/target/${RUST_PROFILE}/tempo-bench /usr/local/bin/tempo-bench
ENTRYPOINT ["/usr/local/bin/tempo-bench"]
