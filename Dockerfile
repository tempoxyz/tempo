ARG CHEF_IMAGE=chef

FROM ${CHEF_IMAGE} AS builder

ARG TARGETARCH
ARG RUST_PROFILE=profiling
ARG RUST_FEATURES="asm-keccak,jemalloc,otlp"
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
        --bin tempo --features "${RUST_FEATURES},localnet" \
        --bin tempo-localnet --features "${RUST_FEATURES},localnet" \
        --bin tempo-sidecar \
        --bin tempo-xtask && \
    profile_dir="${RUST_PROFILE}" && \
    if [ "$profile_dir" = dev ]; then profile_dir=debug; fi && \
    mkdir -p dist && \
    cp target/"$profile_dir"/tempo target/"$profile_dir"/tempo-localnet \
       target/"$profile_dir"/tempo-sidecar target/"$profile_dir"/tempo-xtask dist/

FROM builder AS history-builder
RUN --mount=type=cache,target=/usr/local/cargo/registry,sharing=locked,id=cargo-registry-${TARGETARCH} \
    --mount=type=cache,target=/usr/local/cargo/git,sharing=locked,id=cargo-git-${TARGETARCH} \
    --mount=type=cache,target=$SCCACHE_DIR,sharing=locked,id=sccache-${TARGETARCH} \
    RUSTFLAGS="-C link-arg=-fuse-ld=mold ${EXTRA_RUSTFLAGS}" \
    python3 scripts/bundle-history.py --output dist --profile ${RUST_PROFILE}

# Reuse the regular build artifacts, enabling custom PCRs only for the devnet binary.
FROM builder AS devnet-builder
RUN --mount=type=cache,target=/usr/local/cargo/registry,sharing=locked,id=cargo-registry-${TARGETARCH} \
    --mount=type=cache,target=/usr/local/cargo/git,sharing=locked,id=cargo-git-${TARGETARCH} \
    --mount=type=cache,target=$SCCACHE_DIR,sharing=locked,id=sccache-${TARGETARCH} \
    RUSTFLAGS="-C link-arg=-fuse-ld=mold ${EXTRA_RUSTFLAGS}" \
    cargo build --profile ${RUST_PROFILE} \
        --bin tempo --features "${RUST_FEATURES},localnet,custom-pcrs" && \
    profile_dir="${RUST_PROFILE}" && \
    if [ "$profile_dir" = dev ]; then profile_dir=debug; fi && \
    cp target/"$profile_dir"/tempo dist/tempo

FROM debian:bookworm-slim@sha256:4724b8cc51e33e398f0e2e15e18d5ec2851ff0c2280647e1310bc1642182655d AS base

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /data

FROM base AS node-base
COPY --from=history-builder /app/dist/eras /usr/local/bin/eras
COPY --from=history-builder /app/dist/tempo-eras.json /usr/local/bin/tempo-eras.json
COPY --from=history-builder /app/dist/history /usr/local/bin/history

# tempo
FROM node-base AS tempo
COPY --from=builder /app/dist/tempo /usr/local/bin/tempo
ENTRYPOINT ["/usr/local/bin/tempo"]

# tempo-devnet
FROM node-base AS tempo-devnet
COPY --from=devnet-builder /app/dist/tempo /usr/local/bin/tempo
ENTRYPOINT ["/usr/local/bin/tempo"]

# tempo-localnet
FROM node-base AS tempo-localnet
COPY --from=builder /app/dist/tempo /usr/local/bin/tempo
COPY --from=builder /app/dist/tempo-localnet /usr/local/bin/tempo-localnet
EXPOSE 8545
VOLUME ["/data"]
HEALTHCHECK --interval=2s --timeout=2s --start-period=120s --retries=5 CMD ["/usr/local/bin/tempo-localnet", "--health"]
ENTRYPOINT ["/usr/local/bin/tempo-localnet"]

# tempo-sidecar
FROM base AS tempo-sidecar
COPY --from=builder /app/dist/tempo-sidecar /usr/local/bin/tempo-sidecar
ENTRYPOINT ["/usr/local/bin/tempo-sidecar"]

# tempo-xtask
FROM base AS tempo-xtask
COPY --from=builder /app/dist/tempo-xtask /usr/local/bin/tempo-xtask
ENTRYPOINT ["/usr/local/bin/tempo-xtask"]
