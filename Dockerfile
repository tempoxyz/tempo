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
        --bin tempo-xtask

# Reuse the regular build artifacts, enabling custom PCRs only for the devnet binary.
FROM builder AS devnet-builder
RUN --mount=type=cache,target=/usr/local/cargo/registry,sharing=locked,id=cargo-registry-${TARGETARCH} \
    --mount=type=cache,target=/usr/local/cargo/git,sharing=locked,id=cargo-git-${TARGETARCH} \
    --mount=type=cache,target=$SCCACHE_DIR,sharing=locked,id=sccache-${TARGETARCH} \
    RUSTFLAGS="-C link-arg=-fuse-ld=mold ${EXTRA_RUSTFLAGS}" \
    cargo build --profile ${RUST_PROFILE} \
        --bin tempo --features "${RUST_FEATURES},localnet,custom-pcrs"

# Distroless: only glibc, libstdc++/libgcc and CA certificates, which is all the
# binaries need. Keeps util-linux, perl, openssl etc. (and their CVEs) out of the image.
FROM gcr.io/distroless/cc-debian13@sha256:b2e43dc72acf58a146ed6feaf350806ae3bf4243eb5c68062d06bc13228ca2bd AS base

WORKDIR /data

# tempo
FROM base AS tempo
ARG RUST_PROFILE=profiling
COPY --from=builder /app/target/${RUST_PROFILE}/tempo /usr/local/bin/tempo
ENTRYPOINT ["/usr/local/bin/tempo"]

# tempo-devnet
FROM base AS tempo-devnet
ARG RUST_PROFILE=profiling
COPY --from=devnet-builder /app/target/${RUST_PROFILE}/tempo /usr/local/bin/tempo
ENTRYPOINT ["/usr/local/bin/tempo"]

# tempo-localnet
FROM base AS tempo-localnet
ARG RUST_PROFILE=profiling
COPY --from=builder /app/target/${RUST_PROFILE}/tempo /usr/local/bin/tempo
COPY --from=builder /app/target/${RUST_PROFILE}/tempo-localnet /usr/local/bin/tempo-localnet
EXPOSE 8545
VOLUME ["/data"]
HEALTHCHECK --interval=2s --timeout=2s --start-period=120s --retries=5 CMD ["/usr/local/bin/tempo-localnet", "--health"]
ENTRYPOINT ["/usr/local/bin/tempo-localnet"]

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
