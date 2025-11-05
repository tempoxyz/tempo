FROM rust:1.88-bookworm AS builder

RUN cargo install cargo-chef sccache --locked
RUN apt-get update \
    && apt-get install --no-install-recommends -y \
    pkg-config \
    libssl-dev \
    build-essential \
    clang \
    libclang-dev \
    && rm -rf /var/lib/apt/lists/*

ENV RUSTC_WRAPPER=sccache \
    SCCACHE_DIR=/sccache

WORKDIR /app

COPY Cargo.toml Cargo.lock ./

RUN cargo chef prepare --recipe-path recipe.json

RUN --mount=type=cache,target=/usr/local/cargo/registry,sharing=locked \
    --mount=type=cache,target=/usr/local/cargo/git,sharing=locked \
    --mount=type=cache,target=$SCCACHE_DIR,sharing=locked \
    cargo chef cook --release --recipe-path recipe.json


# Copy workspace files
COPY bin/ ./bin/
COPY crates/ ./crates/
COPY xtask/ ./xtask/

ARG RUST_BINARY
ARG RUST_PROFILE
ARG RUST_FEATURES
ARG VERGEN_GIT_SHA=""
ARG VERGEN_GIT_SHA_SHORT=""
ENV VERGEN_GIT_SHA=${VERGEN_GIT_SHA:-}
ENV VERGEN_GIT_SHA_SHORT=${VERGEN_GIT_SHA_SHORT:-}

# Install nightly Rust and build the tempo binary
RUN cargo build --bin ${RUST_BINARY} --profile ${RUST_PROFILE} --features "${RUST_FEATURES}"

FROM debian:bookworm-slim

# Install runtime dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

ARG RUST_BINARY
ARG RUST_PROFILE

# Copy the binary
COPY --from=builder /app/target/${RUST_PROFILE}/${RUST_BINARY} /usr/local/bin/${RUST_BINARY}

WORKDIR /data

RUN echo "#!/bin/bash\n/usr/local/bin/${RUST_BINARY} \$@" > /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
