FROM rust:1.88-bookworm AS chef

RUN cargo install cargo-chef sccache

ENV RUSTC_WRAPPER=sccache \
    SCCACHE_DIR=/sccache

WORKDIR /app

FROM chef AS planner

COPY . .
RUN cargo chef prepare --recipe-path recipe.json

FROM chef AS builder

ARG RUST_PROFILE=release
ARG RUST_FEATURES=""

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

COPY --from=planner /app/recipe.json recipe.json
COPY Cargo.toml Cargo.lock ./

# Cook dependencies with the SAME profile used for the final build
RUN --mount=type=cache,target=/usr/local/cargo/registry,sharing=locked,id=cargo-registry \
    --mount=type=cache,target=/usr/local/cargo/git,sharing=locked,id=cargo-git \
    --mount=type=cache,target=$SCCACHE_DIR,sharing=locked,id=sccache \
    cargo chef cook --profile ${RUST_PROFILE} --features "${RUST_FEATURES}" --recipe-path recipe.json

COPY . .

ARG RUST_BINARY
ARG VERGEN_GIT_SHA
ARG VERGEN_GIT_SHA_SHORT

RUN --mount=type=cache,target=/usr/local/cargo/registry,sharing=locked,id=cargo-registry \
    --mount=type=cache,target=/usr/local/cargo/git,sharing=locked,id=cargo-git \
    --mount=type=cache,target=$SCCACHE_DIR,sharing=locked,id=sccache \
    cargo build --bin ${RUST_BINARY} --profile ${RUST_PROFILE} --features "${RUST_FEATURES}"

FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

ARG RUST_BINARY
ARG RUST_PROFILE

COPY --from=builder /app/target/${RUST_PROFILE}/${RUST_BINARY} /usr/local/bin/${RUST_BINARY}

WORKDIR /data

RUN echo "#!/bin/bash\n/usr/local/bin/${RUST_BINARY} \$@" > /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
