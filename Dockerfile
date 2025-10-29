FROM rust:1.88-bookworm AS builder

WORKDIR /app

# Install system dependencies
RUN apt-get update \
    && apt-get install -y \
    pkg-config \
    libssl-dev \
    build-essential \
    clang \
    libclang-dev \
    && rm -rf /var/lib/apt/lists/*

# Copy workspace files
COPY Cargo.toml Cargo.lock ./
COPY bin/ ./bin/
COPY crates/ ./crates/
COPY xtask/ ./xtask/

ARG RUST_BINARY
ARG RUST_PROFILE
ARG RUST_FEATURES

# Install nightly Rust and build the tempo binary
RUN rustup toolchain install nightly && rustup default nightly
RUN cargo build --bin ${RUST_BINARY} --profile ${RUST_PROFILE} --features "${RUST_FEATURES}"

FROM debian:bookworm-slim

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

ARG RUST_BINARY
ARG RUST_PROFILE

# Copy the binary
COPY --from=builder /app/target/${RUST_PROFILE}/${RUST_BINARY} /usr/local/bin/${RUST_BINARY}

WORKDIR /data

ENTRYPOINT ["${RUST_BINARY}"]
