FROM rust:1.88-slim-bookworm AS builder

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
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

# NOTE: Remove xtask from workspace to avoid missing dependency error for now
RUN sed -i '/xtask/d' Cargo.toml

# Install nightly Rust and build the tempo binary
RUN rustup toolchain install nightly && rustup default nightly
RUN cargo build --bin tempo

FROM debian:bookworm-slim

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
  ca-certificates \
  && rm -rf /var/lib/apt/lists/*

# Copy the binary
COPY --from=builder /app/target/debug/tempo /usr/local/bin/tempo

WORKDIR /data

# Expose default ports
EXPOSE 8000 8545 8546 30303 30303/udp

ENTRYPOINT ["tempo"]
