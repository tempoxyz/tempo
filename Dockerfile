FROM rust:1.83-slim-bookworm AS builder

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

# Remove xtask from workspace to avoid missing dependency error
RUN sed -i '/xtask/d' Cargo.toml

# Install nightly Rust and build the tempo binary
RUN rustup toolchain install nightly && rustup default nightly
RUN cargo build --release --bin tempo-commonware

FROM debian:bookworm-slim

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
  ca-certificates \
  && rm -rf /var/lib/apt/lists/*

# Copy the binary
COPY --from=builder /app/target/release/tempo-commonware /usr/local/bin/tempo-commonware

# Create data directory
RUN mkdir -p /data

WORKDIR /data

# Expose default ports
EXPOSE 8545 8546 30303 30303/udp

ENTRYPOINT ["tempo-commonware"]
