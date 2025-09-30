FROM rust:1.80-slim-bookworm AS builder

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Copy workspace files
COPY Cargo.toml Cargo.lock ./
COPY crates/ ./crates/

# Build the tempo binary
RUN cargo build --release --bin tempo

FROM debian:bookworm-slim

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Copy the binary
COPY --from=builder /app/target/release/tempo /usr/local/bin/tempo

# Create data directory
RUN mkdir -p /data

WORKDIR /data

# Expose default ports
EXPOSE 8545 8546 30303 30303/udp

ENTRYPOINT ["tempo"]