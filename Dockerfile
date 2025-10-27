FROM rust:1.88-slim-bookworm AS builder

WORKDIR /app

# Install system dependencies
RUN wget -qO - 'https://proget.makedeb.org/debian-feeds/prebuilt-mpr.pub' \
    | gpg --dearmor \
    | sudo tee /usr/share/keyrings/prebuilt-mpr-archive-keyring.gpg 1> /dev/null \
    && echo "deb [arch=all,$(dpkg --print-architecture) signed-by=/usr/share/keyrings/prebuilt-mpr-archive-keyring.gpg] https://proget.makedeb.org prebuilt-mpr $(lsb_release -cs)" \
    | sudo tee /etc/apt/sources.list.d/prebuilt-mpr.list \
    && apt-get update \
    && apt-get install -y \
    pkg-config \
    libssl-dev \
    build-essential \
    clang \
    libclang-dev \
    just \
    && rm -rf /var/lib/apt/lists/*

# Copy workspace files
COPY Cargo.toml Cargo.lock ./
COPY bin/ ./bin/
COPY crates/ ./crates/

# NOTE: Remove xtask from workspace to avoid missing dependency error for now
RUN sed -i '/xtask/d' Cargo.toml

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

# Copy the binary
COPY --from=builder /app/target/${RUST_PROFILE}/${RUST_BINARY} /usr/local/bin/${RUST_BINARY}

WORKDIR /data

ENTRYPOINT ["${RUST_BINARY}"]
