ARG CHEF_IMAGE=chef

FROM ${CHEF_IMAGE} AS chef-base

FROM chef-base AS builder

ARG RUST_BINARY
ARG RUST_PROFILE=profiling
ARG RUST_FEATURES=""
ARG VERGEN_GIT_SHA
ARG VERGEN_GIT_SHA_SHORT

COPY . .

RUN --mount=type=cache,target=/usr/local/cargo/registry,sharing=locked,id=cargo-registry \
    --mount=type=cache,target=/usr/local/cargo/git,sharing=locked,id=cargo-git \
    --mount=type=cache,target=$SCCACHE_DIR,sharing=locked,id=sccache \
    cargo build --bin ${RUST_BINARY} --profile ${RUST_PROFILE} --features "${RUST_FEATURES}"

FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

ARG RUST_BINARY
ARG RUST_PROFILE=profiling

COPY --from=builder /app/target/${RUST_PROFILE}/${RUST_BINARY} /usr/local/bin/${RUST_BINARY}

WORKDIR /data

RUN echo "#!/bin/bash\n/usr/local/bin/${RUST_BINARY} \$@" > /usr/local/bin/entrypoint.sh \
    && chmod +x /usr/local/bin/entrypoint.sh

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
