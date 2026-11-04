# Image for Anthropic's OSS Scanner (https://github.com/anthropics/oss-scanner): the whole tempo workspace, built
# with its tests, so the scanner can run them offline. threat_model.md, next to this file, says what matters.
#
# The scanner builds this with the repository as the context and removes the network afterwards, so everything
# cargo needs is fetched here. Dockerfile.dockerignore keeps .git in the context: vergen reads it at build time.

# Latest stable Rust, which is what CI tests with.
FROM rust:1-trixie
ENV DEBIAN_FRONTEND=noninteractive
# libclang for bindgen (rocksdb, jemalloc), mold for linking as CI does.
RUN apt-get update && apt-get install -y --no-install-recommends \
      clang libclang-dev mold cmake pkg-config git jq \
    && rm -rf /var/lib/apt/lists/*

# cargo-nextest, at the version CI pins.
ARG NEXTEST_VERSION=0.9.127
RUN curl -fsSL "https://get.nexte.st/${NEXTEST_VERSION}/linux" | tar -xzf - -C "${CARGO_HOME}/bin" \
    && cargo nextest --version

# Nightly and cargo-fuzz for crates/nitro-attestation/fuzz, the repository's fuzz harness.
ARG CARGO_FUZZ_VERSION=0.13.2
RUN rustup toolchain install nightly --profile minimal \
    && cargo install --locked cargo-fuzz --version "${CARGO_FUZZ_VERSION}"

# scanner contract: the checkout lives inside the image, at /src
COPY . /src
WORKDIR /src

# Some e2e tests overflow the default stack, as in CI.
ENV RUST_BACKTRACE=1 \
    CARGO_TERM_COLOR=never \
    RUST_MIN_STACK=8388608

# In cargo's global config so later builds in the image use the same profile and reuse these artifacts. Line tables
# for workspace crates only, and no incremental cache: with either, the image grows past 90 GB.
RUN printf '%s\n' \
      '[build]' 'incremental = false' \
      '[target.x86_64-unknown-linux-gnu]' 'rustflags = ["-C", "link-arg=-fuse-ld=mold"]' \
      '[profile.dev]' 'debug = "line-tables-only"' \
      '[profile.dev.package."*"]' 'debug = 0' \
      > "${CARGO_HOME}/config.toml"

RUN cargo fetch --locked

# Every test binary and example in the workspace (cargo's default test targets, so the commands in threat_model.md
# rebuild nothing), then the binaries, including tempo-localnet for a dev node. Always --workspace: -p changes
# feature unification and rebuilds hundreds of crates. A step that fails fails the build.
RUN cargo nextest run --locked --workspace --no-run \
    && cargo build --locked --workspace --bins --features tempo/localnet

# The fuzz target, with cargo-fuzz's default address sanitizer.
RUN cd crates/nitro-attestation && cargo +nightly fuzz build parse_attestation

# A cheap slice of the tests so the log shows the image works, without letting a failure abort the build.
RUN timeout 600 cargo nextest run --locked --workspace --lib --no-fail-fast \
      -E 'package(tempo-precompiles) | package(tempo-transaction-pool) | package(tempo-primitives)' \
    || echo "WARNING: cargo nextest reported failures"

# Everything is fetched. From here on cargo must not try to reach a registry.
ENV CARGO_NET_OFFLINE=true
