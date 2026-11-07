#!/usr/bin/env bash
# Install the pinned Linux x86_64 proof tools outside the repository.
set -euo pipefail
if [[ $(uname -sm) != 'Linux x86_64' ]]; then
    echo 'This bootstrap supports Linux x86_64 only.' >&2
    exit 1
fi
tools=${1:-${XDG_CACHE_HOME:-$HOME/.cache}/tempo-pop-refinement}
mkdir -p "$tools"
cd "$tools"
tools=$PWD
url='https://github.com/verus-lang/verus/releases/download/release/0.2026.11.02.8bf68ee/verus-0.2026.11.02.8bf68ee-x86-linux.zip'
curl --fail --location --retry 3 "$url" -o verus.zip
printf '%s\n' 'f3a0119292df8855e4435da8130bee1873b0e6a60c306accf81a08ea687bba3c  verus.zip' | sha256sum -c -
unzip -qo verus.zip
rustup toolchain install 1.99.1 --profile minimal
rustup toolchain install nightly-2026-09-17 --profile minimal --component rustc-dev,llvm-tools,rust-src
if [[ ! -d charon/.git ]]; then
    git clone https://github.com/AeneasVerif/charon.git charon
fi
git -C charon fetch origin c04983bc802b402d9f81407317a8fba8e15044d8
git -C charon checkout --detach c04983bc802b402d9f81407317a8fba8e15044d8
git -C charon submodule update --init --recursive
CARGO_TARGET_DIR="$tools/charon-target" cargo +nightly-2026-09-17 build --locked \
    --manifest-path charon/charon/Cargo.toml --bin charon --bin charon-driver
printf 'export VERUS_BIN=%q\nexport CHARON_BIN=%q\n' \
    "$tools/verus-x86-linux/verus" "$tools/charon-target/debug/charon" > env.sh
printf 'Tools installed. Load paths with: source %q\n' "$tools/env.sh"
