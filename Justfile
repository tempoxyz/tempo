default:
    @just --list

[group('build')]
build-all:
    cargo build --workspace
    cd tips/verify && forge build

[group('deps')]
[doc('Bump all reth dependencies to a specific commit hash')]
bump-reth commit:
    sed -i '' 's/\(reth[a-z_-]* = { git = "https:\/\/github.com\/paradigmxyz\/reth", rev = "\)[a-f0-9]*"/\1{{commit}}"/g' Cargo.toml
    cargo update

mod scripts

[group('dev')]
tempo-dev-up:
    @just scripts::tempo-dev-up

[group('dev')]
tempo-dev-down:
    @just scripts::tempo-dev-down

[group('specs')]
[doc('Build tempo-std interfaces and compare them against Rust sol! ABIs')]
check-abi tempo_std="":
    @if [ -n "{{tempo_std}}" ]; then cd "{{tempo_std}}" && forge build --sizes 2>&1 | tail -1; else cd tips/verify/lib/tempo-std && forge build --sizes 2>&1 | tail -1; fi
    @cargo run -q -p tempo-xtask -- check-abi {{ if tempo_std != "" { "--tempo-std " + tempo_std } else { "" } }}
