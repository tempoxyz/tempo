[group('deps')]
[doc('Bump all reth dependencies to a specific commit hash')]
bump-reth commit:
    sed -i '' 's/\(reth[a-z_-]* = { git = "https:\/\/github.com\/paradigmxyz\/reth", rev = "\)[a-f0-9]*"/\1{{commit}}"/g' Cargo.toml
    cargo update

mod scripts

[group('dev')]
tempo-dev-up: scripts::tempo-dev-up
tempo-dev-down: scripts::tempo-dev-down

[group('dev')]
[doc('Check ABI compatibility between Rust precompiles and Solidity interfaces')]
check-abi:
    cd tips/ref-impls && forge build --sizes
    cargo run -p tempo-xtask -- check-abi
