[group('deps')]
[doc('Bump all reth dependencies to latest main or a specific commit hash')]
bump-reth commit="latest":
    ./scripts/bump-reth.sh {{commit}}

mod scripts

[group('dev')]
tempo-dev-up: scripts::tempo-dev-up
tempo-dev-down: scripts::tempo-dev-down

[group('specs')]
[doc('Build tempo-std interfaces and compare them against Rust sol! ABIs')]
check-abi tempo_std="":
    @if [ -n "{{tempo_std}}" ]; then cd "{{tempo_std}}" && forge build --sizes 2>&1 | tail -1; else cd tips/verify/lib/tempo-std && forge build --sizes 2>&1 | tail -1; fi
    @cargo run -q -p tempo-xtask -- check-abi {{ if tempo_std != "" { "--tempo-std " + tempo_std } else { "" } }}
