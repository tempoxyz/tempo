#!/bin/sh
# One deterministic consensus genesis and matching keys, shared by all L1 nodes.
set -eu
OUT=${1:-/genesis}
TEMPO_XTASK=${TEMPO_XTASK:-/out/tempo-xtask}
ZONE_XTASK=${ZONE_XTASK:-/out/tempo-zone-xtask}
SPECS_OUT=${SPECS_OUT:-/app/crates/zones/contracts/out}

"$TEMPO_XTASK" generate-localnet --output "$OUT" --seed 0 --accounts 20 \
    --epoch-length 100 --t15-time 0 \
    --validators 10.20.0.41:8000,10.20.0.42:8000,10.20.0.43:8000,10.20.0.44:8000
# Keep consensus extraData, allocations and hardfork schedule intact while installing
# the same reference factory/runtime and dev-account owner as the dev-mode fixture.
"$ZONE_XTASK" install-reference-zone-factory \
    --genesis "$OUT/genesis.json" \
    --owner 0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266 \
    --specs-out "$SPECS_OUT" --output "$OUT/l1-genesis.json"
printf '%s\n' tempo-localnet-signing-key-secret > "$OUT/signing.secret"
