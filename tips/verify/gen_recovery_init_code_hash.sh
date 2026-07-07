#!/usr/bin/env bash
# Regenerates MULTISIG_RECOVERY_WALLET_INIT_CODE_HASH (committed in tip-1061.md and the
# tempo-primitives multisig module) from the canonical standard-EVM build of
# TempoMultisigRecoveryWallet. The recovery contracts must build under standard Cancun (not the
# tempo hardfork the rest of tips/verify uses), so this uses an isolated Foundry config.
#
# Usage: tips/verify/gen_recovery_init_code_hash.sh
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
mkdir -p "$tmp/src"
cp "$here/src/TempoMultisigRecovery.sol" "$tmp/src/"
cat > "$tmp/foundry.toml" <<'TOML'
[profile.default]
solc = "0.8.34"
evm_version = "cancun"
optimizer = true
via_ir = true
bytecode_hash = "none"
cbor_metadata = false
TOML
forge inspect --root "$tmp" src/TempoMultisigRecovery.sol:TempoMultisigRecoveryWallet bytecode \
  | cast keccak
