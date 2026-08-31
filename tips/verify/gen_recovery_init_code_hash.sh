#!/usr/bin/env bash
# Regenerates and optionally checks the canonical TIP-1061 cross-chain recovery artifacts.
#
# Usage:
#   tips/verify/gen_recovery_init_code_hash.sh
#   tips/verify/gen_recovery_init_code_hash.sh --check
set -euo pipefail

readonly FOUNDRY_COMMIT="423ac0d4080830fd2ec6ea52175b323a095973e9"
readonly SINGLETON_FACTORY="0x914d7fec6aac8cd542e72bca78b30650d45643d7"
readonly SINGLETON_FACTORY_RUNTIME_HASH="0x2fa86add0aed31f33a762c9d88e807c475bd51d0f52bd0955754b2608f7e4989"
readonly FACTORY_DEPLOYMENT_SALT="0x0000000000000000000000000000000000000000000000000000000000000000"
readonly EXPECTED_FACTORY="0x8a196a227c48ae8a3e36eebd4e106675cc0f6e64"
readonly EXPECTED_FACTORY_INIT_CODE_HASH="0x7b42ecafbba234c24f2ff2048bafe1d7c0117bac1676006e32e83788b2d6af59"
readonly EXPECTED_FACTORY_RUNTIME_HASH="0x652767050367e6f3b47e14e416d212a549f6666a2c4867e157a39a7306b357ad"
readonly EXPECTED_WALLET_INIT_CODE_HASH="0x4b5ff53c5328a10a6ec5224adf16de5e204a47057c98af037ee30b7de660a8a6"

here="$(cd "$(dirname "$0")" && pwd)"
repo="$(cd "$here/../.." && pwd)"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
mkdir -p "$tmp/src"
cp "$here/src/TempoMultisigRecovery.sol" "$tmp/src/"
cat > "$tmp/foundry.toml" <<'TOML'
[profile.default]
src = "src"
out = "out"
solc = "0.8.34"
evm_version = "paris"
optimizer = true
optimizer_runs = 200
via_ir = true
bytecode_hash = "none"
cbor_metadata = false
TOML

# Keep canonical compilation independent of ambient Foundry profiles and overrides.
task_path="$PATH"
task_home="$HOME"
run_forge() {
  env -i HOME="$task_home" PATH="$task_path" FOUNDRY_DISABLE_NIGHTLY_WARNING=1 forge "$@"
}
run_cast() {
  env -i HOME="$task_home" PATH="$task_path" FOUNDRY_DISABLE_NIGHTLY_WARNING=1 cast "$@"
}

forge_version="$(run_forge --version)"
if [[ "$forge_version" != *"$FOUNDRY_COMMIT"* ]]; then
  printf 'error: canonical recovery artifacts require Foundry commit %s\n' "$FOUNDRY_COMMIT" >&2
  printf '%s\n' "$forge_version" >&2
  exit 1
fi

config="$(run_forge config --root "$tmp" --json)"
jq -e '
  .solc == "0.8.34" and
  .evm_version == "paris" and
  .optimizer == true and
  .optimizer_runs == 200 and
  .via_ir == true and
  .bytecode_hash == "none" and
  .cbor_metadata == false
' >/dev/null <<<"$config"

wallet_bytecode="$(
  run_forge inspect --root "$tmp" \
    src/TempoMultisigRecovery.sol:TempoMultisigRecoveryWallet bytecode
)"
factory_bytecode="$(
  run_forge inspect --root "$tmp" \
    src/TempoMultisigRecovery.sol:TempoMultisigRecoveryFactory bytecode
)"
factory_runtime="$(
  run_forge inspect --root "$tmp" \
    src/TempoMultisigRecovery.sol:TempoMultisigRecoveryFactory deployedBytecode
)"

wallet_init_code_hash="$(printf '%s' "$wallet_bytecode" | run_cast keccak)"
factory_init_code_hash="$(printf '%s' "$factory_bytecode" | run_cast keccak)"
factory_runtime_hash="$(printf '%s' "$factory_runtime" | run_cast keccak)"
factory_digest="$(
  printf '0xff%s%s%s' \
    "${SINGLETON_FACTORY#0x}" \
    "${FACTORY_DEPLOYMENT_SALT#0x}" \
    "${factory_init_code_hash#0x}" \
    | run_cast keccak
)"
factory="0x${factory_digest: -40}"

printf 'singleton_factory=%s\n' "$SINGLETON_FACTORY"
printf 'singleton_factory_runtime_hash=%s\n' "$SINGLETON_FACTORY_RUNTIME_HASH"
printf 'factory_deployment_salt=%s\n' "$FACTORY_DEPLOYMENT_SALT"
printf 'factory=%s\n' "$factory"
printf 'factory_init_code_hash=%s\n' "$factory_init_code_hash"
printf 'factory_runtime_hash=%s\n' "$factory_runtime_hash"
printf 'wallet_init_code_hash=%s\n' "$wallet_init_code_hash"

check_tip_constant() {
  local name="$1"
  local value="${2#0x}"
  sed -n "/^pub const ${name}:/,/;$/p" "$repo/tips/tip-1061.md" | grep -Fqi "$value"
}

if [[ "${1:-}" == "--check" ]]; then
  [[ "$factory" == "$EXPECTED_FACTORY" ]]
  [[ "$factory_init_code_hash" == "$EXPECTED_FACTORY_INIT_CODE_HASH" ]]
  [[ "$factory_runtime_hash" == "$EXPECTED_FACTORY_RUNTIME_HASH" ]]
  [[ "$wallet_init_code_hash" == "$EXPECTED_WALLET_INIT_CODE_HASH" ]]
  [[ "$FACTORY_DEPLOYMENT_SALT" == "0x$(printf '%064d' 0)" ]]

  check_tip_constant MULTISIG_RECOVERY_SINGLETON_FACTORY "$SINGLETON_FACTORY"
  check_tip_constant MULTISIG_RECOVERY_SINGLETON_FACTORY_RUNTIME_HASH "$SINGLETON_FACTORY_RUNTIME_HASH"
  check_tip_constant MULTISIG_RECOVERY_FACTORY_DEPLOYMENT_SALT B256::ZERO
  check_tip_constant MULTISIG_RECOVERY_FACTORY "$EXPECTED_FACTORY"
  check_tip_constant MULTISIG_RECOVERY_FACTORY_INIT_CODE_HASH "$EXPECTED_FACTORY_INIT_CODE_HASH"
  check_tip_constant MULTISIG_RECOVERY_FACTORY_RUNTIME_HASH "$EXPECTED_FACTORY_RUNTIME_HASH"
  check_tip_constant MULTISIG_RECOVERY_WALLET_INIT_CODE_HASH "$EXPECTED_WALLET_INIT_CODE_HASH"
elif [[ $# -ne 0 ]]; then
  printf 'usage: %s [--check]\n' "$0" >&2
  exit 2
fi
