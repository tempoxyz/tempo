#!/usr/bin/env bash

# Build and validate the immutable Tempo L1 baseline used by the Zones benchmark.
# The caller owns the Schelk restore/promote lifecycle; this script only mutates
# the currently mounted private scratch volumes.

set -Eeuo pipefail

readonly L1_SNAPSHOT_SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
readonly L1_SNAPSHOT_ZONES_ROOT="$(cd -- "$L1_SNAPSHOT_SCRIPT_DIR/../.." && pwd)"
readonly L1_SNAPSHOT_SCHEMA=1
readonly L1_SNAPSHOT_FUTURE_HARDFORK_TIME=4102444800
readonly L1_SNAPSHOT_ZONE_FACTORY="0x5aF2000000000000000000000000000000000000"
readonly L1_SNAPSHOT_PORTAL_IMPL="0x5AD1000000000000000000000000000000000000"
readonly L1_SNAPSHOT_VERIFIER="0x5a56000000000000000000000000000000000000"
readonly L1_SNAPSHOT_MESSENGER="0x5A4d000000000000000000000000000000000000"
readonly L1_SNAPSHOT_HISTORY="0x0000F90827F1C53a10cb7A02335B175320002935"
readonly L1_SNAPSHOT_PUBLIC_DEV_MNEMONIC="test test test test test test test test test test test junk"

l1_snapshot_die() {
    echo "error: $*" >&2
    exit 1
}

l1_snapshot_require_command() {
    command -v "$1" >/dev/null 2>&1 || l1_snapshot_die "required command not found: $1"
}

l1_snapshot_require_file() {
    [[ -f "$1" ]] || l1_snapshot_die "required file not found: $1"
}

l1_snapshot_require_executable() {
    [[ -x "$1" ]] || l1_snapshot_die "required executable not found: $1"
}

l1_snapshot_require_uint() {
    local name="$1"
    local value="${!name:-}"
    [[ "$value" =~ ^[0-9]+$ ]] || l1_snapshot_die "$name must be an unsigned integer"
}

l1_snapshot_resolve_hardfork() {
    local requested="${ZONES_BENCH_TEMPO_HARDFORK:-latest}"
    requested="$(printf '%s' "$requested" | tr '[:upper:]' '[:lower:]')"
    [[ "$requested" == latest || "$requested" =~ ^t[0-9]+[a-z]*$ ]] \
        || l1_snapshot_die "ZONES_BENCH_TEMPO_HARDFORK must be latest or a hardfork such as t11"

    L1_SNAPSHOT_SUPPORTED_HARDFORKS=()
    local hardfork
    while IFS= read -r hardfork; do
        L1_SNAPSHOT_SUPPORTED_HARDFORKS+=("$hardfork")
    done < <(
        "$L1_SNAPSHOT_TEMPO_XTASK_BIN" generate-localnet --help \
            | sed -nE 's/^[[:space:]]*--(t[0-9]+[a-z]*)-time([[:space:]].*)?$/\1/p'
    )
    (( ${#L1_SNAPSHOT_SUPPORTED_HARDFORKS[@]} > 0 )) \
        || l1_snapshot_die "could not discover Tempo hardfork arguments"

    if [[ "$requested" == latest ]]; then
        local last_index
        last_index=$((${#L1_SNAPSHOT_SUPPORTED_HARDFORKS[@]} - 1))
        L1_SNAPSHOT_HARDFORK="${L1_SNAPSHOT_SUPPORTED_HARDFORKS[$last_index]}"
    else
        local found=0
        for hardfork in "${L1_SNAPSHOT_SUPPORTED_HARDFORKS[@]}"; do
            if [[ "$hardfork" == "$requested" ]]; then
                found=1
                L1_SNAPSHOT_HARDFORK="$hardfork"
                break
            fi
        done
        (( found )) \
            || l1_snapshot_die "Tempo revision does not support hardfork '$requested'; supported: ${L1_SNAPSHOT_SUPPORTED_HARDFORKS[*]}"
    fi

    L1_SNAPSHOT_HARDFORK_ARGS=()
    local activation=0 selected=0
    for hardfork in "${L1_SNAPSHOT_SUPPORTED_HARDFORKS[@]}"; do
        if (( selected )); then
            activation=$L1_SNAPSHOT_FUTURE_HARDFORK_TIME
        fi
        L1_SNAPSHOT_HARDFORK_ARGS+=("--${hardfork}-time" "$activation")
        if [[ "$hardfork" == "$L1_SNAPSHOT_HARDFORK" ]]; then
            selected=1
        fi
    done
}

l1_snapshot_sha256() {
    sha256sum -- "$1" | awk '{print $1}'
}

l1_snapshot_available_mib() {
    df -Pm -- "$1" | awk 'NR == 2 { print $4 }'
}

l1_snapshot_check_free_space() {
    local state_a_root="$1"
    local state_b_root="$2"
    local bloat_mib="$3"
    (( bloat_mib > 0 )) || return 0

    local import_multiplier=7
    local free_margin_mib=51200
    local import_working_set_mib=$((bloat_mib * import_multiplier))
    local required_a_mib=$((bloat_mib + import_working_set_mib + free_margin_mib))
    local required_b_mib=$((import_working_set_mib + free_margin_mib))
    local available_a_mib available_b_mib
    available_a_mib="$(l1_snapshot_available_mib "$state_a_root")"
    available_b_mib="$(l1_snapshot_available_mib "$state_b_root")"
    [[ "$available_a_mib" =~ ^[0-9]+$ ]] \
        || l1_snapshot_die "could not determine free space for $state_a_root"
    [[ "$available_b_mib" =~ ^[0-9]+$ ]] \
        || l1_snapshot_die "could not determine free space for $state_b_root"

    echo "checking Tempo L1 bloat import free space"
    echo "  validator A: available=$available_a_mib MiB required=$required_a_mib MiB"
    echo "  validator B: available=$available_b_mib MiB required=$required_b_mib MiB"
    (( available_a_mib >= required_a_mib )) \
        || l1_snapshot_die "validator A bloat import needs at least $required_a_mib MiB, but $state_a_root has $available_a_mib MiB"
    (( available_b_mib >= required_b_mib )) \
        || l1_snapshot_die "validator B bloat import needs at least $required_b_mib MiB, but $state_b_root has $available_b_mib MiB"
}

l1_snapshot_derive_address() {
    cast wallet address --mnemonic "$L1_SNAPSHOT_MNEMONIC_FILE" --mnemonic-index "$1"
}

l1_snapshot_artifact_hash() {
    local contract="$1"
    local artifact="$L1_SNAPSHOT_ZONES_ROOT/crates/contracts/out/$contract.sol/$contract.json"
    l1_snapshot_require_file "$artifact"
    jq -cS '{deployedBytecode, storageLayout}' "$artifact" | sha256sum | awk '{print $1}'
}

l1_snapshot_inputs_hash() {
    local relative path
    {
        for relative in \
            Cargo.lock \
            xtask/Cargo.toml \
            xtask/src/install_reference_zone_factory.rs \
            crates/contracts/Cargo.toml \
            crates/contracts/src/lib.rs \
            crates/contracts/src/precompiles/zone_factory.rs \
            crates/contracts/out/ZonePortal.sol/ZonePortal.json \
            crates/contracts/out/Verifier.sol/Verifier.json \
            crates/contracts/out/ZoneMessenger.sol/ZoneMessenger.json
        do
            path="$L1_SNAPSHOT_ZONES_ROOT/$relative"
            l1_snapshot_require_file "$path"
            printf '%s %s\n' "$relative" "$(l1_snapshot_sha256 "$path")"
        done
    } | sha256sum | awk '{print $1}'
}

l1_snapshot_allocation_hash() {
    jq -cS \
        --arg factory "${L1_SNAPSHOT_ZONE_FACTORY,,}" \
        --arg portalImpl "${L1_SNAPSHOT_PORTAL_IMPL,,}" \
        --arg verifier "${L1_SNAPSHOT_VERIFIER,,}" \
        --arg messenger "${L1_SNAPSHOT_MESSENGER,,}" \
        --arg history "${L1_SNAPSHOT_HISTORY,,}" '
        .alloc
        | to_entries
        | map(select(
            (.key | ascii_downcase) == $factory or
            (.key | ascii_downcase) == $portalImpl or
            (.key | ascii_downcase) == $verifier or
            (.key | ascii_downcase) == $messenger or
            (.key | ascii_downcase) == $history
        ))
        | sort_by(.key | ascii_downcase)
    ' "$L1_SNAPSHOT_PATCHED_GENESIS" | sha256sum | awk '{print $1}'
}

l1_snapshot_validate_secret_file() {
    [[ -n "${ZONES_BENCH_MNEMONIC_FILE:-}" ]] \
        || l1_snapshot_die "ZONES_BENCH_MNEMONIC_FILE must be set"
    L1_SNAPSHOT_MNEMONIC_FILE="$ZONES_BENCH_MNEMONIC_FILE"
    [[ ! -L "$L1_SNAPSHOT_MNEMONIC_FILE" ]] \
        || l1_snapshot_die "benchmark mnemonic file must not be a symbolic link"
    l1_snapshot_require_file "$L1_SNAPSHOT_MNEMONIC_FILE"
    [[ -s "$L1_SNAPSHOT_MNEMONIC_FILE" ]] \
        || l1_snapshot_die "benchmark mnemonic file is empty"

    local permissions
    permissions="$(stat -Lc '%a' "$L1_SNAPSHOT_MNEMONIC_FILE")"
    [[ "$permissions" =~ ^[0-7]{3,4}$ ]] \
        || l1_snapshot_die "could not parse permissions for $L1_SNAPSHOT_MNEMONIC_FILE"
    (( (8#$permissions & 077) == 0 )) \
        || l1_snapshot_die "benchmark mnemonic file must not be accessible by group or other users"

    [[ "$(awk 'END { print NR }' "$L1_SNAPSHOT_MNEMONIC_FILE")" == 1 ]] \
        || l1_snapshot_die "benchmark mnemonic file must contain exactly one line"
    if grep -Fqx -- "$L1_SNAPSHOT_PUBLIC_DEV_MNEMONIC" "$L1_SNAPSHOT_MNEMONIC_FILE"; then
        l1_snapshot_die "refusing to use the public Tempo development mnemonic"
    fi
}

l1_snapshot_load_config() {
    l1_snapshot_require_command awk
    l1_snapshot_require_command cast
    l1_snapshot_require_command df
    l1_snapshot_require_command forge
    l1_snapshot_require_command jq
    l1_snapshot_require_command sed
    l1_snapshot_require_command sha256sum
    l1_snapshot_require_command stat
    l1_snapshot_require_command tr
    l1_snapshot_validate_secret_file

    [[ -n "${TEMPO_ROOT:-}" ]] || l1_snapshot_die "TEMPO_ROOT must be set"
    L1_SNAPSHOT_TEMPO_BIN="${TEMPO_BIN:-$TEMPO_ROOT/target/profiling/tempo}"
    L1_SNAPSHOT_TEMPO_XTASK_BIN="${TEMPO_XTASK_BIN:-$TEMPO_ROOT/target/profiling/tempo-xtask}"
    L1_SNAPSHOT_ZONES_XTASK_BIN="${ZONES_XTASK_BIN:-$L1_SNAPSHOT_ZONES_ROOT/target/profiling/tempo-xtask}"
    l1_snapshot_require_executable "$L1_SNAPSHOT_TEMPO_BIN"
    l1_snapshot_require_executable "$L1_SNAPSHOT_TEMPO_XTASK_BIN"
    l1_snapshot_require_executable "$L1_SNAPSHOT_ZONES_XTASK_BIN"
    l1_snapshot_resolve_hardfork
    ZONES_BENCH_TEMPO_HARDFORK="$L1_SNAPSHOT_HARDFORK"

    ZONES_BENCH_ACCOUNT_START="${ZONES_BENCH_ACCOUNT_START:-16}"
    ZONES_BENCH_ACCOUNTS="${ZONES_BENCH_ACCOUNTS:-200}"
    ZONES_BENCH_ACCOUNT_CAPACITY="${ZONES_BENCH_ACCOUNT_CAPACITY:-10000}"
    ZONES_BENCH_L1_CHAIN_ID="${ZONES_BENCH_L1_CHAIN_ID:-1337}"
    ZONES_BENCH_L1_GAS_LIMIT="${ZONES_BENCH_L1_GAS_LIMIT:-30000000}"
    ZONES_BENCH_L1_GENERAL_GAS_LIMIT="${ZONES_BENCH_L1_GENERAL_GAS_LIMIT:-$ZONES_BENCH_L1_GAS_LIMIT}"
    ZONES_BENCH_BLOAT_MIB="${ZONES_BENCH_BLOAT_MIB:-0}"
    ZONES_BENCH_BLOAT_BALANCE="${ZONES_BENCH_BLOAT_BALANCE:-18446744073709551615}"
    ZONES_BENCH_LOCALNET_SEED="${ZONES_BENCH_LOCALNET_SEED:-42}"
    ZONES_BENCH_FORCE_BLOAT="${ZONES_BENCH_FORCE_BLOAT:-0}"
    for name in \
        ZONES_BENCH_ACCOUNT_START ZONES_BENCH_ACCOUNTS ZONES_BENCH_ACCOUNT_CAPACITY \
        ZONES_BENCH_L1_CHAIN_ID ZONES_BENCH_L1_GAS_LIMIT \
        ZONES_BENCH_L1_GENERAL_GAS_LIMIT ZONES_BENCH_BLOAT_MIB \
        ZONES_BENCH_BLOAT_BALANCE ZONES_BENCH_LOCALNET_SEED ZONES_BENCH_FORCE_BLOAT
    do
        l1_snapshot_require_uint "$name"
    done
    L1_SNAPSHOT_ACCOUNT_START=$((10#$ZONES_BENCH_ACCOUNT_START))
    L1_SNAPSHOT_ACCOUNTS=$((10#$ZONES_BENCH_ACCOUNTS))
    L1_SNAPSHOT_ACCOUNT_CAPACITY=$((10#$ZONES_BENCH_ACCOUNT_CAPACITY))
    L1_SNAPSHOT_CHAIN_ID=$((10#$ZONES_BENCH_L1_CHAIN_ID))
    L1_SNAPSHOT_GAS_LIMIT=$((10#$ZONES_BENCH_L1_GAS_LIMIT))
    L1_SNAPSHOT_GENERAL_GAS_LIMIT=$((10#$ZONES_BENCH_L1_GENERAL_GAS_LIMIT))
    L1_SNAPSHOT_BLOAT_MIB=$((10#$ZONES_BENCH_BLOAT_MIB))
    L1_SNAPSHOT_LOCALNET_SEED=$((10#$ZONES_BENCH_LOCALNET_SEED))
    L1_SNAPSHOT_FORCE=$((10#$ZONES_BENCH_FORCE_BLOAT))

    (( L1_SNAPSHOT_ACCOUNT_START >= 5 )) \
        || l1_snapshot_die "ZONES_BENCH_ACCOUNT_START must be at least 5"
    (( L1_SNAPSHOT_ACCOUNTS > 0 )) \
        || l1_snapshot_die "ZONES_BENCH_ACCOUNTS must be greater than zero"
    (( L1_SNAPSHOT_ACCOUNT_CAPACITY > 0 )) \
        || l1_snapshot_die "ZONES_BENCH_ACCOUNT_CAPACITY must be greater than zero"
    (( L1_SNAPSHOT_ACCOUNTS <= L1_SNAPSHOT_ACCOUNT_CAPACITY )) \
        || l1_snapshot_die "benchmark accounts exceed the cached funded-account capacity"
    (( L1_SNAPSHOT_CHAIN_ID > 0 && L1_SNAPSHOT_GAS_LIMIT > 0 && L1_SNAPSHOT_GENERAL_GAS_LIMIT > 0 )) \
        || l1_snapshot_die "chain ID and gas limits must be greater than zero"
    (( L1_SNAPSHOT_FORCE == 0 || L1_SNAPSHOT_FORCE == 1 )) \
        || l1_snapshot_die "ZONES_BENCH_FORCE_BLOAT must be 0 or 1"

    L1_SNAPSHOT_GENESIS_ACCOUNTS=$((L1_SNAPSHOT_ACCOUNT_START + L1_SNAPSHOT_ACCOUNT_CAPACITY))
    L1_SNAPSHOT_STATE_A_ROOT="${ZONES_BENCH_STATE_A_ROOT:-/reth-bench-a/zones-l1-${L1_SNAPSHOT_BLOAT_MIB}mb}"
    L1_SNAPSHOT_STATE_B_ROOT="${ZONES_BENCH_STATE_B_ROOT:-/reth-bench-b/zones-l1-${L1_SNAPSHOT_BLOAT_MIB}mb}"
    ZONES_BENCH_STATE_A_ROOT="$L1_SNAPSHOT_STATE_A_ROOT"
    ZONES_BENCH_STATE_B_ROOT="$L1_SNAPSHOT_STATE_B_ROOT"
    L1_SNAPSHOT_LOCALNET_DIR="$L1_SNAPSHOT_STATE_A_ROOT/localnet"
    L1_SNAPSHOT_RAW_GENESIS="$L1_SNAPSHOT_LOCALNET_DIR/genesis.json"
    L1_SNAPSHOT_PATCHED_GENESIS="$L1_SNAPSHOT_STATE_A_ROOT/tempo-genesis.json"
    L1_SNAPSHOT_A_DB="$L1_SNAPSHOT_STATE_A_ROOT/l1-a"
    L1_SNAPSHOT_B_DB="$L1_SNAPSHOT_STATE_B_ROOT/l1-b"
    L1_SNAPSHOT_A_MANIFEST="$L1_SNAPSHOT_STATE_A_ROOT/manifest.json"
    L1_SNAPSHOT_B_MANIFEST="$L1_SNAPSHOT_STATE_B_ROOT/manifest.json"
    L1_SNAPSHOT_STATUS_FILE="${ZONES_BENCH_L1_CACHE_STATUS_FILE:-}"
}

l1_snapshot_prepare_expectations() {
    echo "building native ZoneFactory shared runtime artifacts"
    forge build --root "$L1_SNAPSHOT_ZONES_ROOT/crates/contracts" --skip test --no-lint >/dev/null

    local factory_hash portal_hash verifier_hash messenger_hash genesis_inputs_hash tempo_patch_hash
    factory_hash="$(l1_snapshot_sha256 "$L1_SNAPSHOT_ZONES_ROOT/crates/contracts/src/precompiles/zone_factory.rs")"
    portal_hash="$(l1_snapshot_artifact_hash ZonePortal)"
    verifier_hash="$(l1_snapshot_artifact_hash Verifier)"
    messenger_hash="$(l1_snapshot_artifact_hash ZoneMessenger)"
    genesis_inputs_hash="$(l1_snapshot_inputs_hash)"
    local tempo_patch="$L1_SNAPSHOT_ZONES_ROOT/contrib/bench/patches/tempo-xtask-mnemonic-file.patch"
    l1_snapshot_require_file "$tempo_patch"
    tempo_patch_hash="$(l1_snapshot_sha256 "$tempo_patch")"

    local tempo_revision="${ZONES_BENCH_TEMPO_REF:-}"
    if [[ -z "$tempo_revision" ]]; then
        tempo_revision="$(git -C "$TEMPO_ROOT" rev-parse HEAD)"
    fi
    [[ "$tempo_revision" =~ ^[0-9a-fA-F]{40}$ ]] \
        || l1_snapshot_die "ZONES_BENCH_TEMPO_REF must be an exact commit SHA"

    local owner validator_a validator_b admin sequencer first last
    owner="$(l1_snapshot_derive_address 0)"
    validator_a="$(l1_snapshot_derive_address 1)"
    validator_b="$(l1_snapshot_derive_address 2)"
    admin="$(l1_snapshot_derive_address 3)"
    sequencer="$(l1_snapshot_derive_address 4)"
    first="$(l1_snapshot_derive_address "$L1_SNAPSHOT_ACCOUNT_START")"
    last="$(l1_snapshot_derive_address $((L1_SNAPSHOT_ACCOUNT_START + L1_SNAPSHOT_ACCOUNT_CAPACITY - 1)))"

    L1_SNAPSHOT_EXPECTED_CONFIG="$(jq -cnS \
        --arg tempoRevision "${tempo_revision,,}" \
        --arg tempoHardfork "$L1_SNAPSHOT_HARDFORK" \
        --arg tempoPatchSha256 "$tempo_patch_hash" \
        --arg genesisInputsSha256 "$genesis_inputs_hash" \
        --arg factoryArtifactSha256 "$factory_hash" \
        --arg portalArtifactSha256 "$portal_hash" \
        --arg verifierArtifactSha256 "$verifier_hash" \
        --arg messengerArtifactSha256 "$messenger_hash" \
        --arg owner "$owner" --arg validatorA "$validator_a" --arg validatorB "$validator_b" \
        --arg admin "$admin" --arg sequencer "$sequencer" --arg first "$first" --arg last "$last" \
        --arg bloatBalance "$ZONES_BENCH_BLOAT_BALANCE" \
        --argjson schema "$L1_SNAPSHOT_SCHEMA" \
        --argjson accountStart "$L1_SNAPSHOT_ACCOUNT_START" \
        --argjson accountCapacity "$L1_SNAPSHOT_ACCOUNT_CAPACITY" \
        --argjson genesisAccounts "$L1_SNAPSHOT_GENESIS_ACCOUNTS" \
        --argjson chainId "$L1_SNAPSHOT_CHAIN_ID" \
        --argjson gasLimit "$L1_SNAPSHOT_GAS_LIMIT" \
        --argjson generalGasLimit "$L1_SNAPSHOT_GENERAL_GAS_LIMIT" \
        --argjson bloatMiB "$L1_SNAPSHOT_BLOAT_MIB" \
        --argjson localnetSeed "$L1_SNAPSHOT_LOCALNET_SEED" '
        {
          schema: $schema,
          tempo: {
            revision: $tempoRevision,
            hardfork: $tempoHardfork,
            mnemonicFilePatchSha256: $tempoPatchSha256
          },
          zonesGenesis: {
            inputsSha256: $genesisInputsSha256,
            factoryArtifactSha256: $factoryArtifactSha256,
            portalArtifactSha256: $portalArtifactSha256,
            verifierArtifactSha256: $verifierArtifactSha256,
            messengerArtifactSha256: $messengerArtifactSha256
          },
          l1: {
            chainId: $chainId,
            blockGasLimit: $gasLimit,
            generalGasLimit: $generalGasLimit,
            localnetSeed: $localnetSeed,
            validators: ["127.0.0.2:8000", "127.0.0.3:8100"]
          },
          accounts: {
            start: $accountStart,
            capacity: $accountCapacity,
            genesisAccounts: $genesisAccounts,
            publicIdentity: {
              owner: $owner,
              validatorA: $validatorA,
              validatorB: $validatorB,
              portalAdmin: $admin,
              sequencer: $sequencer,
              firstBenchmark: $first,
              lastBenchmark: $last
            }
          },
          bloat: {
            sizeMiB: $bloatMiB,
            balance: $bloatBalance,
            signableCount: $genesisAccounts,
            tokenIds: [0, 1, 2, 3]
          }
        }
    ')"
    L1_SNAPSHOT_CACHE_KEY="$(printf '%s' "$L1_SNAPSHOT_EXPECTED_CONFIG" | sha256sum | awk '{print $1}')"
}

l1_snapshot_required_files_exist() {
    local validator_a="$L1_SNAPSHOT_LOCALNET_DIR/127.0.0.2:8000"
    local validator_b="$L1_SNAPSHOT_LOCALNET_DIR/127.0.0.3:8100"
    local path
    for path in \
        "$L1_SNAPSHOT_RAW_GENESIS" "$L1_SNAPSHOT_PATCHED_GENESIS" \
        "$L1_SNAPSHOT_A_MANIFEST" "$L1_SNAPSHOT_B_MANIFEST" \
        "$validator_a/signing.key" "$validator_a/signing.share" \
        "$validator_a/enode.key" "$validator_a/enode.identity" \
        "$validator_b/signing.key" "$validator_b/signing.share" \
        "$validator_b/enode.key" "$validator_b/enode.identity"
    do
        [[ -f "$path" ]] || { echo "missing $path" >&2; return 1; }
    done
    for path in \
        "$L1_SNAPSHOT_A_DB/db" "$L1_SNAPSHOT_A_DB/static_files" \
        "$L1_SNAPSHOT_B_DB/db" "$L1_SNAPSHOT_B_DB/static_files"
    do
        [[ -d "$path" ]] || { echo "missing $path" >&2; return 1; }
    done
}

l1_snapshot_validate_cache() {
    l1_snapshot_required_files_exist || return 1

    jq -e --arg role a --arg key "$L1_SNAPSHOT_CACHE_KEY" \
        --argjson expected "$L1_SNAPSHOT_EXPECTED_CONFIG" '
        .schema == 1 and .role == $role and .cacheKey == $key and .config == $expected
    ' "$L1_SNAPSHOT_A_MANIFEST" >/dev/null || { echo "validator A manifest does not match requested inputs" >&2; return 1; }
    jq -e --arg role b --arg key "$L1_SNAPSHOT_CACHE_KEY" \
        --argjson expected "$L1_SNAPSHOT_EXPECTED_CONFIG" '
        .schema == 1 and .role == $role and .cacheKey == $key and .config == $expected
    ' "$L1_SNAPSHOT_B_MANIFEST" >/dev/null || { echo "validator B manifest does not match requested inputs" >&2; return 1; }

    local generation_a generation_b patched_a patched_b raw_a raw_b allocation_a allocation_b
    generation_a="$(jq -er '.generationId' "$L1_SNAPSHOT_A_MANIFEST")"
    generation_b="$(jq -er '.generationId' "$L1_SNAPSHOT_B_MANIFEST")"
    [[ -n "$generation_a" && "$generation_a" == "$generation_b" ]] \
        || { echo "validator snapshots are from different generations" >&2; return 1; }
    patched_a="$(jq -er '.patchedGenesisSha256' "$L1_SNAPSHOT_A_MANIFEST")"
    patched_b="$(jq -er '.patchedGenesisSha256' "$L1_SNAPSHOT_B_MANIFEST")"
    raw_a="$(jq -er '.rawGenesisSha256' "$L1_SNAPSHOT_A_MANIFEST")"
    raw_b="$(jq -er '.rawGenesisSha256' "$L1_SNAPSHOT_B_MANIFEST")"
    allocation_a="$(jq -er '.factoryGenesisAllocationSha256' "$L1_SNAPSHOT_A_MANIFEST")"
    allocation_b="$(jq -er '.factoryGenesisAllocationSha256' "$L1_SNAPSHOT_B_MANIFEST")"
    [[ "$patched_a" == "$patched_b" && "$patched_a" == "$(l1_snapshot_sha256 "$L1_SNAPSHOT_PATCHED_GENESIS")" ]] \
        || { echo "patched genesis hash does not match both manifests" >&2; return 1; }
    [[ "$raw_a" == "$raw_b" && "$raw_a" == "$(l1_snapshot_sha256 "$L1_SNAPSHOT_RAW_GENESIS")" ]] \
        || { echo "raw genesis hash does not match both manifests" >&2; return 1; }
    [[ "$allocation_a" == "$allocation_b" && "$allocation_a" == "$(l1_snapshot_allocation_hash)" ]] \
        || { echo "factory genesis allocation hash does not match both manifests" >&2; return 1; }
    L1_SNAPSHOT_GENERATION_ID="$generation_a"
}

l1_snapshot_validate_root_for_rebuild() {
    local root="$1"
    [[ "$root" == /* && "$root" != / ]] \
        || l1_snapshot_die "unsafe L1 snapshot root: $root"
    [[ "$(basename -- "$root")" == zones-l1-* ]] \
        || l1_snapshot_die "L1 snapshot root basename must start with zones-l1-: $root"
    [[ "$(dirname -- "$root")" != / ]] \
        || l1_snapshot_die "refusing broad L1 snapshot root: $root"
    [[ ! -L "$root" ]] || l1_snapshot_die "L1 snapshot root must not be a symbolic link: $root"
}

l1_snapshot_write_status() {
    local rebuilt="$1"
    [[ -n "$L1_SNAPSHOT_STATUS_FILE" ]] || return 0
    mkdir -p -- "$(dirname -- "$L1_SNAPSHOT_STATUS_FILE")"
    local temporary="$L1_SNAPSHOT_STATUS_FILE.tmp.$$"
    (umask 077; {
        printf 'export ZONES_BENCH_L1_CACHE_REBUILT=%q\n' "$rebuilt"
        printf 'export ZONES_BENCH_TEMPO_HARDFORK=%q\n' "$L1_SNAPSHOT_HARDFORK"
        printf 'export ZONES_BENCH_L1_CACHE_KEY=%q\n' "$L1_SNAPSHOT_CACHE_KEY"
        printf 'export ZONES_BENCH_L1_CACHE_GENERATION=%q\n' "$L1_SNAPSHOT_GENERATION_ID"
    } >"$temporary")
    mv -f -- "$temporary" "$L1_SNAPSHOT_STATUS_FILE"
}

l1_snapshot_build() {
    l1_snapshot_validate_root_for_rebuild "$L1_SNAPSHOT_STATE_A_ROOT"
    l1_snapshot_validate_root_for_rebuild "$L1_SNAPSHOT_STATE_B_ROOT"
    rm -rf -- "$L1_SNAPSHOT_STATE_A_ROOT" "$L1_SNAPSHOT_STATE_B_ROOT"
    mkdir -p "$L1_SNAPSHOT_STATE_A_ROOT" "$L1_SNAPSHOT_STATE_B_ROOT"
    l1_snapshot_check_free_space "$L1_SNAPSHOT_STATE_A_ROOT" "$L1_SNAPSHOT_STATE_B_ROOT" "$L1_SNAPSHOT_BLOAT_MIB"

    "$L1_SNAPSHOT_TEMPO_XTASK_BIN" generate-localnet --help | grep -F -- '--mnemonic-file' >/dev/null \
        || l1_snapshot_die "pinned Tempo xtask lacks required --mnemonic-file support"
    "$L1_SNAPSHOT_TEMPO_XTASK_BIN" generate-state-bloat --help | grep -F -- '--mnemonic-file' >/dev/null \
        || l1_snapshot_die "pinned Tempo bloat generator lacks required --mnemonic-file support"

    echo "generating two-validator Tempo consensus genesis"
    "$L1_SNAPSHOT_TEMPO_XTASK_BIN" generate-localnet \
        --output "$L1_SNAPSHOT_LOCALNET_DIR" \
        --accounts "$L1_SNAPSHOT_GENESIS_ACCOUNTS" \
        --mnemonic-file "$L1_SNAPSHOT_MNEMONIC_FILE" \
        --chain-id "$L1_SNAPSHOT_CHAIN_ID" \
        --gas-limit "$L1_SNAPSHOT_GAS_LIMIT" \
        --general-gas-limit "$L1_SNAPSHOT_GENERAL_GAS_LIMIT" \
        --validators 127.0.0.2:8000,127.0.0.3:8100 \
        "${L1_SNAPSHOT_HARDFORK_ARGS[@]}" \
        --seed "$L1_SNAPSHOT_LOCALNET_SEED"

    echo "installing the native ZoneFactory marker and shared runtimes in genesis"
    "$L1_SNAPSHOT_ZONES_XTASK_BIN" install-reference-zone-factory \
        --genesis "$L1_SNAPSHOT_RAW_GENESIS" \
        --output "$L1_SNAPSHOT_PATCHED_GENESIS" \
        --owner "$(l1_snapshot_derive_address 0)" \
        --specs-out "$L1_SNAPSHOT_ZONES_ROOT/crates/contracts/out"
    [[ "$(jq -er '.config.chainId' "$L1_SNAPSHOT_PATCHED_GENESIS")" == "$L1_SNAPSHOT_CHAIN_ID" ]] \
        || l1_snapshot_die "patched genesis chain ID is incorrect"
    [[ "$(jq -er '.config.generalGasLimit' "$L1_SNAPSHOT_PATCHED_GENESIS")" == "$L1_SNAPSHOT_GENERAL_GAS_LIMIT" ]] \
        || l1_snapshot_die "patched genesis general gas limit is incorrect"

    mkdir -p "$L1_SNAPSHOT_A_DB" "$L1_SNAPSHOT_B_DB"
    "$L1_SNAPSHOT_TEMPO_BIN" init --chain "$L1_SNAPSHOT_PATCHED_GENESIS" --datadir "$L1_SNAPSHOT_A_DB"
    "$L1_SNAPSHOT_TEMPO_BIN" init --chain "$L1_SNAPSHOT_PATCHED_GENESIS" --datadir "$L1_SNAPSHOT_B_DB"

    if (( L1_SNAPSHOT_BLOAT_MIB > 0 )); then
        local bloat_tmp_dir="${ZONES_BENCH_BLOAT_TMP_DIR:-$L1_SNAPSHOT_STATE_A_ROOT/.bloat-tmp}"
        local bloat_file="$bloat_tmp_dir/state-bloat.bin"
        mkdir -p "$bloat_tmp_dir"
        local bloat_accounts_per_token=$(((L1_SNAPSHOT_BLOAT_MIB * 1024 * 1024 - 4 * 104) / (64 * 4)))
        (( bloat_accounts_per_token >= L1_SNAPSHOT_GENESIS_ACCOUNTS )) \
            || l1_snapshot_die "$L1_SNAPSHOT_BLOAT_MIB MiB of four-token bloat covers only $bloat_accounts_per_token signable accounts per token; need $L1_SNAPSHOT_GENESIS_ACCOUNTS"
        echo "generating $L1_SNAPSHOT_BLOAT_MIB MiB of four-token Tempo state bloat"
        "$L1_SNAPSHOT_TEMPO_XTASK_BIN" generate-state-bloat \
            --size "$L1_SNAPSHOT_BLOAT_MIB" \
            --out "$bloat_file" \
            --mnemonic-file "$L1_SNAPSHOT_MNEMONIC_FILE" \
            --balance "$ZONES_BENCH_BLOAT_BALANCE" \
            --signable-count "$L1_SNAPSHOT_GENESIS_ACCOUNTS" \
            --token 0 --token 1 --token 2 --token 3
        "$L1_SNAPSHOT_TEMPO_BIN" init-from-binary-dump \
            --chain "$L1_SNAPSHOT_PATCHED_GENESIS" --datadir "$L1_SNAPSHOT_A_DB" "$bloat_file"
        "$L1_SNAPSHOT_TEMPO_BIN" init-from-binary-dump \
            --chain "$L1_SNAPSHOT_PATCHED_GENESIS" --datadir "$L1_SNAPSHOT_B_DB" "$bloat_file"
        rm -f -- "$bloat_file"
        rmdir -- "$bloat_tmp_dir" 2>/dev/null || true
    fi

    local patched_sha raw_sha allocation_sha generation_id manifest_tmp
    patched_sha="$(l1_snapshot_sha256 "$L1_SNAPSHOT_PATCHED_GENESIS")"
    raw_sha="$(l1_snapshot_sha256 "$L1_SNAPSHOT_RAW_GENESIS")"
    allocation_sha="$(l1_snapshot_allocation_hash)"
    generation_id="$(printf '%s:%s:%s' "$L1_SNAPSHOT_CACHE_KEY" "$(date +%s%N)" "$$" | sha256sum | awk '{print $1}')"
    local role manifest
    for role in a b; do
        if [[ "$role" == a ]]; then
            manifest="$L1_SNAPSHOT_A_MANIFEST"
        else
            manifest="$L1_SNAPSHOT_B_MANIFEST"
        fi
        manifest_tmp="$manifest.tmp.$$"
        jq -nS \
            --argjson schema "$L1_SNAPSHOT_SCHEMA" \
            --arg role "$role" \
            --arg cacheKey "$L1_SNAPSHOT_CACHE_KEY" \
            --arg generationId "$generation_id" \
            --arg patchedGenesisSha256 "$patched_sha" \
            --arg rawGenesisSha256 "$raw_sha" \
            --arg factoryGenesisAllocationSha256 "$allocation_sha" \
            --argjson config "$L1_SNAPSHOT_EXPECTED_CONFIG" '
            {
              schema: $schema,
              role: $role,
              cacheKey: $cacheKey,
              generationId: $generationId,
              patchedGenesisSha256: $patchedGenesisSha256,
              rawGenesisSha256: $rawGenesisSha256,
              factoryGenesisAllocationSha256: $factoryGenesisAllocationSha256,
              config: $config
            }
        ' >"$manifest_tmp"
        mv -f -- "$manifest_tmp" "$manifest"
    done
    l1_snapshot_validate_cache || l1_snapshot_die "new L1 snapshot failed validation"
}

l1_snapshot_prepare() {
    l1_snapshot_load_config
    l1_snapshot_prepare_expectations
    if (( L1_SNAPSHOT_FORCE == 0 )) && l1_snapshot_validate_cache; then
        echo "Tempo L1 snapshot cache hit: $L1_SNAPSHOT_CACHE_KEY"
        l1_snapshot_write_status 0
        return
    fi
    if (( L1_SNAPSHOT_FORCE == 1 )); then
        echo "force-bloat requested; rebuilding the paired Tempo L1 snapshot"
    else
        echo "Tempo L1 snapshot cache miss; rebuilding both validators"
    fi
    l1_snapshot_build
    echo "Tempo L1 snapshot prepared for promotion: $L1_SNAPSHOT_CACHE_KEY"
    l1_snapshot_write_status 1
}

l1_snapshot_verify() {
    l1_snapshot_load_config
    l1_snapshot_prepare_expectations
    l1_snapshot_validate_cache || l1_snapshot_die "Tempo L1 snapshot validation failed"
    echo "Tempo L1 snapshot verified: $L1_SNAPSHOT_CACHE_KEY"
    l1_snapshot_write_status "${ZONES_BENCH_L1_CACHE_REBUILT:-0}"
}

l1_snapshot_usage() {
    cat <<'EOF'
Usage:
  contrib/bench/l1-snapshot.sh prepare
  contrib/bench/l1-snapshot.sh verify

`prepare` validates the restored private Schelk copies and builds both L1
baselines on a cache miss or when ZONES_BENCH_FORCE_BLOAT=1. The caller must
promote both volumes and restore private copies before calling `verify`.
EOF
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
    case "${1:-}" in
        prepare) l1_snapshot_prepare ;;
        verify) l1_snapshot_verify ;;
        *) l1_snapshot_usage >&2; exit 2 ;;
    esac
fi
