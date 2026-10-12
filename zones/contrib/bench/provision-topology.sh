#!/usr/bin/env bash

# Provision the production-shaped local topology used by the Zones benchmark:
# two real Tempo consensus validators plus one release/profiling Zone sequencer.
#
# The caller must build the binaries first. A typical workflow uses the Tempo
# revision pinned in the Zones workspace and passes:
#
#   TEMPO_ROOT=/path/to/tempo
#   TEMPO_BIN=/path/to/tempo/target/profiling/tempo
#   TEMPO_XTASK_BIN=/path/to/tempo/target/profiling/tempo-xtask
#   ZONES_XTASK_BIN=/path/to/zones/target/profiling/tempo-xtask
#   ZONE_BIN=/path/to/zones/target/profiling/tempo-zone
#
# `prepare-l1` builds the paired L1 baseline on a cache miss but deliberately
# leaves Schelk promotion to the caller. `up` starts from a verified private
# restored copy and stops after node and contract readiness. It does not fund
# Zone accounts, submit benchmark deposits, or wait for benchmark bridge events.
# On success the processes remain alive for the neobank scenario runner.
# Always call `cleanup` from the workflow's `if: always()` teardown step.

set -Eeuo pipefail

readonly SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
readonly ZONES_ROOT="$(cd -- "$SCRIPT_DIR/../.." && pwd)"
readonly ZONE_FACTORY="0x5aF2000000000000000000000000000000000000"
readonly PATH_USD="0x20C0000000000000000000000000000000000000"
readonly DLUSD="0x20C0000000000000000000000000000000000001"
readonly TEMPO_STATE="0x1c00000000000000000000000000000000000000"
readonly EIP2935_HISTORY_STORAGE="0x0000F90827F1C53a10cb7A02335B175320002935"
readonly LOCALNET_SIGNING_SECRET="tempo-localnet-signing-key-secret"

provision_succeeded=0
provision_pid_file=""
provision_secret_files=()

die() {
    echo "error: $*" >&2
    exit 1
}

require_command() {
    command -v "$1" >/dev/null 2>&1 || die "required command not found: $1"
}

require_file() {
    [[ -f "$1" ]] || die "required file not found: $1"
}

require_executable() {
    [[ -x "$1" ]] || die "required executable not found: $1"
}

require_uint() {
    local name="$1"
    local value="${!name:-}"
    [[ "$value" =~ ^[0-9]+$ ]] || die "$name must be an unsigned integer"
}

rpc() {
    local url="$1"
    local method="$2"
    local params="${3:-[]}" response
    response="$(curl --silent --show-error --fail \
        --header 'Content-Type: application/json' \
        --data "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"$method\",\"params\":$params}" \
        "$url")" || return 1
    jq -e '.error == null' >/dev/null <<<"$response" || return 1
    jq -r '.result' <<<"$response"
}

hex_to_dec() {
    local value="$1"
    [[ "$value" =~ ^0x[0-9a-fA-F]+$ ]] || return 1
    printf '%d\n' "$((16#${value#0x}))"
}

wait_for_rpc() {
    local url="$1"
    local label="$2"
    local timeout="$3"
    local deadline=$((SECONDS + timeout))
    while (( SECONDS < deadline )); do
        if rpc "$url" eth_blockNumber >/dev/null 2>&1; then
            return 0
        fi
        sleep 1
    done
    die "timed out waiting for $label RPC at $url"
}

wait_for_peer() {
    local url="$1"
    local label="$2"
    local timeout="$3"
    local deadline=$((SECONDS + timeout)) peer_hex peer_count
    while (( SECONDS < deadline )); do
        peer_hex="$(rpc "$url" net_peerCount 2>/dev/null || true)"
        peer_count="$(hex_to_dec "$peer_hex" 2>/dev/null || true)"
        if [[ -n "$peer_count" ]] && (( peer_count >= 1 )); then
            return 0
        fi
        sleep 1
    done
    die "timed out waiting for $label to connect to its Tempo peer"
}

wait_for_chain_advance() {
    local url="$1"
    local label="$2"
    local timeout="$3"
    local start_hex start_block current_hex current_block
    local deadline=$((SECONDS + timeout))

    start_hex="$(rpc "$url" eth_blockNumber)"
    start_block="$(hex_to_dec "$start_hex")"
    while (( SECONDS < deadline )); do
        current_hex="$(rpc "$url" eth_blockNumber 2>/dev/null || true)"
        current_block="$(hex_to_dec "$current_hex" 2>/dev/null || true)"
        if [[ -n "$current_block" ]] && (( current_block > start_block )); then
            return 0
        fi
        sleep 1
    done
    die "timed out waiting for $label chain to advance past block $start_block"
}

verify_shared_runtimes() {
    local url="$1" label="$2" block spec contract address expected observed
    block="$(rpc "$url" eth_blockNumber)" || die "$label failed to read the runtime verification block"
    (( $(hex_to_dec "$block") > 0 )) || die "$label has not produced a block to verify shared runtimes"
    for spec in \
        ZonePortal:0x5AD1000000000000000000000000000000000000 \
        Verifier:0x5a56000000000000000000000000000000000000 \
        ZoneMessenger:0x5A4d000000000000000000000000000000000000
    do
        contract="${spec%%:*}" address="${spec#*:}"
        expected="$(jq -er '.deployedBytecode.object | sub("^0x"; "") | select(test("^([0-9a-fA-F]{2})+$"))' \
            "$ZONES_ROOT/crates/contracts/out/$contract.sol/$contract.json")" \
            || die "invalid or missing $contract deployed bytecode artifact"
        observed="$(rpc "$url" eth_getCode "[\"$address\",\"$block\"]")" \
            || die "$label failed to read $contract runtime at $address"
        [[ "${observed,,}" == "0x${expected,,}" ]] \
            || die "$label $contract runtime at $address differs from the local artifact after block $block; refusing to benchmark replaced runtimes"
    done
}

verify_history_storage() {
    local url="$1"
    local label="$2"
    local code current_hex current_block probe_block probe_hex calldata expected observed

    code="$(rpc "$url" eth_getCode "[\"$EIP2935_HISTORY_STORAGE\",\"latest\"]")"
    [[ "$code" != "0x" ]] \
        || die "$label is missing the EIP-2935 history storage contract"

    current_hex="$(rpc "$url" eth_blockNumber)"
    current_block="$(hex_to_dec "$current_hex")"
    (( current_block > 0 )) \
        || die "$label has not advanced far enough to verify EIP-2935 history"
    probe_block=$((current_block - 1))
    printf -v probe_hex '0x%x' "$probe_block"
    printf -v calldata '0x%064x' "$probe_block"
    expected="$(rpc "$url" eth_getBlockByNumber "[\"$probe_hex\",false]" | jq -er '.hash')"
    observed="$(rpc "$url" eth_call \
        "[{\"to\":\"$EIP2935_HISTORY_STORAGE\",\"data\":\"$calldata\"},\"latest\"]")"
    [[ "${observed,,}" == "${expected,,}" ]] \
        || die "$label EIP-2935 history mismatch for block $probe_block: expected $expected, got $observed"
}

process_matches() {
    local pid="$1"
    local expected="$2"
    [[ -r "/proc/$pid/cmdline" ]] || return 1
    tr '\0' ' ' <"/proc/$pid/cmdline" | grep -F -- "$expected" >/dev/null
}

cleanup_pid_file() {
    local pid_file="$1"
    [[ -f "$pid_file" ]] || return 0

    local -a records=()
    mapfile -t records <"$pid_file"

    local index name pid expected
    for ((index = ${#records[@]} - 1; index >= 0; index--)); do
        read -r name pid expected <<<"${records[index]}"
        [[ "$pid" =~ ^[0-9]+$ ]] || continue
        if kill -0 "$pid" 2>/dev/null; then
            if ! process_matches "$pid" "$expected"; then
                echo "warning: refusing to signal reused PID $pid for $name" >&2
                continue
            fi
            echo "stopping $name (PID $pid)"
            kill -INT "$pid" 2>/dev/null || true
        fi
    done

    local deadline=$((SECONDS + 30)) any_running
    while (( SECONDS < deadline )); do
        any_running=0
        for record in "${records[@]}"; do
            read -r name pid expected <<<"$record"
            if [[ "$pid" =~ ^[0-9]+$ ]] && kill -0 "$pid" 2>/dev/null \
                && process_matches "$pid" "$expected"; then
                any_running=1
                break
            fi
        done
        (( any_running == 0 )) && break
        sleep 1
    done

    for ((index = ${#records[@]} - 1; index >= 0; index--)); do
        read -r name pid expected <<<"${records[index]}"
        if [[ "$pid" =~ ^[0-9]+$ ]] && kill -0 "$pid" 2>/dev/null \
            && process_matches "$pid" "$expected"; then
            echo "forcing $name to stop (PID $pid)" >&2
            kill -KILL "$pid" 2>/dev/null || true
        fi
    done

    rm -f -- "$pid_file"
}

stop_stale_listener() {
    local port="$1"
    local expected="$2"
    local label="$3"
    local -a pids=()
    local pid deadline

    mapfile -t pids < <(lsof -nP -t -iTCP:"$port" -sTCP:LISTEN 2>/dev/null | sort -u || true)
    (( ${#pids[@]} == 0 )) && return 0

    for pid in "${pids[@]}"; do
        [[ "$pid" =~ ^[0-9]+$ ]] || continue
        process_matches "$pid" "$expected" ||
            die "TCP port $port is owned by PID $pid, not a stale $label process; refusing to signal it"
        echo "stopping stale $label listener on TCP port $port (PID $pid)" >&2
        kill -INT "$pid" 2>/dev/null || true
    done

    deadline=$((SECONDS + 30))
    while (( SECONDS < deadline )); do
        for pid in "${pids[@]}"; do
            if [[ "$pid" =~ ^[0-9]+$ ]] && kill -0 "$pid" 2>/dev/null \
                && process_matches "$pid" "$expected"; then
                sleep 1
                continue 2
            fi
        done
        return 0
    done

    for pid in "${pids[@]}"; do
        if [[ "$pid" =~ ^[0-9]+$ ]] && kill -0 "$pid" 2>/dev/null \
            && process_matches "$pid" "$expected"; then
            echo "forcing stale $label listener to stop on TCP port $port (PID $pid)" >&2
            kill -KILL "$pid" 2>/dev/null || true
        fi
    done
}

provision_on_exit() {
    local status=$?
    trap - EXIT INT TERM
    if (( ${#provision_secret_files[@]} > 0 )); then
        rm -f -- "${provision_secret_files[@]}"
    fi
    if (( provision_succeeded == 0 )) && [[ -n "$provision_pid_file" ]]; then
        cleanup_pid_file "$provision_pid_file"
    fi
    exit "$status"
}

start_process() {
    local name="$1"
    local expected="$2"
    local cpu_set="$3"
    local log_file="$4"
    shift 4

    local -a command=("$@")
    if [[ -n "$cpu_set" ]]; then
        command=(taskset --cpu-list "$cpu_set" "${command[@]}")
    fi

    "${command[@]}" >"$log_file" 2>&1 &
    local pid=$!
    printf '%s %s %s\n' "$name" "$pid" "$expected" >>"$pid_file"

    sleep 2
    if ! kill -0 "$pid" 2>/dev/null; then
        echo "$name exited during startup; log follows:" >&2
        tail -n 200 "$log_file" >&2 || true
        return 1
    fi
}

derive_key() {
    local mnemonic_file="$1"
    local index="$2"
    cast wallet private-key --mnemonic "$mnemonic_file" --mnemonic-index "$index"
}

derive_address() {
    local mnemonic_file="$1"
    local index="$2"
    cast wallet address --mnemonic "$mnemonic_file" --mnemonic-index "$index"
}

wait_for_zone_enabled_token() {
    local zone_rpc="$1" token="$2" timeout="$3"
    local deadline=$((SECONDS + timeout)) code
    while (( SECONDS < deadline )); do
        code="$(rpc "$zone_rpc" eth_getCode "[\"$token\",\"latest\"]" 2>/dev/null || true)"
        [[ -n "$code" && "$code" != "0x" ]] && return 0
        sleep 1
    done
    die "timed out waiting for Zone to deploy enabled token $token"
}



verify_neobank_token_topology() {
    local l1_rpc="$1"
    local portal="$2"
    local base_token="$3"
    local earn_token="$4"
    local count enabled active token token0 token1

    for token in "$base_token" "$earn_token"; do
        enabled="$(cast call "$portal" 'isTokenEnabled(address)(bool)' "$token" \
            --rpc-url "$l1_rpc" | awk '{print $1}')"
        active="$(cast call "$portal" 'areDepositsActive(address)(bool)' "$token" \
            --rpc-url "$l1_rpc" | awk '{print $1}')"
        [[ "$enabled" == "true" ]] || die "neobank Zone token $token is not enabled"
        [[ "$active" == "true" ]] || die "neobank Zone deposits are inactive for token $token"
    done

    count="$(cast call "$portal" 'enabledTokenCount()(uint256)' \
        --rpc-url "$l1_rpc" | awk '{print $1}')"
    [[ "$count" == "2" ]] ||
        die "neobank Zone must have exactly two enabled tokens; portal reports $count"
    token0="$(cast call "$portal" 'enabledTokenAt(uint256)(address)' 0 \
        --rpc-url "$l1_rpc" | awk '{print $1}')"
    token1="$(cast call "$portal" 'enabledTokenAt(uint256)(address)' 1 \
        --rpc-url "$l1_rpc" | awk '{print $1}')"
    if [[ "${token0,,}" != "${base_token,,}" || "${token1,,}" != "${earn_token,,}" ]] \
        && [[ "${token1,,}" != "${base_token,,}" || "${token0,,}" != "${earn_token,,}" ]]; then
        die "neobank Zone enabled-token set does not match the preset base token and EarnToken"
    fi
}

verify_neobank_fixture_topology() {
    local l1_rpc="$1"
    local metadata="$2"
    local expected_owner="$3"
    local expected_asset="$4"
    local expected_swap_mechanism="$5"
    local expected_private_asset="$6"
    local field address code vault engine earn_factory earn_vault earn_fees earn_router
    local contribution_controller earn_share dlusd pathusd private_asset bridge_wallet zone_id
    local swap_mechanism route_swapper route_override controller reserve_ledger
    local observed observed_asset observed_owner observed_engine observed_vault transaction_limit
    local observed_earn_vault observed_earn_share observed_earn_fees
    local earn_vault_implementation earn_fees_implementation
    local tip20_factory="0x20FC000000000000000000000000000000000000"

    vault="$(jq -er '.vault' "$metadata")"
    engine="$(jq -er '.engine' "$metadata")"
    earn_factory="$(jq -er '.earnFactory' "$metadata")"
    earn_vault="$(jq -er '.earnVault' "$metadata")"
    earn_fees="$(jq -er '.earnFees' "$metadata")"
    earn_router="$(jq -er '.earnRouter' "$metadata")"
    contribution_controller="$(jq -er '.contributionController' "$metadata")"
    earn_share="$(jq -er '.earnShare' "$metadata")"
    bridge_wallet="$(jq -er '.bridgeWallet' "$metadata")"
    dlusd="$(jq -er '.dlusd' "$metadata")"
    pathusd="$(jq -er '.pathusd' "$metadata")"
    private_asset="$(jq -er '.privateAsset' "$metadata")"
    zone_id="$(jq -er '.zoneId' "$metadata")"
    swap_mechanism="$(jq -er '.swapMechanism' "$metadata")"
    route_swapper="$(jq -r '.routeSwapper // empty' "$metadata")"
    route_override="$(jq -er \
        '.routeOverride | if type == "boolean" then tostring else error("routeOverride must be boolean") end' \
        "$metadata")"
    [[ "$swap_mechanism" == "$expected_swap_mechanism" ]] \
        || die "fixture swap mechanism $swap_mechanism does not match requested $expected_swap_mechanism"
    [[ "${private_asset,,}" == "${expected_private_asset,,}" ]] \
        || die "fixture private asset does not match the preset Zone token"

    for field in \
        vault engine earn_factory earn_vault earn_fees earn_router \
        contribution_controller bridge_wallet
    do
        address="${!field}"
        code="$(rpc "$l1_rpc" eth_getCode "[\"$address\",\"latest\"]")"
        [[ "$code" != "0x" ]] || die "neobank $field fixture has no code at $address"
    done

    observed_asset="$(cast call "$vault" 'asset()(address)' --rpc-url "$l1_rpc" | awk '{print $1}')"
    [[ "${observed_asset,,}" == "${expected_asset,,}" ]] ||
        die "ERC-4626 fixture asset does not match pathUSD"

    observed_engine="$(cast call "$earn_vault" 'engine()(address)' --rpc-url "$l1_rpc" | awk '{print $1}')"
    observed_asset="$(cast call "$earn_vault" 'asset()(address)' --rpc-url "$l1_rpc" | awk '{print $1}')"
    observed_earn_share="$(cast call "$earn_vault" 'earnShare()(address)' --rpc-url "$l1_rpc" | awk '{print $1}')"
    observed_earn_fees="$(cast call "$earn_vault" 'earnFees()(address)' --rpc-url "$l1_rpc" | awk '{print $1}')"
    observed_owner="$(cast call "$earn_vault" 'operator()(address)' --rpc-url "$l1_rpc" | awk '{print $1}')"
    [[ "${observed_engine,,}" == "${engine,,}" ]] ||
        die "EarnVault engine does not match fixture metadata"
    [[ "${observed_asset,,}" == "${expected_asset,,}" ]] ||
        die "EarnVault asset does not match pathUSD"
    [[ "${observed_earn_share,,}" == "${earn_share,,}" ]] ||
        die "EarnVault EarnShare does not match fixture metadata"
    [[ "${observed_earn_fees,,}" == "${earn_fees,,}" ]] ||
        die "EarnVault EarnFees does not match fixture metadata"
    [[ "${observed_owner,,}" == "${expected_owner,,}" ]] ||
        die "EarnVault operator does not match the benchmark control account"

    observed_vault="$(cast call "$engine" 'vault()(address)' --rpc-url "$l1_rpc" | awk '{print $1}')"
    observed_earn_vault="$(cast call "$engine" 'earnVault()(address)' --rpc-url "$l1_rpc" | awk '{print $1}')"
    observed_asset="$(cast call "$engine" 'asset()(address)' --rpc-url "$l1_rpc" | awk '{print $1}')"
    [[ "${observed_vault,,}" == "${vault,,}" ]] ||
        die "ERC4626Engine vault does not match fixture metadata"
    [[ "${observed_earn_vault,,}" == "${earn_vault,,}" ]] ||
        die "ERC4626Engine EarnVault does not match fixture metadata"
    [[ "${observed_asset,,}" == "${expected_asset,,}" ]] ||
        die "ERC4626Engine asset does not match pathUSD"

    observed_earn_vault="$(cast call "$contribution_controller" 'earnVault()(address)' --rpc-url "$l1_rpc" | awk '{print $1}')"
    observed_asset="$(cast call "$contribution_controller" 'asset()(address)' --rpc-url "$l1_rpc" | awk '{print $1}')"
    observed_owner="$(cast call "$contribution_controller" 'owner()(address)' --rpc-url "$l1_rpc" | awk '{print $1}')"
    [[ "${observed_earn_vault,,}" == "${earn_vault,,}" ]] ||
        die "EarnContributionController EarnVault does not match fixture metadata"
    [[ "${observed_asset,,}" == "${expected_asset,,}" ]] ||
        die "EarnContributionController asset does not match pathUSD"
    [[ "${observed_owner,,}" == "${expected_owner,,}" ]] ||
        die "EarnContributionController owner does not match the benchmark control account"

    observed_earn_vault="$(cast call "$earn_fees" 'earnVault()(address)' --rpc-url "$l1_rpc" | awk '{print $1}')"
    observed_earn_share="$(cast call "$earn_fees" 'earnShare()(address)' --rpc-url "$l1_rpc" | awk '{print $1}')"
    [[ "${observed_earn_vault,,}" == "${earn_vault,,}" ]] ||
        die "EarnFees EarnVault does not match fixture metadata"
    [[ "${observed_earn_share,,}" == "${earn_share,,}" ]] ||
        die "EarnFees EarnShare does not match fixture metadata"

    [[ "$(cast call "$earn_router" 'supportsFlow(uint8)(bool)' 0 --rpc-url "$l1_rpc" | awk '{print $1}')" == "true" ]] ||
        die "EarnRouter does not support deposit callbacks"
    [[ "$(cast call "$earn_router" 'supportsFlow(uint8)(bool)' 1 --rpc-url "$l1_rpc" | awk '{print $1}')" == "true" ]] ||
        die "EarnRouter does not support redeem callbacks"

    observed="$(cast call "$earn_factory" 'tip20Factory()(address)' --rpc-url "$l1_rpc" | awk '{print $1}')"
    [[ "${observed,,}" == "${tip20_factory,,}" ]] ||
        die "EarnFactory TIP-20 factory does not match the canonical precompile"
    earn_vault_implementation="$(cast call "$earn_factory" 'earnVaultImplementation()(address)' --rpc-url "$l1_rpc" | awk '{print $1}')"
    earn_fees_implementation="$(cast call "$earn_factory" 'earnFeesImplementation()(address)' --rpc-url "$l1_rpc" | awk '{print $1}')"
    for address in "$earn_vault_implementation" "$earn_fees_implementation"; do
        code="$(rpc "$l1_rpc" eth_getCode "[\"$address\",\"latest\"]")"
        [[ "$code" != "0x" ]] || die "EarnFactory implementation has no code at $address"
    done

    observed="$(cast call "$earn_router" 'earnVault()(address)' --rpc-url "$l1_rpc" | awk '{print $1}')"
    [[ "${observed,,}" == "${earn_vault,,}" ]] ||
        die "single-Zone Earn router vault does not match fixture metadata"
    observed="$(cast call "$earn_router" 'privateAsset()(address)' --rpc-url "$l1_rpc" | awk '{print $1}')"
    [[ "${observed,,}" == "${private_asset,,}" ]] ||
        die "single-Zone Earn router private asset does not match fixture metadata"
    observed="$(cast call "$earn_router" 'vaultAsset()(address)' --rpc-url "$l1_rpc" | awk '{print $1}')"
    [[ "${observed,,}" == "${pathusd,,}" ]] ||
        die "single-Zone Earn router vault asset does not match pathUSD"
    observed="$(cast call "$earn_router" 'earnShare()(address)' --rpc-url "$l1_rpc" | awk '{print $1}')"
    [[ "${observed,,}" == "${earn_share,,}" ]] ||
        die "single-Zone Earn router EarnShare does not match fixture metadata"
    observed="$(cast call "$earn_router" 'allowedZoneId()(uint32)' --rpc-url "$l1_rpc" | awk '{print $1}')"
    [[ "$observed" == "$zone_id" ]] ||
        die "single-Zone Earn router Zone ID does not match fixture metadata"

    case "$swap_mechanism" in
        direct-swap)
            controller="$(jq -er '.tokenAuthority' "$metadata")"
            reserve_ledger="$(jq -er '.reserveLedger' "$metadata")"
            for field in controller reserve_ledger; do
                address="${!field}"
                code="$(rpc "$l1_rpc" eth_getCode "[\"$address\",\"latest\"]")"
                [[ "$code" != "0x" ]] || die "neobank $field fixture has no code at $address"
            done
            [[ "$route_override" == "true" ]] ||
                die "current Earn requires its immutable single-Zone router route"
            [[ "${route_swapper,,}" == "${earn_router,,}" ]] ||
                die "Earn router metadata addresses differ"

            observed="$(cast call "$earn_router" 'tokenAuthority()(address)' --rpc-url "$l1_rpc" | awk '{print $1}')"
            [[ "${observed,,}" == "${controller,,}" ]] ||
                die "single-Zone Earn router token authority does not match fixture metadata"
            observed="$(cast call "$earn_router" 'reserveToken()(address)' --rpc-url "$l1_rpc" | awk '{print $1}')"
            [[ "${observed,,}" == "${reserve_ledger,,}" ]] ||
                die "single-Zone Earn router reserve token does not match fixture metadata"
            observed="$(cast call "$controller" 'RESERVE_LEDGER_TOKEN()(address)' --rpc-url "$l1_rpc" | awk '{print $1}')"
            [[ "${observed,,}" == "${reserve_ledger,,}" ]] ||
                die "token authority reserve token does not match fixture metadata"

            transaction_limit="$(jq -er '.liquidity' "$metadata")"
            observed="$(cast call "$earn_router" 'transactionLimit()(uint256)' --rpc-url "$l1_rpc" | awk '{print $1}')"
            [[ "$observed" == "$transaction_limit" ]] ||
                die "single-Zone Earn router transaction limit does not match fixture liquidity"
            for address in "$dlusd" "$pathusd"; do
                observed="$(cast call "$controller" 'getStablecoinTxnMintLimit(address)(uint256)' \
                    "$address" --rpc-url "$l1_rpc" | awk '{print $1}')"
                [[ "$observed" == "$transaction_limit" ]] ||
                    die "token authority transaction limit does not match fixture liquidity"
                observed="$(cast call "$controller" 'getReserveStore(address)(address)' \
                    "$address" --rpc-url "$l1_rpc" | awk '{print $1}')"
                [[ "${observed,,}" != "0x0000000000000000000000000000000000000000" ]] ||
                    die "token authority reserve store was not created"
                code="$(rpc "$l1_rpc" eth_getCode "[\"$observed\",\"latest\"]")"
                [[ "$code" != "0x" ]] || die "token authority reserve store has no code at $observed"
            done
            ;;
        *)
            die "unsupported fixture swap mechanism in metadata: $swap_mechanism"
            ;;
    esac
}

write_env() {
    local env_file="$1"
    shift
    mkdir -p -- "$(dirname -- "$env_file")"
    : >"$env_file"
    chmod 600 "$env_file"
    while (( $# > 0 )); do
        local name="$1"
        local value="$2"
        shift 2
        printf 'export %s=%q\n' "$name" "$value" >>"$env_file"
    done
}

provision_up() {
    require_command awk
    require_command cast
    require_command curl
    require_command jq
    require_command lsof
    require_command mktemp
    require_command taskset

    [[ -n "${ZONES_BENCH_MNEMONIC_FILE:-}" ]] || die "ZONES_BENCH_MNEMONIC_FILE must be set"
    require_file "$ZONES_BENCH_MNEMONIC_FILE"
    [[ -n "${TEMPO_ROOT:-}" ]] || die "TEMPO_ROOT must be set"

    TEMPO_BIN="${TEMPO_BIN:-$TEMPO_ROOT/target/profiling/tempo}"
    TEMPO_XTASK_BIN="${TEMPO_XTASK_BIN:-$TEMPO_ROOT/target/profiling/tempo-xtask}"
    ZONES_XTASK_BIN="${ZONES_XTASK_BIN:-$ZONES_ROOT/target/profiling/tempo-xtask}"
    ZONE_BIN="${ZONE_BIN:-$ZONES_ROOT/target/profiling/tempo-zone}"
    require_executable "$TEMPO_BIN"
    require_executable "$TEMPO_XTASK_BIN"
    require_executable "$ZONES_XTASK_BIN"
    require_executable "$ZONE_BIN"

    # A cancelled workflow can prevent its checkout-scoped teardown from
    # running. Only reclaim listeners owned by the exact benchmark binaries;
    # fail rather than signal an unrelated process.
    stop_stale_listener 8545 "$TEMPO_BIN" "Tempo validator A"
    stop_stale_listener 8645 "$TEMPO_BIN" "Tempo validator B"
    stop_stale_listener 8546 "$ZONE_BIN" "Zone"

    local account_start="${ZONES_BENCH_ACCOUNT_START:-16}"
    local accounts="${ZONES_BENCH_ACCOUNTS:-100}"
    local account_capacity="${ZONES_BENCH_ACCOUNT_CAPACITY:-10000}"
    local l1_chain_id="${ZONES_BENCH_L1_CHAIN_ID:-1337}"
    local l1_gas_limit="${ZONES_BENCH_L1_GAS_LIMIT:-30000000}"
    local l1_general_gas_limit="${ZONES_BENCH_L1_GENERAL_GAS_LIMIT:-$l1_gas_limit}"
    local zone_gas_limit="${ZONES_BENCH_ZONE_GAS_LIMIT:-30000000}"
    local l1_max_fee_per_gas="${ZONES_BENCH_L1_MAX_FEE_PER_GAS:-12000000000}"
    local zone_max_fee_per_gas="${ZONES_BENCH_ZONE_MAX_FEE_PER_GAS:-10000000000}"
    local bloat_mib="${ZONES_BENCH_BLOAT_MIB:-1024}"
    local bloat_balance="${ZONES_BENCH_BLOAT_BALANCE:-18446744073709551615}"
    local rpc_timeout="${ZONES_BENCH_RPC_TIMEOUT_SECS:-300}"
    local zone_timeout="${ZONES_BENCH_ZONE_TIMEOUT_SECS:-300}"
    local swap_mechanism="${ZONES_BENCH_SWAP_MECHANISM:-direct-swap}"
    local recipient_mode="${ZONES_BENCH_RECIPIENT_MODE:-existing}"
    local swap_liquidity="${ZONES_BENCH_SWAP_LIQUIDITY:-10000000000}"
    local count="${ZONES_BENCH_COUNT:-100}"
    local max_concurrent="${ZONES_BENCH_MAX_CONCURRENT:-12}"
    local withdrawal_amount="${ZONES_BENCH_WITHDRAWAL_AMOUNT:-1000000}"
    local callback_gas_limit="${ZONES_BENCH_CALLBACK_GAS_LIMIT:-5000000}"
    local withdrawal_max_batch_gas="${ZONES_BENCH_WITHDRAWAL_MAX_BATCH_GAS:-20000000}"
    local withdrawal_max_in_flight_batches="${ZONES_BENCH_WITHDRAWAL_MAX_IN_FLIGHT_BATCHES:-12}"
    local zone_batch_interval_blocks="${ZONES_BENCH_ZONE_BATCH_INTERVAL_BLOCKS:-120}"
    local withdrawal_poll_interval_secs="${ZONES_BENCH_WITHDRAWAL_POLL_INTERVAL_SECS:-5}"
    local step_timeout="${ZONES_BENCH_STEP_TIMEOUT:-10m}"
    local setup_settlement_timeout_secs="${ZONES_BENCH_SETUP_SETTLEMENT_TIMEOUT_SECS:-120}"
    local drain_timeout="${ZONES_BENCH_DRAIN_TIMEOUT:-300}"
    local run_key="${GITHUB_RUN_ID:-local}-${GITHUB_RUN_ATTEMPT:-1}"
    local neobank_preset="${ZONES_BENCH_NEOBANK_PRESET:-full-journey}"
    case "$neobank_preset" in
        encrypted-deposit|private-withdrawal|full-journey|slippage-bounce|swapped-lifecycle|swapped-redemption) ;;
        *) die "unsupported neobank preset for provisioning: $neobank_preset" ;;
    esac

    ZONES_BENCH_ACCOUNT_START="$account_start"
    ZONES_BENCH_ACCOUNTS="$accounts"
    ZONES_BENCH_ACCOUNT_CAPACITY="$account_capacity"
    ZONES_BENCH_L1_CHAIN_ID="$l1_chain_id"
    ZONES_BENCH_L1_GAS_LIMIT="$l1_gas_limit"
    ZONES_BENCH_L1_GENERAL_GAS_LIMIT="$l1_general_gas_limit"
    ZONES_BENCH_ZONE_GAS_LIMIT="$zone_gas_limit"
    ZONES_BENCH_L1_MAX_FEE_PER_GAS="$l1_max_fee_per_gas"
    ZONES_BENCH_ZONE_MAX_FEE_PER_GAS="$zone_max_fee_per_gas"
    ZONES_BENCH_BLOAT_MIB="$bloat_mib"
    ZONES_BENCH_BLOAT_BALANCE="$bloat_balance"
    ZONES_BENCH_RPC_TIMEOUT_SECS="$rpc_timeout"
    ZONES_BENCH_ZONE_TIMEOUT_SECS="$zone_timeout"
    ZONES_BENCH_SWAP_MECHANISM="$swap_mechanism"
    ZONES_BENCH_RECIPIENT_MODE="$recipient_mode"
    ZONES_BENCH_SWAP_LIQUIDITY="$swap_liquidity"
    ZONES_BENCH_COUNT="$count"
    ZONES_BENCH_MAX_CONCURRENT="$max_concurrent"
    ZONES_BENCH_WITHDRAWAL_AMOUNT="$withdrawal_amount"
    ZONES_BENCH_CALLBACK_GAS_LIMIT="$callback_gas_limit"
    ZONES_BENCH_WITHDRAWAL_MAX_BATCH_GAS="$withdrawal_max_batch_gas"
    ZONES_BENCH_WITHDRAWAL_MAX_IN_FLIGHT_BATCHES="$withdrawal_max_in_flight_batches"
    ZONES_BENCH_ZONE_BATCH_INTERVAL_BLOCKS="$zone_batch_interval_blocks"
    ZONES_BENCH_WITHDRAWAL_POLL_INTERVAL_SECS="$withdrawal_poll_interval_secs"
    ZONES_BENCH_SETUP_SETTLEMENT_TIMEOUT_SECS="$setup_settlement_timeout_secs"
    ZONES_BENCH_DRAIN_TIMEOUT="$drain_timeout"
    for name in \
        ZONES_BENCH_ACCOUNT_START ZONES_BENCH_ACCOUNTS ZONES_BENCH_ACCOUNT_CAPACITY \
        ZONES_BENCH_L1_CHAIN_ID \
        ZONES_BENCH_L1_GAS_LIMIT ZONES_BENCH_L1_GENERAL_GAS_LIMIT ZONES_BENCH_ZONE_GAS_LIMIT \
        ZONES_BENCH_L1_MAX_FEE_PER_GAS ZONES_BENCH_ZONE_MAX_FEE_PER_GAS \
        ZONES_BENCH_BLOAT_MIB ZONES_BENCH_BLOAT_BALANCE \
        ZONES_BENCH_RPC_TIMEOUT_SECS ZONES_BENCH_ZONE_TIMEOUT_SECS \
        ZONES_BENCH_SWAP_LIQUIDITY ZONES_BENCH_COUNT ZONES_BENCH_MAX_CONCURRENT \
        ZONES_BENCH_WITHDRAWAL_AMOUNT ZONES_BENCH_CALLBACK_GAS_LIMIT \
        ZONES_BENCH_WITHDRAWAL_MAX_BATCH_GAS ZONES_BENCH_WITHDRAWAL_MAX_IN_FLIGHT_BATCHES \
        ZONES_BENCH_ZONE_BATCH_INTERVAL_BLOCKS ZONES_BENCH_WITHDRAWAL_POLL_INTERVAL_SECS \
        ZONES_BENCH_SETUP_SETTLEMENT_TIMEOUT_SECS ZONES_BENCH_DRAIN_TIMEOUT
    do
        require_uint "$name"
    done
    account_start=$((10#$account_start))
    accounts=$((10#$accounts))
    account_capacity=$((10#$account_capacity))
    l1_chain_id=$((10#$l1_chain_id))
    l1_gas_limit=$((10#$l1_gas_limit))
    l1_general_gas_limit=$((10#$l1_general_gas_limit))
    zone_gas_limit=$((10#$zone_gas_limit))
    l1_max_fee_per_gas=$((10#$l1_max_fee_per_gas))
    zone_max_fee_per_gas=$((10#$zone_max_fee_per_gas))
    bloat_mib=$((10#$bloat_mib))
    rpc_timeout=$((10#$rpc_timeout))
    zone_timeout=$((10#$zone_timeout))
    swap_liquidity=$((10#$swap_liquidity))
    count=$((10#$count))
    max_concurrent=$((10#$max_concurrent))
    withdrawal_amount=$((10#$withdrawal_amount))
    callback_gas_limit=$((10#$callback_gas_limit))
    withdrawal_max_batch_gas=$((10#$withdrawal_max_batch_gas))
    withdrawal_max_in_flight_batches=$((10#$withdrawal_max_in_flight_batches))
    zone_batch_interval_blocks=$((10#$zone_batch_interval_blocks))
    withdrawal_poll_interval_secs=$((10#$withdrawal_poll_interval_secs))
    setup_settlement_timeout_secs=$((10#$setup_settlement_timeout_secs))
    drain_timeout=$((10#$drain_timeout))
    (( accounts > 0 )) || die "ZONES_BENCH_ACCOUNTS must be greater than zero"
    (( accounts <= account_capacity )) \
        || die "ZONES_BENCH_ACCOUNTS exceeds the cached funded-account capacity"
    (( account_start >= 5 )) || die "ZONES_BENCH_ACCOUNT_START must be at least 5; indices 0-4 are reserved for the factory owner, two validator identities, portal admin, and sequencer"
    (( l1_chain_id > 0 )) || die "ZONES_BENCH_L1_CHAIN_ID must be greater than zero"
    (( l1_gas_limit > 0 )) || die "ZONES_BENCH_L1_GAS_LIMIT must be greater than zero"
    (( l1_general_gas_limit > 0 )) \
        || die "ZONES_BENCH_L1_GENERAL_GAS_LIMIT must be greater than zero"
    (( zone_gas_limit > 0 )) || die "ZONES_BENCH_ZONE_GAS_LIMIT must be greater than zero"
    (( l1_general_gas_limit <= l1_gas_limit )) \
        || die "ZONES_BENCH_L1_GENERAL_GAS_LIMIT cannot exceed ZONES_BENCH_L1_GAS_LIMIT"
    (( l1_max_fee_per_gas > 0 )) \
        || die "ZONES_BENCH_L1_MAX_FEE_PER_GAS must be greater than zero"
    (( zone_max_fee_per_gas > 0 )) \
        || die "ZONES_BENCH_ZONE_MAX_FEE_PER_GAS must be greater than zero"
    (( rpc_timeout > 0 )) || die "ZONES_BENCH_RPC_TIMEOUT_SECS must be greater than zero"
    (( zone_timeout > 0 )) || die "ZONES_BENCH_ZONE_TIMEOUT_SECS must be greater than zero"
    case "$swap_mechanism" in
        direct-swap) ;;
        *) die "current Earn only supports ZONES_BENCH_SWAP_MECHANISM=direct-swap" ;;
    esac
    case "$recipient_mode" in
        existing|random) ;;
        *) die "ZONES_BENCH_RECIPIENT_MODE must be existing or random" ;;
    esac
    (( swap_liquidity > 0 )) || die "ZONES_BENCH_SWAP_LIQUIDITY must be greater than zero"
    (( count > 0 )) || die "ZONES_BENCH_COUNT must be greater than zero"
    (( max_concurrent > 0 )) || die "ZONES_BENCH_MAX_CONCURRENT must be greater than zero"
    (( withdrawal_amount > 0 )) || die "ZONES_BENCH_WITHDRAWAL_AMOUNT must be greater than zero"
    local required_swap_uses=0
    case "$neobank_preset" in
        full-journey|swapped-lifecycle) required_swap_uses="$max_concurrent" ;;
        private-withdrawal|swapped-redemption)
            local setup_journeys_per_account
            setup_journeys_per_account=$(((count + accounts - 1) / accounts))
            local callback_reservation callbacks_per_batch setup_batch_uses
            callback_reservation=$((1750000 + callback_gas_limit))
            callbacks_per_batch=$(((withdrawal_max_batch_gas - 500000) / callback_reservation))
            (( callbacks_per_batch > 0 )) || callbacks_per_batch=1
            setup_batch_uses=$((callbacks_per_batch * setup_journeys_per_account))
            required_swap_uses="$max_concurrent"
            (( setup_batch_uses <= required_swap_uses )) ||
                required_swap_uses="$setup_batch_uses"
            ;;
        slippage-bounce) required_swap_uses=1 ;;
    esac
    if (( required_swap_uses > 0 && swap_liquidity / withdrawal_amount < required_swap_uses )); then
        die "$swap_mechanism liquidity must cover $required_swap_uses swap(s) of ZONES_BENCH_WITHDRAWAL_AMOUNT=$withdrawal_amount for $neobank_preset"
    fi
    (( callback_gas_limit > 0 && callback_gas_limit <= 10000000 )) \
        || die "ZONES_BENCH_CALLBACK_GAS_LIMIT must be between 1 and 10000000"
    (( withdrawal_max_batch_gas > 0 && withdrawal_max_batch_gas <= 20000000 )) \
        || die "ZONES_BENCH_WITHDRAWAL_MAX_BATCH_GAS must be between 1 and 20000000"
    (( withdrawal_max_batch_gas <= l1_general_gas_limit )) \
        || die "ZONES_BENCH_WITHDRAWAL_MAX_BATCH_GAS cannot exceed ZONES_BENCH_L1_GENERAL_GAS_LIMIT"
    local planned_singleton_withdrawal_gas=0
    case "$neobank_preset" in
        encrypted-deposit) ;;
        # The untimed Earn warmup always uses the 10M protocol maximum.
        *) planned_singleton_withdrawal_gas=$((500000 + 1750000 + 10000000)) ;;
    esac
    (( planned_singleton_withdrawal_gas == 0 ||
       planned_singleton_withdrawal_gas <= l1_general_gas_limit )) \
        || die "ZONES_BENCH_L1_GENERAL_GAS_LIMIT cannot fit a withdrawal planned at $planned_singleton_withdrawal_gas gas"
    (( withdrawal_max_in_flight_batches > 0 )) \
        || die "ZONES_BENCH_WITHDRAWAL_MAX_IN_FLIGHT_BATCHES must be greater than zero"
    (( withdrawal_max_in_flight_batches <= 10000 )) \
        || die "ZONES_BENCH_WITHDRAWAL_MAX_IN_FLIGHT_BATCHES cannot exceed 10000"
    (( zone_batch_interval_blocks > 0 && zone_batch_interval_blocks <= 1000000 )) \
        || die "ZONES_BENCH_ZONE_BATCH_INTERVAL_BLOCKS must be between 1 and 1000000"
    (( withdrawal_poll_interval_secs > 0 && withdrawal_poll_interval_secs <= 86400 )) \
        || die "ZONES_BENCH_WITHDRAWAL_POLL_INTERVAL_SECS must be between 1 and 86400"
    (( setup_settlement_timeout_secs > 0 && setup_settlement_timeout_secs <= 86400 )) \
        || die "ZONES_BENCH_SETUP_SETTLEMENT_TIMEOUT_SECS must be between 1 and 86400"
    (( drain_timeout <= 86400 )) \
        || die "ZONES_BENCH_DRAIN_TIMEOUT cannot exceed 86400"
    [[ "$step_timeout" =~ ^[1-9][0-9]*(ms|s|m|h)$ ]] \
        || die "ZONES_BENCH_STEP_TIMEOUT must be a positive duration ending in ms, s, m, or h"

    export ZONES_BENCH_ACCOUNT_START ZONES_BENCH_ACCOUNTS ZONES_BENCH_ACCOUNT_CAPACITY
    export ZONES_BENCH_L1_CHAIN_ID ZONES_BENCH_L1_GAS_LIMIT ZONES_BENCH_L1_GENERAL_GAS_LIMIT
    export ZONES_BENCH_ZONE_GAS_LIMIT
    export ZONES_BENCH_L1_MAX_FEE_PER_GAS ZONES_BENCH_ZONE_MAX_FEE_PER_GAS
    export ZONES_BENCH_BLOAT_MIB ZONES_BENCH_BLOAT_BALANCE
    export ZONES_BENCH_SWAP_MECHANISM ZONES_BENCH_RECIPIENT_MODE ZONES_BENCH_SWAP_LIQUIDITY
    export ZONES_BENCH_CALLBACK_GAS_LIMIT
    export ZONES_BENCH_WITHDRAWAL_MAX_BATCH_GAS ZONES_BENCH_WITHDRAWAL_MAX_IN_FLIGHT_BATCHES
    export ZONES_BENCH_ZONE_BATCH_INTERVAL_BLOCKS ZONES_BENCH_WITHDRAWAL_POLL_INTERVAL_SECS

    "$SCRIPT_DIR/l1-snapshot.sh" verify

    local control_root="${ZONES_BENCH_TOPOLOGY_DIR:-}"
    if [[ -z "$control_root" ]]; then
        control_root="$(mktemp -d "${RUNNER_TEMP:-/tmp}/zones-benchmark-topology.XXXXXX")"
    else
        [[ ! -e "$control_root" ]] || die "ZONES_BENCH_TOPOLOGY_DIR already exists: $control_root"
        mkdir -p "$control_root"
    fi

    local state_a_root="${ZONES_BENCH_STATE_A_ROOT:-/reth-bench-a/zones-l1-${bloat_mib}mb}"
    local state_b_root="${ZONES_BENCH_STATE_B_ROOT:-/reth-bench-b/zones-l1-${bloat_mib}mb}"
    [[ -d "$state_a_root" ]] || die "validator A L1 snapshot is missing: $state_a_root"
    [[ -d "$state_b_root" ]] || die "validator B L1 snapshot is missing: $state_b_root"
    local zone_state_root="${ZONES_BENCH_ZONE_STATE_ROOT:-/reth-bench-a/zones-runtime-$run_key}"
    [[ ! -e "$zone_state_root" ]] || die "Zone runtime state path already exists: $zone_state_root"
    mkdir -p "$zone_state_root"

    local localnet_dir="$state_a_root/localnet"
    local patched_genesis="$state_a_root/tempo-genesis.json"
    local l1_a_db="$state_a_root/l1-a"
    local l1_b_db="$state_b_root/l1-b"
    local zone_db="$zone_state_root/zone"
    local zone_dir="$control_root/zone"
    local log_dir="$control_root/logs"
    local env_file="${ZONES_BENCH_ENV_FILE:-$control_root/topology.env}"
    pid_file="${ZONES_BENCH_PID_FILE:-$control_root/topology.pids}"
    mkdir -p "$log_dir" "$(dirname -- "$pid_file")"
    : >"$pid_file"
    chmod 600 "$pid_file"

    provision_succeeded=0
    provision_pid_file="$pid_file"
    trap provision_on_exit EXIT
    trap 'exit 130' INT TERM

    local mnemonic_file="$ZONES_BENCH_MNEMONIC_FILE"
    local owner_key sequencer_key admin_key owner_address admin_address sequencer_address
    owner_key="$(derive_key "$mnemonic_file" 0)"
    admin_key="$(derive_key "$mnemonic_file" 3)"
    sequencer_key="$(derive_key "$mnemonic_file" 4)"
    owner_address="$(derive_address "$mnemonic_file" 0)"
    admin_address="$(derive_address "$mnemonic_file" 3)"
    sequencer_address="$(derive_address "$mnemonic_file" 4)"
    local -a neobank_allowed_accounts=()
    neobank_allowed_accounts+=("$owner_address")
    local account_index account_address
    for ((account_index = account_start; account_index < account_start + accounts; account_index++)); do
        account_address="$(derive_address "$mnemonic_file" "$account_index")"
        neobank_allowed_accounts+=("$account_address")
    done
    local neobank_allowed_accounts_file
    neobank_allowed_accounts_file="$(mktemp \
        "${RUNNER_TEMP:-/tmp}/zones-neobank-allowed-accounts.XXXXXX")"
    chmod 600 "$neobank_allowed_accounts_file"
    provision_secret_files+=("$neobank_allowed_accounts_file")
    printf '%s\n' "${neobank_allowed_accounts[@]}" >"$neobank_allowed_accounts_file"

    mkdir -p "$zone_db" "$zone_dir"

    local validator_a="$localnet_dir/127.0.0.2:8000"
    local validator_b="$localnet_dir/127.0.0.3:8100"
    for path in \
        "$validator_a/signing.key" "$validator_a/signing.share" "$validator_a/enode.key" "$validator_a/enode.identity" \
        "$validator_b/signing.key" "$validator_b/signing.share" "$validator_b/enode.key" "$validator_b/enode.identity"
    do
        require_file "$path"
    done
    local trusted_peers
    trusted_peers="enode://$(tr -d '[:space:]' <"$validator_a/enode.identity")@127.0.0.2:8001,enode://$(tr -d '[:space:]' <"$validator_b/enode.identity")@127.0.0.3:8101"
    local consensus_secret="$control_root/consensus-secret"
    (umask 077; printf '%s\n' "$LOCALNET_SIGNING_SECRET" >"$consensus_secret")

    local -a common_l1_args=(
        --ipcdisable
        --disable-discovery
        --trusted-only
        --tempo.bootnodes-endpoint none
        --consensus.no-legacy-archive
        --engine.share-execution-cache-with-payload-builder
        --builder.enable-prewarming
        --builder.gaslimit "$l1_gas_limit"
        --rpc.eth-proof-window 1024
        --rpc.max-connections 10000
        --txpool.pending-max-count 200000
        --txpool.basefee-max-count 200000
        --txpool.queued-max-count 200000
        --txpool.max-pending-txns 200000
        --txpool.max-new-txns 200000
        --txpool.max-batch-size 200000
    )

    start_process tempo-a "$TEMPO_BIN" "${ZONES_BENCH_L1_A_CPUS:-0-3,16-19}" "$log_dir/tempo-a.log" \
        "$TEMPO_BIN" node \
        --chain "$patched_genesis" --datadir "$l1_a_db" \
        --http --http.addr 127.0.0.1 --http.port 8545 --http.api all \
        --ws --ws.addr 127.0.0.1 --ws.port 8545 --ws.api all \
        --metrics 127.0.0.1:9001 \
        --log.file.directory "$log_dir/tempo-a" \
        --consensus.signing-key "$validator_a/signing.key" \
        --consensus.secret "$consensus_secret" \
        --consensus.signing-share "$validator_a/signing.share" \
        --consensus.listen-address 127.0.0.2:8000 \
        --consensus.metrics-address 127.0.0.2:8002 \
        --trusted-peers "$trusted_peers" \
        --port 8001 --discovery.port 8001 --discovery.v5.port 8004 \
        --p2p-secret-key "$validator_a/enode.key" --authrpc.port 8003 \
        --consensus.use-local-defaults --consensus.bypass-ip-check \
        "${common_l1_args[@]}"

    start_process tempo-b "$TEMPO_BIN" "${ZONES_BENCH_L1_B_CPUS:-4-7,20-23}" "$log_dir/tempo-b.log" \
        "$TEMPO_BIN" node \
        --chain "$patched_genesis" --datadir "$l1_b_db" \
        --http --http.addr 127.0.0.1 --http.port 8645 --http.api all \
        --ws --ws.addr 127.0.0.1 --ws.port 8645 --ws.api all \
        --metrics 127.0.0.1:9101 \
        --log.file.directory "$log_dir/tempo-b" \
        --consensus.signing-key "$validator_b/signing.key" \
        --consensus.secret "$consensus_secret" \
        --consensus.signing-share "$validator_b/signing.share" \
        --consensus.listen-address 127.0.0.3:8100 \
        --consensus.metrics-address 127.0.0.3:8102 \
        --trusted-peers "$trusted_peers" \
        --port 8101 --discovery.port 8101 --discovery.v5.port 8104 \
        --p2p-secret-key "$validator_b/enode.key" --authrpc.port 8103 \
        --consensus.use-local-defaults --consensus.bypass-ip-check \
        "${common_l1_args[@]}"

    local l1_a_rpc="http://127.0.0.1:8545"
    local l1_b_rpc="http://127.0.0.1:8645"
    wait_for_rpc "$l1_a_rpc" "Tempo validator A" "$rpc_timeout"
    wait_for_rpc "$l1_b_rpc" "Tempo validator B" "$rpc_timeout"
    wait_for_peer "$l1_a_rpc" "Tempo validator A" "$rpc_timeout"
    wait_for_peer "$l1_b_rpc" "Tempo validator B" "$rpc_timeout"
    wait_for_chain_advance "$l1_a_rpc" "Tempo validator A" "$rpc_timeout"
    wait_for_chain_advance "$l1_b_rpc" "Tempo validator B" "$rpc_timeout"
    verify_shared_runtimes "$l1_a_rpc" "Tempo validator A"
    verify_shared_runtimes "$l1_b_rpc" "Tempo validator B"
    verify_history_storage "$l1_a_rpc" "Tempo validator A"
    verify_history_storage "$l1_b_rpc" "Tempo validator B"

    local chain_a chain_b genesis_a genesis_b
    chain_a="$(hex_to_dec "$(rpc "$l1_a_rpc" eth_chainId)")"
    chain_b="$(hex_to_dec "$(rpc "$l1_b_rpc" eth_chainId)")"
    [[ "$chain_a" == "$chain_b" ]] || die "Tempo validators returned different chain IDs: $chain_a and $chain_b"
    [[ "$chain_a" == "$l1_chain_id" ]] || die "Tempo RPC chain ID $chain_a does not match generated chain ID $l1_chain_id"
    genesis_a="$(rpc "$l1_a_rpc" eth_getBlockByNumber '["0x0",false]' | jq -r '.hash')"
    genesis_b="$(rpc "$l1_b_rpc" eth_getBlockByNumber '["0x0",false]' | jq -r '.hash')"
    [[ -n "$genesis_a" && "$genesis_a" == "$genesis_b" ]] || die "Tempo validators returned different genesis hashes"
    [[ "$(rpc "$l1_a_rpc" eth_getCode "[\"$ZONE_FACTORY\",\"latest\"]")" != "0x" ]] \
        || die "canonical ZoneFactory has no code on Tempo L1"

    local zone_token
    zone_token="$DLUSD"

    echo "creating a Zone through the canonical factory"
    local -a create_zone_args=(
        --output "$zone_dir"
        --l1-rpc-url "$l1_a_rpc"
        --zone-factory "$ZONE_FACTORY"
        --initial-token "$zone_token"
        --admin "$admin_address"
        --sequencer "$sequencer_address"
        --gas-limit "$zone_gas_limit"
        --access-mode
    )
    # Access starts closed with an empty allowlist; untimed fixture setup applies the map.
    ZONE_FACTORY_OWNER_KEY="$owner_key" "$ZONES_XTASK_BIN" create-zone "${create_zone_args[@]}"
    local zone_json="$zone_dir/zone.json"
    local zone_genesis="$zone_dir/genesis.json"
    require_file "$zone_json"
    require_file "$zone_genesis"
    local portal zone_id zone_chain_id anchor_block
    portal="$(jq -er '.portal' "$zone_json")"
    zone_id="$(jq -er '.zoneId' "$zone_json")"
    zone_chain_id="$(jq -er '.chainId' "$zone_json")"
    anchor_block="$(jq -er '.tempoAnchorBlock' "$zone_json")"
    [[ "$(rpc "$l1_a_rpc" eth_getCode "[\"$portal\",\"latest\"]")" != "0x" ]] \
        || die "created ZonePortal has no code on Tempo L1"

    echo "registering the sequencer encryption key"
    L1_RPC_URL="$l1_a_rpc" L1_PORTAL_ADDRESS="$portal" PRIVATE_KEY="$sequencer_key" \
        "$ZONES_XTASK_BIN" set-encryption-key

    local fixture_metadata="$control_root/neobank-fixtures.json"
    echo "deploying and configuring private-Zone benchmark fixtures"
    FIXTURE_DEPLOYER_KEY="$owner_key" PORTAL_ADMIN_KEY="$admin_key" \
        "$ZONES_XTASK_BIN" deploy-neobank-fixtures \
            --l1-rpc-url "$l1_a_rpc" \
            --portal "$portal" \
            --dlusd "$DLUSD" \
            --pathusd "$PATH_USD" \
            --private-asset "$zone_token" \
            --earn-revision "${ZONES_BENCH_EARN_REVISION:?external Earn revision is required}" \
            --swap-mechanism "$swap_mechanism" \
            --liquidity "$swap_liquidity" \
            --allowed-accounts-file "$neobank_allowed_accounts_file" \
            --output "$fixture_metadata"
    rm -f -- "$neobank_allowed_accounts_file"
    provision_secret_files=()
    require_file "$fixture_metadata"
    verify_neobank_fixture_topology \
        "$l1_a_rpc" "$fixture_metadata" "$owner_address" "$PATH_USD" \
        "$swap_mechanism" "$zone_token"
    verify_neobank_token_topology \
        "$l1_a_rpc" "$portal" "$zone_token" "$(jq -er '.earnToken' "$fixture_metadata")"
    echo "configuring zero user bridge and withdrawal protocol fees"
    SEQUENCER_KEY="$sequencer_key" "$ZONES_XTASK_BIN" configure-benchmark-fees \
        --l1-rpc-url "$l1_a_rpc" \
        --portal "$portal" \
        --token "$zone_token" \
        --zone-gas-rate 0 \
        --bounceback-gas 0

    local -a prover_args=()
    if [[ -n "${ZONES_BENCH_PROVER_ADDRESS:-}" ]]; then
        [[ "$ZONES_BENCH_PROVER_ADDRESS" =~ ^[^[:space:]:]+:[0-9]+$ ]] \
            || die "ZONES_BENCH_PROVER_ADDRESS must be HOST:PORT"
        local prover_address="$ZONES_BENCH_PROVER_ADDRESS"
        local zone_help
        zone_help="$("$ZONE_BIN" node --help)"
        if [[ "$zone_help" == *HARDFORK=HOST:PORT* ]]; then
            # Newer Zone binaries route by the active L1 fork. The snapshot schedules
            # later forks in year 2100, so this benchmark needs one assignment.
            local hardfork
            hardfork="$(jq -er '.config.tempo.hardfork | select(test("^t[0-9]+[a-z]*$"))' "$state_a_root/manifest.json")" \
                || die "verified L1 snapshot has no Tempo hardfork"
            prover_address="T${hardfork#t}=$prover_address"
        fi
        prover_args=(--sequencer.enable-prover --sequencer.prover-address "$prover_address")
    fi

    # The pinned Reth revision predates the retained-branch pruning fix. Its
    # default sparse-trie pruning can make a multi-transaction Zone payload
    # disagree with the root obtained during final validation.
    start_process zone "$ZONE_BIN" "${ZONES_BENCH_ZONE_CPUS:-8-13,24-29}" "$log_dir/zone.log" \
        "$ZONE_BIN" node \
        --chain "$zone_genesis" --datadir "$zone_db" \
        --l1.rpc-url ws://127.0.0.1:8545 \
        --l1.portal-address "$portal" \
        --http --http.addr 127.0.0.1 --http.port 8546 \
        --http.api all \
        --ws --ws.addr 127.0.0.1 --ws.port 8546 \
        --ws.api all \
        --rpc.max-connections 10000 \
        --metrics 127.0.0.1:9201 \
        --redacted-rpc.port 8544 \
        --zone.batch-interval-blocks "$zone_batch_interval_blocks" \
        --withdrawal-poll-interval-secs "$withdrawal_poll_interval_secs" \
        --withdrawal-max-batch-gas "$withdrawal_max_batch_gas" \
        --withdrawal-max-in-flight-batches "$withdrawal_max_in_flight_batches" \
        --log.file.directory "$log_dir/zone" \
        --ipcdisable \
        --engine.disable-sparse-trie-cache-pruning \
        --sequencer \
        "${prover_args[@]}" \
        --sequencer-key-file <(printf '%s\n' "$sequencer_key")
    unset sequencer_key owner_key admin_key

    local zone_rpc="http://127.0.0.1:8546"
    local zone_redacted_rpc="http://127.0.0.1:8544"
    wait_for_rpc "$zone_rpc" "Zone" "$zone_timeout"
    wait_for_chain_advance "$zone_rpc" "Zone" "$zone_timeout"
    wait_for_zone_enabled_token "$zone_rpc" "$(jq -er '.earnToken' "$fixture_metadata")" "$zone_timeout"
    neobank_allowed_accounts+=("$(jq -er '.bridgeWallet' "$fixture_metadata")")
    local queried_zone_chain_id queried_zone_gas_limit
    queried_zone_chain_id="$(hex_to_dec "$(rpc "$zone_rpc" eth_chainId)")"
    [[ "$queried_zone_chain_id" == "$zone_chain_id" ]] \
        || die "Zone RPC chain ID $queried_zone_chain_id does not match zone.json chain ID $zone_chain_id"
    queried_zone_gas_limit="$(hex_to_dec "$(rpc "$zone_rpc" eth_getBlockByNumber '["latest",false]' | jq -er '.gasLimit')")"
    [[ "$queried_zone_gas_limit" == "$zone_gas_limit" ]] \
        || die "Zone RPC gas limit $queried_zone_gas_limit does not match configured gas limit $zone_gas_limit"

    local target_id="local-consensus-${genesis_a#0x}-zone-$zone_id"
    local -a env_pairs=(
        L1_RPC_URL "$l1_a_rpc" \
        L1_WS_RPC_URL "ws://127.0.0.1:8545" \
        ZONES_BENCH_L1_B_RPC_URL "$l1_b_rpc" \
        ZONES_BENCH_L1_QUERY_RPC_URL "$l1_b_rpc" \
        ZONES_BENCH_L1_SUBMIT_RPC_URLS "$l1_a_rpc,$l1_b_rpc" \
        ZONE_RPC_URL "$zone_rpc" \
        ZONE_WS_RPC_URL "ws://127.0.0.1:8546" \
        ZONE_PRIVATE_RPC_URL "$zone_redacted_rpc" \
        ZONE_REDACTED_RPC_URL "$zone_redacted_rpc" \
        ZONES_BENCH_TEMPO_GENESIS "$patched_genesis" \
        ZONES_BENCH_ZONE_GENESIS "$zone_genesis" \
        ZONES_BENCH_TOKEN "$zone_token" \
        L1_PORTAL_ADDRESS "$portal" \
        ZONES_BENCH_EXPECTED_L1_CHAIN_ID "$chain_a" \
        ZONES_BENCH_EXPECTED_ZONE_CHAIN_ID "$queried_zone_chain_id" \
        ZONES_BENCH_EXPECTED_ZONE_ID "$zone_id" \
        ZONES_BENCH_ACCOUNT_END "$((account_start + accounts))" \
        ZONES_BENCH_CONTROL_ACCOUNT_INDEX 0 \
        ZONES_BENCH_CONTROL_ACCOUNT_END 1 \
        ZONES_BENCH_CONTROL_ADDRESS "$owner_address" \
        ZONES_BENCH_SEQUENCER_ACCOUNT_INDEX 4 \
        ZONES_BENCH_SEQUENCER_ACCOUNT_END 5 \
        ZONES_BENCH_SEQUENCER_ADDRESS "$sequencer_address" \
        ZONES_BENCH_INBOX "0x1c00000000000000000000000000000000000001" \
        ZONES_BENCH_OUTBOX "0x1c00000000000000000000000000000000000002" \
        ZONES_BENCH_L1_MAX_FEE_PER_GAS "$l1_max_fee_per_gas" \
        ZONES_BENCH_L1_MAX_PRIORITY_FEE_PER_GAS 0 \
        ZONES_BENCH_ZONE_MAX_FEE_PER_GAS "$zone_max_fee_per_gas" \
        ZONES_BENCH_ZONE_MAX_PRIORITY_FEE_PER_GAS 0 \
        ZONES_BENCH_L1_GAS_LIMIT "$l1_gas_limit" \
        ZONES_BENCH_L1_GENERAL_GAS_LIMIT "$l1_general_gas_limit" \
        ZONES_BENCH_ZONE_GAS_LIMIT "$zone_gas_limit" \
        ZONES_BENCH_SWAP_MECHANISM "$swap_mechanism" \
        ZONES_BENCH_RECIPIENT_MODE "$recipient_mode" \
        ZONES_BENCH_SWAP_LIQUIDITY "$swap_liquidity" \
        ZONES_BENCH_CALLBACK_GAS_LIMIT "$callback_gas_limit" \
        ZONES_BENCH_WITHDRAWAL_MAX_BATCH_GAS "$withdrawal_max_batch_gas" \
        ZONES_BENCH_WITHDRAWAL_MAX_IN_FLIGHT_BATCHES "$withdrawal_max_in_flight_batches" \
        ZONES_BENCH_ZONE_BATCH_INTERVAL_BLOCKS "$zone_batch_interval_blocks" \
        ZONES_BENCH_WITHDRAWAL_POLL_INTERVAL_SECS "$withdrawal_poll_interval_secs" \
        ZONES_BENCH_STEP_TIMEOUT "$step_timeout" \
        ZONES_BENCH_SETUP_SETTLEMENT_TIMEOUT_SECS "$setup_settlement_timeout_secs" \
        ZONES_BENCH_DRAIN_TIMEOUT "$drain_timeout" \
        ZONES_BENCH_TARGET_ID "$target_id" \
        ZONES_BENCH_ACCOUNT_START "$account_start" \
        ZONES_BENCH_ACCOUNTS "$accounts" \
        ZONES_BENCH_L1_METRICS_URL "a:http://127.0.0.1:9001/metrics,b:http://127.0.0.1:9101/metrics" \
        ZONES_BENCH_ZONE_METRICS_URL "http://127.0.0.1:9201/metrics" \
        ZONES_BENCH_PID_FILE "$pid_file" \
        ZONES_BENCH_TOPOLOGY_DIR "$control_root" \
        ZONES_BENCH_STATE_A_ROOT "$state_a_root" \
        ZONES_BENCH_STATE_B_ROOT "$state_b_root" \
        ZONES_BENCH_ZONE_STATE_ROOT "$zone_state_root" \
        ZONES_BENCH_NEOBANK_PRESET "$neobank_preset" \
        ZONES_BENCH_DLUSD "$DLUSD" \
        ZONES_BENCH_PATHUSD "$PATH_USD" \
        ZONES_BENCH_EARN_REVISION "$(jq -er '.earnFixtureRevision' "$fixture_metadata")" \
        ZONES_BENCH_EARN_TOKEN "$(jq -er '.earnToken' "$fixture_metadata")" \
        ZONES_BENCH_EARN_ROUTER "$(jq -er '.earnRouter' "$fixture_metadata")" \
        ZONES_BENCH_EARN_VAULT "$(jq -er '.earnVault' "$fixture_metadata")" \
        ZONES_BENCH_EARN_CONTRIBUTION_CONTROLLER "$(jq -er '.contributionController' "$fixture_metadata")" \
        ZONES_BENCH_GATEWAY "$(jq -er '.gateway' "$fixture_metadata")" \
        ZONES_BENCH_BRIDGE_WALLET "$(jq -er '.bridgeWallet' "$fixture_metadata")" \
        ZONES_BENCH_ROUTE_SWAPPER "$(jq -r '.routeSwapper // empty' "$fixture_metadata")" \
        ZONES_BENCH_VAULT "$(jq -er '.vault' "$fixture_metadata")" \
        ZONES_BENCH_ENGINE "$(jq -er '.engine' "$fixture_metadata")" \
        ZONES_BENCH_VAULT_ADAPTER "$(jq -er '.vaultAdapter' "$fixture_metadata")" \
        ZONES_BENCH_REWARDS "$(jq -er '.rewards' "$fixture_metadata")" \
        ZONES_BENCH_FIXTURE_METADATA "$fixture_metadata"
    )
    write_env "$env_file" "${env_pairs[@]}"

    provision_succeeded=1
    provision_pid_file=""
    trap - EXIT INT TERM
    echo "topology ready; source $env_file before invoking a benchmark runner"
    echo "$env_file"
}

usage() {
    cat <<'EOF'
Usage:
  contrib/bench/provision-topology.sh prepare-l1
  contrib/bench/provision-topology.sh verify-l1
  contrib/bench/provision-topology.sh up
  contrib/bench/provision-topology.sh cleanup [PID_FILE]

`prepare-l1` builds both L1 baselines on the restored Schelk scratch volumes;
the caller promotes and restores them before `verify-l1`. `up` leaves the
provisioned nodes running and prints the generated non-secret
environment file path. `cleanup` stops exactly the processes recorded in the
PID file; pass it explicitly or set ZONES_BENCH_PID_FILE.
EOF
}

case "${1:-}" in
    prepare-l1)
        "$SCRIPT_DIR/l1-snapshot.sh" prepare
        ;;
    verify-l1)
        "$SCRIPT_DIR/l1-snapshot.sh" verify
        ;;
    up)
        provision_up
        ;;
    cleanup)
        cleanup_target="${2:-${ZONES_BENCH_PID_FILE:-}}"
        [[ -n "$cleanup_target" ]] || die "cleanup requires a PID file argument or ZONES_BENCH_PID_FILE"
        cleanup_pid_file "$cleanup_target"
        ;;
    *)
        usage >&2
        exit 2
        ;;
esac
