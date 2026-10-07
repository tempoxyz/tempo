#!/usr/bin/env bash

# Run the complete private-Zone journey. Provisioning, fixture deployment,
# admission seeding, approvals, and redacted-RPC authentication are deliberately
# outside the scenario measurement.
set -Eeuo pipefail

bench_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scenario-reporting.sh
source "$bench_dir/scenario-reporting.sh"

die() { echo "error: $*" >&2; exit 1; }
need() { [[ -n "${!1:-}" ]] || die "$1 must be set"; }
uint() { [[ "${!1:-}" =~ ^[0-9]+$ ]] || die "$1 must be an unsigned integer"; }
positive_rate() {
    local value="${!1:-}"
    if ! [[ "$value" =~ ^([0-9]+([.][0-9]+)?|[.][0-9]+)$ ]] ||
        ! awk -v value="$value" 'BEGIN { exit !(value > 0 && value <= 999999999) }'; then
        die "$1 must be a positive decimal no greater than 999999999"
    fi
}
bigint_eval() {
    local expression="$1" value
    value="$(printf '%s\n' "$expression" | BC_LINE_LENGTH=0 bc)" ||
        die "could not evaluate integer expression"
    [[ "$value" =~ ^-?[0-9]+$ ]] ||
        die "integer expression returned an invalid result"
    printf '%s\n' "$value"
}
bigint_true() {
    [[ "$(bigint_eval "$1")" == 1 ]]
}

load_benchmark_mnemonic() {
    local mode

    need ZONES_BENCH_MNEMONIC_FILE
    [[ ! -L "$ZONES_BENCH_MNEMONIC_FILE" ]] ||
        die "ZONES_BENCH_MNEMONIC_FILE must not be a symbolic link"
    [[ -f "$ZONES_BENCH_MNEMONIC_FILE" ]] ||
        die "ZONES_BENCH_MNEMONIC_FILE must be a regular file"
    [[ -s "$ZONES_BENCH_MNEMONIC_FILE" ]] ||
        die "ZONES_BENCH_MNEMONIC_FILE must not be empty"
    [[ -r "$ZONES_BENCH_MNEMONIC_FILE" ]] ||
        die "ZONES_BENCH_MNEMONIC_FILE must be readable"

    mode="$(stat -c '%a' -- "$ZONES_BENCH_MNEMONIC_FILE")"
    [[ "$mode" =~ ^[0-7]{3,4}$ ]] ||
        die "could not validate ZONES_BENCH_MNEMONIC_FILE permissions"
    (( (8#$mode & 8#077) == 0 )) ||
        die "ZONES_BENCH_MNEMONIC_FILE must not be accessible by group or other users"

    ZONES_BENCH_MNEMONIC="$(<"$ZONES_BENCH_MNEMONIC_FILE")"
    [[ "$ZONES_BENCH_MNEMONIC" =~ [^[:space:]] ]] ||
        die "ZONES_BENCH_MNEMONIC_FILE must contain a mnemonic"
    export ZONES_BENCH_MNEMONIC
}

load_benchmark_mnemonic

# Accept the legacy topology names from older cached/provisioned environments,
# but use the canonical Earn v1 contract identities throughout this runtime.
ZONES_BENCH_EARN_ROUTER="${ZONES_BENCH_EARN_ROUTER:-${ZONES_BENCH_GATEWAY:-}}"
ZONES_BENCH_EARN_VAULT="${ZONES_BENCH_EARN_VAULT:-${ZONES_BENCH_VAULT_ADAPTER:-}}"
ZONES_BENCH_EARN_CONTRIBUTION_CONTROLLER="${ZONES_BENCH_EARN_CONTRIBUTION_CONTROLLER:-${ZONES_BENCH_REWARDS:-}}"

for name in L1_RPC_URL L1_WS_RPC_URL ZONE_RPC_URL ZONE_WS_RPC_URL ZONE_REDACTED_RPC_URL \
    L1_PORTAL_ADDRESS ZONES_BENCH_TOKEN ZONES_BENCH_DLUSD ZONES_BENCH_PATHUSD ZONES_BENCH_EARN_TOKEN \
    ZONES_BENCH_EARN_ROUTER ZONES_BENCH_BRIDGE_WALLET ZONES_BENCH_VAULT ZONES_BENCH_ENGINE \
    ZONES_BENCH_EARN_VAULT ZONES_BENCH_EARN_CONTRIBUTION_CONTROLLER ZONES_BENCH_SEED \
    ZONES_BENCH_EXPECTED_L1_CHAIN_ID ZONES_BENCH_EXPECTED_ZONE_CHAIN_ID \
    ZONES_BENCH_EXPECTED_ZONE_ID ZONES_BENCH_SEQUENCER_ADDRESS
do need "$name"; done

ZONES_BENCH_CONTROL_ACCOUNT_INDEX="${ZONES_BENCH_CONTROL_ACCOUNT_INDEX:-0}"
ZONES_BENCH_ACCOUNT_START="${ZONES_BENCH_ACCOUNT_START:-16}"
ZONES_BENCH_ACCOUNTS="${ZONES_BENCH_ACCOUNTS:-100}"
ZONES_BENCH_SEQUENCER_ACCOUNT_INDEX="${ZONES_BENCH_SEQUENCER_ACCOUNT_INDEX:-4}"
ZONES_BENCH_COUNT="${ZONES_BENCH_COUNT:-100}"
ZONES_BENCH_TPS="${ZONES_BENCH_TPS:-20}"
ZONES_BENCH_MAX_CONCURRENT="${ZONES_BENCH_MAX_CONCURRENT:-12}"
ZONES_BENCH_DEPOSIT_AMOUNT="${ZONES_BENCH_DEPOSIT_AMOUNT:-2000000}"
ZONES_BENCH_ACTIVITY_AMOUNT="${ZONES_BENCH_ACTIVITY_AMOUNT:-1}"
ZONES_BENCH_WITHDRAWAL_AMOUNT="${ZONES_BENCH_WITHDRAWAL_AMOUNT:-1000000}"
ZONES_BENCH_BOOTSTRAP_DEPOSIT_AMOUNT="${ZONES_BENCH_BOOTSTRAP_DEPOSIT_AMOUNT:-10000000}"
ZONES_BENCH_CALLBACK_GAS_LIMIT="${ZONES_BENCH_CALLBACK_GAS_LIMIT:-5000000}"
ZONES_BENCH_OUTPUT="${ZONES_BENCH_OUTPUT:-target/zones-benchmark/neobank-e2e}"
ZONES_BENCH_REPORT="${ZONES_BENCH_REPORT:-target/zones-benchmark/report-neobank-e2e.json}"
ZONES_BENCH_RENDERED_SCENARIO="${ZONES_BENCH_RENDERED_SCENARIO:-$ZONES_BENCH_OUTPUT/scenario.rendered.yml}"
ZONES_BENCH_SPF_RANGE="${ZONES_BENCH_SPF_RANGE:-target/zones-benchmark/spf-range.env}"
ZONES_BENCH_AUTH_TTL_SECS="${ZONES_BENCH_AUTH_TTL_SECS:-600}"
ZONES_BENCH_AUTH_REFRESH_SECS="${ZONES_BENCH_AUTH_REFRESH_SECS:-60}"
ZONES_BENCH_STEP_TIMEOUT="${ZONES_BENCH_STEP_TIMEOUT:-10m}"
ZONES_BENCH_SAMPLE_INSTANCES="${ZONES_BENCH_SAMPLE_INSTANCES:-10}"
ZONES_BENCH_RUN_ID="${ZONES_BENCH_RUN_ID:-local}"
ZONES_BENCH_RECIPIENT_MODE="${ZONES_BENCH_RECIPIENT_MODE:-existing}"
ZONES_BENCH_NEOBANK_PRESET="${ZONES_BENCH_NEOBANK_PRESET:-full-journey}"
ZONES_BENCH_SWAP_MECHANISM="${ZONES_BENCH_SWAP_MECHANISM:-direct-swap}"
ZONES_BENCH_L1_QUERY_RPC_URL="${ZONES_BENCH_L1_QUERY_RPC_URL:-$L1_RPC_URL}"
ZONES_BENCH_ACCOUNT_END="${ZONES_BENCH_ACCOUNT_END:-$((10#$ZONES_BENCH_ACCOUNT_START + 10#$ZONES_BENCH_ACCOUNTS))}"
ZONES_BENCH_CONTROL_ACCOUNT_END="${ZONES_BENCH_CONTROL_ACCOUNT_END:-$((10#$ZONES_BENCH_CONTROL_ACCOUNT_INDEX + 1))}"
ZONES_BENCH_SEQUENCER_ACCOUNT_END="${ZONES_BENCH_SEQUENCER_ACCOUNT_END:-$((10#$ZONES_BENCH_SEQUENCER_ACCOUNT_INDEX + 1))}"
ZONES_BENCH_INBOX="${ZONES_BENCH_INBOX:-0x1c00000000000000000000000000000000000001}"
ZONES_BENCH_OUTBOX="${ZONES_BENCH_OUTBOX:-0x1c00000000000000000000000000000000000002}"
ZONES_BENCH_L1_MAX_FEE_PER_GAS="${ZONES_BENCH_L1_MAX_FEE_PER_GAS:-12000000000}"
ZONES_BENCH_L1_MAX_PRIORITY_FEE_PER_GAS=0
ZONES_BENCH_ZONE_MAX_FEE_PER_GAS="${ZONES_BENCH_ZONE_MAX_FEE_PER_GAS:-10000000000}"
ZONES_BENCH_ZONE_MAX_PRIORITY_FEE_PER_GAS=0
ZONES_BENCH_DEPOSIT_GAS_LIMIT="${ZONES_BENCH_DEPOSIT_GAS_LIMIT:-2000000}"
ZONES_BENCH_ACTIVITY_GAS_LIMIT="${ZONES_BENCH_ACTIVITY_GAS_LIMIT:-500000}"
ZONES_BENCH_WITHDRAWAL_TX_GAS_LIMIT="${ZONES_BENCH_WITHDRAWAL_TX_GAS_LIMIT:-10000000}"
ZONES_BENCH_APPROVAL_GAS_LIMIT="${ZONES_BENCH_APPROVAL_GAS_LIMIT:-2000000}"
ZONES_BENCH_ADMISSION_SEED_AMOUNT="${ZONES_BENCH_ADMISSION_SEED_AMOUNT:-1}"
ZONES_BENCH_ADMISSION_SEED_TPS="${ZONES_BENCH_ADMISSION_SEED_TPS:-200}"
ZONES_BENCH_RECIPIENT_ACCOUNT_START="${ZONES_BENCH_RECIPIENT_ACCOUNT_START:-$ZONES_BENCH_ACCOUNT_START}"
ZONES_BENCH_RECIPIENT_ACCOUNT_END="${ZONES_BENCH_RECIPIENT_ACCOUNT_END:-$ZONES_BENCH_ACCOUNT_END}"
if [[ -z "${ZONES_BENCH_RECIPIENT_GENERATOR:-}" ]]; then
    ZONES_BENCH_RECIPIENT_GENERATOR='{ pool: { pool: users, select: random } }'
fi
ZONES_BENCH_POSITION_RECIPIENT='{ var: account.address }'
case "$ZONES_BENCH_RECIPIENT_MODE" in
    existing) ZONES_BENCH_PRIVATE_TRANSFER_RECIPIENT='{ var: recipient.address }' ;;
    random) ZONES_BENCH_PRIVATE_TRANSFER_RECIPIENT=random ;;
    *) die "ZONES_BENCH_RECIPIENT_MODE must be existing or random" ;;
esac
case "$ZONES_BENCH_NEOBANK_PRESET" in
    encrypted-deposit)
        scenario_file=encrypted-deposit-scenario.yml
        base_token_label=dlusd
        expected_base_token="$ZONES_BENCH_DLUSD"
        leases_per_journey=1
        ;;
    full-journey)
        scenario_file=private-flow-scenario.yml
        base_token_label=dlusd
        expected_base_token="$ZONES_BENCH_DLUSD"
        leases_per_journey=1
        ;;
    private-withdrawal)
        scenario_file=private-withdrawal-scenario.yml
        base_token_label=dlusd
        expected_base_token="$ZONES_BENCH_DLUSD"
        leases_per_journey=1
        ;;
    slippage-bounce)
        scenario_file=slippage-bounce-scenario.yml
        base_token_label=dlusd
        expected_base_token="$ZONES_BENCH_DLUSD"
        leases_per_journey=1
        ;;
    swapped-lifecycle)
        scenario_file=swapped-lifecycle-scenario.yml
        base_token_label=dlusd
        expected_base_token="$ZONES_BENCH_DLUSD"
        leases_per_journey=1
        ;;
    swapped-redemption)
        scenario_file=swapped-redemption-scenario.yml
        base_token_label=dlusd
        expected_base_token="$ZONES_BENCH_DLUSD"
        leases_per_journey=1
        ;;
    *) die "unsupported neobank preset: $ZONES_BENCH_NEOBANK_PRESET" ;;
esac
case "$ZONES_BENCH_SWAP_MECHANISM" in
    direct-swap) ;;
    *) die "current Earn only supports ZONES_BENCH_SWAP_MECHANISM=direct-swap" ;;
esac
[[ "${ZONES_BENCH_TOKEN,,}" == "${expected_base_token,,}" ]] ||
    die "ZONES_BENCH_TOKEN must match the $base_token_label token for $ZONES_BENCH_NEOBANK_PRESET"
for name in ZONES_BENCH_CONTROL_ACCOUNT_INDEX ZONES_BENCH_ACCOUNT_START ZONES_BENCH_ACCOUNTS ZONES_BENCH_SEQUENCER_ACCOUNT_INDEX ZONES_BENCH_COUNT \
    ZONES_BENCH_MAX_CONCURRENT ZONES_BENCH_DEPOSIT_AMOUNT ZONES_BENCH_ACTIVITY_AMOUNT \
    ZONES_BENCH_WITHDRAWAL_AMOUNT ZONES_BENCH_BOOTSTRAP_DEPOSIT_AMOUNT \
    ZONES_BENCH_CALLBACK_GAS_LIMIT ZONES_BENCH_SAMPLE_INSTANCES ZONES_BENCH_SEED \
    ZONES_BENCH_ACCOUNT_END ZONES_BENCH_CONTROL_ACCOUNT_END \
    ZONES_BENCH_SEQUENCER_ACCOUNT_END ZONES_BENCH_EXPECTED_L1_CHAIN_ID \
    ZONES_BENCH_EXPECTED_ZONE_CHAIN_ID ZONES_BENCH_EXPECTED_ZONE_ID \
    ZONES_BENCH_L1_MAX_FEE_PER_GAS ZONES_BENCH_ZONE_MAX_FEE_PER_GAS \
    ZONES_BENCH_DEPOSIT_GAS_LIMIT ZONES_BENCH_ACTIVITY_GAS_LIMIT \
    ZONES_BENCH_WITHDRAWAL_TX_GAS_LIMIT ZONES_BENCH_APPROVAL_GAS_LIMIT \
    ZONES_BENCH_ADMISSION_SEED_AMOUNT ZONES_BENCH_RECIPIENT_ACCOUNT_START \
    ZONES_BENCH_RECIPIENT_ACCOUNT_END
do uint "$name"; done
positive_rate ZONES_BENCH_TPS
positive_rate ZONES_BENCH_ADMISSION_SEED_TPS
(( 10#$ZONES_BENCH_ACCOUNTS > 0 && 10#$ZONES_BENCH_COUNT > 0 )) || die "accounts and count must be positive"
(( 10#$ZONES_BENCH_MAX_CONCURRENT > 0 )) || die "max concurrency must be positive"
(( 10#$ZONES_BENCH_SAMPLE_INSTANCES > 0 )) ||
    die "sample instances must be positive"
sample_instances="$ZONES_BENCH_SAMPLE_INSTANCES"
if (( 10#$ZONES_BENCH_COUNT < 10#$sample_instances )); then
    sample_instances="$ZONES_BENCH_COUNT"
fi
[[ "$ZONES_BENCH_CONTROL_ACCOUNT_INDEX" == 0 ]] ||
    die "this topology fixes the neobank control account at mnemonic index 0"
[[ "$ZONES_BENCH_SEQUENCER_ACCOUNT_INDEX" == 4 ]] ||
    die "this topology fixes the approval sponsor at mnemonic index 4"
required_accounts=$((10#$ZONES_BENCH_MAX_CONCURRENT * leases_per_journey))
(( required_accounts <= 10#$ZONES_BENCH_ACCOUNTS )) ||
    die "$ZONES_BENCH_NEOBANK_PRESET requires at least $required_accounts accounts for max-concurrent=$ZONES_BENCH_MAX_CONCURRENT"

# Reward sizing uses arbitrary-precision arithmetic so configured uint128
# amounts cannot silently wrap in the shell.
reward_onramp_per_account="$ZONES_BENCH_DEPOSIT_AMOUNT"
reward_position_per_account="$ZONES_BENCH_WITHDRAWAL_AMOUNT"
reward_total_position=0
reward_fund_amount=1
reward_first_redeem_amount=1
reward_second_redeem_amount=1
reward_expected_remaining=0
if [[ "$ZONES_BENCH_NEOBANK_PRESET" == "rewards-redemption" ]]; then
    bigint_true "$ZONES_BENCH_WITHDRAWAL_AMOUNT > 1" ||
        die "rewards-redemption requires withdrawal-amount greater than 1"
    bigint_true "$ZONES_BENCH_DEPOSIT_AMOUNT > $ZONES_BENCH_WITHDRAWAL_AMOUNT" ||
        die "rewards-redemption requires deposit-amount greater than withdrawal-amount for Zone fees"

    journeys_per_account="$(bigint_eval \
        "($ZONES_BENCH_COUNT + $ZONES_BENCH_ACCOUNTS - 1) / $ZONES_BENCH_ACCOUNTS")"
    reward_position_per_account="$(bigint_eval \
        "$journeys_per_account * $ZONES_BENCH_WITHDRAWAL_AMOUNT")"
    reward_onramp_per_account="$(bigint_eval \
        "$journeys_per_account * $ZONES_BENCH_DEPOSIT_AMOUNT")"
    reward_total_position="$(bigint_eval \
        "$ZONES_BENCH_ACCOUNTS * $reward_position_per_account")"
    reward_fund_amount="$(bigint_eval "$reward_total_position / 10")"
    reward_first_redeem_amount="$(bigint_eval "$ZONES_BENCH_WITHDRAWAL_AMOUNT / 2")"
    reward_second_redeem_amount="$(bigint_eval \
        "$ZONES_BENCH_WITHDRAWAL_AMOUNT - $reward_first_redeem_amount")"
    reward_redeemed="$(bigint_eval \
        "$ZONES_BENCH_COUNT * $ZONES_BENCH_WITHDRAWAL_AMOUNT")"
    reward_expected_remaining="$(bigint_eval \
        "$reward_total_position - $reward_redeemed")"

    uint128_max="$(bigint_eval '2^128 - 1')"
    uint256_max="$(bigint_eval '2^256 - 1')"
    for value in "$reward_onramp_per_account" "$reward_position_per_account" \
        "$reward_first_redeem_amount" "$reward_second_redeem_amount"
    do
        bigint_true "$value <= $uint128_max" ||
            die "reward scenario uint128 call amount overflow"
    done
    for value in "$reward_total_position" "$reward_fund_amount" \
        "$reward_redeemed" "$reward_expected_remaining"
    do
        bigint_true "$value <= $uint256_max" ||
            die "reward scenario uint256 accounting overflow"
    done
    bigint_true "$reward_fund_amount > 0 && $reward_first_redeem_amount > 0 && $reward_second_redeem_amount > 0 && $reward_expected_remaining >= 0" ||
        die "invalid reward scenario sizing result"
fi

swapped_redemption_onramp_per_account=1
swapped_redemption_position_per_account=1
swapped_redemption_total_position=0
swapped_redemption_expected_remaining=0
if [[ "$ZONES_BENCH_NEOBANK_PRESET" == "private-withdrawal" ||
      "$ZONES_BENCH_NEOBANK_PRESET" == "swapped-redemption" ]]; then
    bigint_true "$ZONES_BENCH_DEPOSIT_AMOUNT > $ZONES_BENCH_WITHDRAWAL_AMOUNT" ||
        die "swapped-redemption requires deposit-amount greater than withdrawal-amount for Zone fees"

    journeys_per_account="$(bigint_eval \
        "($ZONES_BENCH_COUNT + $ZONES_BENCH_ACCOUNTS - 1) / $ZONES_BENCH_ACCOUNTS")"
    swapped_redemption_onramp_per_account="$(bigint_eval \
        "$journeys_per_account * $ZONES_BENCH_DEPOSIT_AMOUNT")"
    swapped_redemption_position_per_account="$(bigint_eval \
        "$journeys_per_account * $ZONES_BENCH_WITHDRAWAL_AMOUNT")"
    swapped_redemption_total_position="$(bigint_eval \
        "$ZONES_BENCH_ACCOUNTS * $swapped_redemption_position_per_account")"
    swapped_redemption_redeemed="$(bigint_eval \
        "$ZONES_BENCH_COUNT * $ZONES_BENCH_WITHDRAWAL_AMOUNT")"
    swapped_redemption_expected_remaining="$(bigint_eval \
        "$swapped_redemption_total_position - $swapped_redemption_redeemed")"

    uint128_max="$(bigint_eval '2^128 - 1')"
    uint256_max="$(bigint_eval '2^256 - 1')"
    for value in "$swapped_redemption_onramp_per_account" \
        "$swapped_redemption_position_per_account" "$ZONES_BENCH_WITHDRAWAL_AMOUNT"
    do
        bigint_true "$value <= $uint128_max" ||
            die "swapped-redemption uint128 call amount overflow"
    done
    for value in "$swapped_redemption_total_position" \
        "$swapped_redemption_redeemed" "$swapped_redemption_expected_remaining"
    do
        bigint_true "$value <= $uint256_max" ||
            die "swapped-redemption uint256 accounting overflow"
    done
    bigint_true "$swapped_redemption_expected_remaining >= 0" ||
        die "invalid swapped-redemption sizing result"
fi

ZONES_BENCH_REWARD_ONRAMP_PER_ACCOUNT="$reward_onramp_per_account"
ZONES_BENCH_REWARD_POSITION_PER_ACCOUNT="$reward_position_per_account"
ZONES_BENCH_REWARD_FUND_AMOUNT="$reward_fund_amount"
ZONES_BENCH_REWARD_MAX_EARN_SHARE_SUPPLY="$reward_total_position"
ZONES_BENCH_REWARD_FIRST_REDEEM_AMOUNT="$reward_first_redeem_amount"
ZONES_BENCH_REWARD_SECOND_REDEEM_AMOUNT="$reward_second_redeem_amount"
ZONES_BENCH_SWAPPED_REDEMPTION_ONRAMP_PER_ACCOUNT="$swapped_redemption_onramp_per_account"
ZONES_BENCH_SWAPPED_REDEMPTION_POSITION_PER_ACCOUNT="$swapped_redemption_position_per_account"
export L1_RPC_URL L1_WS_RPC_URL ZONE_RPC_URL ZONE_WS_RPC_URL ZONE_REDACTED_RPC_URL
export L1_PORTAL_ADDRESS ZONES_BENCH_L1_QUERY_RPC_URL ZONES_BENCH_MNEMONIC
export ZONES_BENCH_ACCOUNT_START ZONES_BENCH_ACCOUNT_END ZONES_BENCH_ACCOUNTS
export ZONES_BENCH_CONTROL_ACCOUNT_INDEX ZONES_BENCH_CONTROL_ACCOUNT_END
export ZONES_BENCH_SEQUENCER_ACCOUNT_INDEX ZONES_BENCH_SEQUENCER_ACCOUNT_END
export ZONES_BENCH_SEQUENCER_ADDRESS
export ZONES_BENCH_EXPECTED_L1_CHAIN_ID ZONES_BENCH_EXPECTED_ZONE_CHAIN_ID
export ZONES_BENCH_EXPECTED_ZONE_ID ZONES_BENCH_INBOX ZONES_BENCH_OUTBOX
export ZONES_BENCH_L1_MAX_FEE_PER_GAS ZONES_BENCH_L1_MAX_PRIORITY_FEE_PER_GAS
export ZONES_BENCH_ZONE_MAX_FEE_PER_GAS ZONES_BENCH_ZONE_MAX_PRIORITY_FEE_PER_GAS
export ZONES_BENCH_DEPOSIT_GAS_LIMIT ZONES_BENCH_ACTIVITY_GAS_LIMIT
export ZONES_BENCH_WITHDRAWAL_TX_GAS_LIMIT ZONES_BENCH_APPROVAL_GAS_LIMIT
export ZONES_BENCH_ADMISSION_SEED_AMOUNT
export ZONES_BENCH_RECIPIENT_ACCOUNT_START ZONES_BENCH_RECIPIENT_ACCOUNT_END
export ZONES_BENCH_RECIPIENT_GENERATOR ZONES_BENCH_POSITION_RECIPIENT
export ZONES_BENCH_TOKEN ZONES_BENCH_DLUSD ZONES_BENCH_PATHUSD ZONES_BENCH_EARN_TOKEN
export ZONES_BENCH_EARN_ROUTER ZONES_BENCH_EARN_VAULT
export ZONES_BENCH_EARN_CONTRIBUTION_CONTROLLER ZONES_BENCH_BRIDGE_WALLET
export ZONES_BENCH_DEPOSIT_AMOUNT ZONES_BENCH_ACTIVITY_AMOUNT
export ZONES_BENCH_WITHDRAWAL_AMOUNT ZONES_BENCH_BOOTSTRAP_DEPOSIT_AMOUNT
export ZONES_BENCH_CALLBACK_GAS_LIMIT ZONES_BENCH_PRIVATE_TRANSFER_RECIPIENT
export ZONES_BENCH_REWARD_ONRAMP_PER_ACCOUNT ZONES_BENCH_REWARD_POSITION_PER_ACCOUNT
export ZONES_BENCH_REWARD_FUND_AMOUNT ZONES_BENCH_REWARD_MAX_EARN_SHARE_SUPPLY
export ZONES_BENCH_REWARD_FIRST_REDEEM_AMOUNT ZONES_BENCH_REWARD_SECOND_REDEEM_AMOUNT
export ZONES_BENCH_SWAPPED_REDEMPTION_ONRAMP_PER_ACCOUNT
export ZONES_BENCH_SWAPPED_REDEMPTION_POSITION_PER_ACCOUNT

stage_start() { echo "neobank stage=start run_id=$ZONES_BENCH_RUN_ID preset=$ZONES_BENCH_NEOBANK_PRESET stage=$1"; }
stage_end() { echo "neobank stage=end run_id=$ZONES_BENCH_RUN_ID preset=$ZONES_BENCH_NEOBANK_PRESET stage=$1"; }

read_l1_uint() {
    local address="$1" signature="$2"
    shift 2
    local value
    value="$(cast call "$address" "$signature" "$@" --rpc-url "$L1_RPC_URL" | awk '{print $1}')"
    [[ "$value" =~ ^[0-9]+$ ]] || die "could not read $signature from $address"
    printf '%s\n' "$value"
}

assert_scenario_report() {
    local report="$1" expected="$2" label="$3"
    jq -e --argjson expected "$expected" '
        .started == $expected and
        .completed == $expected and
        .failed == 0 and
        .timed_out == 0
    ' "$report" >/dev/null || die "$label did not complete successfully"
}

# Query private balances without putting authorization tokens in argv, stdout,
# or uploaded artifacts. Curl reads each token from a mode-0600 temporary config.
verify_reward_zone_balances() {
    local mode="$1" expected_total="$2" expected_unit="$3"
    local maximum_unit="${4:-$expected_unit}"
    local accounts_file="$ZONES_BENCH_OUTPUT/accounts.json"
    local request_file="$secret_dir/private-balance-request.json"
    local config_file="$secret_dir/private-balance.curl"
    local address normalized_address authorization calldata response result balance
    local request_id=0 observed_total=0
    local -a accounts

    expected_total="$(bigint_eval "$expected_total")"
    expected_unit="$(bigint_eval "$expected_unit")"
    maximum_unit="$(bigint_eval "$maximum_unit")"
    mapfile -t accounts < <(jq -er '.[] | select(type == "string")' "$accounts_file")
    (( ${#accounts[@]} == 10#$ZONES_BENCH_ACCOUNTS )) ||
        die "account list contains ${#accounts[@]} accounts, expected $ZONES_BENCH_ACCOUNTS"

    for address in "${accounts[@]}"; do
        request_id=$((request_id + 1))
        normalized_address="${address,,}"
        authorization="$(jq -er --arg address "$normalized_address" \
            '.[$address] | select(type == "string" and length > 0)' \
            "$ZONES_BENCH_ZONE_AUTH_MAP")" ||
            die "authorization map has no entry for benchmark account $address"
        calldata="$(cast calldata 'balanceOf(address)' "$address")"

        (
            umask 077
            jq -nc \
                --argjson id "$request_id" \
                --arg from "$address" \
                --arg to "$ZONES_BENCH_EARN_TOKEN" \
                --arg data "$calldata" \
                '{
                    jsonrpc: "2.0",
                    id: $id,
                    method: "eth_call",
                    params: [{from: $from, to: $to, data: $data}, "latest"]
                }' > "$request_file"
            {
                printf 'url = "%s"\n' "$ZONE_REDACTED_RPC_URL"
                printf 'request = "POST"\n'
                printf 'header = "Content-Type: application/json"\n'
                printf 'header = "X-Authorization-Token: %s"\n' "$authorization"
                printf 'data-binary = "@%s"\n' "$request_file"
                printf 'silent\nshow-error\nfail-with-body\n'
                printf 'connect-timeout = 10\nmax-time = 10\n'
            } > "$config_file"
        )
        if ! response="$(curl --config "$config_file")"; then
            rm -f -- "$request_file" "$config_file"
            die "private Zone balance query failed for $address"
        fi
        rm -f -- "$request_file" "$config_file"
        result="$(jq -er '
            if .error != null then
                error(.error.message // (.error | tostring))
            elif (.result | type) == "string" then
                .result
            else
                error("missing result")
            end
        ' <<<"$response")" ||
            die "private Zone balance query returned an error for $address"
        balance="$(cast to-dec "$result")"
        [[ "$balance" =~ ^[0-9]+$ ]] ||
            die "private Zone balance query returned an invalid balance for $address"
        balance="$(bigint_eval "$balance")"

        case "$mode" in
            seeded)
                [[ "$balance" == "$expected_unit" ]] ||
                    die "reward position balance $balance does not equal expected $expected_unit"
                ;;
            remaining)
                [[ "$balance" == 0 || "$balance" == "$expected_unit" ]] ||
                    die "terminal reward balance $balance is neither zero nor $expected_unit"
                ;;
            distributed_remaining)
                bigint_true "$balance <= $maximum_unit && $balance % $expected_unit == 0" ||
                    die "terminal EarnToken balance $balance is not a valid multiple of $expected_unit within the per-account maximum $maximum_unit"
                ;;
            *) die "unknown reward balance validation mode: $mode" ;;
        esac
        observed_total="$(bigint_eval "$observed_total + $balance")"
    done

    [[ "$observed_total" == "$expected_total" ]] ||
        die "aggregate Zone EarnToken balance $observed_total does not equal expected $expected_total"
    echo "verified ${#accounts[@]} private Zone EarnToken balances; aggregate=$observed_total"
}

txgen_bin="${TXGEN_TEMPO_BIN:-txgen-tempo}"
for command in "$txgen_bin" awk bc cast curl jq; do
    command -v "$command" >/dev/null || die "missing $command"
done

neobank_specs="$bench_dir/neobank"
scenario_path="$neobank_specs/$scenario_file"
bootstrap_scenario="$neobank_specs/bootstrap-scenario.yml"
portal_approval_scenario="$neobank_specs/l1-portal-approval-scenario.yml"
zone_approval_scenario="$neobank_specs/zone-outbox-approvals-scenario.yml"
admission_seed_scenario="$neobank_specs/admission-seed-scenario.yml"
for file in "$scenario_path" "$bootstrap_scenario" "$portal_approval_scenario" \
    "$zone_approval_scenario" "$admission_seed_scenario"
do
    [[ -f "$file" ]] || die "missing txgen scenario $file"
done

mkdir -p "$ZONES_BENCH_OUTPUT" "$(dirname "$ZONES_BENCH_RENDERED_SCENARIO")"
secret_dir="$(mktemp -d "${RUNNER_TEMP:-/tmp}/zones-neobank-auth.XXXXXX")"
chmod 700 "$secret_dir"
export ZONES_BENCH_ZONE_AUTH_MAP="$secret_dir/zone-auth.json"
auth_pid=""
cleanup() {
    local status=$?
    [[ -z "$auth_pid" ]] || { kill -TERM "$auth_pid" 2>/dev/null || true; wait "$auth_pid" 2>/dev/null || true; }
    rm -f -- "$secret_dir/mnemonic" "$secret_dir/zone-auth.json" \
        "$secret_dir/auth-token-map.log" "$secret_dir/private-balance-request.json" \
        "$secret_dir/private-balance.curl"
    rmdir "$secret_dir" 2>/dev/null || true
    unset ZONES_BENCH_MNEMONIC
    exit "$status"
}
trap cleanup EXIT INT TERM

run_setup_scenario() {
    local stage="$1" scenario="$2" count="$3" report="$4" context="${5:-}"
    local starts_per_second="${6:-0}"
    local concurrency="$ZONES_BENCH_MAX_CONCURRENT"
    if (( 10#$concurrency > 10#$count )); then concurrency="$count"; fi

    echo "neobank stage=start run_id=$ZONES_BENCH_RUN_ID preset=$ZONES_BENCH_NEOBANK_PRESET stage=$stage${context:+ $context}"
    "$txgen_bin" scenario run \
        --scenario "$scenario" --count "$count" --starts-per-second "$starts_per_second" \
        --max-in-flight "$concurrency" --max-rpc-in-flight "$concurrency" \
        --failure-policy fail-fast --step-timeout "$ZONES_BENCH_STEP_TIMEOUT" \
        --seed "$ZONES_BENCH_SEED" --report "$report"
    assert_scenario_report "$report" "$count" "$stage"
    echo "neobank stage=end run_id=$ZONES_BENCH_RUN_ID preset=$ZONES_BENCH_NEOBANK_PRESET stage=$stage${context:+ $context}"
}

# Zone transaction-pool admission requires every sender to hold a nonzero
# balance of an enabled token. Run one exact encrypted onramp per benchmark
# account before the untimed outbox approvals. Pace the deposits so a large
# account pool is not packed into one L1 block and rejected by ZonePortal's
# per-block deposit cap. This setup scenario uses account leases, so
# count=accounts touches every account exactly once while respecting the
# configured max-in-flight cap.
seed_zone_admission_balances() {
    local seed_report="$ZONES_BENCH_OUTPUT/admission-seed-report.json"
    local total=$((10#$ZONES_BENCH_ACCOUNTS))

    run_setup_scenario \
        zone_admission_seed "$admission_seed_scenario" "$total" "$seed_report" \
        "starts_per_second=$ZONES_BENCH_ADMISSION_SEED_TPS" \
        "$ZONES_BENCH_ADMISSION_SEED_TPS"
    echo "Zone admission seed verified: $total/$total exact encrypted deposits processed"
}

stage_start render_scenario
"$txgen_bin" scenario render \
    --scenario "$scenario_path" \
    --output "$ZONES_BENCH_RENDERED_SCENARIO"
[[ -s "$ZONES_BENCH_RENDERED_SCENARIO" ]] ||
    die "txgen did not render the selected neobank scenario"
stage_end render_scenario

# The bootstrap scenario approves the control account before depositing the
# Zone fee token to the sequencer.
run_setup_scenario \
    bootstrap "$bootstrap_scenario" 1 \
    "$ZONES_BENCH_OUTPUT/bootstrap-report.json"

run_setup_scenario \
    portal_approval "$portal_approval_scenario" "$ZONES_BENCH_ACCOUNTS" \
    "$ZONES_BENCH_OUTPUT/portal-approval-report.json" "approval_round=portal"

# Deposit-only never submits a user transaction to the Zone. Every other preset
# seeds the enabled-token balance required by current Zone txpool admission.
if [[ "$ZONES_BENCH_NEOBANK_PRESET" != "encrypted-deposit" ]]; then
    seed_zone_admission_balances
fi

# The auth map is intentionally mode 0600 and is never copied to benchmark artifacts.
stage_start auth_token_map
"$txgen_bin" auth-token-map --spec "$neobank_specs/zone-flow.yml" --pool users \
    --zone-id "$ZONES_BENCH_EXPECTED_ZONE_ID" \
    --chain-id "$ZONES_BENCH_EXPECTED_ZONE_CHAIN_ID" \
    --ttl-secs "$ZONES_BENCH_AUTH_TTL_SECS" \
    --refresh-before-secs "$ZONES_BENCH_AUTH_REFRESH_SECS" \
    --watch --output "$secret_dir/zone-auth.json" >"$secret_dir/auth-token-map.log" 2>&1 &
auth_pid=$!
for _ in $(seq 1 60); do [[ -f "$secret_dir/zone-auth.json" ]] && break; sleep 1; done
[[ -f "$secret_dir/zone-auth.json" ]] || die "timed out creating private Zone auth map"
jq -e 'to_entries | all(.[]; (.key | type) == "string" and (.value | type) == "string")' \
    "$secret_dir/zone-auth.json" >/dev/null ||
    die "private Zone auth map is malformed"
jq -S 'keys | sort' "$secret_dir/zone-auth.json" >"$ZONES_BENCH_OUTPUT/accounts.json"
jq -e --argjson expected "$ZONES_BENCH_ACCOUNTS" '
    length == $expected and
    all(.[]; type == "string") and
    (unique | length) == $expected
' "$ZONES_BENCH_OUTPUT/accounts.json" >/dev/null ||
    die "auth map did not derive the expected unique benchmark account pool"
stage_end auth_token_map

# Approvals are untimed. Deposit-only submits no user Zone transaction.
# The fixed scenario approves both enabled assets for each leased account.
if [[ "$ZONES_BENCH_NEOBANK_PRESET" != "encrypted-deposit" ]]; then
    run_setup_scenario \
        zone_approvals "$zone_approval_scenario" "$ZONES_BENCH_ACCOUNTS" \
        "$ZONES_BENCH_OUTPUT/zone-approvals-report.json" \
        "approval_round=base_and_earn"
fi

# Seed Earn before any setup or measured Earn callback: make one untimed deposit
# with the full callback allowance and leave its returned EarnToken in an unrelated
# Zone account. This keeps the EarnVault and engine nonempty, so the benchmark runs
# steady-state deposit and redemption paths instead of empty-pool transitions.
earn_warmup_amount="$ZONES_BENCH_WITHDRAWAL_AMOUNT"
if [[ "$ZONES_BENCH_NEOBANK_PRESET" != "encrypted-deposit" ]]; then
    readonly earn_warmup_callback_gas_limit=10000000
    earn_warmup_recipient_hash="$(cast keccak "zones-benchmark-earn-warmup:$ZONES_BENCH_SEED")"
    earn_warmup_recipient="0x${earn_warmup_recipient_hash: -40}"
    ZONES_BENCH_CALLBACK_GAS_LIMIT="$earn_warmup_callback_gas_limit" \
    ZONES_BENCH_SWAPPED_REDEMPTION_ONRAMP_PER_ACCOUNT="$ZONES_BENCH_DEPOSIT_AMOUNT" \
    ZONES_BENCH_SWAPPED_REDEMPTION_POSITION_PER_ACCOUNT="$earn_warmup_amount" \
    ZONES_BENCH_POSITION_RECIPIENT="\"$earn_warmup_recipient\"" run_setup_scenario \
        earn_warmup "$neobank_specs/swapped-redemption-position-scenario.yml" 1 \
        "$ZONES_BENCH_OUTPUT/earn-warmup-report.json" \
        "callback_gas_limit=$earn_warmup_callback_gas_limit amount=$earn_warmup_amount"

    warmup_share_supply_after="$(read_l1_uint "$ZONES_BENCH_EARN_VAULT" 'totalEarnShares()(uint256)')"
    warmup_earn_supply_after="$(read_l1_uint "$ZONES_BENCH_EARN_TOKEN" 'totalSupply()(uint256)')"
    [[ "$warmup_share_supply_after" == "$earn_warmup_amount" ]] ||
        die "Earn warmup share supply $warmup_share_supply_after does not equal $earn_warmup_amount"
    [[ "$warmup_earn_supply_after" == "$earn_warmup_amount" ]] ||
        die "Earn warmup token supply $warmup_earn_supply_after does not equal $earn_warmup_amount"
fi

if [[ "$ZONES_BENCH_NEOBANK_PRESET" == "rewards-redemption" ]]; then
    initial_share_supply="$(read_l1_uint "$ZONES_BENCH_EARN_VAULT" 'totalEarnShares()(uint256)')"
    initial_earn_supply="$(read_l1_uint "$ZONES_BENCH_EARN_TOKEN" 'totalSupply()(uint256)')"
    [[ "$initial_share_supply" == 0 && "$initial_earn_supply" == 0 ]] ||
        die "reward position setup requires zero initial EarnToken supply"

    stage_start rewards_position_setup
    position_concurrency="$ZONES_BENCH_MAX_CONCURRENT"
    if (( 10#$position_concurrency > 10#$ZONES_BENCH_ACCOUNTS )); then
        position_concurrency="$ZONES_BENCH_ACCOUNTS"
    fi
    "$txgen_bin" scenario run \
        --scenario "$neobank_specs/rewards-position-scenario.yml" \
        --count "$ZONES_BENCH_ACCOUNTS" \
        --max-in-flight "$position_concurrency" --max-rpc-in-flight "$position_concurrency" \
        --failure-policy fail-fast --step-timeout "$ZONES_BENCH_STEP_TIMEOUT" \
        --seed "$ZONES_BENCH_SEED" \
        --report "$ZONES_BENCH_OUTPUT/rewards-position-report.json"
    assert_scenario_report \
        "$ZONES_BENCH_OUTPUT/rewards-position-report.json" \
        "$ZONES_BENCH_ACCOUNTS" "reward position setup"
    stage_end rewards_position_setup

    stage_start rewards_position_check
    positioned_share_supply="$(read_l1_uint "$ZONES_BENCH_EARN_VAULT" 'totalEarnShares()(uint256)')"
    positioned_earn_supply="$(read_l1_uint "$ZONES_BENCH_EARN_TOKEN" 'totalSupply()(uint256)')"
    [[ "$positioned_share_supply" == "$reward_total_position" ]] ||
        die "reward position share supply $positioned_share_supply does not equal $reward_total_position"
    [[ "$positioned_earn_supply" == "$reward_total_position" ]] ||
        die "reward position EarnToken supply $positioned_earn_supply does not equal $reward_total_position"
    verify_reward_zone_balances seeded "$reward_total_position" "$reward_position_per_account"
    reward_quote_before="$(read_l1_uint \
        "$ZONES_BENCH_EARN_VAULT" 'previewRedeem(uint256)(uint256)' \
        "$ZONES_BENCH_WITHDRAWAL_AMOUNT")"
    stage_end rewards_position_check

    stage_start rewards_funding
    "$txgen_bin" scenario run \
        --scenario "$neobank_specs/rewards-funding-scenario.yml" \
        --count 1 --max-in-flight 1 --max-rpc-in-flight 2 \
        --failure-policy fail-fast --step-timeout 2m \
        --seed "$ZONES_BENCH_SEED" \
        --report "$ZONES_BENCH_OUTPUT/rewards-funding-report.json"
    assert_scenario_report \
        "$ZONES_BENCH_OUTPUT/rewards-funding-report.json" 1 "reward funding setup"
    stage_end rewards_funding

    stage_start rewards_funding_check
    funded_share_supply="$(read_l1_uint "$ZONES_BENCH_EARN_VAULT" 'totalEarnShares()(uint256)')"
    funded_earn_supply="$(read_l1_uint "$ZONES_BENCH_EARN_TOKEN" 'totalSupply()(uint256)')"
    reward_quote_after="$(read_l1_uint \
        "$ZONES_BENCH_EARN_VAULT" 'previewRedeem(uint256)(uint256)' \
        "$ZONES_BENCH_WITHDRAWAL_AMOUNT")"
    [[ "$funded_share_supply" == "$reward_total_position" ]] ||
        die "reward funding changed EarnVault share supply"
    [[ "$funded_earn_supply" == "$reward_total_position" ]] ||
        die "reward funding changed EarnToken total supply"
    bigint_true "$reward_quote_after > $reward_quote_before" ||
        die "reward funding did not increase redemption value: $reward_quote_before -> $reward_quote_after"
    echo "reward redemption quote increased: $reward_quote_before -> $reward_quote_after"
    stage_end rewards_funding_check
fi

if [[ "$ZONES_BENCH_NEOBANK_PRESET" == "private-withdrawal" ||
      "$ZONES_BENCH_NEOBANK_PRESET" == "swapped-redemption" ]]; then
    initial_share_supply="$(read_l1_uint "$ZONES_BENCH_EARN_VAULT" 'totalEarnShares()(uint256)')"
    initial_earn_supply="$(read_l1_uint "$ZONES_BENCH_EARN_TOKEN" 'totalSupply()(uint256)')"
    [[ "$initial_share_supply" == "$earn_warmup_amount" &&
       "$initial_earn_supply" == "$earn_warmup_amount" ]] ||
        die "$ZONES_BENCH_NEOBANK_PRESET position setup requires only the startup Earn warmup position"

    stage_start redemption_position_setup
    position_concurrency="$ZONES_BENCH_MAX_CONCURRENT"
    if (( 10#$position_concurrency > 10#$ZONES_BENCH_ACCOUNTS )); then
        position_concurrency="$ZONES_BENCH_ACCOUNTS"
    fi
    "$txgen_bin" scenario run \
        --scenario "$neobank_specs/swapped-redemption-position-scenario.yml" \
        --count "$ZONES_BENCH_ACCOUNTS" \
        --max-in-flight "$position_concurrency" --max-rpc-in-flight "$position_concurrency" \
        --failure-policy fail-fast --step-timeout "$ZONES_BENCH_STEP_TIMEOUT" \
        --seed "$ZONES_BENCH_SEED" \
        --report "$ZONES_BENCH_OUTPUT/swapped-redemption-position-report.json"
    assert_scenario_report \
        "$ZONES_BENCH_OUTPUT/swapped-redemption-position-report.json" \
        "$ZONES_BENCH_ACCOUNTS" "$ZONES_BENCH_NEOBANK_PRESET position setup"
    stage_end redemption_position_setup

    stage_start redemption_position_check
    positioned_share_supply="$(read_l1_uint "$ZONES_BENCH_EARN_VAULT" 'totalEarnShares()(uint256)')"
    positioned_earn_supply="$(read_l1_uint "$ZONES_BENCH_EARN_TOKEN" 'totalSupply()(uint256)')"
    expected_redemption_position="$(bigint_eval "$swapped_redemption_total_position + $earn_warmup_amount")"
    [[ "$positioned_share_supply" == "$expected_redemption_position" ]] ||
        die "$ZONES_BENCH_NEOBANK_PRESET share supply $positioned_share_supply does not equal $expected_redemption_position"
    [[ "$positioned_earn_supply" == "$expected_redemption_position" ]] ||
        die "$ZONES_BENCH_NEOBANK_PRESET EarnToken supply $positioned_earn_supply does not equal $expected_redemption_position"
    verify_reward_zone_balances \
        seeded "$swapped_redemption_total_position" \
        "$swapped_redemption_position_per_account"
    stage_end redemption_position_check
fi

if [[ "$ZONES_BENCH_NEOBANK_PRESET" == "slippage-bounce" ]]; then
    stage_start slippage_precondition
    bounce_earn_supply="$(cast call "$ZONES_BENCH_EARN_TOKEN" 'totalSupply()(uint256)' \
        --rpc-url "$L1_RPC_URL" | awk '{print $1}')"
    bounce_vault_balance="$(cast call "$ZONES_BENCH_VAULT" 'balanceOf(address)(uint256)' \
        "$ZONES_BENCH_ENGINE" --rpc-url "$L1_RPC_URL" | awk '{print $1}')"
    [[ "$bounce_earn_supply" =~ ^[0-9]+$ && "$bounce_vault_balance" =~ ^[0-9]+$ ]] ||
        die "could not read slippage-bounce L1 preconditions"
    stage_end slippage_precondition
fi

measured_token_balance_before=""
measured_token_balance_holder=""
case "$ZONES_BENCH_NEOBANK_PRESET" in
    encrypted-deposit)
        measured_token_balance_holder="$L1_PORTAL_ADDRESS"
        measured_token_balance_before="$(read_l1_uint \
            "$ZONES_BENCH_DLUSD" 'balanceOf(address)(uint256)' \
            "$measured_token_balance_holder")"
        ;;
esac

private_flow_parent_block="$(cast block-number --rpc-url "$ZONE_RPC_URL")"
[[ "$private_flow_parent_block" =~ ^[0-9]+$ ]] ||
    die "could not read the Zone head before the measured private flow"
if [[ -n "${ZONES_BENCH_SETTLEMENT_START_FILE:-}" ]]; then
    mkdir -p "$(dirname -- "$ZONES_BENCH_SETTLEMENT_START_FILE")"
    settlement_start_index="$(read_l1_uint "$L1_PORTAL_ADDRESS" 'withdrawalBatchIndex()(uint64)')"
    jq -n --argjson batch_index "$settlement_start_index" --argjson timestamp "$(date +%s)" \
        '{batch_index:$batch_index,timestamp:$timestamp}' \
        >"$ZONES_BENCH_SETTLEMENT_START_FILE"
fi
# Optional prover-benchmark snapshot, after setup and before measured traffic.
if [[ -n "${ZONES_BENCH_METRICS_BEFORE_FILE:-}" ]]; then
    mkdir -p "$(dirname -- "$ZONES_BENCH_METRICS_BEFORE_FILE")"
    curl --fail --silent --show-error \
        "${ZONES_BENCH_METRICS_URL:-http://127.0.0.1:9201/metrics}" \
        >"$ZONES_BENCH_METRICS_BEFORE_FILE"
    [[ -s "$ZONES_BENCH_METRICS_BEFORE_FILE" ]] ||
        die "Zone metrics were empty before the measured private flow"
fi
stage_start private_flow
scenario_report_args=()
build_scenario_report_args scenario_report_args "$ZONES_BENCH_REPORT"
"$txgen_bin" scenario run --scenario "$scenario_path" --count "$ZONES_BENCH_COUNT" \
    --starts-per-second "$ZONES_BENCH_TPS" --max-in-flight "$ZONES_BENCH_MAX_CONCURRENT" --max-rpc-in-flight "$ZONES_BENCH_MAX_CONCURRENT" \
    --failure-policy fail-fast --step-timeout "$ZONES_BENCH_STEP_TIMEOUT" --seed "$ZONES_BENCH_SEED" \
    --sample-instances "$sample_instances" "${scenario_report_args[@]}"
stage_end private_flow
private_flow_tip_block="$(cast block-number --rpc-url "$ZONE_RPC_URL")"
[[ "$private_flow_tip_block" =~ ^[0-9]+$ ]] ||
    die "could not read the Zone head after the measured private flow"
(( 10#$private_flow_tip_block > 10#$private_flow_parent_block )) ||
    die "the measured private flow produced no Zone blocks"
mkdir -p "$(dirname "$ZONES_BENCH_SPF_RANGE")"
{
    printf 'ZONES_BENCH_SPF_FROM_BLOCK=%s\n' "$((10#$private_flow_parent_block + 1))"
    printf 'ZONES_BENCH_SPF_TO_BLOCK=%s\n' "$((10#$private_flow_tip_block))"
} >"$ZONES_BENCH_SPF_RANGE"

if [[ "$ZONES_BENCH_NEOBANK_PRESET" == "slippage-bounce" ]]; then
    stage_start slippage_postcondition
    final_earn_supply="$(cast call "$ZONES_BENCH_EARN_TOKEN" 'totalSupply()(uint256)' \
        --rpc-url "$L1_RPC_URL" | awk '{print $1}')"
    final_vault_balance="$(cast call "$ZONES_BENCH_VAULT" 'balanceOf(address)(uint256)' \
        "$ZONES_BENCH_ENGINE" --rpc-url "$L1_RPC_URL" | awk '{print $1}')"
    [[ "$final_earn_supply" == "$bounce_earn_supply" ]] ||
        die "slippage bounce changed EarnToken total supply"
    [[ "$final_vault_balance" == "$bounce_vault_balance" ]] ||
        die "slippage bounce changed the engine vault balance"
    stage_end slippage_postcondition
fi

if [[ "$ZONES_BENCH_NEOBANK_PRESET" == "rewards-redemption" ]]; then
    stage_start rewards_postcondition
    final_share_supply="$(read_l1_uint "$ZONES_BENCH_EARN_VAULT" 'totalEarnShares()(uint256)')"
    final_earn_supply="$(read_l1_uint "$ZONES_BENCH_EARN_TOKEN" 'totalSupply()(uint256)')"
    [[ "$final_share_supply" == "$reward_expected_remaining" ]] ||
        die "terminal reward share supply $final_share_supply does not equal $reward_expected_remaining"
    [[ "$final_earn_supply" == "$reward_expected_remaining" ]] ||
        die "terminal reward EarnToken supply $final_earn_supply does not equal $reward_expected_remaining"
    verify_reward_zone_balances \
        remaining "$reward_expected_remaining" "$ZONES_BENCH_WITHDRAWAL_AMOUNT"
    stage_end rewards_postcondition
fi

if [[ "$ZONES_BENCH_NEOBANK_PRESET" == "private-withdrawal" ||
      "$ZONES_BENCH_NEOBANK_PRESET" == "swapped-redemption" ]]; then
    stage_start redemption_postcondition
    final_share_supply="$(read_l1_uint "$ZONES_BENCH_EARN_VAULT" 'totalEarnShares()(uint256)')"
    final_earn_supply="$(read_l1_uint "$ZONES_BENCH_EARN_TOKEN" 'totalSupply()(uint256)')"
    expected_redemption_remaining="$(bigint_eval "$swapped_redemption_expected_remaining + $earn_warmup_amount")"
    [[ "$final_share_supply" == "$expected_redemption_remaining" ]] ||
        die "terminal $ZONES_BENCH_NEOBANK_PRESET share supply $final_share_supply does not equal $expected_redemption_remaining"
    [[ "$final_earn_supply" == "$expected_redemption_remaining" ]] ||
        die "terminal $ZONES_BENCH_NEOBANK_PRESET EarnToken supply $final_earn_supply does not equal $expected_redemption_remaining"
    verify_reward_zone_balances \
        distributed_remaining "$swapped_redemption_expected_remaining" \
        "$ZONES_BENCH_WITHDRAWAL_AMOUNT" \
        "$swapped_redemption_position_per_account"
    stage_end redemption_postcondition
fi

assert_scenario_report "$ZONES_BENCH_REPORT" "$ZONES_BENCH_COUNT" "private flow"

if [[ -n "$measured_token_balance_before" ]]; then
    measured_token_balance_after="$(read_l1_uint \
        "$ZONES_BENCH_DLUSD" 'balanceOf(address)(uint256)' \
        "$measured_token_balance_holder")"
    case "$ZONES_BENCH_NEOBANK_PRESET" in
        encrypted-deposit) measured_balance_amount="$ZONES_BENCH_DEPOSIT_AMOUNT" ;;
        *) die "unexpected measured balance preset" ;;
    esac
    expected_token_delta="$(bigint_eval "$ZONES_BENCH_COUNT * $measured_balance_amount")"
    observed_token_delta="$(bigint_eval \
        "$measured_token_balance_after - $measured_token_balance_before")"
    [[ "$observed_token_delta" == "$expected_token_delta" ]] ||
        die "$ZONES_BENCH_NEOBANK_PRESET terminal L1 token delta $observed_token_delta does not equal $expected_token_delta"
    echo "$ZONES_BENCH_NEOBANK_PRESET terminal L1 token delta verified: $observed_token_delta"
fi
