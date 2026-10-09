#!/usr/bin/env bash

# Build txgen scenario reporter arguments without placing ClickHouse credentials
# in argv. The endpoint is credential-free; authentication stays in txgen's
# CLICKHOUSE_USER and CLICKHOUSE_PASSWORD environment variables.
build_scenario_report_args() {
    local destination_name="$1"
    local json_report="$2"
    local -n destination="$destination_name"
    local name pair metadata_name environment_name
    local -a configuration_metadata=(
        "accounts:ZONES_BENCH_ACCOUNTS"
        "count:ZONES_BENCH_COUNT"
        "target-rate:ZONES_BENCH_TPS"
        "max-concurrent:ZONES_BENCH_MAX_CONCURRENT"
        "deposit-amount:ZONES_BENCH_DEPOSIT_AMOUNT"
        "activity-amount:ZONES_BENCH_ACTIVITY_AMOUNT"
        "withdrawal-amount:ZONES_BENCH_WITHDRAWAL_AMOUNT"
        "bootstrap-deposit-amount:ZONES_BENCH_BOOTSTRAP_DEPOSIT_AMOUNT"
        "l1-gas-limit:ZONES_BENCH_L1_GAS_LIMIT"
        "l1-general-gas-limit:ZONES_BENCH_L1_GENERAL_GAS_LIMIT"
        "zone-gas-limit:ZONES_BENCH_ZONE_GAS_LIMIT"
        "withdrawal-max-batch-gas:ZONES_BENCH_WITHDRAWAL_MAX_BATCH_GAS"
        "withdrawal-max-in-flight-batches:ZONES_BENCH_WITHDRAWAL_MAX_IN_FLIGHT_BATCHES"
        "zone-batch-interval-blocks:ZONES_BENCH_ZONE_BATCH_INTERVAL_BLOCKS"
        "withdrawal-poll-interval-secs:ZONES_BENCH_WITHDRAWAL_POLL_INTERVAL_SECS"
        "step-timeout:ZONES_BENCH_STEP_TIMEOUT"
        "setup-settlement-timeout-secs:ZONES_BENCH_SETUP_SETTLEMENT_TIMEOUT_SECS"
        "drain-timeout-secs:ZONES_BENCH_DRAIN_TIMEOUT"
        "seed:ZONES_BENCH_SEED"
        "force-bloat:ZONES_BENCH_FORCE_BLOAT"
        "tempo-hardfork:ZONES_BENCH_TEMPO_HARDFORK"
        "tempo-revision:ZONES_BENCH_TEMPO_REF"
        "txgen-revision:ZONES_BENCH_TXGEN_REF"
        "earn-revision:ZONES_BENCH_EARN_REVISION"
    )

    destination=(--report "$json_report")
    if [[ -z "${CLICKHOUSE_URL:-}" ]]; then
        if [[ "${ZONES_BENCH_REQUIRE_CLICKHOUSE:-0}" == 1 ]]; then
            echo "error: CLICKHOUSE_URL is required for this benchmark run" >&2
            return 1
        fi
        return 0
    fi

    for name in \
        CLICKHOUSE_USER CLICKHOUSE_PASSWORD \
        ZONES_BENCH_ZONES_REF ZONES_BENCH_GIT_REF ZONES_BENCH_PHASE \
        ZONES_BENCH_NEOBANK_PRESET
    do
        if [[ -z "${!name:-}" ]]; then
            echo "error: $name is required when ClickHouse reporting is enabled" >&2
            return 1
        fi
    done

    destination+=(
        --report "clickhouse:$CLICKHOUSE_URL"
        --metadata "git-sha=$ZONES_BENCH_ZONES_REF"
        --metadata "git-ref=$ZONES_BENCH_GIT_REF"
        --metadata "phase=$ZONES_BENCH_PHASE"
    )
    destination+=(--metadata "neobank-preset=$ZONES_BENCH_NEOBANK_PRESET")
    [[ -z "${ZONES_BENCH_SWAP_MECHANISM:-}" ]] ||
        destination+=(--metadata "swap-mechanism=$ZONES_BENCH_SWAP_MECHANISM")
    [[ -z "${ZONES_BENCH_SWAP_LIQUIDITY:-}" ]] ||
        destination+=(--metadata "swap-liquidity=$ZONES_BENCH_SWAP_LIQUIDITY")
    [[ -z "${ZONES_BENCH_CALLBACK_GAS_LIMIT:-}" ]] ||
        destination+=(--metadata "callback-gas-limit=$ZONES_BENCH_CALLBACK_GAS_LIMIT")
    [[ -z "${ZONES_BENCH_RECIPIENT_MODE:-}" ]] ||
        destination+=(--metadata "recipient-mode=$ZONES_BENCH_RECIPIENT_MODE")
    for pair in "${configuration_metadata[@]}"; do
        metadata_name="${pair%%:*}"
        environment_name="${pair#*:}"
        [[ -z "${!environment_name:-}" ]] ||
            destination+=(--metadata "$metadata_name=${!environment_name}")
    done
    [[ -z "${ZONES_BENCH_RUN_ID:-}" ]] ||
        destination+=(--metadata "zones-run-id=$ZONES_BENCH_RUN_ID")
    [[ -z "${ZONES_BENCH_BLOAT_GIB:-}" ]] ||
        destination+=(--metadata "state-bloat-gib=$ZONES_BENCH_BLOAT_GIB")
    [[ -z "${ZONES_BENCH_GITHUB_REPOSITORY:-}" ]] ||
        destination+=(--metadata "github-repository=$ZONES_BENCH_GITHUB_REPOSITORY")
    [[ -z "${ZONES_BENCH_GITHUB_RUN_ID:-}" ]] ||
        destination+=(--metadata "github-run-id=$ZONES_BENCH_GITHUB_RUN_ID")
    [[ -z "${ZONES_BENCH_GITHUB_WORKFLOW:-}" ]] ||
        destination+=(--metadata "github-workflow-file=$ZONES_BENCH_GITHUB_WORKFLOW")
    [[ -z "${ZONES_BENCH_GITHUB_PR_NUMBER:-}" ]] ||
        destination+=(--metadata "github-pr-number=$ZONES_BENCH_GITHUB_PR_NUMBER")
}
