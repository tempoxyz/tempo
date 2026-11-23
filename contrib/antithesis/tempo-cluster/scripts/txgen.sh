#!/bin/bash
set -euo pipefail
export TXGEN_ACCOUNTS=16
export TXGEN_EXISTING_RECIPIENTS_START=16 TXGEN_EXISTING_RECIPIENTS_END=64
# Match the four default benchmark fee tokens; these are test genesis addresses.
export TXGEN_TIP20_TOKENS='["0x20c0000000000000000000000000000000000000","0x20c0000000000000000000000000000000000001","0x20c0000000000000000000000000000000000002","0x20c0000000000000000000000000000000000003"]'
mode="${1:?prepare or burst}"; rpc="${2:?RPC URL}"
if [[ "$mode" == prepare ]]; then
    # No retries of partially executed fixed-nonce setup. Fail setup visibly instead.
    if [[ -e /state/setup-started ]]; then
        echo 'Incomplete setup: recreate the compose volumes before retrying' >&2
        exit 1
    fi
    touch /state/setup-started
    nu /driver/prepare.nu "$rpc"
    eval "$(jq -r 'to_entries[] | "export \(.key)=\(.value|@sh)"' /state/env.json)"
    txgen-tempo generate -s /state/public-mix.yml -n 0 --seed 99 --rpc "$rpc" \
        --setup-state-out /state/setup.json > /state/setup.ndjson
    bench send --rpc-url "$rpc" --tps 100 --max-concurrent 8 --retries 0 \
        --drain-timeout 0 < /state/setup.ndjson
    touch /state/setup-confirmed
elif [[ "$mode" == burst ]]; then
    eval "$(jq -r 'to_entries[] | "export \(.key)=\(.value|@sh)"' /state/env.json)"
    seed="${3:?seed}"; report="${4:?report}"
    # The driver checks finalized receipts; draining adds three one-second polls
    # even for an empty pool, and cannot succeed with the former two-second limit.
    txgen-tempo generate -s /state/public-mix.yml -n 32 --seed "$seed" --rpc "$rpc" \
        --setup-state-in /state/setup.json --signing-workers 1 \
        | bench send --rpc-url "$rpc" --tps 32 --max-concurrent 8 --retries 0 \
            --skip-setup --drain-timeout 0 --report "json:$report"
else
    echo "Unknown mode: $mode" >&2; exit 2
fi
