cross_compile := "false"
cargo_build_binary := if cross_compile == "true" { "cross" } else { "cargo" }
act_debug_mode := env("ACT", "false")
zone_rpc := env("ZONE_RPC_URL", "http://localhost:8546")
zone_http_port := env("ZONE_HTTP_PORT", "8546")
zone_dev_genesis_tmp := "./target/zone-dev-genesis"

[group('deps')]
install-cross:
    cargo install cross --git https://github.com/cross-rs/cross

[group('build')]
[doc('Builds all zone binaries in cargo release mode')]
build-all-release extra_args="": (build-release "tempo-zone" extra_args)

[group('build')]
[doc('Builds all zone binaries')]
build-all extra_args="": (build "tempo-zone" extra_args)

build-release binary extra_args="": (build binary "-r " + extra_args)

build binary extra_args="":
    {{cargo_build_binary}} build {{extra_args}} --bin {{binary}}

[group('zone')]
[doc('Regenerates the bundled zone dev genesis')]
regen-zone-dev-genesis:
    #!/bin/bash
    set -euo pipefail
    rm -rf {{zone_dev_genesis_tmp}}
    cargo run -p tempo-xtask -- generate-zone-genesis \
        --output {{zone_dev_genesis_tmp}} \
        --chain-id 1337 \
        --admin 0xaAaAaAaa00000000000000000000000000000000 \
        --with-createx \
        --with-safe-deployer \
        --with-create2-factory
    mv {{zone_dev_genesis_tmp}}/genesis.json crates/node/assets/zone-dev-genesis.json
    rm -rf {{zone_dev_genesis_tmp}}

[group('localnet')]
[doc('Generates a genesis file')]
genesis accounts="1000" output="./" profile="maxperf":
    cargo run -p tempo-xtask --profile {{profile}} -- generate-genesis --output {{output}} -a {{accounts}} --no-dkg-in-genesis

[group('localnet')]
[doc('Deletes local network data and launches a new localnet')]
[confirm('This will wipe your data directory (unless you have reset=false) - please confirm before proceeding (y/n):')]
localnet accounts="1000" reset="false" profile="maxperf" features="asm-keccak" args="":
    #!/bin/bash
    if [[ "{{reset}}" = "true" ]]; then
        rm -r ./localnet/ || true
        mkdir ./localnet/
        just genesis {{accounts}} ./localnet {{profile}}
    fi;
    cargo run --bin tempo --profile {{profile}} --features {{features}} -- \
                      node \
                      --chain ./localnet/genesis.json \
                      --dev \
                      --dev.block-time 1sec \
                      --datadir ./localnet/reth \
                      --http \
                      --http.addr 0.0.0.0 \
                      --http.port 8545 \
                      --http.api all \
                      --engine.disable-precompile-cache \
                      --engine.legacy-state-root \
                      --builder.gaslimit 3000000000 \
                      --builder.max-tasks 8 \
                      --builder.deadline 3 \
                      --log.file.directory ./localnet/logs \
                      --faucet.enabled \
                      --faucet.private-key 0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80 \
                      --faucet.amount 1000000000000 \
                      --faucet.address 0x20c0000000000000000000000000000000000001 \
                      {{args}}

[group('zone')]
[doc('Approves the ZonePortal to spend max tokens. Requires L1_RPC_URL, L1_PORTAL_ADDRESS, and PRIVATE_KEY env vars.')]
max-approve-portal token="0x20C0000000000000000000000000000000000000":
    #!/bin/bash
    set -euo pipefail
    RPC="${L1_RPC_URL:?Set L1_RPC_URL env var}"
    PK="${PRIVATE_KEY:?Set PRIVATE_KEY env var}"
    PORTAL="${L1_PORTAL_ADDRESS:?Set L1_PORTAL_ADDRESS env var}"
    HTTP_RPC=$(echo "$RPC" | sed 's|^wss://|https://|' | sed 's|^ws://|http://|')
    echo "Approving ZonePortal for max tokens ({{token}})..."
    cast send "{{token}}" "approve(address,uint256)" "$PORTAL" "$(cast max-uint)" \
        --rpc-url "$HTTP_RPC" --private-key "$PK"
    echo "Approved!"

[group('zone')]
[doc('Sends a deposit to the ZonePortal on L1 (recipient and memo are hidden on-chain). Requires L1_RPC_URL, L1_PORTAL_ADDRESS, and PRIVATE_KEY env vars. Run max-approve-portal first.')]
send-deposit amount="1000000" to="" memo="0x0000000000000000000000000000000000000000000000000000000000000000" token="0x20C0000000000000000000000000000000000000" rpc=zone_rpc:
    #!/bin/bash
    set -euo pipefail
    PK="${PRIVATE_KEY:?Set PRIVATE_KEY env var}"
    TO="{{to}}"
    if [[ -z "$TO" ]]; then
        TO=$(cast wallet address "$PK")
    fi
    ARGS="--amount {{amount}} --token {{token}} --memo {{memo}} --to $TO --zone-rpc-url {{rpc}}"
    PRIVATE_KEY="$PK" cargo run -p tempo-xtask -- deposit $ARGS

[group('zone')]
[doc('Fetches and prints zone info from the ZoneFactory. Pass a zone ID (integer) or portal address (0x...). Set ZONE_FACTORY to override the Moderato default.')]
zone-info identifier:
    cargo run -p tempo-xtask -- zone-info {{identifier}}

[group('zone')]
[doc('Creates a new zone on L1 via ZoneFactory and generates genesis + zone.json in generated/<name>/. Enforcement defaults to false. Initial membership and gateways are optional via ZONE_ALLOWED_ACCOUNTS and ZONE_GATEWAYS.')]
create-zone name token="" access_enforced="false" gateway_enforced="false":
    #!/bin/bash
    set -euo pipefail
    PK="${PRIVATE_KEY:?Set PRIVATE_KEY env var}"
    ZONE_TOKEN_L1="{{token}}"
    if [[ -z "$ZONE_TOKEN_L1" ]]; then
        ZONE_TOKEN_L1="${ZONE_TOKEN:-0x20C0000000000000000000000000000000000000}"
    fi
    # Resolve well-known aliases (lowercased for case-insensitive matching)
    ZONE_TOKEN_LOWER=$(echo "$ZONE_TOKEN_L1" | tr '[:upper:]' '[:lower:]')
    case "$ZONE_TOKEN_LOWER" in
        pathusd|path-usd|path_usd)
            ZONE_TOKEN_L1="0x20C0000000000000000000000000000000000000" ;;
        alphausd|alpha-usd|alpha_usd)
            ZONE_TOKEN_L1="0x20c0000000000000000000000000000000000001" ;;
        betausd|beta-usd|beta_usd)
            ZONE_TOKEN_L1="0x20c0000000000000000000000000000000000002" ;;
    esac
    SEQ_KEY="${SEQUENCER_KEY:?Set SEQUENCER_KEY env var}"
    ADMIN_ADDR="${ADMIN_ADDR:-}"
    if [[ -z "$ADMIN_ADDR" ]]; then
        ADMIN_KEY="${ADMIN_KEY:?Set ADMIN_KEY env var or ADMIN_ADDR env var}"
        ADMIN_ADDR=$(cast wallet address "$ADMIN_KEY")
    fi
    L1_RPC="${L1_RPC_URL:?Set L1_RPC_URL env var (wss://...)}"
    HTTP_RPC=$(echo "$L1_RPC" | sed 's|^wss://|https://|' | sed 's|^ws://|http://|')
    SEQUENCER_ADDR=$(cast wallet address "$SEQ_KEY")
    OUTPUT="generated/{{name}}"
    mkdir -p "$OUTPUT"
    echo "Building Solidity contracts..."
    (cd crates/contracts && forge build --skip test) || true
    echo "Building xtask..."
    cargo build -p tempo-xtask
    echo "Creating zone '{{name}}' on L1 and generating genesis..."
    echo "Initial portal token: $ZONE_TOKEN_L1"
    echo "Admin: $ADMIN_ADDR"
    echo "Sequencer: $SEQUENCER_ADDR"
    ACCESS_ENFORCED="{{access_enforced}}"
    GATEWAY_ENFORCED="{{gateway_enforced}}"
    CREATE_ARGS=()
    if [[ "$ACCESS_ENFORCED" == "true" ]]; then
        CREATE_ARGS+=(--access-mode)
    elif [[ "$ACCESS_ENFORCED" != "false" ]]; then
        echo "Error: access_enforced must be 'true' or 'false'" >&2
        exit 1
    fi
    IFS=',' read -ra ALLOWED <<< "${ZONE_ALLOWED_ACCOUNTS:-}"
    for account in "${ALLOWED[@]}"; do
        [[ -n "$account" ]] && CREATE_ARGS+=(--allowed-account "$account")
    done
    if [[ "$GATEWAY_ENFORCED" == "true" ]]; then
        CREATE_ARGS+=(--gateway-mode)
    elif [[ "$GATEWAY_ENFORCED" != "false" ]]; then
        echo "Error: gateway_enforced must be 'true' or 'false'" >&2
        exit 1
    fi
    IFS=',' read -ra GATEWAYS <<< "${ZONE_GATEWAYS:-}"
    for gateway in "${GATEWAYS[@]}"; do
        [[ -n "$gateway" ]] && CREATE_ARGS+=(--zone-gateway "$gateway")
    done
    ZONE_FACTORY_OWNER_KEY="$PK" cargo run -p tempo-xtask -- create-zone \
        --output "$OUTPUT" \
        --l1-rpc-url "$HTTP_RPC" \
        --initial-token "$ZONE_TOKEN_L1" \
        --admin "$ADMIN_ADDR" \
        --sequencer "$SEQUENCER_ADDR" \
        "${CREATE_ARGS[@]}"
    echo "Zone '{{name}}' created. Artifacts in $OUTPUT/"

[group('zone')]
[doc('Deploys SwapAndDepositRouter on L1 for an existing zone and saves it to generated/<name>/zone.json. Requires L1_RPC_URL and PRIVATE_KEY env vars.')]
deploy-router name dex="0xDEc0000000000000000000000000000000000000":
    #!/bin/bash
    set -euo pipefail
    PK="${PRIVATE_KEY:?Set PRIVATE_KEY env var}"
    L1_RPC="${L1_RPC_URL:?Set L1_RPC_URL env var (wss://...)}"
    HTTP_RPC=$(echo "$L1_RPC" | sed 's|^wss://|https://|' | sed 's|^ws://|http://|')
    ZONE_DIR="generated/{{name}}"
    ZONE_JSON="$ZONE_DIR/zone.json"
    if [[ ! -f "$ZONE_JSON" ]]; then
        echo "Error: $ZONE_JSON not found. Run 'just create-zone {{name}}' first." >&2
        exit 1
    fi
    echo "Building Solidity contracts..."
    (cd crates/contracts && forge build --skip test) || true
    PRIVATE_KEY="$PK" cargo run -p tempo-xtask -- deploy-router \
        --zone-dir "$ZONE_DIR" \
        --l1-rpc-url "$HTTP_RPC" \
        --stablecoin-dex "{{dex}}"

[group('zone')]
[doc('Checks an Earn router and its ZonePortal closed-loop configuration, then prints Account roles for manual review. Requires L1_RPC_URL.')]
verify-closed-loop earn_router:
    #!/bin/bash
    set -euo pipefail
    L1_RPC="${L1_RPC_URL:?Set L1_RPC_URL env var}"
    cargo run -p tempo-xtask -- verify-closed-loop \
        --l1-rpc-url "$L1_RPC" \
        --earn-router "{{earn_router}}"

[group('zone')]
[doc('Runs a same-zone router demo: creates temporary tokens + DEX liquidity, withdraws token A from the zone, swaps on L1, and deposits token B back into the same zone. Requires L1_RPC_URL and PRIVATE_KEY env vars.')]
demo-swap-and-deposit name amount="100000000" tick="0" rpc=zone_rpc:
    #!/bin/bash
    set -euo pipefail
    PK="${PRIVATE_KEY:?Set PRIVATE_KEY env var}"
    L1_RPC="${L1_RPC_URL:?Set L1_RPC_URL env var (wss://...)}"
    HTTP_RPC=$(echo "$L1_RPC" | sed 's|^wss://|https://|' | sed 's|^ws://|http://|')
    ZONE_DIR="generated/{{name}}"
    ZONE_JSON="$ZONE_DIR/zone.json"
    if [[ ! -f "$ZONE_JSON" ]]; then
        echo "Error: $ZONE_JSON not found. Run 'just create-zone {{name}}' first." >&2
        exit 1
    fi
    PRIVATE_KEY="$PK" cargo run -p tempo-xtask -- demo-swap-and-deposit \
        --zone-dir "$ZONE_DIR" \
        --l1-rpc-url "$HTTP_RPC" \
        --zone-rpc-url "{{rpc}}" \
        --amount "{{amount}}" \
        --tick "{{tick}}"

[group('zone')]
[doc('Starts a Tempo Zone L2 node, subscribing to L1 deposits. Pass the zone name used in create-zone. Use profile=release for production.')]
zone-up name reset="false" profile="dev" args="":
    #!/bin/bash
    set -euo pipefail
    ZONE_DIR="generated/{{name}}"
    ZONE_JSON="$ZONE_DIR/zone.json"
    GENESIS_JSON="$ZONE_DIR/genesis.json"
    if [[ ! -f "$ZONE_JSON" ]]; then
        echo "Error: $ZONE_JSON not found. Run 'just create-zone {{name}}' first." >&2
        exit 1
    fi
    if [[ ! -f "$GENESIS_JSON" ]]; then
        echo "Error: $GENESIS_JSON not found. Run 'just create-zone {{name}}' first." >&2
        exit 1
    fi
    PORTAL=$(jq -r '.portal' "$ZONE_JSON")
    ANCHOR_BLOCK=$(jq -r '.tempoAnchorBlock' "$ZONE_JSON")
    ZONE_ID=$(jq -r '.zoneId' "$ZONE_JSON")
    SEQ_KEY_FILE="${SEQUENCER_KEY_FILE:-}"
    if [[ -z "$SEQ_KEY_FILE" ]] && ! jq -e '.sequencerKey? | strings | select(length > 0)' "$ZONE_JSON" > /dev/null; then
        echo "Error: SEQUENCER_KEY_FILE env var not set and no sequencer key found in $ZONE_JSON" >&2
        exit 1
    fi
    if [[ -z "$SEQ_KEY_FILE" ]]; then
        SEQ_KEY_FILE=<(jq -r '.sequencerKey' "$ZONE_JSON")
    fi
    DATADIR="/tmp/tempo-zone-{{name}}"
    if [[ "{{reset}}" = "true" ]]; then
        rm -rf "$DATADIR" || true
    fi
    PROFILE_FLAG=""
    if [[ "{{profile}}" == "release" ]]; then
        PROFILE_FLAG="--release"
    elif [[ "{{profile}}" != "dev" ]]; then
        PROFILE_FLAG="--profile {{profile}}"
    fi
    cargo run $PROFILE_FLAG --bin tempo-zone -- \
                      node \
                      --chain "$GENESIS_JSON" \
                      --l1.rpc-url "${L1_RPC_URL:?Set L1_RPC_URL env var (wss://...)}" \
                      --l1.portal-address "$PORTAL" \
                      --zone.id "$ZONE_ID" \
                      --http \
                      --http.addr 0.0.0.0 \
                      --http.port {{zone_http_port}} \
                      --http.api all \
                      --datadir "$DATADIR" \
                      --log.file.directory "$DATADIR/logs" \
                      --sequencer \
                      --sequencer-key-file "$SEQ_KEY_FILE" \
                      {{args}}

[group('zone')]
[doc('Approves the ZoneOutbox to spend max zone tokens on L2. Requires PRIVATE_KEY env var.')]
max-approve-outbox token="0x20C0000000000000000000000000000000000000" rpc=zone_rpc:
    #!/bin/bash
    set -euo pipefail
    PK="${PRIVATE_KEY:?Set PRIVATE_KEY env var}"
    OUTBOX="0x1c00000000000000000000000000000000000002"
    echo "Approving ZoneOutbox for max zone tokens..."
    TX_OUTPUT=$(cast send "{{token}}" "approve(address,uint256)" "$OUTBOX" "$(cast max-uint)" \
        --rpc-url "{{rpc}}" --private-key "$PK" --gas-limit 500000 --json)
    STATUS=$(echo "$TX_OUTPUT" | jq -r '.status')
    if [[ "$STATUS" == "0x1" ]]; then
        echo "Approved!"
    else
        echo "Transaction failed!"
        echo "$TX_OUTPUT" | jq .
        exit 1
    fi

[group('zone')]
[doc('Sends a withdrawal request on the zone (L2) back to Tempo L1. Requires PRIVATE_KEY env var. Run max-approve-outbox first.')]
send-withdrawal amount="1000000" to="" token="0x20C0000000000000000000000000000000000000" memo="0x0000000000000000000000000000000000000000000000000000000000000000" gas-limit="0" fallback-recipient="" data="0x" reveal-to="0x" rpc=zone_rpc:
    #!/bin/bash
    set -euo pipefail
    PK="${PRIVATE_KEY:?Set PRIVATE_KEY env var}"
    OUTBOX="0x1c00000000000000000000000000000000000002"
    TO="{{to}}"
    if [[ -z "$TO" ]]; then
        TO=$(cast wallet address "$PK")
    fi
    FALLBACK="{{fallback-recipient}}"
    if [[ -z "$FALLBACK" ]]; then
        FALLBACK="$TO"
    fi
    echo "Requesting withdrawal of {{amount}} to $TO (fallback: $FALLBACK)..."
    L2_OUTPUT=$(cast send "$OUTBOX" \
        "requestWithdrawal(address,address,uint128,bytes32,uint64,address,bytes,bytes)" \
        "{{token}}" "$TO" "{{amount}}" "{{memo}}" "{{gas-limit}}" "$FALLBACK" "{{data}}" "{{reveal-to}}" \
        --rpc-url "{{rpc}}" --private-key "$PK" --gas-limit 10000000 --json)
    L2_STATUS=$(echo "$L2_OUTPUT" | jq -r '.status')
    if [[ "$L2_STATUS" != "0x1" ]]; then
        echo "Withdrawal request failed on L2!"
        echo "$L2_OUTPUT" | jq .
        exit 1
    fi
    L2_TX=$(echo "$L2_OUTPUT" | jq -r '.transactionHash')
    L2_BLOCK=$(echo "$L2_OUTPUT" | jq -r '.blockNumber')
    echo "Withdrawal requested on L2! tx: $L2_TX (block $(printf '%d' "$L2_BLOCK"))"

    # Wait for the withdrawal to be processed on L1
    L1_RPC="${L1_RPC_URL:-}"
    PORTAL="${L1_PORTAL_ADDRESS:-}"
    if [[ -z "$L1_RPC" || -z "$PORTAL" ]]; then
        echo "Set L1_RPC_URL and L1_PORTAL_ADDRESS env vars to wait for L1 processing."
        exit 0
    fi
    HTTP_RPC=$(echo "$L1_RPC" | sed 's|^wss://|https://|' | sed 's|^ws://|http://|')
    FROM_BLOCK=$(cast block-number --rpc-url "$HTTP_RPC")
    echo "Waiting for withdrawal to be processed on L1 (from block $FROM_BLOCK)..."
    while true; do
        LOGS=$(cast logs --address "$PORTAL" --from-block "$FROM_BLOCK" --rpc-url "$HTTP_RPC" \
            "WithdrawalProcessed(address indexed to, bytes32 indexed senderTag, address token, uint128 amount, bool callbackSuccess)" \
            "$TO" --json 2>/dev/null || echo "[]")
        if [[ "$LOGS" != "[]" && "$LOGS" != "" && "$LOGS" != "null" ]]; then
            L1_TX=$(echo "$LOGS" | jq -r '.[-1].transactionHash')
            L1_BLOCK=$(echo "$LOGS" | jq -r '.[-1].blockNumber')
            L1_BLOCK_DEC=$(printf '%d' "$L1_BLOCK")
            echo "Withdrawal processed on L1! (block $L1_BLOCK_DEC)"
            echo "Explorer: https://explore.moderato.tempo.xyz/tx/$L1_TX"
            break
        fi
        sleep 0.25
    done

[group('zone')]
[doc('Enables a TIP-20 token on the ZonePortal for bridging. Token can be an address or alias (pathusd, alphausd, betausd). Requires L1_RPC_URL, L1_PORTAL_ADDRESS, and ADMIN_KEY env vars. SEQUENCER_KEY works for legacy zones where admin == sequencer.')]
enable-token token:
    #!/bin/bash
    set -euo pipefail
    RPC="${L1_RPC_URL:?Set L1_RPC_URL env var}"
    PK="${ADMIN_KEY:-${SEQUENCER_KEY:-}}"
    if [[ -z "$PK" ]]; then
        echo "Set ADMIN_KEY env var (or SEQUENCER_KEY for legacy zones where admin == sequencer)" >&2
        exit 1
    fi
    PORTAL="${L1_PORTAL_ADDRESS:?Set L1_PORTAL_ADDRESS env var}"
    HTTP_RPC=$(echo "$RPC" | sed 's|^wss://|https://|' | sed 's|^ws://|http://|')
    # enableToken is onlyAdmin: reject the sequencer fallback unless it is the admin.
    SIGNER_ADDR=$(cast wallet address "$PK" | tr '[:upper:]' '[:lower:]')
    ONCHAIN_ADMIN=$(cast call "$PORTAL" "admin()(address)" --rpc-url "$HTTP_RPC" | tr '[:upper:]' '[:lower:]')
    if [[ "$SIGNER_ADDR" != "$ONCHAIN_ADMIN" ]]; then
        echo "Signer $SIGNER_ADDR is not the portal admin $ONCHAIN_ADMIN. Set ADMIN_KEY for this zone (SEQUENCER_KEY only works when admin == sequencer)." >&2
        exit 1
    fi
    TOKEN="{{token}}"
    # Resolve well-known aliases (lowercased for case-insensitive matching)
    TOKEN_LOWER=$(echo "$TOKEN" | tr '[:upper:]' '[:lower:]')
    case "$TOKEN_LOWER" in
        pathusd|path-usd|path_usd)
            TOKEN="0x20C0000000000000000000000000000000000000" ;;
        alphausd|alpha-usd|alpha_usd)
            TOKEN="0x20c0000000000000000000000000000000000001" ;;
        betausd|beta-usd|beta_usd)
            TOKEN="0x20c0000000000000000000000000000000000002" ;;
    esac
    echo "Enabling token $TOKEN on portal $PORTAL..."
    TX_OUTPUT=$(cast send "$PORTAL" "enableToken(address)" "$TOKEN" \
        --rpc-url "$HTTP_RPC" --private-key "$PK" --json)
    TX_HASH=$(echo "$TX_OUTPUT" | jq -r '.transactionHash')
    L1_BLOCK=$(echo "$TX_OUTPUT" | jq -r '.blockNumber')
    L1_BLOCK_DEC=$(printf '%d' "$L1_BLOCK")
    echo "L1 tx: $TX_HASH (block $L1_BLOCK_DEC)"
    echo "Explorer: https://explore.moderato.tempo.xyz/tx/$TX_HASH"
    # Read token metadata from L1
    NAME=$(cast call "$TOKEN" "name()(string)" --rpc-url "$HTTP_RPC" 2>/dev/null || echo "???")
    SYMBOL=$(cast call "$TOKEN" "symbol()(string)" --rpc-url "$HTTP_RPC" 2>/dev/null || echo "???")
    echo "Waiting for zone to process L1 block $L1_BLOCK_DEC (token: $NAME / $SYMBOL)..."
    ZONE_RPC="${ZONE_RPC_URL:-http://localhost:8546}"
    INBOX="0x1c00000000000000000000000000000000000001"
    while true; do
        LOGS=$(cast logs --address "$INBOX" --from-block 1 --rpc-url "$ZONE_RPC" \
            "TokenEnabled(address indexed token, string name, string symbol, string currency)" \
            "$TOKEN" --json 2>/dev/null || echo "[]")
        if [[ "$LOGS" != "[]" && "$LOGS" != "" && "$LOGS" != "null" ]]; then
            echo "✅ Token enabled on zone: $NAME ($SYMBOL) at $TOKEN"
            break
        fi
        sleep 0.5
    done

# Shared implementation for admin-only portal calls that take a single token
# argument (pauseDeposits / resumeDeposits). Resolves the token alias, signs with
# ADMIN_KEY (SEQUENCER_KEY fallback only when it is the on-chain admin).
[private]
_portal-admin-token-call action token:
    #!/bin/bash
    set -euo pipefail
    RPC="${L1_RPC_URL:?Set L1_RPC_URL env var}"
    PK="${ADMIN_KEY:-${SEQUENCER_KEY:-}}"
    if [[ -z "$PK" ]]; then
        echo "Set ADMIN_KEY env var (or SEQUENCER_KEY for legacy zones where admin == sequencer)" >&2
        exit 1
    fi
    PORTAL="${L1_PORTAL_ADDRESS:?Set L1_PORTAL_ADDRESS env var}"
    HTTP_RPC=$(echo "$RPC" | sed 's|^wss://|https://|' | sed 's|^ws://|http://|')
    # {{action}} is onlyAdmin: reject the sequencer fallback unless it is the admin.
    SIGNER_ADDR=$(cast wallet address "$PK" | tr '[:upper:]' '[:lower:]')
    ONCHAIN_ADMIN=$(cast call "$PORTAL" "admin()(address)" --rpc-url "$HTTP_RPC" | tr '[:upper:]' '[:lower:]')
    if [[ "$SIGNER_ADDR" != "$ONCHAIN_ADMIN" ]]; then
        echo "Signer $SIGNER_ADDR is not the portal admin $ONCHAIN_ADMIN. Set ADMIN_KEY for this zone (SEQUENCER_KEY only works when admin == sequencer)." >&2
        exit 1
    fi
    TOKEN="{{token}}"
    TOKEN_LOWER=$(echo "$TOKEN" | tr '[:upper:]' '[:lower:]')
    case "$TOKEN_LOWER" in
        pathusd|path-usd|path_usd)
            TOKEN="0x20C0000000000000000000000000000000000000" ;;
        alphausd|alpha-usd|alpha_usd)
            TOKEN="0x20c0000000000000000000000000000000000001" ;;
        betausd|beta-usd|beta_usd)
            TOKEN="0x20c0000000000000000000000000000000000002" ;;
    esac
    echo "Calling {{action}}($TOKEN) on portal $PORTAL..."
    TX_OUTPUT=$(cast send "$PORTAL" "{{action}}(address)" "$TOKEN" \
        --rpc-url "$HTTP_RPC" --private-key "$PK" --json)
    TX_HASH=$(echo "$TX_OUTPUT" | jq -r '.transactionHash')
    echo "L1 tx: $TX_HASH"
    echo "Explorer: https://explore.moderato.tempo.xyz/tx/$TX_HASH"

[group('zone')]
[doc('Pauses deposits for an enabled TIP-20 on the ZonePortal (withdrawals unaffected). Token can be an address or alias. Requires L1_RPC_URL, L1_PORTAL_ADDRESS, and ADMIN_KEY env vars.')]
pause-deposits token:
    just _portal-admin-token-call pauseDeposits {{token}}

[group('zone')]
[doc('Resumes deposits for a previously paused TIP-20 on the ZonePortal. Token can be an address or alias. Requires L1_RPC_URL, L1_PORTAL_ADDRESS, and ADMIN_KEY env vars.')]
resume-deposits token:
    just _portal-admin-token-call resumeDeposits {{token}}

[group('zone')]
[doc('Pauses batch submissions, all new deposits, and L1 withdrawal processing for 30 days. Requires L1_RPC_URL, L1_PORTAL_ADDRESS, and PRIVATE_KEY.')]
pause-portal:
    cargo run -p tempo-xtask -- pause-portal

[group('zone')]
[doc('Enables or disables closed-loop account enforcement. Pass true to close access or false to open it. Requires L1_RPC_URL, L1_PORTAL_ADDRESS, and ADMIN_KEY.')]
set-access-mode enforced:
    #!/bin/bash
    set -euo pipefail
    ENFORCED="{{enforced}}"
    case "$ENFORCED" in
        true) ARGS=(--enforced) ;;
        false) ARGS=() ;;
        *) echo "Error: enforced must be 'true' or 'false'" >&2; exit 1 ;;
    esac
    cargo run -p tempo-xtask -- set-access-mode "${ARGS[@]}"

[group('zone')]
[doc('Enables or disables callback gateway enforcement. Pass true to enforce registered gateways or false to allow arbitrary targets. Requires L1_RPC_URL, L1_PORTAL_ADDRESS, and ADMIN_KEY.')]
set-gateway-mode enforced:
    #!/bin/bash
    set -euo pipefail
    ENFORCED="{{enforced}}"
    case "$ENFORCED" in
        true) ARGS=(--enforced) ;;
        false) ARGS=() ;;
        *) echo "Error: enforced must be 'true' or 'false'" >&2; exit 1 ;;
    esac
    cargo run -p tempo-xtask -- set-gateway-mode "${ARGS[@]}"

[group('zone')]
[doc('Adds or removes an account from closed-loop portal flows. Pass true to add or false to remove. Requires L1_RPC_URL, L1_PORTAL_ADDRESS, and ADMIN_KEY.')]
set-allowed-account account allowed:
    #!/bin/bash
    set -euo pipefail
    ALLOWED="{{allowed}}"
    case "$ALLOWED" in
        true) ARGS=(--allowed) ;;
        false) ARGS=() ;;
        *) echo "Error: allowed must be 'true' or 'false'" >&2; exit 1 ;;
    esac
    cargo run -p tempo-xtask -- set-allowed-account "{{account}}" "${ARGS[@]}"

[group('zone')]
[doc('Adds or removes a callback gateway. Pass true to add or false to remove. Requires L1_RPC_URL, L1_PORTAL_ADDRESS, and ADMIN_KEY.')]
set-gateway account allowed:
    #!/bin/bash
    set -euo pipefail
    ALLOWED="{{allowed}}"
    case "$ALLOWED" in
        true) ARGS=(--allowed) ;;
        false) ARGS=() ;;
        *) echo "Error: allowed must be 'true' or 'false'" >&2; exit 1 ;;
    esac
    cargo run -p tempo-xtask -- set-gateway "{{account}}" "${ARGS[@]}"

[group('zone')]
[doc('Lists TIP-20 token addresses currently enabled on the ZonePortal. Pass a portal address or set L1_PORTAL_ADDRESS. Requires L1_RPC_URL.')]
list-enabled-tokens portal="":
    #!/bin/bash
    set -euo pipefail
    RPC="${L1_RPC_URL:?Set L1_RPC_URL env var}"
    PORTAL="{{portal}}"
    if [[ -z "$PORTAL" ]]; then
        PORTAL="${L1_PORTAL_ADDRESS:?Set L1_PORTAL_ADDRESS env var or pass a portal address}"
    fi
    HTTP_RPC=$(echo "$RPC" | sed 's|^wss://|https://|' | sed 's|^ws://|http://|')
    for ((i=0,n=$(cast call "$PORTAL" "enabledTokenCount()(uint256)" --rpc-url "$HTTP_RPC"); i<n; i++)); do cast call "$PORTAL" "enabledTokenAt(uint256)(address)" "$i" --rpc-url "$HTTP_RPC"; done

[group('tip403')]
[doc('Creates a new TIP-20 token on L1 via TIP20Factory. Returns the token address. Requires L1_RPC_URL and PRIVATE_KEY env vars.')]
create-token name symbol salt="0xabcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890":
    #!/bin/bash
    set -euo pipefail
    RPC="${L1_RPC_URL:?Set L1_RPC_URL env var}"
    PK="${PRIVATE_KEY:?Set PRIVATE_KEY env var}"
    HTTP_RPC=$(echo "$RPC" | sed 's|^wss://|https://|' | sed 's|^ws://|http://|')
    FACTORY="0x20FC000000000000000000000000000000000000"
    QUOTE_TOKEN="0x20C0000000000000000000000000000000000000"
    ADMIN=$(cast wallet address "$PK")
    # Predict the address first
    TOKEN_ADDR=$(cast call "$FACTORY" \
        "getTokenAddress(address,bytes32)(address)" "$ADMIN" "{{salt}}" \
        --rpc-url "$HTTP_RPC")
    echo "Creating TIP-20 token '{{name}}' ({{symbol}}) at $TOKEN_ADDR..."
    TX_OUTPUT=$(cast send "$FACTORY" \
        "createToken(string,string,string,address,address,bytes32)" \
        "{{name}}" "{{symbol}}" "USD" "$QUOTE_TOKEN" "$ADMIN" "{{salt}}" \
        --rpc-url "$HTTP_RPC" --private-key "$PK" --json)
    TX_HASH=$(echo "$TX_OUTPUT" | jq -r '.transactionHash')
    echo "Token created!"
    echo "  Address:  $TOKEN_ADDR"
    echo "  Name:     {{name}}"
    echo "  Symbol:   {{symbol}}"
    echo "  Currency: USD"
    echo "  Admin:    $ADMIN"
    echo "  L1 tx:    $TX_HASH"

[group('tip403')]
[doc('Mints TIP-20 tokens to an address on L1. Requires L1_RPC_URL and PRIVATE_KEY env vars. Caller must have ISSUER_ROLE.')]
mint-tokens token to="" amount="1000000000":
    #!/bin/bash
    set -euo pipefail
    RPC="${L1_RPC_URL:?Set L1_RPC_URL env var}"
    PK="${PRIVATE_KEY:?Set PRIVATE_KEY env var}"
    HTTP_RPC=$(echo "$RPC" | sed 's|^wss://|https://|' | sed 's|^ws://|http://|')
    TO="{{to}}"
    if [[ -z "$TO" ]]; then
        TO=$(cast wallet address "$PK")
    fi
    echo "Minting {{amount}} tokens to $TO on token {{token}}..."
    cast send "{{token}}" "mint(address,uint256)" "$TO" "{{amount}}" \
        --rpc-url "$HTTP_RPC" --private-key "$PK"
    BALANCE=$(cast call "{{token}}" "balanceOf(address)(uint256)" "$TO" --rpc-url "$HTTP_RPC")
    echo "Balance of $TO: $BALANCE"

[group('tip403')]
[doc('Sets the supply cap for a TIP-20 token on L1. Requires L1_RPC_URL and PRIVATE_KEY env vars. Caller must be token admin.')]
set-supply-cap token cap="340282366920938463463374607431768211455":
    #!/bin/bash
    set -euo pipefail
    RPC="${L1_RPC_URL:?Set L1_RPC_URL env var}"
    PK="${PRIVATE_KEY:?Set PRIVATE_KEY env var}"
    HTTP_RPC=$(echo "$RPC" | sed 's|^wss://|https://|' | sed 's|^ws://|http://|')
    echo "Setting supply cap to {{cap}} on token {{token}}..."
    cast send "{{token}}" "setSupplyCap(uint256)" "{{cap}}" \
        --rpc-url "$HTTP_RPC" --private-key "$PK"
    echo "Supply cap set!"

[group('tip403')]
[doc('Grants ISSUER_ROLE on a TIP-20 token so the caller can mint. Requires L1_RPC_URL and PRIVATE_KEY env vars. Caller must be token admin.')]
grant-issuer-role token to="":
    #!/bin/bash
    set -euo pipefail
    RPC="${L1_RPC_URL:?Set L1_RPC_URL env var}"
    PK="${PRIVATE_KEY:?Set PRIVATE_KEY env var}"
    HTTP_RPC=$(echo "$RPC" | sed 's|^wss://|https://|' | sed 's|^ws://|http://|')
    TO="{{to}}"
    if [[ -z "$TO" ]]; then
        TO=$(cast wallet address "$PK")
    fi
    ISSUER_ROLE=$(cast keccak "ISSUER_ROLE")
    echo "Granting ISSUER_ROLE to $TO on token {{token}}..."
    cast send "{{token}}" "grantRole(bytes32,address)" "$ISSUER_ROLE" "$TO" \
        --rpc-url "$HTTP_RPC" --private-key "$PK"
    echo "Done!"

[group('tip403')]
[doc('Creates a TIP-403 whitelist or blacklist policy on L1. Type: 0=whitelist, 1=blacklist. Requires L1_RPC_URL and PRIVATE_KEY env vars.')]
create-policy type="0":
    #!/bin/bash
    set -euo pipefail
    RPC="${L1_RPC_URL:?Set L1_RPC_URL env var}"
    PK="${PRIVATE_KEY:?Set PRIVATE_KEY env var}"
    HTTP_RPC=$(echo "$RPC" | sed 's|^wss://|https://|' | sed 's|^ws://|http://|')
    REGISTRY="0x403C000000000000000000000000000000000000"
    ADMIN=$(cast wallet address "$PK")
    TYPE_NAME="whitelist"
    if [[ "{{type}}" == "1" ]]; then
        TYPE_NAME="blacklist"
    fi
    echo "Creating $TYPE_NAME policy on L1 (admin: $ADMIN)..."
    TX_OUTPUT=$(cast send "$REGISTRY" \
        "createPolicy(address,uint8)(uint64)" "$ADMIN" "{{type}}" \
        --rpc-url "$HTTP_RPC" --private-key "$PK" --json)
    TX_HASH=$(echo "$TX_OUTPUT" | jq -r '.transactionHash')
    # Extract the policy ID from the PolicyCreated event log in the receipt
    POLICY_ID_HEX=$(echo "$TX_OUTPUT" | jq -r '.logs[] | select(.topics[0] == "0x718d87917f0c4cfd1263707ef0e77c656ed8d8bfaca06152bdb0b8094142ec27") | .topics[1]')
    POLICY_ID=$(printf '%d' "$POLICY_ID_HEX")
    echo "Policy created!"
    echo "  Policy ID: $POLICY_ID"
    echo "  Type:      $TYPE_NAME"
    echo "  Admin:     $ADMIN"
    echo "  L1 tx:     $TX_HASH"

[group('tip403')]
[doc('Creates a compound TIP-403 policy from existing sub-policies. Requires L1_RPC_URL and PRIVATE_KEY env vars.')]
create-compound-policy sender-policy-id recipient-policy-id mint-recipient-policy-id="1":
    #!/bin/bash
    set -euo pipefail
    RPC="${L1_RPC_URL:?Set L1_RPC_URL env var}"
    PK="${PRIVATE_KEY:?Set PRIVATE_KEY env var}"
    HTTP_RPC=$(echo "$RPC" | sed 's|^wss://|https://|' | sed 's|^ws://|http://|')
    REGISTRY="0x403C000000000000000000000000000000000000"
    echo "Creating compound policy (sender={{sender-policy-id}}, recipient={{recipient-policy-id}}, mint={{mint-recipient-policy-id}})..."
    TX_OUTPUT=$(cast send "$REGISTRY" \
        "createCompoundPolicy(uint64,uint64,uint64)" \
        "{{sender-policy-id}}" "{{recipient-policy-id}}" "{{mint-recipient-policy-id}}" \
        --rpc-url "$HTTP_RPC" --private-key "$PK" --json)
    TX_HASH=$(echo "$TX_OUTPUT" | jq -r '.transactionHash')
    COUNTER=$(cast call "$REGISTRY" "policyIdCounter()(uint64)" --rpc-url "$HTTP_RPC" | awk '{print $1}')
    POLICY_ID=$((COUNTER - 1))
    echo "Compound policy created!"
    echo "  Policy ID:         $POLICY_ID"
    echo "  Sender sub-policy: {{sender-policy-id}}"
    echo "  Recipient sub-policy: {{recipient-policy-id}}"
    echo "  Mint recipient sub-policy: {{mint-recipient-policy-id}}"
    echo "  L1 tx:             $TX_HASH"

[group('tip403')]
[doc('Adds or removes an account from a whitelist policy on L1. Requires L1_RPC_URL and PRIVATE_KEY env vars.')]
modify-whitelist policy-id account allowed="true":
    #!/bin/bash
    set -euo pipefail
    RPC="${L1_RPC_URL:?Set L1_RPC_URL env var}"
    PK="${PRIVATE_KEY:?Set PRIVATE_KEY env var}"
    HTTP_RPC=$(echo "$RPC" | sed 's|^wss://|https://|' | sed 's|^ws://|http://|')
    REGISTRY="0x403C000000000000000000000000000000000000"
    echo "Modifying whitelist policy {{policy-id}}: account={{account}} allowed={{allowed}}..."
    cast send "$REGISTRY" \
        "modifyPolicyWhitelist(uint64,address,bool)" "{{policy-id}}" "{{account}}" "{{allowed}}" \
        --rpc-url "$HTTP_RPC" --private-key "$PK"
    echo "Done!"

[group('tip403')]
[doc('Adds or removes an account from a blacklist policy on L1. Requires L1_RPC_URL and PRIVATE_KEY env vars.')]
modify-blacklist policy-id account restricted="true":
    #!/bin/bash
    set -euo pipefail
    RPC="${L1_RPC_URL:?Set L1_RPC_URL env var}"
    PK="${PRIVATE_KEY:?Set PRIVATE_KEY env var}"
    HTTP_RPC=$(echo "$RPC" | sed 's|^wss://|https://|' | sed 's|^ws://|http://|')
    REGISTRY="0x403C000000000000000000000000000000000000"
    echo "Modifying blacklist policy {{policy-id}}: account={{account}} restricted={{restricted}}..."
    cast send "$REGISTRY" \
        "modifyPolicyBlacklist(uint64,address,bool)" "{{policy-id}}" "{{account}}" "{{restricted}}" \
        --rpc-url "$HTTP_RPC" --private-key "$PK"
    echo "Done!"

[group('tip403')]
[doc('Assigns a transfer policy to a TIP-20 token on L1. Requires L1_RPC_URL and PRIVATE_KEY env vars. Caller must be token admin.')]
set-transfer-policy token policy-id:
    #!/bin/bash
    set -euo pipefail
    RPC="${L1_RPC_URL:?Set L1_RPC_URL env var}"
    PK="${PRIVATE_KEY:?Set PRIVATE_KEY env var}"
    HTTP_RPC=$(echo "$RPC" | sed 's|^wss://|https://|' | sed 's|^ws://|http://|')
    echo "Setting transfer policy {{policy-id}} on token {{token}}..."
    cast send "{{token}}" "changeTransferPolicyId(uint64)" "{{policy-id}}" \
        --rpc-url "$HTTP_RPC" --private-key "$PK"
    CURRENT=$(cast call "{{token}}" "transferPolicyId()(uint64)" --rpc-url "$HTTP_RPC")
    echo "Transfer policy set to: $CURRENT"

[group('tip403')]
[doc('Checks if an address is authorized under a policy on L1. Requires L1_RPC_URL env var.')]
check-authorized policy-id account:
    #!/bin/bash
    set -euo pipefail
    RPC="${L1_RPC_URL:?Set L1_RPC_URL env var}"
    HTTP_RPC=$(echo "$RPC" | sed 's|^wss://|https://|' | sed 's|^ws://|http://|')
    REGISTRY="0x403C000000000000000000000000000000000000"
    RESULT=$(cast call "$REGISTRY" "isAuthorized(uint64,address)(bool)" "{{policy-id}}" "{{account}}" --rpc-url "$HTTP_RPC")
    echo "Policy {{policy-id}}, account {{account}}: authorized=$RESULT"

[group('tip403')]
[doc('Reads the transfer policy ID for a TIP-20 token. Requires L1_RPC_URL env var.')]
token-policy token rpc="":
    #!/bin/bash
    set -euo pipefail
    RPC_URL="{{rpc}}"
    if [[ -z "$RPC_URL" ]]; then
        RPC_URL="${L1_RPC_URL:?Set L1_RPC_URL env var or pass rpc= parameter}"
        RPC_URL=$(echo "$RPC_URL" | sed 's|^wss://|https://|' | sed 's|^ws://|http://|')
    fi
    POLICY_ID=$(cast call "{{token}}" "transferPolicyId()(uint64)" --rpc-url "$RPC_URL")
    NAME=$(cast call "{{token}}" "name()(string)" --rpc-url "$RPC_URL" 2>/dev/null || echo "???")
    echo "$NAME ({{token}}): transferPolicyId=$POLICY_ID"

[group('zone')]
[doc('Checks TIP-20 token balance for an account on the zone (port 8546)')]
check-balance account token="0x20C0000000000000000000000000000000000000" rpc=zone_rpc:
    @printf "Balance of {{account}}: " && cast call "{{token}}" "balanceOf(address)(uint256)" "{{account}}" --from "{{account}}" --rpc-url "{{rpc}}"

[group('zone')]
[doc('Generates a signed auth token for the redacted zone RPC. Requires PRIVATE_KEY env var. Reads zone metadata from generated/<name>/zone.json.')]
zone-auth-token name:
    #!/bin/bash
    set -euo pipefail
    PK="${PRIVATE_KEY:?Set PRIVATE_KEY env var}"
    ZONE_JSON="generated/{{name}}/zone.json"
    if [[ ! -f "$ZONE_JSON" ]]; then
        echo "Error: $ZONE_JSON not found. Run 'just create-zone {{name}}' first." >&2
        exit 1
    fi
    ZONE_ID=$(jq -r '.zoneId' "$ZONE_JSON")
    GENESIS_JSON="generated/{{name}}/genesis.json"
    CHAIN_ID=$(jq -r '.config.chainId' "$GENESIS_JSON")
    NOW=$(date +%s)
    EXPIRES=$((NOW + 600))
    MAGIC="54656d706f5a6f6e655250430000000000000000000000000000000000000000"
    VERSION="00"
    ZONE_ID_HEX=$(printf '%08x' "$ZONE_ID")
    CHAIN_ID_HEX=$(printf '%016x' "$CHAIN_ID")
    ISSUED_HEX=$(printf '%016x' "$NOW")
    EXPIRES_HEX=$(printf '%016x' "$EXPIRES")
    FIELDS="${VERSION}${ZONE_ID_HEX}${CHAIN_ID_HEX}${ISSUED_HEX}${EXPIRES_HEX}"
    DIGEST=$(cast keccak "0x${MAGIC}${FIELDS}")
    SIG=$(cast wallet sign --no-hash "$DIGEST" --private-key "$PK")
    SIG_HEX=$(echo "$SIG" | sed 's/0x//')
    echo "${SIG_HEX}${FIELDS}"

[group('zone')]
[doc('Checks TIP-20 token balance via the redacted RPC (with auth token). Requires PRIVATE_KEY env var.')]
check-balance-redacted name token="0x20C0000000000000000000000000000000000000" rpc="http://localhost:8544":
    #!/bin/bash
    set -euo pipefail
    PK="${PRIVATE_KEY:?Set PRIVATE_KEY env var}"
    ACCOUNT=$(cast wallet address "$PK")
    TOKEN=$(just zone-auth-token {{name}})
    ACCOUNT_LOWER=$(echo "$ACCOUNT" | sed 's/0x//' | tr '[:upper:]' '[:lower:]')
    RESPONSE=$(curl -sS -w '\n%{http_code}' -X POST "{{rpc}}" \
        -H "Content-Type: application/json" \
        -H "x-authorization-token: ${TOKEN}" \
        -d "{\"jsonrpc\":\"2.0\",\"method\":\"eth_call\",\"params\":[{\"from\":\"$ACCOUNT\",\"to\":\"{{token}}\",\"data\":\"0x70a08231000000000000000000000000${ACCOUNT_LOWER}\"}],\"id\":1}") || {
            echo "Failed to reach redacted RPC at {{rpc}}"
            exit 1
        }
    HTTP_STATUS=$(printf '%s' "$RESPONSE" | tail -n1)
    RESULT=$(printf '%s' "$RESPONSE" | sed '$d')
    if [[ "$HTTP_STATUS" != "200" ]]; then
        echo "Redacted RPC HTTP $HTTP_STATUS"
        echo "${RESULT:-<empty response>}"
        exit 1
    fi
    RAW=$(echo "$RESULT" | jq -r '.result // empty')
    ERROR=$(echo "$RESULT" | jq -r '.error.message // empty')
    if [[ -n "$ERROR" ]]; then
        echo "RPC error: $ERROR"
        exit 1
    fi
    if [[ -z "$RAW" ]]; then
        echo "No result from RPC"
        echo "$RESULT"
        exit 1
    fi
    BALANCE=$(cast --to-dec "$RAW")
    echo "Balance of $ACCOUNT: $BALANCE"

[group('zone')]
[doc('End-to-end zone deployment. Enforcement defaults to false. Initial membership and gateways are optional via ZONE_ALLOWED_ACCOUNTS and ZONE_GATEWAYS.')]
deploy-zone name token="" access_enforced="false" gateway_enforced="false":
    #!/bin/bash
    set -euo pipefail
    umask 077
    L1_RPC="${L1_RPC_URL:?Set L1_RPC_URL env var (wss://...)}"
    HTTP_RPC=$(echo "$L1_RPC" | sed 's|^wss://|https://|' | sed 's|^ws://|http://|')
    OUTPUT="generated/{{name}}"
    ZONE_TOKEN_L1="{{token}}"
    if [[ -z "$ZONE_TOKEN_L1" ]]; then
        ZONE_TOKEN_L1="${ZONE_TOKEN:-0x20C0000000000000000000000000000000000000}"
    fi
    # Resolve well-known aliases (lowercased for case-insensitive matching)
    ZONE_TOKEN_LOWER=$(echo "$ZONE_TOKEN_L1" | tr '[:upper:]' '[:lower:]')
    case "$ZONE_TOKEN_LOWER" in
        pathusd|path-usd|path_usd)
            ZONE_TOKEN_L1="0x20C0000000000000000000000000000000000000" ;;
        alphausd|alpha-usd|alpha_usd)
            ZONE_TOKEN_L1="0x20c0000000000000000000000000000000000001" ;;
        betausd|beta-usd|beta_usd)
            ZONE_TOKEN_L1="0x20c0000000000000000000000000000000000002" ;;
    esac

    echo "============================================"
    echo "  Deploying Zone: {{name}}"
    echo "============================================"
    echo ""
    echo "  Initial portal token: $ZONE_TOKEN_L1"
    echo ""

    # Step 1: Resolve the admin key/address and generate a new sequencer keypair
    echo "Step 1: Resolving admin and generating sequencer keypairs..."
    ADMIN_KEY="${ADMIN_KEY:-}"
    ADMIN_ADDR="${ADMIN_ADDR:-}"
    if [[ -n "$ADMIN_KEY" ]]; then
        ADMIN_ADDR=$(cast wallet address "$ADMIN_KEY")
    elif [[ -z "$ADMIN_ADDR" ]]; then
        ADMIN_OUTPUT=$(cast wallet new 2>/dev/null)
        ADMIN_ADDR=$(echo "$ADMIN_OUTPUT" | grep 'Address:' | awk '{print $2}')
        ADMIN_KEY=$(echo "$ADMIN_OUTPUT" | grep 'Private key:' | awk '{print $3}')
    fi
    KEY_OUTPUT=$(cast wallet new 2>/dev/null)
    SEQUENCER_ADDR=$(echo "$KEY_OUTPUT" | grep 'Address:' | awk '{print $2}')
    SEQUENCER_KEY=$(echo "$KEY_OUTPUT" | grep 'Private key:' | awk '{print $3}')
    echo "  Admin address:    $ADMIN_ADDR"
    echo "  Sequencer address: $SEQUENCER_ADDR"
    echo ""

    # Step 2: Fund the admin and sequencer on L1
    echo "Step 2: Funding admin and sequencer on L1 (via tempo_fundAddress)..."
    cast rpc tempo_fundAddress "$SEQUENCER_ADDR" --rpc-url "$HTTP_RPC" > /dev/null 2>&1
    if [[ "$(echo "$ADMIN_ADDR" | tr '[:upper:]' '[:lower:]')" != "$(echo "$SEQUENCER_ADDR" | tr '[:upper:]' '[:lower:]')" ]]; then
        cast rpc tempo_fundAddress "$ADMIN_ADDR" --rpc-url "$HTTP_RPC" > /dev/null 2>&1
    fi
    echo "  Admin funded:    https://explore.moderato.tempo.xyz/address/$ADMIN_ADDR"
    echo "  Sequencer funded: https://explore.moderato.tempo.xyz/address/$SEQUENCER_ADDR"
    echo ""

    # Step 3: Build Solidity contracts
    echo "Step 3: Building Solidity contracts..."
    (cd crates/contracts && forge build --skip test) || true
    echo ""

    # Step 4: Create zone on L1 and generate genesis
    echo "Step 4: Creating zone on L1 via ZoneFactory..."
    mkdir -p "$OUTPUT"
    ACCESS_ENFORCED="{{access_enforced}}"
    GATEWAY_ENFORCED="{{gateway_enforced}}"
    CREATE_ARGS=()
    if [[ "$ACCESS_ENFORCED" == "true" ]]; then
        CREATE_ARGS+=(--access-mode)
    elif [[ "$ACCESS_ENFORCED" != "false" ]]; then
        echo "Error: access_enforced must be 'true' or 'false'" >&2
        exit 1
    fi
    IFS=',' read -ra ALLOWED <<< "${ZONE_ALLOWED_ACCOUNTS:-}"
    for account in "${ALLOWED[@]}"; do
        [[ -n "$account" ]] && CREATE_ARGS+=(--allowed-account "$account")
    done
    if [[ "$GATEWAY_ENFORCED" == "true" ]]; then
        CREATE_ARGS+=(--gateway-mode)
    elif [[ "$GATEWAY_ENFORCED" != "false" ]]; then
        echo "Error: gateway_enforced must be 'true' or 'false'" >&2
        exit 1
    fi
    IFS=',' read -ra GATEWAYS <<< "${ZONE_GATEWAYS:-}"
    for gateway in "${GATEWAYS[@]}"; do
        [[ -n "$gateway" ]] && CREATE_ARGS+=(--zone-gateway "$gateway")
    done
    ZONE_FACTORY_OWNER_KEY="$SEQUENCER_KEY" cargo run -p tempo-xtask -- create-zone \
        --output "$OUTPUT" \
        --l1-rpc-url "$HTTP_RPC" \
        --initial-token "$ZONE_TOKEN_L1" \
        --admin "$ADMIN_ADDR" \
        --sequencer "$SEQUENCER_ADDR" \
        "${CREATE_ARGS[@]}"
    echo ""

    # Save generated keys into zone.json for later use.
    if [[ -n "$ADMIN_KEY" ]]; then
        jq --arg sk "$SEQUENCER_KEY" --arg sa "$SEQUENCER_ADDR" --arg ak "$ADMIN_KEY" --arg aa "$ADMIN_ADDR" \
            '. + {sequencerKey: $sk, sequencerAddress: $sa, adminKey: $ak, adminAddress: $aa}' "$OUTPUT/zone.json" > "$OUTPUT/zone.json.tmp" \
            && mv "$OUTPUT/zone.json.tmp" "$OUTPUT/zone.json"
    else
        jq --arg sk "$SEQUENCER_KEY" --arg sa "$SEQUENCER_ADDR" --arg aa "$ADMIN_ADDR" \
            '. + {sequencerKey: $sk, sequencerAddress: $sa, adminAddress: $aa}' "$OUTPUT/zone.json" > "$OUTPUT/zone.json.tmp" \
            && mv "$OUTPUT/zone.json.tmp" "$OUTPUT/zone.json"
    fi

    PORTAL=$(jq -r '.portal' "$OUTPUT/zone.json")
    ZONE_ID=$(jq -r '.zoneId' "$OUTPUT/zone.json")
    ANCHOR_BLOCK=$(jq -r '.tempoAnchorBlock' "$OUTPUT/zone.json")

    # Step 5: Register sequencer encryption key on the portal
    echo "Step 5: Registering sequencer encryption key on ZonePortal..."
    PRIVATE_KEY="$SEQUENCER_KEY" cargo run -p tempo-xtask -- set-encryption-key \
        --l1-rpc-url "$HTTP_RPC" \
        --portal "$PORTAL"
    echo ""

    # Step 6: Display summary
    echo "============================================"
    echo "  Zone Deployed Successfully!"
    echo "============================================"
    echo ""
    echo "  Zone ID:         $ZONE_ID"
    echo "  Zone Name:       {{name}}"
    echo "  Portal:          $PORTAL"
    echo "  Initial Token:   $ZONE_TOKEN_L1"
    echo "  Admin:           $ADMIN_ADDR"
    echo "  Sequencer:       $SEQUENCER_ADDR"
    echo "  Anchor Block:    $ANCHOR_BLOCK"
    echo ""
    echo "  Artifacts:       $OUTPUT/"
    echo "  Genesis:         $OUTPUT/genesis.json"
    echo "  Zone Metadata:   $OUTPUT/zone.json"
    echo ""
    echo "  Explorer:        https://explore.moderato.tempo.xyz/address/$PORTAL"
    echo ""
    if [[ -n "$ADMIN_KEY" ]]; then
        echo "  Admin key saved to $OUTPUT/zone.json"
    else
        echo "  Admin key not saved (ADMIN_ADDR was provided without ADMIN_KEY)"
    fi
    echo "  Sequencer key saved to $OUTPUT/zone.json"
    echo ""

    # Step 7: Build and start the zone node
    echo "Step 7: Building and starting zone node (release)..."
    echo ""
    cargo build --bin tempo-zone --release
    DATADIR="/tmp/tempo-zone-{{name}}"
    rm -rf "$DATADIR" || true
    exec cargo run --release --bin tempo-zone -- \
                      node \
                      --chain "$OUTPUT/genesis.json" \
                      --l1.rpc-url "$L1_RPC" \
                      --l1.portal-address "$PORTAL" \
                      --zone.id "$ZONE_ID" \
                      --http \
                      --http.addr 0.0.0.0 \
                      --http.port {{zone_http_port}} \
                      --http.api all \
                      --datadir "$DATADIR" \
                      --log.file.directory "$DATADIR/logs" \
                      --sequencer \
                      --sequencer-key-file <(jq -r '.sequencerKey' "$OUTPUT/zone.json")

[group('zone')]
[doc('Spam deposit transactions to measure portal throughput. Requires L1_RPC_URL, L1_PORTAL_ADDRESS, and PRIVATE_KEY env vars. Example: just spam-deposits 10 10 200000')]
spam-deposits total="20" per-block="10" amount="1000000" token="0x20C0000000000000000000000000000000000000" lead-time="3":
    #!/bin/bash
    set -euo pipefail
    PK="${PRIVATE_KEY:?Set PRIVATE_KEY env var}"
    ARGS="--total {{total}} --per-block {{per-block}} --amount {{amount}} --token {{token}} --lead-time {{lead-time}}"
    PRIVATE_KEY="$PK" cargo run -p tempo-xtask -- spam-deposits $ARGS

[group('zone')]
[doc('Runs the full TIP-20 + TIP-403 blacklist demo: creates token, enables on zone, blacklists address, shows deposit bounce, unblacklists, shows deposit success, withdraws. Requires PRIVATE_KEY for the token admin/depositor, L1_PORTAL_ADDRESS, and portal admin authority via ADMIN_KEY or matching generated/<name>/zone.json adminKey.')]
demo-blacklist amount="500000" rpc=zone_rpc zone-dir="":
    #!/bin/bash
    set -euo pipefail
    ARGS=(--zone-rpc-url "{{rpc}}" --amount "{{amount}}")
    if [[ -n "{{zone-dir}}" ]]; then
        ARGS+=(--zone-dir "{{zone-dir}}")
    fi
    cargo run -p tempo-xtask -- demo-blacklist "${ARGS[@]}"

# Docs commands
[group('docs')]
[doc('Install docs dependencies')]
docs-install:
    cd docs && bun install

[group('docs')]
[doc('Start docs dev server')]
docs-dev:
    cd docs && bun run dev

[group('docs')]
[doc('Build docs for production')]
docs-build:
    cd docs && bun run build

[group('docs')]
[doc('Run docs linting and type checks')]
docs-check:
    cd docs && bun run check && bun run check:types

[group('docs')]
[doc('Run Solidity contract tests')]
docs-specs-test:
    cd crates/contracts && forge test -vvv

[group('docs')]
[doc('Build Solidity contracts')]
docs-specs-build:
    cd crates/contracts && forge build --skip test
    cd crates/contracts && forge build --sizes --skip 'test/**' src/runtime/tempo/ZonePortal.sol src/runtime/tempo/ZoneMessenger.sol src/runtime/tempo/Verifier.sol
