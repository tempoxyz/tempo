#!/bin/bash
#
# E2E email ownership verification on Tempo.
#
# Proves on-chain that you own an email address by:
#   1. Starting a Tempo localnet (builds node + generates genesis)
#   2. Fetching your email from Google's userinfo API (real HTTPS call)
#   3. Computing a Notary-signed attestation over the response
#   4. Submitting the attestation on-chain to the TLSEmailOwnership precompile
#   5. Querying the precompile to confirm verification
#
# Usage:
#   ./scripts/verify-email.sh <google_access_token>
#
# Getting a Google access token:
#   Option A (gcloud CLI):
#     gcloud auth login
#     gcloud auth print-access-token --scopes=email
#
#   Option B (OAuth playground):
#     https://developers.google.com/oauthplayground
#     Select "Google OAuth2 API v2 > email" scope, authorize, get access token.
#
# Prerequisites:
#   - cast (foundry) installed
#   - curl installed
#   - jq installed
#   - cargo installed (to build the node)
#
set -euo pipefail

# --- Configuration ---
RPC_URL="http://localhost:8545"
RPC_PORT=8545
PRECOMPILE="0x714E000000000000000000000000000000000000"
GOOGLE_USERINFO_URL="https://www.googleapis.com/oauth2/v3/userinfo"
BUILD_PROFILE="${BUILD_PROFILE:-dev}"
NODE_LOG="./localnet/logs/node.log"

# Dev Notary key (Hardhat account #0 — pre-registered in genesis)
NOTARY_PK="0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
NOTARY_KEY_ID="0x0101010101010101010101010101010101010101010101010101010101010101"

# --- Input ---
GOOGLE_TOKEN="${1:-}"
if [ -z "$GOOGLE_TOKEN" ]; then
    echo "Usage: $0 <google_access_token>"
    echo ""
    echo "Get a token via:  gcloud auth print-access-token --scopes=email"
    echo "Or:               https://developers.google.com/oauthplayground"
    exit 1
fi

# --- Dependency checks ---
for cmd in cast curl jq cargo; do
    if ! command -v "$cmd" &>/dev/null; then
        echo "Error: '$cmd' is not installed."
        exit 1
    fi
done

# --- Cleanup handler ---
NODE_PID=""
cleanup() {
    if [ -n "$NODE_PID" ] && kill -0 "$NODE_PID" 2>/dev/null; then
        echo ""
        echo "==> Shutting down localnet (PID $NODE_PID)..."
        kill "$NODE_PID" 2>/dev/null || true
        wait "$NODE_PID" 2>/dev/null || true
    fi
}
trap cleanup EXIT INT TERM

# --- Helper: wait for RPC ---
wait_for_rpc() {
    local timeout=120
    local elapsed=0
    echo "    Waiting for RPC at $RPC_URL (timeout ${timeout}s)..."
    while [ $elapsed -lt $timeout ]; do
        if curl -s -X POST "$RPC_URL" \
            -H "Content-Type: application/json" \
            -d '{"jsonrpc":"2.0","method":"eth_blockNumber","params":[],"id":1}' 2>/dev/null | jq -e '.result' &>/dev/null; then
            echo "    RPC is up."
            return 0
        fi
        sleep 2
        elapsed=$((elapsed + 2))
    done
    echo "    ERROR: RPC did not become available within ${timeout}s"
    echo "    Check logs: $NODE_LOG"
    exit 1
}

# --- Helper: wait for blocks ---
wait_for_blocks() {
    local count=${1:-2}
    echo "    Waiting for $count blocks..."
    local start_block
    start_block=$(curl -s -X POST "$RPC_URL" \
        -H "Content-Type: application/json" \
        -d '{"jsonrpc":"2.0","method":"eth_blockNumber","params":[],"id":1}' | jq -r '.result' | xargs printf "%d\n")
    local target=$((start_block + count))
    local timeout=30
    local elapsed=0
    while [ $elapsed -lt $timeout ]; do
        local current
        current=$(curl -s -X POST "$RPC_URL" \
            -H "Content-Type: application/json" \
            -d '{"jsonrpc":"2.0","method":"eth_blockNumber","params":[],"id":1}' | jq -r '.result' | xargs printf "%d\n")
        if [ "$current" -ge "$target" ]; then
            echo "    Block $current reached."
            return 0
        fi
        sleep 1
        elapsed=$((elapsed + 1))
    done
    echo "    WARNING: timeout waiting for blocks"
}

echo ""
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║           Tempo Email Ownership Verification                ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo ""

# =========================================================================
# STEP 1: Fetch email from Google
# =========================================================================
echo "==> Step 1: Fetching email from Google userinfo API..."

RESPONSE_BODY=$(curl -sf -H "Authorization: Bearer $GOOGLE_TOKEN" "$GOOGLE_USERINFO_URL") || {
    echo "    ERROR: Failed to fetch Google userinfo. Is your token valid?"
    echo "    Get a new one: gcloud auth print-access-token --scopes=email"
    exit 1
}

EMAIL=$(echo "$RESPONSE_BODY" | jq -r '.email // empty')
EMAIL_VERIFIED=$(echo "$RESPONSE_BODY" | jq -r '.email_verified // "false"')

if [ -z "$EMAIL" ]; then
    echo "    ERROR: No email found in Google response."
    echo "    Response: $RESPONSE_BODY"
    exit 1
fi

if [ "$EMAIL_VERIFIED" != "true" ]; then
    echo "    WARNING: Google reports email is not verified."
fi

echo "    Email:    $EMAIL"
echo "    Verified: $EMAIL_VERIFIED"
echo "    Response: $(echo "$RESPONSE_BODY" | jq -c .)"

# =========================================================================
# STEP 2: Start localnet
# =========================================================================
echo ""
echo "==> Step 2: Building and starting Tempo localnet..."

# Check if port is already in use
if curl -s -X POST "$RPC_URL" -H "Content-Type: application/json" \
    -d '{"jsonrpc":"2.0","method":"eth_blockNumber","params":[],"id":1}' 2>/dev/null | jq -e '.result' &>/dev/null; then
    echo "    Localnet already running at $RPC_URL, reusing."
else
    # Clean slate
    rm -rf ./localnet/ 2>/dev/null || true
    mkdir -p ./localnet/logs

    echo "    Generating genesis..."
    cargo run -p tempo-xtask --profile "$BUILD_PROFILE" -- \
        generate-genesis --output ./localnet -a 100 --no-dkg-in-genesis 2>&1 | tail -5

    echo "    Starting node..."
    cargo run --bin tempo --profile "$BUILD_PROFILE" -- \
        node \
        --chain ./localnet/genesis.json \
        --dev \
        --dev.block-time 1sec \
        --datadir ./localnet/reth \
        --http \
        --http.addr 0.0.0.0 \
        --http.port "$RPC_PORT" \
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
        > "$NODE_LOG" 2>&1 &
    NODE_PID=$!
    echo "    Node PID: $NODE_PID"

    wait_for_rpc
    wait_for_blocks 2
fi

# =========================================================================
# STEP 3: Create user wallet and fund it
# =========================================================================
echo ""
echo "==> Step 3: Creating and funding user wallet..."

WALLET_JSON=$(cast wallet new --json)
USER_PK=$(echo "$WALLET_JSON" | jq -r '.[0].private_key')
USER_ADDR=$(echo "$WALLET_JSON" | jq -r '.[0].address')

echo "    Address: $USER_ADDR"

cast rpc tempo_fundAddress "$USER_ADDR" --rpc-url "$RPC_URL" > /dev/null 2>&1
wait_for_blocks 2

# =========================================================================
# STEP 4: Compute attestation digest and sign
# =========================================================================
echo ""
echo "==> Step 4: Creating Notary attestation..."

SERVER_NAME="www.googleapis.com"
ENDPOINT="/oauth2/v3/userinfo"

# Convert to hex for hashing
RESPONSE_BODY_HEX=$(cast --from-utf8 "$RESPONSE_BODY")
EMAIL_HEX=$(cast --from-utf8 "$EMAIL")
SERVER_NAME_HEX=$(cast --from-utf8 "$SERVER_NAME")
ENDPOINT_HEX=$(cast --from-utf8 "$ENDPOINT")

# Compute hashes
RESPONSE_HASH=$(cast keccak "$RESPONSE_BODY_HEX")
EMAIL_HASH=$(cast keccak "$EMAIL_HEX")
SERVER_NAME_HASH=$(cast keccak "$SERVER_NAME_HEX")
ENDPOINT_HASH=$(cast keccak "$ENDPOINT_HEX")

echo "    responseBodyHash: $RESPONSE_HASH"
echo "    emailHash:        $EMAIL_HASH"

# Build the attestation digest:
#   keccak256(abi.encodePacked(
#     "TempoEmailAttestationV1",
#     subject,
#     keccak256(serverName),
#     keccak256(endpoint),
#     responseBodyHash,
#     emailHash,
#     notaryKeyId
#   ))
DOMAIN_HEX=$(cast --from-utf8 "TempoEmailAttestationV1" | sed 's/0x//')
SUBJECT_RAW=$(echo "$USER_ADDR" | sed 's/0x//')
SERVER_NAME_HASH_RAW=$(echo "$SERVER_NAME_HASH" | sed 's/0x//')
ENDPOINT_HASH_RAW=$(echo "$ENDPOINT_HASH" | sed 's/0x//')
RESPONSE_HASH_RAW=$(echo "$RESPONSE_HASH" | sed 's/0x//')
EMAIL_HASH_RAW=$(echo "$EMAIL_HASH" | sed 's/0x//')
NOTARY_KEY_ID_RAW=$(echo "$NOTARY_KEY_ID" | sed 's/0x//')

PACKED="0x${DOMAIN_HEX}${SUBJECT_RAW}${SERVER_NAME_HASH_RAW}${ENDPOINT_HASH_RAW}${RESPONSE_HASH_RAW}${EMAIL_HASH_RAW}${NOTARY_KEY_ID_RAW}"
DIGEST=$(cast keccak "$PACKED")

echo "    digest:           $DIGEST"

# Sign with Notary key (--no-hash because digest is already a hash)
SIG=$(cast wallet sign --no-hash "$DIGEST" --private-key "$NOTARY_PK")

# Parse r, s, v from the 65-byte signature
SIG_RAW=$(echo "$SIG" | sed 's/0x//')
R="0x${SIG_RAW:0:64}"
S="0x${SIG_RAW:64:64}"
V_HEX="${SIG_RAW:128:2}"
V=$((16#$V_HEX))

echo "    signature:        0x${SIG_RAW:0:16}..."
echo "    v=$V"

# =========================================================================
# STEP 5: Submit attestation on-chain
# =========================================================================
echo ""
echo "==> Step 5: Submitting attestation to precompile..."

TX_RESULT=$(cast send "$PRECOMPILE" \
    "verifyEmail(bytes32,address,string,string,bytes,uint8,bytes32,bytes32)" \
    "$NOTARY_KEY_ID" \
    "$USER_ADDR" \
    "$SERVER_NAME" \
    "$ENDPOINT" \
    "$RESPONSE_BODY_HEX" \
    "$V" \
    "$R" \
    "$S" \
    --private-key "$USER_PK" \
    --rpc-url "$RPC_URL" \
    --json 2>&1)

TX_HASH=$(echo "$TX_RESULT" | jq -r '.transactionHash // empty')
TX_STATUS=$(echo "$TX_RESULT" | jq -r '.status // empty')

if [ -z "$TX_HASH" ]; then
    echo "    ERROR: Transaction failed to send."
    echo "    $TX_RESULT"
    exit 1
fi

echo "    TX hash:  $TX_HASH"
echo "    Status:   $TX_STATUS"

if [ "$TX_STATUS" = "0x0" ]; then
    echo "    ERROR: Transaction reverted."
    echo "    Debug: cast run $TX_HASH --rpc-url $RPC_URL"
    exit 1
fi

wait_for_blocks 1

# =========================================================================
# STEP 6: Query on-chain state
# =========================================================================
echo ""
echo "==> Step 6: Querying on-chain verification..."

IS_VERIFIED=$(cast call "$PRECOMPILE" \
    "isVerified(address)(bool)" "$USER_ADDR" \
    --rpc-url "$RPC_URL")

CLAIM_RAW=$(cast call "$PRECOMPILE" \
    "getVerifiedEmail(address)((string,bytes32,uint64,bytes32))" "$USER_ADDR" \
    --rpc-url "$RPC_URL")

ONCHAIN_EMAIL=$(echo "$CLAIM_RAW" | head -1 | xargs)

echo "    isVerified:  $IS_VERIFIED"
echo "    onchainEmail: $ONCHAIN_EMAIL"

# =========================================================================
# RESULT
# =========================================================================
echo ""
echo "╔══════════════════════════════════════════════════════════════╗"
if [ "$IS_VERIFIED" = "true" ]; then
    echo "║  ✅  $EMAIL"
    printf "║      is verified on-chain for %-28s ║\n" "$USER_ADDR"
    echo "║                                                              ║"
    echo "║  Precompile: $PRECOMPILE  ║"
    echo "║  TX:         $TX_HASH  ║"
else
    echo "║  ❌  Verification FAILED                                     ║"
    echo "║      Check transaction: cast run $TX_HASH"
fi
echo "╚══════════════════════════════════════════════════════════════╝"
echo ""

if [ "$IS_VERIFIED" != "true" ]; then
    exit 1
fi
