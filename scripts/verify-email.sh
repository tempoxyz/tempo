#!/bin/bash
#
# E2E script to verify email ownership on Tempo localnet.
#
# Usage:
#   ./scripts/verify-email.sh <email> [user_private_key]
#
# Prerequisites:
#   - Tempo localnet running: just localnet
#   - cast (from foundry) installed
#   - The genesis must include TLSEmailOwnership precompile initialization
#
# Example:
#   ./scripts/verify-email.sh zygimantas@tempo.xyz
#
set -euo pipefail

EMAIL="${1:?Usage: $0 <email> [user_private_key]}"

ETH_RPC_URL="${ETH_RPC_URL:-http://localhost:8545}"
PRECOMPILE="0x714E000000000000000000000000000000000000"

# Dev Notary private key (Hardhat account #0 — registered in genesis)
NOTARY_PK="0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
NOTARY_KEY_ID="0x0101010101010101010101010101010101010101010101010101010101010101"

# User wallet — generate a fresh one or use provided
if [ -n "${2:-}" ]; then
    USER_PK="$2"
    USER_ADDR=$(cast wallet address "$USER_PK")
else
    echo "==> Generating a fresh user wallet..."
    WALLET_JSON=$(cast wallet new --json)
    USER_PK=$(echo "$WALLET_JSON" | jq -r '.[0].private_key')
    USER_ADDR=$(echo "$WALLET_JSON" | jq -r '.[0].address')
fi

echo ""
echo "=========================================="
echo " TLS Email Ownership Verification"
echo "=========================================="
echo " Email:      $EMAIL"
echo " User:       $USER_ADDR"
echo " RPC:        $ETH_RPC_URL"
echo " Precompile: $PRECOMPILE"
echo "=========================================="
echo ""

# Step 1: Fund the user wallet
echo "==> Step 1: Funding user wallet..."
cast rpc tempo_fundAddress "$USER_ADDR" --rpc-url "$ETH_RPC_URL" > /dev/null 2>&1
sleep 2
BALANCE=$(cast balance "$USER_ADDR" --rpc-url "$ETH_RPC_URL")
echo "    Balance: $BALANCE wei"

# Step 2: Create the Google userinfo response body (simulated TLSNotary session)
echo ""
echo "==> Step 2: Creating Google userinfo response (simulated TLSNotary session)..."
RESPONSE_BODY="{\"sub\":\"1234567890\",\"email\":\"${EMAIL}\",\"email_verified\":true,\"name\":\"Zygimantas\",\"picture\":\"https://example.com/photo.jpg\"}"
echo "    Response: $RESPONSE_BODY"

# Step 3: Compute attestation digest
echo ""
echo "==> Step 3: Computing attestation digest..."

RESPONSE_BODY_HEX=$(cast --from-utf8 "$RESPONSE_BODY")
RESPONSE_HASH=$(cast keccak "$RESPONSE_BODY_HEX")
EMAIL_HASH=$(cast keccak "$(cast --from-utf8 "$EMAIL")")
SERVER_NAME="www.googleapis.com"
ENDPOINT="/oauth2/v3/userinfo"
SERVER_NAME_HASH=$(cast keccak "$(cast --from-utf8 "$SERVER_NAME")")
ENDPOINT_HASH=$(cast keccak "$(cast --from-utf8 "$ENDPOINT")")

# abi.encodePacked("TempoEmailAttestationV1", subject, serverNameHash, endpointHash, responseBodyHash, emailHash, notaryKeyId)
DOMAIN_HEX=$(cast --from-utf8 "TempoEmailAttestationV1")
SUBJECT_HEX=$(echo "$USER_ADDR" | sed 's/0x//')

# Remove 0x prefix for concatenation
SERVER_NAME_HASH_RAW=$(echo "$SERVER_NAME_HASH" | sed 's/0x//')
ENDPOINT_HASH_RAW=$(echo "$ENDPOINT_HASH" | sed 's/0x//')
RESPONSE_HASH_RAW=$(echo "$RESPONSE_HASH" | sed 's/0x//')
EMAIL_HASH_RAW=$(echo "$EMAIL_HASH" | sed 's/0x//')
NOTARY_KEY_ID_RAW=$(echo "$NOTARY_KEY_ID" | sed 's/0x//')
DOMAIN_HEX_RAW=$(echo "$DOMAIN_HEX" | sed 's/0x//')

PACKED="0x${DOMAIN_HEX_RAW}${SUBJECT_HEX}${SERVER_NAME_HASH_RAW}${ENDPOINT_HASH_RAW}${RESPONSE_HASH_RAW}${EMAIL_HASH_RAW}${NOTARY_KEY_ID_RAW}"
DIGEST=$(cast keccak "$PACKED")

echo "    Digest: $DIGEST"

# Step 4: Notary signs the attestation
echo ""
echo "==> Step 4: Notary signing attestation..."
SIG=$(cast wallet sign --no-hash "$DIGEST" --private-key "$NOTARY_PK")
echo "    Signature: ${SIG:0:20}..."

# Parse signature into r, s, v
R="0x$(echo "$SIG" | sed 's/0x//' | cut -c1-64)"
S="0x$(echo "$SIG" | sed 's/0x//' | cut -c65-128)"
V_HEX=$(echo "$SIG" | sed 's/0x//' | cut -c129-130)
V=$((16#$V_HEX))

echo "    r: $R"
echo "    s: $S"
echo "    v: $V"

# Step 5: Submit the attestation on-chain
echo ""
echo "==> Step 5: Submitting attestation on-chain..."
TX_HASH=$(cast send "$PRECOMPILE" \
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
    --rpc-url "$ETH_RPC_URL" \
    --json 2>&1 | jq -r '.transactionHash')
echo "    TX: $TX_HASH"

sleep 2

# Step 6: Verify on-chain
echo ""
echo "==> Step 6: Querying on-chain verification..."

IS_VERIFIED=$(cast call "$PRECOMPILE" "isVerified(address)(bool)" "$USER_ADDR" --rpc-url "$ETH_RPC_URL")
echo "    isVerified($USER_ADDR) = $IS_VERIFIED"

CLAIM=$(cast call "$PRECOMPILE" "getVerifiedEmail(address)((string,bytes32,uint64,bytes32))" "$USER_ADDR" --rpc-url "$ETH_RPC_URL")
echo "    getVerifiedEmail($USER_ADDR) = $CLAIM"

echo ""
echo "=========================================="
if [ "$IS_VERIFIED" = "true" ]; then
    echo " ✅ SUCCESS: $EMAIL is verified on-chain for $USER_ADDR"
else
    echo " ❌ FAILED: verification did not succeed"
fi
echo "=========================================="
