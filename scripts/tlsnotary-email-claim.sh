#!/bin/bash
set -e

# ─────────────────────────────────────────────────────────────────────────────
# TLSNotary Email Ownership Proof — E2E Demo
#
# This script demonstrates proving email ownership on-chain using the
# TLSNotary precompile. In production, the notary signature comes from
# validators running MPC-TLS with the email provider. Here we simulate
# the notary role using a dev key.
#
# Prerequisites:
#   - A running Tempo localnet: `just localnet`
#   - `cast` (Foundry) installed
#
# Usage:
#   ./scripts/tlsnotary-email-claim.sh [email] [rpc_url]
#
# Example:
#   ./scripts/tlsnotary-email-claim.sh zygimantas@tempo.xyz http://localhost:8545
# ─────────────────────────────────────────────────────────────────────────────

EMAIL="${1:-zygimantas@tempo.xyz}"
ETH_RPC_URL="${2:-http://localhost:8545}"
export ETH_RPC_URL

TLS_NOTARY="0x714E000000000000000000000000000000000000"

# Dev admin key (mnemonic index 0: "test test test test test test test test test test test junk")
ADMIN_PK="0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
ADMIN_ADDR=$(cast wallet address $ADMIN_PK)

echo "═══════════════════════════════════════════════════════════════"
echo "  TLSNotary Email Ownership Proof"
echo "═══════════════════════════════════════════════════════════════"
echo ""
echo "  Email:    $EMAIL"
echo "  RPC:      $ETH_RPC_URL"
echo "  Admin:    $ADMIN_ADDR"
echo ""

# ── Step 1: Generate a notary key pair ────────────────────────────────────────
echo "─── Step 1: Generate notary key pair ─────────────────────────"
NOTARY_WALLET=$(cast wallet new --json)
NOTARY_PK=$(echo "$NOTARY_WALLET" | jq -r '.[0].private_key')
NOTARY_ADDR=$(echo "$NOTARY_WALLET" | jq -r '.[0].address')
echo "  Notary address: $NOTARY_ADDR"

# ── Step 2: Generate the claimant wallet ──────────────────────────────────────
echo ""
echo "─── Step 2: Generate claimant wallet ─────────────────────────"
CLAIMANT_WALLET=$(cast wallet new --json)
CLAIMANT_PK=$(echo "$CLAIMANT_WALLET" | jq -r '.[0].private_key')
CLAIMANT_ADDR=$(echo "$CLAIMANT_WALLET" | jq -r '.[0].address')
echo "  Claimant address: $CLAIMANT_ADDR"

# Fund claimant
echo "  Funding claimant..."
cast rpc tempo_fundAddress $CLAIMANT_ADDR > /dev/null 2>&1
sleep 2

# ── Step 3: Register the notary on-chain ──────────────────────────────────────
echo ""
echo "─── Step 3: Register notary on-chain (admin tx) ──────────────"
cast send $TLS_NOTARY \
  "addNotary(address)" $NOTARY_ADDR \
  --private-key $ADMIN_PK \
  --json | jq -r '"  tx: \(.transactionHash) (status: \(.status))"'

# Verify
IS_NOTARY=$(cast call $TLS_NOTARY "isNotary(address)(bool)" $NOTARY_ADDR)
echo "  isNotary($NOTARY_ADDR) = $IS_NOTARY"

# ── Step 4: Build the attestation ─────────────────────────────────────────────
echo ""
echo "─── Step 4: Build TLSNotary attestation ──────────────────────"
echo "  [Simulating MPC-TLS session with accounts.google.com]"
echo "  In production, validators would jointly verify the TLS session"
echo "  and see that Google's servers confirm $EMAIL ownership."

# Compute hashes
SERVER_NAME_HASH=$(cast keccak "accounts.google.com")
PROOF_HASH=$(cast keccak "tlsnotary-proof:$EMAIL:$(date +%s)")
CHAIN_ID=$(cast chain-id)

# The statement encodes: "email:<email> owner:<claimant>"
STATEMENT="email:$EMAIL owner:$CLAIMANT_ADDR"
STATEMENT_HASH=$(cast keccak "$STATEMENT")

echo "  Server:    accounts.google.com"
echo "  Email:     $EMAIL"
echo "  Statement: $STATEMENT"
echo "  Chain ID:  $CHAIN_ID"

# ── Step 5: Notary signs the attestation ──────────────────────────────────────
echo ""
echo "─── Step 5: Notary signs attestation ─────────────────────────"

# Build the attestation message: TEMPO_TLSNOTARY_V1 || chain_id || proof_hash || statement_hash || server_name_hash
DOMAIN_HEX=$(echo -n "TEMPO_TLSNOTARY_V1" | xxd -p | tr -d '\n')
CHAIN_ID_HEX=$(printf '%016x' $CHAIN_ID)
# Remove 0x prefix from hashes
PROOF_HASH_HEX=${PROOF_HASH#0x}
STATEMENT_HASH_HEX=${STATEMENT_HASH#0x}
SERVER_NAME_HASH_HEX=${SERVER_NAME_HASH#0x}

ATTESTATION_PREIMAGE="0x${DOMAIN_HEX}${CHAIN_ID_HEX}${PROOF_HASH_HEX}${STATEMENT_HASH_HEX}${SERVER_NAME_HASH_HEX}"
ATTESTATION_MESSAGE=$(cast keccak $ATTESTATION_PREIMAGE)

echo "  Attestation message: $ATTESTATION_MESSAGE"

# Sign with notary key (produces 65-byte r||s||v signature)
SIGNATURE=$(cast wallet sign --no-hash $ATTESTATION_MESSAGE --private-key $NOTARY_PK)
echo "  Signature: ${SIGNATURE:0:20}..."

# ── Step 6: Submit email claim on-chain ───────────────────────────────────────
echo ""
echo "─── Step 6: Submit email claim on-chain ──────────────────────"

RESULT=$(cast send $TLS_NOTARY \
  "claimEmail(string,bytes32,bytes32,bytes)(bytes32)" \
  "$EMAIL" \
  $SERVER_NAME_HASH \
  $PROOF_HASH \
  $SIGNATURE \
  --private-key $CLAIMANT_PK \
  --json)

TX_HASH=$(echo "$RESULT" | jq -r '.transactionHash')
TX_STATUS=$(echo "$RESULT" | jq -r '.status')
echo "  tx: $TX_HASH (status: $TX_STATUS)"

if [ "$TX_STATUS" != "0x1" ]; then
  echo ""
  echo "  ✗ Transaction reverted!"
  echo "  Logs: $(echo "$RESULT" | jq -r '.logs')"
  exit 1
fi

# ── Step 7: Verify email ownership on-chain ───────────────────────────────────
echo ""
echo "─── Step 7: Verify email ownership on-chain ──────────────────"

EMAIL_HASH=$(cast keccak "$EMAIL")
echo "  emailHash = $EMAIL_HASH"

OWNER_RESULT=$(cast call $TLS_NOTARY \
  "emailOwner(bytes32)(address,uint64)" \
  $EMAIL_HASH)
echo "  emailOwner($EMAIL_HASH) ="
echo "    $OWNER_RESULT"

PROOF_REGISTERED=$(cast call $TLS_NOTARY \
  "isProofRegistered(bytes32)(bool)" \
  $PROOF_HASH)
echo "  isProofRegistered = $PROOF_REGISTERED"

echo ""
echo "═══════════════════════════════════════════════════════════════"
echo "  ✓ Email ownership proven on-chain!"
echo ""
echo "  $CLAIMANT_ADDR owns $EMAIL"
echo "  Verified via TLSNotary + accounts.google.com"
echo "═══════════════════════════════════════════════════════════════"
