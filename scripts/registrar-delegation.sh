#!/bin/bash

# Test registrar delegation functionality
# Uses existing ETH_RPC_URL or defaults to localhost:8545

set -e

# Use existing ETH_RPC_URL or default to localhost
if [ -z "$ETH_RPC_URL" ]; then
  export ETH_RPC_URL="http://localhost:8545"
fi

echo "Testing registrar type delegation..."

export TOKEN_ADDR=0x20c0000000000000000000000000000000000000
export REGISTRAR_ADDR=0x7702ac0000000000000000000000000000000000
export DEFAULT_DELEGATE_ADDR=0x7702c00000000000000000000000000000000000

SENDER_WALLET_JSON=$(cast wallet new --json)
export SENDER_PRIVATE_KEY=$(echo "$SENDER_WALLET_JSON" | jq -r '.[0].private_key')
export SENDER_ADDR=$(echo "$SENDER_WALLET_JSON" | jq -r '.[0].address')
echo "Generated sender wallet: $SENDER_ADDR"

SIGNER_WALLET_JSON=$(cast wallet new --json)
export SIGNER_PRIVATE_KEY=$(echo "$SIGNER_WALLET_JSON" | jq -r '.[0].private_key')
export SIGNER_ADDR=$(echo "$SIGNER_WALLET_JSON" | jq -r '.[0].address')
echo "Generated signer wallet: $SIGNER_ADDR"

echo "Funding sender address $SENDER_ADDR..."
cast rpc tempo_fundAddress $SENDER_ADDR
sleep 2
echo "Sender token balance: $(cast balance --erc20 $TOKEN_ADDR $SENDER_ADDR)"

echo "Checking signer account initial state..."
SIGNER_INITIAL_NONCE=$(cast nonce $SIGNER_ADDR)
SIGNER_INITIAL_CODE=$(cast code $SIGNER_ADDR)

if [ "$SIGNER_INITIAL_NONCE" != "0" ]; then
  echo "ERROR: Expected signer nonce 0, got: $SIGNER_INITIAL_NONCE"
  exit 1
fi

if [ "$SIGNER_INITIAL_CODE" != "0x" ]; then
  echo "ERROR: Expected signer empty code (0x), got: $SIGNER_INITIAL_CODE"
  exit 1
fi

echo "Creating signature for delegation..."
TEST_HASH=$(cast keccak "test")
SIGNATURE=$(cast wallet sign --no-hash $TEST_HASH --private-key $SIGNER_PRIVATE_KEY)

echo "Sending delegation tx..."
cast send $REGISTRAR_ADDR "delegateToDefault(bytes32,bytes)" $TEST_HASH $SIGNATURE --private-key $SENDER_PRIVATE_KEY
sleep 2

SIGNER_NONCE=$(cast nonce $SIGNER_ADDR)
SIGNER_CODE=$(cast code $SIGNER_ADDR)

if [ "$SIGNER_NONCE" != "0" ]; then
  echo "ERROR: Expected signer nonce 0, got: $SIGNER_NONCE"
  exit 1
fi

EXPECTED_7702_CODE="0xef01007702c00000000000000000000000000000000000"
if [ "$SIGNER_CODE" != "$EXPECTED_7702_CODE" ]; then
  echo "Code after delegation ($SIGNER_CODE) doesn't match expected 7702 code ($EXPECTED_7702_CODE)"
  exit 1
fi
