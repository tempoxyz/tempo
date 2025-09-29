#!/bin/bash

# Test eth_estimateGas with 0x77 transactions and fee tokens
# Verifies that estimateGas correctly uses the fee token specified in the transaction
# rather than the user's configured fee token
# Uses existing ETH_RPC_URL or defaults to localhost:8545

set -e

# Track test failures
TEST_FAILED=0

# Use existing ETH_RPC_URL or default to localhost
if [ -z "$ETH_RPC_URL" ]; then
  export ETH_RPC_URL="http://localhost:8545"
fi

echo "Testing eth_estimateGas with 0x77 transactions and fee tokens..."
echo "RPC URL: $ETH_RPC_URL"

# Contract addresses
export TIP_FEE_MANAGER="0xfeec000000000000000000000000000000000000"
export DEFAULT_TOKEN="0x20c0000000000000000000000000000000000000"
export ALT_TOKEN="0x20c0000000000000000000000000000000000001"

# Test account (from anvil default accounts)
export TEST_ADDR="0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"
export TEST_PK="0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"

echo ""
echo "=== Step 0: Check test account balance ==="
# The test account is the faucet account, which should be pre-funded by tempo-dev
# If not, we'll fund another address and use that
BALANCE=$(cast balance --erc20 $DEFAULT_TOKEN $TEST_ADDR)
echo "Test account balance in default token: $BALANCE"

if [ "$BALANCE" = "0" ]; then
  echo "Test account has no balance. Generating a new test account and funding it..."
  # Generate a new test account
  NEW_WALLET_JSON=$(cast wallet new --json)
  export TEST_ADDR=$(echo "$NEW_WALLET_JSON" | jq -r '.[0].address')
  export TEST_PK=$(echo "$NEW_WALLET_JSON" | jq -r '.[0].private_key')
  echo "New test account: $TEST_ADDR"

  # Fund the new account
  cast rpc tempo_fundAddress $TEST_ADDR >/dev/null 2>&1
  sleep 2

  # Verify funding worked
  BALANCE=$(cast balance --erc20 $DEFAULT_TOKEN $TEST_ADDR)
  echo "New account balance in default token: $BALANCE"
  if [ "$BALANCE" = "0" ]; then
    echo "ERROR: Failed to fund test account"
    exit 1
  fi
fi

echo ""
echo "=== Step 1: Check user's current fee token setting ==="
USER_FEE_TOKEN_RAW=$(cast call $TIP_FEE_MANAGER "userTokens(address)" $TEST_ADDR)
USER_FEE_TOKEN=$(cast parse-bytes32-address "$USER_FEE_TOKEN_RAW" || echo "0x0000000000000000000000000000000000000000")
echo "User's current fee token: $USER_FEE_TOKEN"

echo ""
echo "=== Step 2: Test eth_estimateGas with default token ==="
echo "Expected behavior: Should succeed since account has balance in default token"
echo "Calling eth_estimateGas with feeToken: $DEFAULT_TOKEN"
echo "Testing with account: $TEST_ADDR"
echo "Account has balance in default token: $BALANCE"

# First try with regular EIP-1559 transaction to verify account works
echo ""
echo "Testing with regular EIP-1559 transaction first (baseline)..."
REGULAR_ESTIMATE=$(curl -s -X POST -H "Content-Type: application/json" -d '{
  "jsonrpc": "2.0",
  "id": 1,
  "method": "eth_estimateGas",
  "params": [{
    "from": "'$TEST_ADDR'",
    "to": "0x0000000000000000000000000000000000000000",
    "value": "0x0"
  }]
}' $ETH_RPC_URL)

if echo "$REGULAR_ESTIMATE" | grep -q '"result"'; then
  echo "PASS: Regular tx estimate succeeded: $(echo "$REGULAR_ESTIMATE" | jq -r '.result')"
else
  echo "FAIL: Regular tx estimate failed unexpectedly"
  echo "Response: $REGULAR_ESTIMATE"
  TEST_FAILED=1
fi

# Now try with 0x77 transaction
echo ""
echo "Now testing with 0x77 transaction with default fee token..."
ESTIMATE_RESULT=$(curl -s -X POST -H "Content-Type: application/json" -d '{
  "jsonrpc": "2.0",
  "id": 1,
  "method": "eth_estimateGas",
  "params": [{
    "from": "'$TEST_ADDR'",
    "maxFeePerGas": "0x34",
    "maxPriorityFeePerGas": "0x0",
    "nonce": "0x0",
    "to": "0x0000000000000000000000000000000000000000",
    "type": "0x77",
    "chainId": "0x539",
    "feeToken": "'$DEFAULT_TOKEN'"
  }]
}' $ETH_RPC_URL)

# Check if the 0x77 estimate succeeded
if echo "$ESTIMATE_RESULT" | grep -q '"result"'; then
  GAS_ESTIMATE=$(echo "$ESTIMATE_RESULT" | jq -r '.result')
  echo "PASS: 0x77 tx with default token estimate succeeded: $GAS_ESTIMATE"
else
  ERROR_MSG=$(echo "$ESTIMATE_RESULT" | jq -r '.error.message')
  echo "FAIL: 0x77 tx estimate failed when it should succeed"
  echo "Error message: $ERROR_MSG"
  echo "This indicates the bug is present - estimateGas should use the fee token"
  echo "specified in the transaction, not the user's configured token."
  TEST_FAILED=1
fi

echo ""
echo "=== Step 3: Set user's fee token to alternative token ==="
echo "Setting fee token to: $ALT_TOKEN"

# Set the fee token for the user
TX_HASH=$(cast send $TIP_FEE_MANAGER 'setUserToken(address)' $ALT_TOKEN \
  --private-key $TEST_PK \
  --json | jq -r '.transactionHash')

echo "Transaction hash: $TX_HASH"

# Wait for transaction to be mined
sleep 2

# Verify the fee token was set
USER_FEE_TOKEN_RAW=$(cast call $TIP_FEE_MANAGER "userTokens(address)" $TEST_ADDR)
USER_FEE_TOKEN=$(cast parse-bytes32-address "$USER_FEE_TOKEN_RAW")
echo "User's fee token is now: $USER_FEE_TOKEN"

# Convert to lowercase for comparison
USER_FEE_TOKEN_LOWER=$(echo "$USER_FEE_TOKEN" | tr '[:upper:]' '[:lower:]')
ALT_TOKEN_LOWER=$(echo "$ALT_TOKEN" | tr '[:upper:]' '[:lower:]')

if [ "$USER_FEE_TOKEN_LOWER" != "$ALT_TOKEN_LOWER" ]; then
  echo "ERROR: Failed to set user fee token"
  exit 1
fi

echo "Fee token set successfully"

echo ""
echo "=== Step 4: Test eth_estimateGas with default token again ==="
echo "Expected behavior: Should still succeed because tx specifies default token"
echo "Calling eth_estimateGas with feeToken: $DEFAULT_TOKEN"

# Get the current nonce
NONCE=$(cast nonce $TEST_ADDR)
echo "Current nonce: $NONCE"

ESTIMATE_RESULT_2=$(curl -s -X POST -H "Content-Type: application/json" -d '{
  "jsonrpc": "2.0",
  "id": 1,
  "method": "eth_estimateGas",
  "params": [{
    "from": "'$TEST_ADDR'",
    "maxFeePerGas": "0x34",
    "maxPriorityFeePerGas": "0x0",
    "nonce": "'$NONCE'",
    "to": "0x0000000000000000000000000000000000000000",
    "type": "0x77",
    "chainId": "0x539",
    "feeToken": "'$DEFAULT_TOKEN'"
  }]
}' $ETH_RPC_URL)

echo "Response: $ESTIMATE_RESULT_2"

# Check the result
if echo "$ESTIMATE_RESULT_2" | grep -q '"result"'; then
  GAS_ESTIMATE_2=$(echo "$ESTIMATE_RESULT_2" | jq -r '.result')
  echo "PASS: Gas estimate succeeded as expected: $GAS_ESTIMATE_2"
  echo "The estimate correctly uses the fee token specified in the transaction."
else
  ERROR_MSG=$(echo "$ESTIMATE_RESULT_2" | jq -r '.error.message')
  echo "FAIL: Gas estimate failed when it should succeed"
  echo "Error message: $ERROR_MSG"

  if echo "$ERROR_MSG" | grep -q "gas required exceeds allowance"; then
    echo "This confirms the bug: eth_estimateGas is checking balance against"
    echo "the user's configured fee token ($ALT_TOKEN) instead of the fee token"
    echo "specified in the transaction ($DEFAULT_TOKEN)."
  fi
  TEST_FAILED=1
fi

echo ""
echo "=== Step 5: Test eth_estimateGas with alternative token ==="
echo "Expected behavior: Should fail since account has no balance in alt token"
echo "Calling eth_estimateGas with feeToken: $ALT_TOKEN"

# Check balance in alternative token
BALANCE_ALT=$(cast balance --erc20 $ALT_TOKEN $TEST_ADDR)
echo "Account balance in alternative token: $BALANCE_ALT"

ESTIMATE_RESULT_3=$(curl -s -X POST -H "Content-Type: application/json" -d '{
  "jsonrpc": "2.0",
  "id": 1,
  "method": "eth_estimateGas",
  "params": [{
    "from": "'$TEST_ADDR'",
    "maxFeePerGas": "0x34",
    "maxPriorityFeePerGas": "0x0",
    "nonce": "'$NONCE'",
    "to": "0x0000000000000000000000000000000000000000",
    "type": "0x77",
    "chainId": "0x539",
    "feeToken": "'$ALT_TOKEN'"
  }]
}' $ETH_RPC_URL)

echo "Response: $ESTIMATE_RESULT_3"

if [ "$BALANCE_ALT" = "0" ]; then
  # Account has no balance in alt token, so estimate should fail
  if echo "$ESTIMATE_RESULT_3" | grep -q '"error"'; then
    echo "PASS: Gas estimate correctly failed due to insufficient balance"
  else
    echo "FAIL: Gas estimate succeeded but account has no balance in alt token"
    echo "This suggests a bug in balance checking"
    TEST_FAILED=1
  fi
else
  # Account has balance in alt token, so estimate should succeed
  if echo "$ESTIMATE_RESULT_3" | grep -q '"result"'; then
    echo "PASS: Gas estimate succeeded as expected (account has balance)"
  else
    echo "FAIL: Gas estimate failed but account has sufficient balance"
    TEST_FAILED=1
  fi
fi

echo ""
echo "=== Test Summary ==="
if [ $TEST_FAILED -eq 0 ]; then
  echo "ALL TESTS PASSED: eth_estimateGas correctly uses the fee token specified in the transaction"
  exit 0
else
  echo "TESTS FAILED: eth_estimateGas has issues with fee token handling"
  echo "The implementation should use the fee token from the transaction, not the user's configured token"
  exit 1
fi