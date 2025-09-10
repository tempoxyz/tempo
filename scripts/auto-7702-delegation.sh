#!/bin/bash

# Test 7702 delegation functionality
# Uses existing ETH_RPC_URL or defaults to localhost:8545

set -e

# Use existing ETH_RPC_URL or default to localhost
if [ -z "$ETH_RPC_URL" ]; then
  export ETH_RPC_URL="http://localhost:8545"
fi

echo "Testing 7702 delegation..."

export TOKEN_ADDR=0x20c0000000000000000000000000000000000000
WALLET_JSON=$(cast wallet new --json)
export TEST_PRIVATE_KEY=$(echo "$WALLET_JSON" | jq -r '.[0].private_key')
export TEST_ADDR=$(echo "$WALLET_JSON" | jq -r '.[0].address')
echo "Generated wallet: $TEST_ADDR"

echo "Funding address $TEST_ADDR..."
cast rpc tempo_fundAddress $TEST_ADDR
sleep 2
echo "Balance: $(cast balance --erc20 $TOKEN_ADDR $TEST_ADDR)"

echo "Checking account code is empty..."
INITIAL_CODE=$(cast code $TEST_ADDR)
echo "Initial code: $INITIAL_CODE"
if [ "$INITIAL_CODE" != "0x" ]; then
  echo "ERROR: Expected empty code (0x), got: $INITIAL_CODE"
  exit 1
fi

# Generate random recipient addresses
export RECIPIENT_0=$(cast wallet new --json | jq -r '.[0].address')
export RECIPIENT_1=$(cast wallet new --json | jq -r '.[0].address')
export RECIPIENT_2=$(cast wallet new --json | jq -r '.[0].address')
echo "Recipients: $RECIPIENT_0, $RECIPIENT_1, $RECIPIENT_2"

export TRANSFER_AMOUNT=1000

echo "Preparing batch transfer calldata..."
TRANSFER_0_CALLDATA=$(cast calldata "transfer(address,uint256)" $RECIPIENT_0 $TRANSFER_AMOUNT)
TRANSFER_1_CALLDATA=$(cast calldata "transfer(address,uint256)" $RECIPIENT_1 $TRANSFER_AMOUNT)
TRANSFER_2_CALLDATA=$(cast calldata "transfer(address,uint256)" $RECIPIENT_2 $TRANSFER_AMOUNT)

export EXEC_MODE=0x0100000000007821000100000000000000000000000000000000000000000000

BATCH_CALLDATA=$(cast abi-encode "f((address,uint256,bytes)[])" "[(${TOKEN_ADDR},0,${TRANSFER_0_CALLDATA}),(${TOKEN_ADDR},0,${TRANSFER_1_CALLDATA}),(${TOKEN_ADDR},0,${TRANSFER_2_CALLDATA})]")

echo "Executing batch transfer via 7702 delegation..."
cast send $TEST_ADDR "execute(bytes32,bytes)" $EXEC_MODE $BATCH_CALLDATA --private-key $TEST_PRIVATE_KEY

echo "Verifying recipient balances..."
BALANCE_0=$(cast balance --erc20 $TOKEN_ADDR $RECIPIENT_0)
echo "Recipient 0 balance ($RECIPIENT_0): $BALANCE_0"
if [ "$BALANCE_0" != "$TRANSFER_AMOUNT" ]; then
  echo "ERROR: Expected $TRANSFER_AMOUNT, got $BALANCE_0"
  exit 1
fi

BALANCE_1=$(cast balance --erc20 $TOKEN_ADDR $RECIPIENT_1)
echo "Recipient 1 balance ($RECIPIENT_1): $BALANCE_1"
if [ "$BALANCE_1" != "$TRANSFER_AMOUNT" ]; then
  echo "ERROR: Expected $TRANSFER_AMOUNT, got $BALANCE_1"
  exit 1
fi

BALANCE_2=$(cast balance --erc20 $TOKEN_ADDR $RECIPIENT_2)
echo "Recipient 2 balance ($RECIPIENT_2): $BALANCE_2"
if [ "$BALANCE_2" != "$TRANSFER_AMOUNT" ]; then
  echo "ERROR: Expected $TRANSFER_AMOUNT, got $BALANCE_2"
  exit 1
fi

echo "Checking account has been auto delegated..."
FINAL_CODE=$(cast code $TEST_ADDR)
echo "Final code: $FINAL_CODE"
if [ "$FINAL_CODE" = "0x" ]; then
  echo "ERROR: Expected delegated code, but got empty code"
  exit 1
fi
echo "Account has been successfully delegated"
