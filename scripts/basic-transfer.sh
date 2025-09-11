#!/bin/bash

# Test basic token transfer functionality
# Uses existing ETH_RPC_URL or defaults to localhost:8545

set -e

# Use existing ETH_RPC_URL or default to localhost
if [ -z "$ETH_RPC_URL" ]; then
  export ETH_RPC_URL="http://localhost:8545"
fi

echo "Testing basic token transfer..."

echo "Generating wallets..."
SENDER_WALLET_JSON=$(cast wallet new --json)
SENDER_PK=$(echo "$SENDER_WALLET_JSON" | jq -r '.[0].private_key')
SENDER_ADDR=$(echo "$SENDER_WALLET_JSON" | jq -r '.[0].address')

RECIPIENT_ADDR=$(cast wallet new --json | jq -r '.[0].address')
TESTUSD="0x20c0000000000000000000000000000000000000"

echo "Funding sender address..."
cast rpc tempo_fundAddress $SENDER_ADDR
sleep 2

echo "Checking initial balances..."
SENDER_NATIVE_BALANCE=$(cast balance $SENDER_ADDR)
echo "Sender native balance: $SENDER_NATIVE_BALANCE"
if [ "$SENDER_NATIVE_BALANCE" != "0" ]; then
  echo "ERROR: Expected sender native balance to be 0, got $SENDER_NATIVE_BALANCE"
  exit 1
fi

SENDER_BALANCE_INITIAL=$(cast balance --erc20 $TESTUSD $SENDER_ADDR)
RECIPIENT_BALANCE_INITIAL=$(cast balance --erc20 $TESTUSD $RECIPIENT_ADDR)
echo "Sender initial token balance: $SENDER_BALANCE_INITIAL"
echo "Recipient initial token balance: $RECIPIENT_BALANCE_INITIAL"

TRANSFER_AMOUNT=1000

echo "Executing transfer..."
cast send $TESTUSD "transfer(address,uint256)" $RECIPIENT_ADDR $TRANSFER_AMOUNT --private-key $SENDER_PK

echo "Checking final balances..."
SENDER_BALANCE_FINAL=$(cast balance --erc20 $TESTUSD $SENDER_ADDR)
RECIPIENT_BALANCE_FINAL=$(cast balance --erc20 $TESTUSD $RECIPIENT_ADDR)
echo "Sender final balance: $SENDER_BALANCE_FINAL"
echo "Recipient final balance: $RECIPIENT_BALANCE_FINAL"

echo "Transfer completed successfully"
