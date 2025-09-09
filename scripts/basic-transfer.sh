#!/bin/bash

# Test basic token transfer functionality
# Uses existing ETH_RPC_URL or defaults to localhost:8545

set -e

# Use existing ETH_RPC_URL or default to localhost
if [ -z "$ETH_RPC_URL" ]; then
  export ETH_RPC_URL="http://localhost:8545"
fi

echo "Testing basic token transfer..."

# Generate test wallets
echo "Generating test wallets..."
WALLET1_OUTPUT=$(cast wallet new)
PK1=$(echo "$WALLET1_OUTPUT" | grep "Private key:" | awk '{print $3}')
ADDR1=$(echo "$WALLET1_OUTPUT" | grep "Address:" | awk '{print $2}')

WALLET2_OUTPUT=$(cast wallet new)
PK2=$(echo "$WALLET2_OUTPUT" | grep "Private key:" | awk '{print $3}')
ADDR2=$(echo "$WALLET2_OUTPUT" | grep "Address:" | awk '{print $2}')

echo "Wallet 1: $ADDR1"
echo "Wallet 2: $ADDR2"

# Token addresses
TESTUSD="0x20c0000000000000000000000000000000000000"

echo "Funding wallet 1..."
cast rpc tempo_fundAddress $ADDR1

echo "Checking gas price..."
GAS_PRICE=$(cast gas-price)
echo "Current gas price: $GAS_PRICE"

echo "Checking initial balances..."
BALANCE1_INITIAL=$(cast balance --erc20 $TESTUSD $ADDR1)
BALANCE2_INITIAL=$(cast balance --erc20 $TESTUSD $ADDR2)
echo "Wallet 1 initial balance: $BALANCE1_INITIAL"
echo "Wallet 2 initial balance: $BALANCE2_INITIAL"

# Transfer amount
TRANSFER_AMOUNT=1000

echo "Estimating gas for transfer..."
GAS_ESTIMATE=$(cast estimate $TESTUSD "transfer(address,uint256)" $ADDR2 $TRANSFER_AMOUNT --from $ADDR1)
echo "Gas estimate: $GAS_ESTIMATE"

echo "Executing transfer..."
cast send $TESTUSD "transfer(address,uint256)" $ADDR2 $TRANSFER_AMOUNT --private-key $PK1 --gas-limit $GAS_ESTIMATE

echo "Checking final balances..."
BALANCE1_FINAL=$(cast balance --erc20 $TESTUSD $ADDR1)
BALANCE2_FINAL=$(cast balance --erc20 $TESTUSD $ADDR2)
echo "Wallet 1 final balance: $BALANCE1_FINAL"
echo "Wallet 2 final balance: $BALANCE2_FINAL"

# Verify transfer
EXPECTED_BALANCE1=$((BALANCE1_INITIAL - TRANSFER_AMOUNT))
EXPECTED_BALANCE2=$((BALANCE2_INITIAL + TRANSFER_AMOUNT))

if [ "$BALANCE1_FINAL" != "$EXPECTED_BALANCE1" ]; then
  echo "ERROR: Wallet 1 balance mismatch. Expected $EXPECTED_BALANCE1, got $BALANCE1_FINAL"
  exit 1
fi

if [ "$BALANCE2_FINAL" != "$TRANSFER_AMOUNT" ]; then
  echo "ERROR: Wallet 2 balance mismatch. Expected $TRANSFER_AMOUNT, got $BALANCE2_FINAL"
  exit 1
fi

echo "✓ Transfer completed successfully"
echo "Basic transfer test completed!"

