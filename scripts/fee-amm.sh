#!/bin/bash

# Test txs when user fee token differs from validator
# Uses existing ETH_RPC_URL or defaults to localhost:8545

set -e

# Use existing ETH_RPC_URL or default to localhost
if [ -z "$ETH_RPC_URL" ]; then
  export ETH_RPC_URL="http://localhost:8545"
fi

echo "Testing fee token system..."

# Contract addresses
export TIP20_FACTORY="0x20FC000000000000000000000000000000000000"
export TIP_FEE_MANAGER="0xfeec000000000000000000000000000000000000"
export DEFAULT_TOKEN="0x20c0000000000000000000000000000000000000"

# Generate test wallet
echo "Generating test wallet..."
USER_WALLET_JSON=$(cast wallet new --json)
export USER_PK=$(echo "$USER_WALLET_JSON" | jq -r '.[0].private_key')
export USER_ADDR=$(echo "$USER_WALLET_JSON" | jq -r '.[0].address')
echo "User wallet: $USER_ADDR"

# Fund the user with default tokens for gas
echo "Funding user address with default tokens..."
cast rpc tempo_fundAddress $USER_ADDR
sleep 2

# Check initial balance
USER_INITIAL_BALANCE=$(cast balance --erc20 $DEFAULT_TOKEN $USER_ADDR)
echo "User initial default token balance: $USER_INITIAL_BALANCE"

# Get the current beneficiary from the latest block
echo "Getting current beneficiary..."
LATEST_BLOCK=$(cast block latest --json)
export BENEFICIARY=$(echo "$LATEST_BLOCK" | jq -r '.miner')
echo "Current beneficiary: $BENEFICIARY"

# Check beneficiary initial balance
BENEFICIARY_TOKEN_INITIAL=$(cast balance --erc20 $DEFAULT_TOKEN $BENEFICIARY)
echo "Beneficiary initial token balance: $BENEFICIARY_TOKEN_INITIAL"

# Create a new token
echo "Creating new fee token..."
CREATE_TX=$(cast send $TIP20_FACTORY "createToken(string,string,string,address)" "T" "T" "USD" $USER_ADDR --private-key $USER_PK --json)
sleep 2

# Get the newly created token address
TX_HASH=$(echo "$CREATE_TX" | jq -r '.transactionHash')
RECEIPT=$(cast receipt "$TX_HASH" --json)
TOPIC1=$(echo "$RECEIPT" | jq -r '.logs[0].topics[1]')
export NEW_TOKEN_ADDR=$(cast parse-bytes32-address "$TOPIC1")
echo "New token address: $NEW_TOKEN_ADDR"

# Grant issuer role to user for minting tokens
echo "Granting issuer role to user..."
ISSUER_ROLE=$(cast keccak "ISSUER_ROLE")
cast send $NEW_TOKEN_ADDR "grantRole(bytes32,address)" $ISSUER_ROLE $USER_ADDR --private-key $USER_PK
sleep 2

# Mint tokens to the user
echo "Minting new tokens to user..."
MINT_AMOUNT="1000000000000000000000000" # 1M tokens for liquidity
cast send $NEW_TOKEN_ADDR "mint(address,uint256)" $USER_ADDR $MINT_AMOUNT --private-key $USER_PK
sleep 2

# Verify user has the new tokens
USER_NEW_TOKEN_BALANCE=$(cast balance --erc20 $NEW_TOKEN_ADDR $USER_ADDR)
echo "User new token balance: $USER_NEW_TOKEN_BALANCE"

# Get validator's fee token
VALIDATOR_FEE_TOKEN_RAW=$(cast call $TIP_FEE_MANAGER "validatorTokens(address)" $BENEFICIARY)
VALIDATOR_FEE_TOKEN=$(cast parse-bytes32-address "$VALIDATOR_FEE_TOKEN_RAW")
echo "Validator's fee token: $VALIDATOR_FEE_TOKEN"

# Assert that validator fee token and user fee token are different
if [ "$VALIDATOR_FEE_TOKEN" = "$NEW_TOKEN_ADDR" ]; then
  echo "ERROR: Validator fee token and user fee token are the same"
  exit 1
fi

# Create a new pool to fx between fee tokens
echo "Creating fee token pool between user and validator tokens..."
cast send $TIP_FEE_MANAGER "createPool(address,address)" $NEW_TOKEN_ADDR $VALIDATOR_FEE_TOKEN --private-key $USER_PK
sleep 2

# Add liquidity to the pool
echo "Adding liquidity to the pool..."
LIQUIDITY_AMOUNT="10000000000000"
cast send $TIP_FEE_MANAGER "mint(address,address,uint256,uint256,address)" $NEW_TOKEN_ADDR $VALIDATOR_FEE_TOKEN $LIQUIDITY_AMOUNT $LIQUIDITY_AMOUNT $USER_ADDR --private-key $USER_PK
sleep 2
echo "Liquidity added successfully"

# Set the new token as the user's fee token
echo "Setting new token as user's fee token..."
cast send $TIP_FEE_MANAGER "setUserToken(address)" $NEW_TOKEN_ADDR --private-key $USER_PK
sleep 2

#  Execute a transfer tx
echo "Executing test transaction..."
RECIPIENT_ADDR=$(cast wallet new --json | jq -r '.[0].address')

TX=$(cast send $DEFAULT_TOKEN "transfer(address,uint256)" $RECIPIENT_ADDR "1" --private-key $USER_PK --json)
sleep 2
TX_HASH=$(echo "$TX" | jq -r '.transactionHash')
RECEIPT=$(cast receipt "$TX_HASH" --json)
TX_STATUS=$(echo "$RECEIPT" | jq -r '.status')

if [ "$TX_STATUS" != "0x1" ]; then
  echo "ERROR: Test transaction failed"
  exit 1
fi
