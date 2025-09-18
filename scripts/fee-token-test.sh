#!/bin/bash

# Test fee token system - create new token, set as user token, verify fee payments
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

# Get the current beneficiary (coinbase) from latest block
echo "Getting current beneficiary/coinbase..."
LATEST_BLOCK=$(cast block latest --json)
export BENEFICIARY=$(echo "$LATEST_BLOCK" | jq -r '.miner')
echo "Current beneficiary: $BENEFICIARY"

# Check beneficiary's initial balances
BENEFICIARY_TOKEN_INITIAL=$(cast balance --erc20 $DEFAULT_TOKEN $BENEFICIARY)
echo "Beneficiary initial token balance: $BENEFICIARY_TOKEN_INITIAL"

# Create a new token
echo "Creating new fee token..."
CREATE_TX=$(cast send $TIP20_FACTORY "createToken(string,string,string,address)" "TestFeeToken" "TFT" "USD" $USER_ADDR --private-key $USER_PK --json)
sleep 2

# Get the token creation event to find the new token address
CREATE_RECEIPT=$(cast receipt $(echo "$CREATE_TX" | jq -r '.transactionHash'))
# Extract TokenCreated event - the token address is in the first topic (after event signature)
TOKEN_CREATED_LOG=$(echo "$CREATE_RECEIPT" | jq -r '.logs[0]')
export NEW_TOKEN_ADDR=$(echo "$TOKEN_CREATED_LOG" | jq -r '.topics[1]' | sed 's/0x000000000000000000000000/0x/')
echo "New token address: $NEW_TOKEN_ADDR"

# Grant issuer role to user for minting tokens
echo "Granting issuer role to user..."
ISSUER_ROLE=$(cast keccak "ISSUER_ROLE")
cast send $NEW_TOKEN_ADDR "grantRole(bytes32,address)" $ISSUER_ROLE $USER_ADDR --private-key $USER_PK
sleep 2

# Mint tokens to the user (need ISSUER_ROLE)
echo "Minting new tokens to user..."
MINT_AMOUNT="1000000000000000000000000" # 1M tokens for liquidity
cast send $NEW_TOKEN_ADDR "mint(address,uint256)" $USER_ADDR $MINT_AMOUNT --private-key $USER_PK
sleep 2

# Verify user has the new tokens
USER_NEW_TOKEN_BALANCE=$(cast balance --erc20 $NEW_TOKEN_ADDR $USER_ADDR)
echo "User new token balance: $USER_NEW_TOKEN_BALANCE"

# Set the new token as the user's fee token
echo "Setting new token as user's fee token..."
cast send $TIP_FEE_MANAGER "setUserToken(address)" $NEW_TOKEN_ADDR --private-key $USER_PK
sleep 2

# Verify the user token was set
USER_FEE_TOKEN=$(cast call $TIP_FEE_MANAGER "userTokens(address)" $USER_ADDR)
echo "User's fee token set to: $USER_FEE_TOKEN"

if [ "$USER_FEE_TOKEN" != "$NEW_TOKEN_ADDR" ]; then
  echo "ERROR: User fee token not set correctly. Expected $NEW_TOKEN_ADDR, got $USER_FEE_TOKEN"
  exit 1
fi

# Get validator's fee token (should be default token)
VALIDATOR_FEE_TOKEN=$(cast call $TIP_FEE_MANAGER "validatorTokens(address)" $BENEFICIARY)
echo "Validator's fee token: $VALIDATOR_FEE_TOKEN"

# If validator fee token is not set, it defaults to the default token
if [ "$VALIDATOR_FEE_TOKEN" = "0x0000000000000000000000000000000000000000" ]; then
  VALIDATOR_FEE_TOKEN=$DEFAULT_TOKEN
  echo "Using default token as validator fee token: $VALIDATOR_FEE_TOKEN"
fi

# Always create fee token pool (we just deployed a new fee token so there shouldn't be a pool)
echo "Creating fee token pool between user and validator tokens..."
cast send $TIP_FEE_MANAGER "createPool(address,address)" $NEW_TOKEN_ADDR $VALIDATOR_FEE_TOKEN --private-key $USER_PK
sleep 2

# Add liquidity to the pool
echo "Adding liquidity to the pool..."
LIQUIDITY_AMOUNT="100000000000000000000000" # 100K tokens

# Mint liquidity
cast send $TIP_FEE_MANAGER "mint(address,address,uint256,uint256,address)" $NEW_TOKEN_ADDR $VALIDATOR_FEE_TOKEN $LIQUIDITY_AMOUNT $LIQUIDITY_AMOUNT $USER_ADDR --private-key $USER_PK
sleep 2
echo "Liquidity added successfully"

# Record balances before transaction
USER_NEW_TOKEN_BEFORE=$(cast balance --erc20 $NEW_TOKEN_ADDR $USER_ADDR)
USER_DEFAULT_TOKEN_BEFORE=$(cast balance --erc20 $DEFAULT_TOKEN $USER_ADDR)
BENEFICIARY_NEW_TOKEN_BEFORE=$(cast balance --erc20 $NEW_TOKEN_ADDR $BENEFICIARY)
BENEFICIARY_DEFAULT_TOKEN_BEFORE=$(cast balance --erc20 $DEFAULT_TOKEN $BENEFICIARY)

#  Execute a transaction
echo "Executing test transaction..."
RECIPIENT_ADDR=$(cast wallet new --json | jq -r '.[0].address')
TRANSFER_AMOUNT="1000000000000000000" # 1 token

# Use the default token for the actual transfer (to ensure the tx goes through)
cast send $DEFAULT_TOKEN "transfer(address,uint256)" $RECIPIENT_ADDR $TRANSFER_AMOUNT --private-key $USER_PK
sleep 2

# Check balances after transaction
USER_NEW_TOKEN_AFTER=$(cast balance --erc20 $NEW_TOKEN_ADDR $USER_ADDR)
USER_DEFAULT_TOKEN_AFTER=$(cast balance --erc20 $DEFAULT_TOKEN $USER_ADDR)
BENEFICIARY_NEW_TOKEN_AFTER=$(cast balance --erc20 $NEW_TOKEN_ADDR $BENEFICIARY)
BENEFICIARY_DEFAULT_TOKEN_AFTER=$(cast balance --erc20 $DEFAULT_TOKEN $BENEFICIARY)

# Verify fee payment logic
USER_NEW_TOKEN_DIFF=$(echo "$USER_NEW_TOKEN_BEFORE - $USER_NEW_TOKEN_AFTER" | bc)
USER_DEFAULT_TOKEN_DIFF=$(echo "$USER_DEFAULT_TOKEN_BEFORE - $USER_DEFAULT_TOKEN_AFTER" | bc)
BENEFICIARY_NEW_TOKEN_DIFF=$(echo "$BENEFICIARY_NEW_TOKEN_AFTER - $BENEFICIARY_NEW_TOKEN_BEFORE" | bc)
BENEFICIARY_DEFAULT_TOKEN_DIFF=$(echo "$BENEFICIARY_DEFAULT_TOKEN_AFTER - $BENEFICIARY_DEFAULT_TOKEN_BEFORE" | bc)

if [ "$BENEFICIARY_DEFAULT_TOKEN_DIFF" -gt "0" ] || [ "$BENEFICIARY_NEW_TOKEN_DIFF" -gt "0" ]; then
  echo "Beneficiary received fee tokens"
  if [ "$BENEFICIARY_DEFAULT_TOKEN_DIFF" -gt "0" ]; then
    echo "Beneficiary received $BENEFICIARY_DEFAULT_TOKEN_DIFF default tokens"
  fi
  if [ "$BENEFICIARY_NEW_TOKEN_DIFF" -gt "0" ]; then
    echo "Beneficiary received $BENEFICIARY_NEW_TOKEN_DIFF new tokens"
  fi
else
  echo "Beneficiary did not receive any fee tokens"
fi

# Verify that the fee tokens are different between user and beneficiary
if [ "$NEW_TOKEN_ADDR" != "$VALIDATOR_FEE_TOKEN" ]; then
  echo "User and validator have different fee tokens"
  echo "User fee token: $NEW_TOKEN_ADDR"
  echo "Validator fee token: $VALIDATOR_FEE_TOKEN"
else
  echo "User and validator have the same fee token"
fi
