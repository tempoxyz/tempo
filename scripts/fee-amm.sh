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

# Get the TokenCreated event and decode it properly
TX_HASH=$(echo "$CREATE_TX" | jq -r '.transactionHash')
export NEW_TOKEN_ADDR=$(cast logs --from-block latest --address $TIP20_FACTORY 'TokenCreated(address indexed token, uint256 indexed id)' | cast decode-log 'TokenCreated(address indexed token, uint256 indexed id)' | head -1 | awk '{print $1}')
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
USER_FEE_TOKEN_BEFORE=$(cast balance --erc20 $NEW_TOKEN_ADDR $USER_ADDR)
BENEFICIARY_FEE_TOKEN_BEFORE=$(cast balance --erc20 $VALIDATOR_FEE_TOKEN $BENEFICIARY)
RECIPIENT_BEFORE=$(cast balance --erc20 $DEFAULT_TOKEN $RECIPIENT_ADDR)

#  Execute a transaction
echo "Executing test transaction..."
RECIPIENT_ADDR=$(cast wallet new --json | jq -r '.[0].address')
TRANSFER_AMOUNT="1000000000000000000" # 1 token

# Use the default token for the actual transfer (to ensure the tx goes through)
cast send $DEFAULT_TOKEN "transfer(address,uint256)" $RECIPIENT_ADDR $TRANSFER_AMOUNT --private-key $USER_PK
sleep 2

# Check balances after transaction
USER_FEE_TOKEN_AFTER=$(cast balance --erc20 $NEW_TOKEN_ADDR $USER_ADDR)
BENEFICIARY_FEE_TOKEN_AFTER=$(cast balance --erc20 $VALIDATOR_FEE_TOKEN $BENEFICIARY)
RECIPIENT_AFTER=$(cast balance --erc20 $DEFAULT_TOKEN $RECIPIENT_ADDR)

# Verify transfer and fee payment logic
echo "Verifying test results..."

# Check recipient received the transfer
RECIPIENT_DIFF=$(echo "$RECIPIENT_AFTER - $RECIPIENT_BEFORE" | bc)
if [ "$RECIPIENT_DIFF" = "$TRANSFER_AMOUNT" ]; then
  echo "Recipient received transfer: $TRANSFER_AMOUNT"
else
  echo "Recipient transfer failed. Expected $TRANSFER_AMOUNT, got $RECIPIENT_DIFF"
fi

# Check user fee token balance decreased (user paid fees)
USER_FEE_TOKEN_DIFF=$(echo "$USER_FEE_TOKEN_BEFORE - $USER_FEE_TOKEN_AFTER" | bc)
if [ "$USER_FEE_TOKEN_DIFF" -gt "0" ]; then
  echo "User paid fees in fee token: $USER_FEE_TOKEN_DIFF"
else
  echo "User fee token balance did not decrease"
fi

# Check beneficiary fee token balance increased (beneficiary received fees)
BENEFICIARY_FEE_TOKEN_DIFF=$(echo "$BENEFICIARY_FEE_TOKEN_AFTER - $BENEFICIARY_FEE_TOKEN_BEFORE" | bc)
if [ "$BENEFICIARY_FEE_TOKEN_DIFF" -gt "0" ]; then
  echo "Beneficiary received fees: $BENEFICIARY_FEE_TOKEN_DIFF"
else
  echo "Beneficiary fee token balance did not increase"
fi
