#!/bin/bash

# Test fee-amm with predeployed tokens
# Uses existing ETH_RPC_URL or defaults to localhost:8545

set -e

ETH_RPC_URL="https://eng:zealous-mayer@rpc-adagietto.tempoxyz.dev"

echo "Testing fee-amm with predeployed tokens..."

# Contract addresses
export TIP_FEE_MANAGER="0xfeec000000000000000000000000000000000000"
export ALPHA_USD="0x20c0000000000000000000000000000000000000"
export BETA_USD="0x20c0000000000000000000000000000000000001"
export THETA_USD="0x20c0000000000000000000000000000000000002"

# Generate test wallet
echo "Generating test wallet..."
USER_WALLET_JSON=$(cast wallet new --json)
export USER_PK=$(echo "$USER_WALLET_JSON" | jq -r '.[0].private_key')
export USER_ADDR=$(echo "$USER_WALLET_JSON" | jq -r '.[0].address')
echo "User wallet: $USER_ADDR"

# Fund the user with all predeployed tokens
echo "Funding user address with all predeployed tokens..."
cast rpc tempo_fundAddress $USER_ADDR
sleep 2

# Check user balances
echo "User balances:"
ALPHA_BALANCE=$(cast balance --erc20 $ALPHA_USD $USER_ADDR)
echo "  AlphaUSD: $ALPHA_BALANCE"
BETA_BALANCE=$(cast balance --erc20 $BETA_USD $USER_ADDR)
echo "  BetaUSD: $BETA_BALANCE"
THETA_BALANCE=$(cast balance --erc20 $THETA_USD $USER_ADDR)
echo "  ThetaUSD: $THETA_BALANCE"

# Set ThetaUSD as the user's fee token
echo "Setting ThetaUSD as user's fee token..."
cast send $TIP_FEE_MANAGER "setUserToken(address)" $THETA_USD --private-key $USER_PK
sleep 2

# Get the current beneficiary from the latest block
echo "Getting current beneficiary..."
LATEST_BLOCK=$(cast block latest --json)
export BENEFICIARY=$(echo "$LATEST_BLOCK" | jq -r '.miner')
echo "Current beneficiary: $BENEFICIARY"

# Get validator's fee token
VALIDATOR_FEE_TOKEN_RAW=$(cast call $TIP_FEE_MANAGER "validatorTokens(address)" $BENEFICIARY)
VALIDATOR_FEE_TOKEN=$(cast parse-bytes32-address "$VALIDATOR_FEE_TOKEN_RAW")
echo "Validator's fee token: $VALIDATOR_FEE_TOKEN"

# Check validator's initial balance in their fee token
echo "Checking validator's initial balance in their fee token..."
VALIDATOR_BALANCE_BEFORE=$(cast balance --erc20 $VALIDATOR_FEE_TOKEN $BENEFICIARY)
echo "  Validator fee token balance before: $VALIDATOR_BALANCE_BEFORE"

# Verify user's fee token is set to ThetaUSD
USER_FEE_TOKEN_RAW=$(cast call $TIP_FEE_MANAGER "userTokens(address)" $USER_ADDR)
USER_FEE_TOKEN=$(cast parse-bytes32-address "$USER_FEE_TOKEN_RAW")
echo "User's fee token: $USER_FEE_TOKEN"

# Execute a normal transfer transaction
echo "Executing test transaction (transfer AlphaUSD)..."
RECIPIENT_ADDR=$(cast wallet new --json | jq -r '.[0].address')
echo "Recipient address: $RECIPIENT_ADDR"

# Transfer some AlphaUSD
TX=$(cast send $ALPHA_USD "transfer(address,uint256)" $RECIPIENT_ADDR "100000000000000000" --private-key $USER_PK --json)
sleep 2
TX_HASH=$(echo "$TX" | jq -r '.transactionHash')
echo "Transaction hash: $TX_HASH"

# Check transaction receipt
RECEIPT=$(cast receipt "$TX_HASH" --json)
TX_STATUS=$(echo "$RECEIPT" | jq -r '.status')

# Check final balances
echo "Final balances:"
ALPHA_BALANCE_FINAL=$(cast balance --erc20 $ALPHA_USD $USER_ADDR)
echo "  User AlphaUSD: $ALPHA_BALANCE_FINAL"
THETA_BALANCE_FINAL=$(cast balance --erc20 $THETA_USD $USER_ADDR)
echo "  User ThetaUSD: $THETA_BALANCE_FINAL (should be reduced by fee)"

# Check validator's final balance in their fee token
echo "Checking validator's final balance in their fee token..."
VALIDATOR_BALANCE_AFTER=$(cast balance --erc20 $VALIDATOR_FEE_TOKEN $BENEFICIARY)
echo "  Validator fee token balance after: $VALIDATOR_BALANCE_AFTER"

# Calculate the difference
echo "Validator fee token balance change: $(echo "$VALIDATOR_BALANCE_AFTER - $VALIDATOR_BALANCE_BEFORE" | bc) (should be increased by fee)"

echo "Test completed successfully!"
