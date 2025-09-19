#!/bin/bash

# Simple TIP20 token creation, minting, and transfer example
# Uses existing ETH_RPC_URL or defaults to localhost:8545

set -e

# Use existing ETH_RPC_URL or default to localhost
if [ -z "$ETH_RPC_URL" ]; then
  export ETH_RPC_URL="http://localhost:8545"
fi

echo "Creating and testing TIP20 token..."

# Contract addresses
export TIP20_FACTORY="0x20FC000000000000000000000000000000000000"

# Generate test wallets
echo "Generating test wallets..."
SENDER_WALLET_JSON=$(cast wallet new --json)
export SENDER_PK=$(echo "$SENDER_WALLET_JSON" | jq -r '.[0].private_key')
export SENDER_ADDR=$(echo "$SENDER_WALLET_JSON" | jq -r '.[0].address')

RECIPIENT_WALLET_JSON=$(cast wallet new --json)
export RECIPIENT_ADDR=$(echo "$RECIPIENT_WALLET_JSON" | jq -r '.[0].address')

echo "Sender wallet: $SENDER_ADDR"
echo "Recipient wallet: $RECIPIENT_ADDR"

# Fund the sender with fee tokens for gas
echo "Funding sender address..."
cast rpc tempo_fundAddress $SENDER_ADDR
sleep 2

# Check sender's initial balance
SENDER_INITIAL_BALANCE=$(cast balance --erc20 0x20c0000000000000000000000000000000000000 $SENDER_ADDR)
echo "Sender initial balance (for gas): $SENDER_INITIAL_BALANCE"

# Create a new token
echo "Creating new TIP20 token..."
CREATE_TX=$(cast send $TIP20_FACTORY "createToken(string,string,string,address)" "T" "T" "USD" $SENDER_ADDR --private-key $SENDER_PK --json)
sleep 2

# Get the newly created token address
TX_HASH=$(echo "$CREATE_TX" | jq -r '.transactionHash')
RECEIPT=$(cast receipt "$TX_HASH" --json)
TOPIC1=$(echo "$RECEIPT" | jq -r '.logs[0].topics[1]')
export NEW_TOKEN_ADDR=$(cast parse-bytes32-address "$TOPIC1")

# Grant issuer role to sender for minting tokens
echo "Granting issuer role to sender..."
ISSUER_ROLE=$(cast keccak "ISSUER_ROLE")
cast send $NEW_TOKEN_ADDR "grantRole(bytes32,address)" $ISSUER_ROLE $SENDER_ADDR --private-key $SENDER_PK
sleep 2

# Mint tokens to the user
echo "Minting tokens to sender..."
MINT_AMOUNT="5000000000000000000000"
cast send $NEW_TOKEN_ADDR "mint(address,uint256)" $SENDER_ADDR $MINT_AMOUNT --private-key $SENDER_PK
sleep 2

# Transfer tokens to recipient
echo "Transferring tokens to recipient..."
TRANSFER_AMOUNT="1000000000000000000000"
cast send $NEW_TOKEN_ADDR "transfer(address,uint256)" $RECIPIENT_ADDR $TRANSFER_AMOUNT --private-key $SENDER_PK
sleep 2
