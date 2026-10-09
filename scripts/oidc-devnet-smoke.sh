#!/usr/bin/env bash

set -euo pipefail

for dependency in cast jq od tr awk; do
  command -v "$dependency" > /dev/null || {
    printf 'Missing required command: %s\n' "$dependency" >&2
    exit 1
  }
done

RPC_URL="${1:-http://127.0.0.1:8545}"
PUBLISHER=0x1132000000000000000000000000000000000000
TOKEN=0x20c0000000000000000000000000000000000000
DEV_KEY=ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80
DEV_ACCOUNT=0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266
NEXT_OWNER=0x70997970C51812dc3A010C7d01b50e0d17dc79C8
ISSUER=$(cast to-uint256 1)
FIRST_KEY=$(cast to-uint256 101)
SECOND_KEY=$(cast to-uint256 202)
SALT="0x$(od -An -N32 -tx1 /dev/urandom | tr -d ' \n')"
PAYMENT_RECIPIENT="0x${SALT:26}"

case "$RPC_URL" in
  http://127.0.0.1:*|http://localhost:*) ;;
  *) echo 'Use a loopback RPC endpoint: this test uses a publicly known development key.' >&2; exit 1 ;;
esac

test "$(cast chain-id --rpc-url "$RPC_URL")" = 1337

read_publisher() {
  cast call "$PUBLISHER" "$@" --rpc-url "$RPC_URL"
}

send_transaction() {
  local receipt
  receipt=$(cast send "$@" --private-key "$DEV_KEY" --rpc-url "$RPC_URL" --json)
  jq -e '.status == "0x1"' <<< "$receipt" > /dev/null
  jq -c '{transactionHash,blockNumber,status}' <<< "$receipt"
}

expect_revert() {
  local expected_error="$1"
  shift
  local output
  if output=$(cast call "$PUBLISHER" "$@" --from "$DEV_ACCOUNT" --rpc-url "$RPC_URL" 2>&1); then
    echo "Expected $expected_error, but the call succeeded" >&2
    exit 1
  fi
  local selector
  selector=$(cast sig "$expected_error")
  if [[ "$output" != *"$selector"* && "$output" != *"${expected_error%()}"* ]]; then
    echo "Expected $expected_error, got: $output" >&2
    exit 1
  fi
  printf 'Rejected: %s\n' "$expected_error"
}

PUBLISHER_ID=$(read_publisher 'computePublisherId(address,bytes32)(bytes32)' "$DEV_ACCOUNT" "$SALT")
test "$PUBLISHER_ID" = "$(cast keccak "$(cast abi-encode 'f(address,bytes32)' "$DEV_ACCOUNT" "$SALT")")"

send_transaction "$PUBLISHER" 'createPublisher(bytes32,address,(bytes32,bytes32[])[])' \
  "$SALT" "$DEV_ACCOUNT" "[($ISSUER,[$FIRST_KEY])]"
test "${DEV_ACCOUNT,,}" = "$(read_publisher 'owner(bytes32)(address)' "$PUBLISHER_ID" | tr '[:upper:]' '[:lower:]')"
test "$(read_publisher 'isKeyActive(bytes32,bytes32,bytes32)(bool)' "$PUBLISHER_ID" "$ISSUER" "$FIRST_KEY")" = true
expect_revert 'PublisherExists()' 'createPublisher(bytes32,address,(bytes32,bytes32[])[])' \
  "$SALT" "$DEV_ACCOUNT" '[]'
expect_revert 'KeysNotSorted()' 'setKeys(bytes32,bytes32,bytes32[])' \
  "$PUBLISHER_ID" "$ISSUER" "[$SECOND_KEY,$FIRST_KEY]"
expect_revert 'InvalidFieldElement()' 'setKeys(bytes32,bytes32,bytes32[])' \
  "$PUBLISHER_ID" "$ISSUER" '[0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001]'

ROTATION_RECEIPT=$(send_transaction "$PUBLISHER" 'setKeys(bytes32,bytes32,bytes32[])' \
  "$PUBLISHER_ID" "$ISSUER" "[$SECOND_KEY]")
printf '%s\n' "$ROTATION_RECEIPT"
ROTATION_BLOCK=$(jq -r '.blockNumber' <<< "$ROTATION_RECEIPT")
ROTATION_TIME=$(cast block "$ROTATION_BLOCK" --rpc-url "$RPC_URL" --json | jq -r '.timestamp')
GRACE_UNTIL=$(read_publisher 'keyValidUntil(bytes32,bytes32,bytes32)(uint64)' "$PUBLISHER_ID" "$ISSUER" "$FIRST_KEY" | awk '{print $1}')
test "$GRACE_UNTIL" -eq "$((ROTATION_TIME + 3600))"
test "$(read_publisher 'isKeyActive(bytes32,bytes32,bytes32)(bool)' "$PUBLISHER_ID" "$ISSUER" "$FIRST_KEY")" = true
test "$(read_publisher 'isKeyActive(bytes32,bytes32,bytes32)(bool)' "$PUBLISHER_ID" "$ISSUER" "$SECOND_KEY")" = true
test "$(read_publisher 'activeKeys(bytes32,bytes32)(bytes32[])' "$PUBLISHER_ID" "$ISSUER")" = "[$SECOND_KEY]"

send_transaction "$PUBLISHER" 'revokeKey(bytes32,bytes32,bytes32)' "$PUBLISHER_ID" "$ISSUER" "$FIRST_KEY"
test "$(read_publisher 'isKeyActive(bytes32,bytes32,bytes32)(bool)' "$PUBLISHER_ID" "$ISSUER" "$FIRST_KEY")" = false
send_transaction "$PUBLISHER" 'revokeKey(bytes32,bytes32,bytes32)' "$PUBLISHER_ID" "$ISSUER" "$SECOND_KEY"
test "$(read_publisher 'activeKeys(bytes32,bytes32)(bytes32[])' "$PUBLISHER_ID" "$ISSUER")" = '[]'

send_transaction "$PUBLISHER" 'transferOwnership(bytes32,address)' "$PUBLISHER_ID" "$NEXT_OWNER"
test "${NEXT_OWNER,,}" = "$(read_publisher 'owner(bytes32)(address)' "$PUBLISHER_ID" | tr '[:upper:]' '[:lower:]')"
expect_revert 'Unauthorized()' 'setKeys(bytes32,bytes32,bytes32[])' "$PUBLISHER_ID" "$ISSUER" "[$FIRST_KEY]"

test "$(cast call "$TOKEN" 'balanceOf(address)(uint256)' "$PAYMENT_RECIPIENT" --rpc-url "$RPC_URL" | awk '{print $1}')" = 0
send_transaction "$TOKEN" 'transfer(address,uint256)' "$PAYMENT_RECIPIENT" 1000
test "$(cast call "$TOKEN" 'balanceOf(address)(uint256)' "$PAYMENT_RECIPIENT" --rpc-url "$RPC_URL" | awk '{print $1}')" = 1000

printf 'PASS: publisher creation, rotation, grace, revocation, ownership, malformed keys, and TIP-20 payment\nPublisher ID: %s\n' "$PUBLISHER_ID"
printf 'This is a publisher devnet test, not an OIDC sign-in or ZK proof test.\n'
