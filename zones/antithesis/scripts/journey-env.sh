#!/bin/sh
# Environment for the txgen zone journeys (/opt/zones/txgen/journey.yml). Source this file.

S=/shared
until [ -f "$S/provisioned" ]; do sleep 1; done

export L1_RPC_URL=http://10.20.0.10:8545
ZONE_ID=$(jq -r .zoneId "$S/zone.json")
ZONE_PORTAL_ADDRESS=$(jq -r .portal "$S/zone.json")
ZONE_CHAIN_ID=$(jq -r .chainId "$S/zone.json")
until L1_CHAIN_ID=$(cast chain-id --rpc-url "$L1_RPC_URL" 2>/dev/null); do sleep 1; done
export ZONE_ID ZONE_PORTAL_ADDRESS ZONE_CHAIN_ID L1_CHAIN_ID
export ZONE_JOURNEY_DEPOSIT_AMOUNT="${ZONE_JOURNEY_DEPOSIT_AMOUNT:-10000000}"
export ZONE_JOURNEY_WITHDRAWAL_AMOUNT="${ZONE_JOURNEY_WITHDRAWAL_AMOUNT:-1000000}"

# Journey and assertion names, shared by the declarations and the driver.
JOURNEY_COMPLETED="zone journey completes: deposits to two fresh accounts, one withdraws to L1"
JOURNEY_FAILURES_FROM_FAULTS="zone journeys fail only in ways faults explain (timeouts, RPC errors)"
PORTAL_BACKED="portal escrow backs zone supply, pending deposits, withdrawals and refunds"
