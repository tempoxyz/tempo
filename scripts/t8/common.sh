#!/usr/bin/env bash

set -euo pipefail

readonly TIP20_FACTORY="0x20FC000000000000000000000000000000000000"
readonly TIP_FEE_MANAGER="0xfeec000000000000000000000000000000000000"
readonly TIP403_REGISTRY="0x403C000000000000000000000000000000000000"
readonly STABLECOIN_DEX="0xdec0000000000000000000000000000000000000"
readonly CURRENT_COMMITTEE="0xC077E00000000000000000000000000000000000"
readonly PATH_USD="0x20C0000000000000000000000000000000000000"

require_env() {
  local name
  for name in "$@"; do
    if [[ -z "${!name:-}" ]]; then
      echo "missing required environment variable: $name" >&2
      exit 2
    fi
  done
}

require_tools() {
  local tool
  for tool in cast jq; do
    command -v "$tool" >/dev/null || { echo "required tool not found: $tool" >&2; exit 2; }
  done
}

require_t8() {
  local schedule
  schedule=$(rpc tempo_forkSchedule)
  if ! jq -e '.schedule[] | select(.name == "T8" and .active == true)' \
    >/dev/null <<<"$schedule"; then
    echo "T8 is not active on $RPC_URL" >&2
    exit 2
  fi
}

rpc() { cast rpc --rpc-url "$RPC_URL" "$@"; }
call() { cast call --rpc-url "$RPC_URL" "$@"; }
scalar() { call "$@" | awk 'NR == 1 { print $1 }'; }

send() {
  cast send --rpc-url "$RPC_URL" --private-key "$PRIVATE_KEY" --json "$@"
}

tx_hash() { jq -er '.transactionHash'; }

assert_eq() {
  local expected="$1" actual="$2" message="$3"
  if [[ "${expected,,}" != "${actual,,}" ]]; then
    echo "FAIL: $message (expected=$expected actual=$actual)" >&2
    exit 1
  fi
}

assert_ne() {
  local unexpected="$1" actual="$2" message="$3"
  if [[ "${unexpected,,}" == "${actual,,}" ]]; then
    echo "FAIL: $message (unexpected=$unexpected)" >&2
    exit 1
  fi
}

receipt_field() {
  local hash="$1" field="$2"
  cast receipt --rpc-url "$RPC_URL" "$hash" --json | jq -er ".$field"
}

send_hash() {
  send "$@" | tx_hash
}

send_ok() {
  local hash status
  hash=$(send_hash "$@")
  status=$(receipt_field "$hash" status)
  assert_eq "0x1" "$status" "transaction $hash reverted"
  echo "$hash"
}

fund_address() {
  local address="$1"
  if [[ "${USE_FAUCET:-1}" == "1" ]]; then
    rpc tempo_fundAddress "$address" >/dev/null
  fi
}

new_salt() {
  cast keccak "t8-network-test:$1:$(date +%s%N):$$"
}

create_tip20() {
  local label="$1" admin="$2" salt token issuer_role
  salt=$(new_salt "$label")
  token=$(call "$TIP20_FACTORY" \
    "getTokenAddress(address,bytes32)(address)" "$admin" "$salt")
  send_ok "$TIP20_FACTORY" \
    "createToken(string,string,string,address,address,bytes32)(address)" \
    "T8 $label" "T8${label:0:3}" "USD" "$PATH_USD" "$admin" "$salt" >/dev/null
  issuer_role=$(cast keccak "ISSUER_ROLE")
  send_ok "$token" "grantRole(bytes32,address)" "$issuer_role" "$admin" >/dev/null
  echo "$token"
}

account_address() {
  cast wallet address --private-key "$PRIVATE_KEY"
}

gas_used_decimal() {
  local hash="$1" gas
  gas=$(receipt_field "$hash" gasUsed)
  cast to-dec "$gas"
}

print_pass() { echo "PASS: $*"; }
