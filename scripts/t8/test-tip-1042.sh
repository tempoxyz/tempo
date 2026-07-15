#!/usr/bin/env bash

set -euo pipefail
source "$(dirname "$0")/common.sh"
require_tools
require_env RPC_URL PRIVATE_KEY
require_t8

admin=$(account_address)
fund_address "$admin"
beneficiary=$(cast block --rpc-url "$RPC_URL" latest --json | jq -er '.miner')
validator_token=$(call "$TIP_FEE_MANAGER" "validatorTokens(address)(address)" "$beneficiary")
if [[ "${validator_token,,}" == "0x0000000000000000000000000000000000000000" ]]; then
  validator_token="$PATH_USD"
fi

fee_token=$(create_tip20 "fee" "$admin")
mint_amount=1000000000000
send_ok "$fee_token" "mint(address,uint256)" "$admin" "$mint_amount" >/dev/null

# Seed the pool while FeeManager is authorized, then make FeeManager explicitly
# unauthorized. TIP-1042 must exempt only protocol fee collection, not public AMM calls.
send_ok "$fee_token" "approve(address,uint256)(bool)" "$TIP_FEE_MANAGER" "$mint_amount" >/dev/null
send_ok "$validator_token" "approve(address,uint256)(bool)" "$TIP_FEE_MANAGER" "$mint_amount" >/dev/null
send_ok "$TIP_FEE_MANAGER" "mint(address,address,uint256,address)(uint256)" \
  "$fee_token" "$validator_token" 1000000 "$admin" >/dev/null
send_ok "$TIP_FEE_MANAGER" "setUserToken(address)" "$fee_token" >/dev/null

policy_before=$(scalar "$TIP403_REGISTRY" "policyIdCounter()(uint64)")
send_ok "$TIP403_REGISTRY" "createPolicy(address,uint8)(uint64)" "$admin" 1 >/dev/null
policy_after=$(scalar "$TIP403_REGISTRY" "policyIdCounter()(uint64)")
assert_ne "$policy_before" "$policy_after" "blacklist policy was not created"
policy_id="$policy_before"

send_ok "$TIP403_REGISTRY" "modifyPolicyBlacklist(uint64,address,bool)" \
  "$policy_id" "$TIP_FEE_MANAGER" true >/dev/null
send_ok "$fee_token" "changeTransferPolicyId(uint64)" "$policy_id" >/dev/null

authorized=$(scalar "$TIP403_REGISTRY" "isAuthorizedRecipient(uint64,address)(bool)" \
  "$policy_id" "$TIP_FEE_MANAGER")
assert_eq "false" "$authorized" "FeeManager must be blacklisted for this test"

balance_before=$(scalar "$fee_token" "balanceOf(address)(uint256)" "$admin")
recipient=$(cast wallet new --json | jq -er '.[0].address')
hash=$(send_ok "$PATH_USD" "transfer(address,uint256)(bool)" "$recipient" 1)
balance_after=$(scalar "$fee_token" "balanceOf(address)(uint256)" "$admin")
if (( balance_after >= balance_before )); then
  echo "FAIL: fee-token balance did not decrease ($balance_before -> $balance_after)" >&2
  exit 1
fi

print_pass "TIP-1042 paid transaction $hash with $fee_token while FeeManager was blacklisted"
