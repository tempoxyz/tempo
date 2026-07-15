#!/usr/bin/env bash

set -euo pipefail
source "$(dirname "$0")/common.sh"
require_tools
require_env RPC_URL PRIVATE_KEY
require_t8

admin=$(account_address)
fund_address "$admin"
token=$(create_tip20 "rewards" "$admin")
recipient=$(cast wallet new --json | jq -er '.[0].address')

send_ok "$token" "mint(address,uint256)" "$admin" 1000000000 >/dev/null

snapshot() {
  jq -nc \
    --arg opted "$(call "$token" "optedInSupply()(uint128)")" \
    --arg global "$(call "$token" "globalRewardPerToken()(uint256)")" \
    --arg info "$(call "$token" "userRewardInfo(address)((address,uint256,uint256))" "$admin")" \
    '{optedInSupply:$opted,globalRewardPerToken:$global,userRewardInfo:$info}'
}

before=$(snapshot)
send_ok "$token" "setRewardRecipient(address)" "$recipient" >/dev/null
send_ok "$token" "distributeReward(uint256)" 1000000 >/dev/null
send_ok "$token" "transfer(address,uint256)(bool)" "$recipient" 1 >/dev/null
send_ok "$token" "mint(address,uint256)" "$admin" 1 >/dev/null
send_ok "$token" "burn(uint256)" 1 >/dev/null
after_paths=$(snapshot)
assert_eq "$before" "$after_paths" "T8 reward state changed through deprecated or balance paths"

claimed=$(scalar "$token" "claimRewards()(uint256)" --from "$admin")
assert_eq "0" "$claimed" "fresh T8 account unexpectedly has claimable rewards"
send_ok "$token" "claimRewards()(uint256)" >/dev/null
after_claim=$(snapshot)
assert_eq "$before" "$after_claim" "claimRewards mutated fresh T8 reward state"

print_pass "TIP-1075 reward APIs and transfer/mint/burn paths left reward state unchanged"
