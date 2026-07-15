#!/usr/bin/env bash

set -euo pipefail
source "$(dirname "$0")/common.sh"
require_tools
require_env RPC_URL PRIVATE_KEY

mode=${1:-post-only}
state_file=${T8_DEX_STATE_FILE:-.t8-dex-state.json}
admin=$(account_address)

if [[ "$mode" != "setup" ]]; then
  require_t8
fi

place_order() {
  local token="$1" order_id hash gas order
  order_id=$(scalar "$STABLECOIN_DEX" "nextOrderId()(uint128)")
  hash=$(send_ok "$STABLECOIN_DEX" "place(address,uint128,bool,int16)(uint128)" \
    "$token" "$(scalar "$STABLECOIN_DEX" "MIN_ORDER_AMOUNT()(uint128)")" false 0)
  gas=$(gas_used_decimal "$hash")
  order=$(call "$STABLECOIN_DEX" \
    "getOrder(uint128)((uint128,address,bytes32,bool,int16,uint128,uint128,uint128,uint128,bool,int16))" \
    "$order_id")
  [[ -n "$order" ]] || { echo "FAIL: order $order_id is not readable" >&2; exit 1; }
  printf '%s %s %s\n' "$order_id" "$hash" "$gas"
}

setup_pair() {
  local token key
  fund_address "$admin"
  token=$(create_tip20 "dex" "$admin")
  send_ok "$token" "mint(address,uint256)" "$admin" 1000000000000 >/dev/null
  send_ok "$token" "approve(address,uint256)(bool)" "$STABLECOIN_DEX" \
    0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff >/dev/null
  key=$(call "$STABLECOIN_DEX" "pairKey(address,address)(bytes32)" "$token" "$PATH_USD")
  send_ok "$STABLECOIN_DEX" "createPair(address)(bytes32)" "$token" >/dev/null
  printf '%s %s\n' "$token" "$key"
}

find_book_index() {
  local wanted="${1,,}" max=${BOOK_INDEX_SCAN_LIMIT:-10000} i key
  for ((i=0; i<max; i++)); do
    if ! key=$(call "$STABLECOIN_DEX" "bookKeyForIndex(uint32)(bytes32)" "$i" 2>/dev/null); then
      break
    fi
    if [[ "${key,,}" == "$wanted" ]]; then echo "$i"; return 0; fi
  done
  echo "book key $1 not found within first $max entries" >&2
  return 1
}

case "$mode" in
  setup)
    read -r token key < <(setup_pair)
    read -r order_id hash gas < <(place_order "$token")
    jq -n --arg token "$token" --arg bookKey "$key" --arg orderId "$order_id" \
      --arg txHash "$hash" --argjson gas "$gas" \
      '{token:$token,bookKey:$bookKey,legacyOrderId:$orderId,legacyTxHash:$txHash,legacyGas:$gas}' \
      >"$state_file"
    chmod 600 "$state_file"
    print_pass "TIP-1062 pre-fork fixture saved to $state_file (order $order_id, gas $gas)"
    ;;
  verify)
    [[ -f "$state_file" ]] || { echo "missing setup state: $state_file" >&2; exit 2; }
    token=$(jq -er '.token' "$state_file")
    key=$(jq -er '.bookKey' "$state_file")
    legacy_order=$(jq -er '.legacyOrderId' "$state_file")
    legacy_gas=$(jq -er '.legacyGas' "$state_file")
    call "$STABLECOIN_DEX" \
      "getOrder(uint128)((uint128,address,bytes32,bool,int16,uint128,uint128,uint128,uint128,bool,int16))" \
      "$legacy_order" >/dev/null
    index=$(find_book_index "$key")
    send_ok "$STABLECOIN_DEX" "setBookIndex(uint32)" "$index" >/dev/null
    indexed=$(call "$STABLECOIN_DEX" "bookIndexForKey(bytes32)(bool,uint32)" "$key" --json)
    assert_eq "true" "$(jq -er '.[0]' <<<"$indexed")" "orderbook index was not persisted"
    read -r v2_order hash v2_gas < <(place_order "$token")
    send_ok "$STABLECOIN_DEX" "cancel(uint128)" "$legacy_order" >/dev/null
    if (( v2_gas >= legacy_gas )); then
      echo "FAIL: indexed V2 placement did not reduce gas ($legacy_gas -> $v2_gas)" >&2
      exit 1
    fi
    print_pass "TIP-1062/1087 migrated legacy order $legacy_order, placed indexed V2 order $v2_order, gas $legacy_gas -> $v2_gas"
    ;;
  post-only)
    read -r token key < <(setup_pair)
    indexed=$(call "$STABLECOIN_DEX" "bookIndexForKey(bytes32)(bool,uint32)" "$key" --json)
    assert_eq "true" "$(jq -er '.[0]' <<<"$indexed")" "new T8 orderbook has no saved index"
    index=$(jq -er '.[1]' <<<"$indexed")
    resolved=$(call "$STABLECOIN_DEX" "bookKeyForIndex(uint32)(bytes32)" "$index")
    assert_eq "$key" "$resolved" "saved index resolves to the wrong orderbook"
    read -r order_id hash gas < <(place_order "$token")
    send_ok "$STABLECOIN_DEX" "cancel(uint128)" "$order_id" >/dev/null
    print_pass "TIP-1062/1087 placed and cancelled indexed V2-eligible order $order_id (gas $gas)"
    ;;
  *)
    echo "usage: $0 setup|verify|post-only" >&2
    exit 2
    ;;
esac
