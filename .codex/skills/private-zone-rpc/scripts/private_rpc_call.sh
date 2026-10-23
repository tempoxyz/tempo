#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage:
  PRIVATE_KEY=0x... private_rpc_call.sh RPC_URL ZONE_ID CHAIN_ID METHOD [PARAMS_JSON]

Examples:
  PRIVATE_KEY=0x... private_rpc_call.sh \
    https://private-zone-rpc.example.com \
    71 \
    421700071 \
    web3_clientVersion

  PRIVATE_KEY=0x... private_rpc_call.sh \
    https://private-zone-rpc.example.com \
    71 \
    421700071 \
    eth_getBalance \
    '["0x0000000000000000000000000000000000000000","latest"]'
EOF
}

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
  usage
  exit 0
fi

if [[ $# -lt 4 || $# -gt 5 ]]; then
  usage >&2
  exit 2
fi

rpc_url="$1"
zone_id="$2"
chain_id="$3"
method="$4"
params="${5:-[]}"
private_key="${PRIVATE_KEY:-}"

if [[ -z "$private_key" ]]; then
  echo "PRIVATE_KEY is required" >&2
  exit 2
fi
if ! command -v cast >/dev/null 2>&1; then
  echo "cast is required" >&2
  exit 127
fi
if ! command -v curl >/dev/null 2>&1; then
  echo "curl is required" >&2
  exit 127
fi

now=$(date +%s)
expires=$((now + 600))
magic="54656d706f5a6f6e655250430000000000000000000000000000000000000000"
fields="00$(printf '%08x' "$zone_id")$(printf '%016x' "$chain_id")$(printf '%016x' "$now")$(printf '%016x' "$expires")"
digest=$(cast keccak "0x${magic}${fields}")
signature=$(cast wallet sign --no-hash "$digest" --private-key "$private_key")
token="${signature#0x}${fields}"
payload=$(printf '{"jsonrpc":"2.0","method":"%s","params":%s,"id":1}' "$method" "$params")

body=$(mktemp)
trap 'rm -f "$body"' EXIT

status=$(curl -sS -o "$body" -w '%{http_code}' \
  -H 'Content-Type: application/json' \
  -H "X-Authorization-Token: ${token}" \
  --data "$payload" \
  "$rpc_url")

cat "$body"
if [[ "$status" != 2* ]]; then
  printf '\nHTTP %s\n' "$status" >&2
  exit 1
fi
