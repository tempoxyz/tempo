#!/bin/bash

# Deploy the shared Zone runtimes (ZonePortal implementation, verifier, messenger) without the
# native ZoneFactory. Needs only a private key and an RPC URL.
#
#   PRIVATE_KEY=0x... ./scripts/deploy-zone-runtimes.sh
#   PRIVATE_KEY=0x... ETH_RPC_URL=https://rpc.moderato.tempo.xyz ./scripts/deploy-zone-runtimes.sh
#
# The runtimes land at CREATE-derived addresses, not the canonical protocol addresses that the T10
# hardfork etches — an EOA cannot write to those. Creating a usable zone still requires the native
# factory; the portal implementation rejects `initialize` from any other caller.

set -e

if [ -z "$PRIVATE_KEY" ]; then
  echo "PRIVATE_KEY must be set (hex encoded, funded on the target chain)" >&2
  exit 1
fi

# Use existing ETH_RPC_URL or default to localhost
if [ -z "$ETH_RPC_URL" ]; then
  export ETH_RPC_URL="http://localhost:8545"
fi

exec cargo run --quiet -p tempo-xtask -- deploy-zone-runtimes \
  --rpc-url "$ETH_RPC_URL" \
  --private-key "$PRIVATE_KEY" \
  "$@"
