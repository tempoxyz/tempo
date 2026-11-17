#!/bin/bash
set -euo pipefail
ip="${1:?node IP required}"
role="${2:-validator}"
case "$role" in
    validator)
        keys="/opt/tempo-cluster/genesis/$ip:8000"
        mode=(--consensus.signing-key "$keys/signing.key"
              --consensus.signing-share "$keys/signing.share"
              --p2p-secret-key "$keys/enode.key")
        ;;
    follower)
        # A separate disposable EL identity; never reuse a validator's consensus keys.
        mkdir -p /data
        if [[ ! -e /data/follower-enode.key ]]; then
            printf '%064x' 5 > /data/follower-enode.key
        fi
        mode=(--follow ws://validator-0:8546 --p2p-secret-key /data/follower-enode.key)
        ;;
    *) echo "Unknown node role: $role" >&2; exit 1 ;;
esac
peers=()
for peer in /opt/tempo-cluster/genesis/*:8000; do
    peers+=("enode://$(cat "$peer/enode.identity")@$(basename "$peer" | cut -d: -f1):8001")
done
trusted=$(IFS=,; echo "${peers[*]}")
# Both execution DB and consensus journal stay in this volume. Never reinitialize on restart.
exec tempo node --chain /opt/tempo-cluster/genesis/genesis.json --datadir /data \
    "${mode[@]}" \
    --consensus.listen-address "$ip:8000" --consensus.metrics-address "$ip:8002" \
    --consensus.use-local-defaults --consensus.bypass-ip-check \
    --trusted-peers "$trusted" \
    --port 8001 --discovery.port 8001 --discovery.v5.port 8004 --authrpc.port 8003 \
    --http --http.addr 0.0.0.0 --http.port 8545 --http.api all \
    --ws --ws.addr 0.0.0.0 --ws.port 8546 --ws.api all --ws.origins '*' \
    --http.corsdomain '*' --rpc.eth-proof-window 1000 \
    --tempo.bootnodes-endpoint none --disable-discovery --no-persist-peers \
    --engine.persistence-threshold 0 --engine.memory-block-buffer-target 0 \
    --faucet.enabled \
    --faucet.private-key 0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80 \
    --faucet.amount 1000000000000 \
    --faucet.address 0x20c0000000000000000000000000000000000000 \
    0x20c0000000000000000000000000000000000001 \
    0x20c0000000000000000000000000000000000002 \
    0x20c0000000000000000000000000000000000003 \
    --color never
