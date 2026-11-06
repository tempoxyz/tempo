#!/bin/sh
# Real validators and a certified RPC follower; every container retains its own /data.
set -eu
NODE=${1:?expected validator index 0..3 or rpc}
NET=/opt/zones/l1
PEERS=
for octet in 41 42 43 44; do
    identity=$(cat "$NET/10.20.0.$octet:8000/enode.identity")
    PEERS="${PEERS}${PEERS:+,}enode://$identity@10.20.0.$octet:8001"
done

# Explicit masking + buffer < threshold on every profile, including the simple path.
case "$NODE" in
    0) ENGINE_ARGS="--engine.persistence-threshold 2 --engine.num-state-masking-blocks 0 --engine.state-root-fallback --engine.disable-prewarming --engine.disable-precompile-cache --engine.disable-state-cache" ;;
    1) ENGINE_ARGS="--engine.persistence-threshold 3 --engine.num-state-masking-blocks 1 --engine.state-root-task-compare-updates" ;;
    2) ENGINE_ARGS="--engine.persistence-threshold 5 --engine.num-state-masking-blocks 2 --engine.state-root-task-timeout 1ms" ;;
    3) ENGINE_ARGS="--engine.persistence-threshold 8 --engine.num-state-masking-blocks 3 --engine.state-root-task-compare-updates --engine.disable-state-cache" ;;
    rpc) ENGINE_ARGS="--engine.persistence-threshold 3 --engine.num-state-masking-blocks 1 --engine.state-root-task-compare-updates" ;;
    *) echo "l1-node: unknown node $NODE" >&2; exit 1 ;;
esac
set -- node --chain "$NET/l1-genesis.json" --datadir /data/node \
    --http --http.addr 0.0.0.0 --http.port 8545 --http.api all \
    --ws --ws.addr 0.0.0.0 --ws.port 8546 --ws.api all \
    --rpc.eth-proof-window 100000 --trusted-peers "$PEERS" \
    --consensus.listen-address 0.0.0.0:8000 \
    --consensus.metrics-address 0.0.0.0:8002 --consensus.allow-private-ips \
    --port 8001 --authrpc.port 8003 \
    --tempo.bootnodes-endpoint none --disable-discovery --no-persist-peers \
    --ipcdisable --color never --engine.memory-block-buffer-target 0
if [ "$NODE" = rpc ]; then
    # No --follow.nocertify: verify consensus certificates, not just execution payloads.
    set -- "$@" --follow ws://10.20.0.41:8546
else
    KEY_DIR="$NET/10.20.0.$((41 + NODE)):8000"
    set -- "$@" --consensus.signing-key "$KEY_DIR/signing.key" \
        --consensus.secret "$NET/signing.secret" \
        --consensus.signing-share "$KEY_DIR/signing.share" \
        --p2p-secret-key "$KEY_DIR/enode.key"
fi
echo "l1-node: node=$NODE flags=$ENGINE_ARGS" >&2
# shellcheck disable=SC2086
exec /usr/local/bin/tempo "$@" $ENGINE_ARGS
