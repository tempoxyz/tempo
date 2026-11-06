#!/bin/sh
# Runs one zone node from the files provision.sh wrote: "0", "1" or "2" for a quorum
# sequencer, "rpc" for the RPC follower that runs the native prover and the checker.
# Restarts reuse the same datadir.
set -eu

S=/shared
NODE=$1
L1_WS=ws://10.20.0.10:8546

case "$NODE" in
    0)
        ROLE_ARGS="--secp256k1.key $S/seq-0.key --sequencer-key-file $S/seq-0.key"
        P2P_KEY=$S/p2p-0.key
        ;;
    1 | 2)
        ROLE_ARGS="--secp256k1.key $S/seq-$NODE.key --sequencer-key-file $S/seq-$NODE.key --deposit-decryption-keys-file $S/decryption.keys"
        P2P_KEY=$S/p2p-$NODE.key
        ;;
    rpc)
        # Without --sequencer.prover-address the shadow prover runs the native prover in-process.
        ROLE_ARGS="--sequencer.enable-prover --checker.mode observe"
        P2P_KEY=$S/p2p-rpc.key
        ;;
    *)
        # Finalized samples can trail the tip; permit bounded historical proof generation.
    ENGINE_ARGS="$ENGINE_ARGS --rpc.eth-proof-window 10000"
    echo "zone-node: unknown node $NODE" >&2
        exit 1
        ;;
esac

# Profiles change execution only; every node still shares the provisioned chain and manifest.
ENGINE_ARGS=""
if [ "${ENGINE_DIFF:-0}" = 1 ]; then
    case "$NODE" in
        0) ENGINE_ARGS="--engine.state-root-task-compare-updates" ;;
        1) ENGINE_ARGS="--engine.state-root-fallback --engine.disable-prewarming --engine.disable-precompile-cache --engine.disable-state-cache --engine.num-state-masking-blocks 0" ;;
        2) ENGINE_ARGS="--engine.state-root-task-compare-updates --engine.disable-state-cache" ;;
        rpc) ENGINE_ARGS="--engine.state-root-task-timeout 1ms" ;;
    esac
    # Finalized samples can trail the tip; permit bounded historical proof generation.
    ENGINE_ARGS="$ENGINE_ARGS --rpc.eth-proof-window 10000"
    echo "zone-node: node=$NODE engine-diff=1 flags=$ENGINE_ARGS" >&2
fi

# shellcheck disable=SC2086
exec /usr/local/bin/tempo-zone node \
    --chain "$S/genesis.json" \
    --l1.rpc-url "$L1_WS" \
    --datadir /data/node \
    --http --http.addr 0.0.0.0 --http.port 8545 --http.api all \
    --ws --ws.addr 0.0.0.0 --ws.port 8546 --ws.api all \
    --redacted-rpc.port 8544 \
    --sequencer.manifest "$S/manifest.toml" \
    --p2p.key "$P2P_KEY" \
    --p2p.listen 0.0.0.0:9200 \
    --zone.batch-interval-blocks 20 \
    --disable-discovery \
    --ipcdisable \
    --color never \
    $ROLE_ARGS $ENGINE_ARGS
