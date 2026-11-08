#!/bin/sh
# Runs one zone node from the files provision.sh wrote: "0", "1" or "2" for a quorum
# sequencer, "rpc" for the RPC follower that runs the native prover and the checker.
# Restarts reuse the same datadir.
#
# Each node computes state roots on a different engine path, so a trie bug on one path shows up
# as nodes disagreeing on a block instead of every node agreeing on the same wrong root:
# zone-0 and zone-rpc use the default sparse-trie task, zone-1 the synchronous fallback over the
# database trie, zone-2 the serial sparse trie. Sequencers also persist at different depths, so
# roots and proofs are computed over different splits of in-memory and database trie state:
# zone-0 keeps its whole sparse trie between blocks and batches more proof targets per
# multiproof and persists often with little state masking, zone-1 persists every block without
# masking, zone-2 keeps up to 64 blocks in memory and masks most of each persisted batch. Nodes
# running the sparse-trie task also compare its trie updates with a serial computation, which
# trie-oracle.sh reports. reth only runs the sparse-trie task with at least 5 CPUs and Antithesis
# containers report fewer, so those nodes claim 8 with --cpu-cores; zone-1 stays synchronous.
# Sequencers zone-0 and zone-2 also build their payloads' state roots on the shared sparse trie.
# Sparse-trie nodes keep their whole trie between blocks, so later proofs target known parents,
# and split proof targets into multiproofs of 64 (zone-0), 1 (zone-2) and 16 (zone-rpc).
set -eu

S=/shared
NODE=$1
L1_WS=ws://10.20.0.10:8546

case "$NODE" in
    0)
        ROLE_ARGS="--secp256k1.key $S/seq-0.key --sequencer-key-file $S/seq-0.key"
        ROLE_ARGS="$ROLE_ARGS --cpu-cores 8 --engine.share-sparse-trie-with-payload-builder --engine.disable-sparse-trie-cache-pruning --engine.multiproof-chunk-size 64 --engine.state-root-task-compare-updates --engine.persistence-threshold 8 --engine.num-state-masking-blocks 2 --engine.memory-block-buffer-target 2"
        P2P_KEY=$S/p2p-0.key
        ;;
    1 | 2)
        ROLE_ARGS="--secp256k1.key $S/seq-$NODE.key --sequencer-key-file $S/seq-$NODE.key --deposit-decryption-keys-file $S/decryption.keys"
        P2P_KEY=$S/p2p-$NODE.key
        if [ "$NODE" = 1 ]; then
            ROLE_ARGS="$ROLE_ARGS --engine.state-root-fallback --engine.persistence-threshold 0"
        else
            ROLE_ARGS="$ROLE_ARGS --cpu-cores 8 --engine.share-sparse-trie-with-payload-builder --engine.disable-sparse-trie-cache-pruning --engine.multiproof-chunk-size 1 --engine.disable-parallel-sparse-trie --engine.state-root-task-compare-updates --engine.persistence-threshold 64 --engine.num-state-masking-blocks 48 --engine.memory-block-buffer-target 8"
        fi
        ;;
    rpc)
        # Without --sequencer.prover-address the shadow prover runs the native prover in-process.
        ROLE_ARGS="--sequencer.enable-prover --checker.mode observe --cpu-cores 8 --engine.disable-sparse-trie-cache-pruning --engine.multiproof-chunk-size 16 --engine.state-root-task-compare-updates"
        P2P_KEY=$S/p2p-rpc.key
        ;;
    *)
        echo "zone-node: unknown node $NODE" >&2
        exit 1
        ;;
esac

# The node logs through trie-oracle.sh, which reports reth's trie self-checks as assertions. A FIFO
# keeps tempo-zone as the process that receives signals.
LOG_FIFO=/tmp/zone-node.log.fifo
rm -f "$LOG_FIFO"
mkfifo "$LOG_FIFO"
/opt/zones/trie-oracle.sh "$NODE" < "$LOG_FIFO" &
exec > "$LOG_FIFO" 2>&1

# shellcheck disable=SC2086
exec /usr/local/bin/tempo-zone node \
    --chain "$S/genesis.json" \
    --l1.rpc-url "$L1_WS" \
    --datadir /data/node \
    --http --http.addr 0.0.0.0 --http.port 8545 --http.api all \
    --rpc.eth-proof-window 100000 \
    --ws --ws.addr 0.0.0.0 --ws.port 8546 --ws.api all \
    --redacted-rpc.port 8544 \
    --sequencer.manifest "$S/manifest.toml" \
    --p2p.key "$P2P_KEY" \
    --p2p.listen 0.0.0.0:9200 \
    --zone.batch-interval-blocks 20 \
    --disable-discovery \
    --ipcdisable \
    --color never \
    --log.stdout.filter info,engine::tree::state_root_strategy=debug \
    $ROLE_ARGS
