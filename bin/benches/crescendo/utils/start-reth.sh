rm -rf /home/ubuntu/.local/share/reth/

ulimit -n 1000000

reth node --http --http.addr 0.0.0.0 \
--http.port 8545 --http.api all \
--dev --dev.block-time 1s \
--engine.disable-precompile-cache \
--builder.gaslimit 3000000000 \
--builder.max-tasks 8 \
--builder.deadline 1 \
--txpool.pending-max-count 10000000000000 \
--txpool.basefee-max-count 10000000000000 \
--txpool.queued-max-count 10000000000000 \
--txpool.pending-max-size 10000 \
--txpool.basefee-max-size 10000 \
--txpool.queued-max-size 10000 \
--txpool.max-new-pending-txs-notifications 10000000 \
--txpool.max-account-slots 500000 \
--txpool.max-pending-txns 10000000000000 \
--txpool.max-new-txns 10000000000000 \
--txpool.disable-transactions-backup \
--txpool.additional-validation-tasks 8 \
--txpool.minimal-protocol-fee 0 \
--txpool.minimum-priority-fee 0 \
--rpc.max-connections 429496729 \
--rpc.max-request-size 1000000 \
--rpc.max-response-size 1000000 \
--max-tx-reqs 1000000 \
--chain utils/genesis.json
