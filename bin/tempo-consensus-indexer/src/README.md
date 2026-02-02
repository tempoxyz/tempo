# tempo-consensus-indexer

Indexes consensus certificates into sqlite and exposes a local consensus RPC surface.

## Usage

```bash
cargo run -p tempo-consensus-indexer -- \
  --db-url sqlite://consensus-indexer.db \
  --upstream-ws-url ws://moderato-stable-rpc-service:8546 \
  --upstream-http-url http://moderato-stable-rpc-service:8545 \
  --http-listen 0.0.0.0:8545 \
  --ws-listen 0.0.0.0:8546
```

On startup the indexer will detect missing finalized heights and fill gaps
up to the latest finalized block.
