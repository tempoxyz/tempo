---
name: run-zone-dev
description: Run and validate `tempo-zone dev` against either Anvil in Tempo mode or a native Tempo dev L1. Use when starting local Zone development, comparing Anvil and Tempo behavior, checking provisioning and L1 sync, confirming batch submission, or debugging dev-mode RPC, funding, header, port, datadir, and process issues in this repository.
---

# Run Zone Dev

Use release builds and isolated datadirs and ports. Keep every started process handle and stop only those processes during cleanup. Set the variables shown below in the shell where the zone runs so validation reuses the selected configuration.

## Prepare

1. Build the binary:

   ```bash
   cargo build --release --bin tempo-zone
   ```

2. Choose unused L1, zone HTTP, and private RPC ports. The zone WebSocket and P2P ports are `HTTP + 1` and `HTTP + 2`.
3. Use a fresh or previously generated dev datadir. `tempo-zone dev` refuses to wipe a non-empty directory without `zone.json`.

## Run with Anvil

Require Foundry 1.8 or newer, or a nightly build from July 11, 2026 or later. When testing a Foundry branch or PR, run the binary from that checkout and confirm the commit SHA from `anvil --version` matches the selected revision; do not rely on the binary on `PATH` as evidence.

Start Anvil in Tempo mode:

```bash
anvil --version
anvil --network tempo --block-time 1 --host 127.0.0.1 --port 8545
```

In a second terminal, configure the zone:

```bash
export L1_HTTP_URL=http://127.0.0.1:8545
export L1_RPC_URL=ws://127.0.0.1:8545
export ZONE_DATADIR=/tmp/tempo-zone-dev-anvil
export ZONE_HTTP_PORT=9545
export ZONE_PRIVATE_RPC_PORT=8544
```

The default dev key already has pathUSD. When using another key, fund that same key before provisioning starts:

```bash
export DEV_KEY=0x...
export DEV_ADDRESS="$(cast wallet address "$DEV_KEY")"
cast rpc --rpc-url "$L1_HTTP_URL" \
  anvil_dealTIP20 \
  "$DEV_ADDRESS" \
  0x20C0000000000000000000000000000000000000 \
  1000000000
```

`DEV_KEY` is also the environment variable for `--dev.key`, so the zone uses the funded account. Start it after any required funding:

```bash
target/release/tempo-zone dev \
  --l1.rpc-url "$L1_RPC_URL" \
  --datadir "$ZONE_DATADIR" \
  --http.port "$ZONE_HTTP_PORT" \
  --private-rpc.port "$ZONE_PRIVATE_RPC_PORT"
```

`tempo_fundAddress` is absent on Anvil. `anvil_dealTIP20` sets the account balance directly without changing total supply.

Anvil may log one RPC deserialization error when the zone probes the unsupported `tempo_fundAddress` method. This is expected when the selected dev account is already funded; repeating funding or transaction errors are not.

The default batch interval is 120 zone blocks, which takes about two minutes with one-second Anvil blocks. For a faster smoke test, append `-- --zone.batch-interval-blocks 10` to the `tempo-zone dev` command.

## Run with a native Tempo dev L1

Prefer an existing Tempo dev endpoint when one is available:

```bash
export L1_RPC_URL=ws://127.0.0.1:8546
export ZONE_DATADIR=/tmp/tempo-zone-dev-native
export ZONE_HTTP_PORT=9545
export ZONE_PRIVATE_RPC_PORT=8544
cast rpc --rpc-url "$L1_RPC_URL" web3_clientVersion
target/release/tempo-zone dev \
  --l1.rpc-url "$L1_RPC_URL" \
  --datadir "$ZONE_DATADIR" \
  --http.port "$ZONE_HTTP_PORT" \
  --private-rpc.port "$ZONE_PRIVATE_RPC_PORT"
```

When starting Tempo itself, require a valid Tempo L1 genesis and make the HTTP and WebSocket ports explicit:

```bash
tempo node \
  --chain "$TEMPO_GENESIS" \
  --dev \
  --dev.block-time 1sec \
  --http --http.addr 127.0.0.1 --http.port 8545 --http.api all \
  --ws --ws.addr 127.0.0.1 --ws.port 8546 --ws.api all \
  --datadir /tmp/tempo-dev-l1
```

If no external Tempo genesis is available, validate the native path with the repository's real-L1 integration test:

```bash
cargo test -p zone-node --features cli --test it \
  test_dev_provisioner_replays_initial_token_event -- --nocapture
```

## Validate

1. Read the generated metadata from the datadir selected above and derive the actual zone RPC URL:

   ```bash
   jq . "$ZONE_DATADIR/zone.json"
   export ZONE_RPC_URL="$(jq -r .rpcUrl "$ZONE_DATADIR/zone.json")"
   ```

2. Confirm the zone advances and pathUSD exists:

   ```bash
   cast block-number --rpc-url "$ZONE_RPC_URL"
   cast code 0x20C0000000000000000000000000000000000000 \
     --rpc-url "$ZONE_RPC_URL"
   ```

3. Inspect the latest zone log. A one-time `enabledTokenCount` warning at the pre-creation anchor is expected because the portal is created in the next L1 block. Require that creation block to be replayed with `enabled_tokens=1`, followed by continued L1 ingestion and no repeating errors.

4. For a full smoke test, wait for both `Submitting batch` and `Batch submitted to L1`. Copy the reported transaction hash and require a successful L1 receipt:

   ```bash
   cast receipt "$TX_HASH" --rpc-url "$L1_RPC_URL" --json \
     | jq -e '.status == "0x1"'
   ```

## Diagnose

- Provisioning before funding receipts settle indicates a regression in `fund_dev_account`.
- A missing custom initial token indicates the genesis anchor skipped the `createZone` block and its `TokenEnabled` event.
- A `canonical Tempo header hash` error means the L1 reports a different block hash from `keccak256(rlp(TempoHeader))`. Upgrade Foundry first; never rewrite header parents in the Zone subscriber.
- If the node appears stalled, compare the L1 tip, the zone's Tempo block number, and the latest subscriber log before restarting.

## Clean up

Send `SIGINT` to the exact zone and L1 process handles started for the run. Wait for them to exit. Never use broad `pkill` commands, and never remove a datadir outside the explicitly selected `/tmp/tempo-zone-dev-*` path.
