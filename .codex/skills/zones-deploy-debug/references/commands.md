# Zone Commands

## Release-first smoke test

```bash
cargo build --bin tempo-zone --release
```

Create a fresh zone when you need a clean router test:

```bash
just deploy-zone my-zone
```

That recipe creates the zone, stores `sequencerKey` and `adminKey` in `generated/my-zone/zone.json`, and starts the node immediately. If you need tighter control, run:

```bash
target/debug/tempo-xtask create-zone --output generated/my-zone --l1-rpc-url "$HTTP_RPC" --sequencer "$SEQUENCER_ADDR" --private-key "$SEQUENCER_KEY"
target/debug/tempo-xtask set-encryption-key --l1-rpc-url "$HTTP_RPC" --portal "$PORTAL" --private-key "$SEQUENCER_KEY"
```

`deploy-zone` also stores `adminKey` and `adminAddress` using the generated sequencer key, because that convenience flow creates zones with `admin == sequencer`. For manual `create-zone` flows, pass `--admin "$ADMIN_ADDR"` when separating the cold admin role from the hot sequencer role, and keep the matching `ADMIN_KEY` available for admin-only portal calls.

## Start a zone in release

```bash
RUST_LOG=warn just zone-up my-zone false release
```

The `zone-up` recipe starts `tempo-zone` with both `--sequencer` and
`--sequencer-key`; block production will not advance with the key alone.

Health check:

```bash
cast block-number --rpc-url http://localhost:8546
```

Read deployment metadata:

```bash
jq '{zoneId, portal, tempoAnchorBlock, zoneFactory, swapAndDepositRouter, admin, sequencer, adminAddress, sequencerAddress}' generated/my-zone/zone.json
```

## Direct deposit + withdrawal validation

Set the active portal first:

```bash
export L1_PORTAL_ADDRESS="$(jq -r '.portal' generated/my-zone/zone.json)"
```

Approve the L1 portal before depositing:

```bash
just max-approve-portal
```

Send a deposit to the zone:

```bash
just send-deposit 1000000
```

Approve the L2 outbox before withdrawing:

```bash
just max-approve-outbox
```

Request a withdrawal back to L1:

```bash
just send-withdrawal 400000
```

`just send-withdrawal` only waits for L1 finalization if both `L1_RPC_URL` and `L1_PORTAL_ADDRESS` are set.

## Router validation flow

Deploy the router:

```bash
just deploy-router my-zone
```

Run the demo with defaults:

```bash
just demo-swap-and-deposit my-zone
```

If you need overrides, pass them positionally because the current recipe treats them as positional args:

```bash
just demo-swap-and-deposit my-zone 100000000 0 http://localhost:8546
```

Direct xtask equivalent:

```bash
target/debug/tempo-xtask demo-swap-and-deposit \
  --zone-dir generated/my-zone \
  --l1-rpc-url "$HTTP_RPC" \
  --zone-rpc-url http://localhost:8546 \
  --private-key "$PRIVATE_KEY" \
  --amount 100000000 \
  --tick 0
```

## Sync debugging

Tail the zone log:

```bash
tail -f /tmp/tempo-zone-my-zone*/logs/*/reth.log
```

Useful patterns:

```bash
rg -n "Prepared L1 block deposits|Including advanceTempo|TokenEnabled|DepositProcessed|WithdrawalProcessed" /tmp/tempo-zone-my-zone*/logs/*/reth.log
```

When `demo-swap-and-deposit` stalls at token enablement:

1. Get the L1 tx block for the `enableToken` tx:

```bash
cast receipt <tx-hash> --rpc-url "$HTTP_RPC"
```

2. Compare it with the latest processed L1 block in the log:

```bash
tail -n 200 /tmp/tempo-zone-my-zone*/logs/*/reth.log | rg "Prepared L1 block deposits|Including advanceTempo"
```

If the zone is still behind the tx block, wait longer or rerun the test with a `release` node.

## Known failure modes

- `swapAndDepositRouter not found`: run `just deploy-router <name>` or pass `--router`.
- `resolved admin ... is not the portal admin`: set `ADMIN_KEY` for the portal's on-chain admin, or use the saved `adminKey` from a `deploy-zone` zone. `SEQUENCER_KEY` only works when `admin == sequencer`.
- Missing sequencer key: read `sequencerKey` from `generated/<name>/zone.json` or set `SEQUENCER_KEY`.
- Timeout waiting for `TokenEnabled`: the zone is usually still catching up.
- Restart crash with `failed to seed transferPolicyId ... Uninitialized`: inspect `crates/tempo-zone/src/l1_state/tip403/cache.rs` and prefer a fresh zone for smoke tests involving temporary tokens.
