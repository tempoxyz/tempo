# Zone portal benchmark

Run `bench-txgen.nu run --preset zones --accounts 1`. The default mix uses equal
weights for deposits and withdrawals. Set `TXGEN_ZONE_MODE=deposit` or `withdraw`
to measure either path alone. Requires `uv`, chain ID 1337, and the shared Zone
runtimes (T10 or later).

Setup deploys one portal with the production ERC-1167 proxy runtime and a local
settlement fixture. Each workload transaction uses Tempo multicalls:

- **Deposit:** call `deposit` with an encrypted recipient, then submit a batch
  advancing the processed-deposit cursor.
- **Withdrawal:** submit a batch committing one withdrawal, then call
  `processWithdrawals` with that item and an empty remaining queue.

Both paths call the production portal implementation. Settlement reads the
current cursors and advances the zone height, so workloads can continue beyond
210 deposits without rotating portals or pre-seeding withdrawal queues. Ordinary
txgen templates use the account's protocol nonce ordering; no sequence or stream
filter is needed. The sender TPS and duration control the run.

The settlement fixture is also a **dummy verifier that always returns true**.
The portal has a zero attestation threshold; the settlement fixture and workload
account have sequencer roles. This benchmarks portal execution and settlement
bookkeeping, including the helper's calls, but excludes zone execution, proof
generation, proof verification, and signature verification. No running zone is
needed. These constructor-seeded fixtures are restricted to chain 1337 and must
never hold real funds.

Each operation transfers one pathUSD base unit. Setup funds withdrawal escrow
for the requested transaction count and approves deposits. Fees and bounce-back
reserves are zero; withdrawals have no callbacks. The existing renderer only
prepares fixture arguments and a deterministic encrypted payload bound to the
predicted portal and sender. All keys are public test material. The portal's
per-block deposit cap still applies; start at 100 TPS. Withdrawal success is
reported by `WithdrawalProcessed(success=true)`, not merely receipt status.

## Rebuild

The artifacts use solc 0.8.30, optimizer 200 runs, Cancun EVM:

```sh
zone_tools=$(mktemp -d)
npm install --prefix "$zone_tools" solc@0.8.30
NODE_PATH="$zone_tools/node_modules" node contrib/bench/txgen/zones/build.cjs
```

Keep fixture storage aligned with `crates/precompiles/src/zone_factory/portal.rs`.
The submitter supports both settlement ABIs, before and after TIP-1096.
