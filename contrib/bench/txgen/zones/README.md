# Zone portal benchmark

Run `bench-txgen.nu run --preset zones --accounts 1000 --tps 10000`. The default mix uses equal
weights for deposits and withdrawals. Set `TXGEN_ZONE_MODE=deposit` or `withdraw`
to measure either path alone. Requires chain ID 1337 and the shared Zone
runtimes (T10 or later).

`--accounts` controls users independently of portals. Setup deploys portals with
the production ERC-1167 proxy runtime and a shared local
settlement fixture. Each workload transaction uses Tempo multicalls:

- **Deposit:** call `deposit` with a synthetic encrypted payload, then submit a batch
  advancing the processed-deposit cursor.
- **Withdrawal:** submit a batch committing one withdrawal, then the registered batch submitter calls
  `processWithdrawals` with that item and an empty remaining queue.

Both paths call the production portal implementation. Settlement reads the
current cursors and advances the zone height, so workloads can continue beyond
210 deposits without rotating portals or pre-seeding withdrawal queues. Ordinary
txgen templates use the account's protocol nonce ordering; no sequence or stream
filter is needed. The sender TPS and duration determine the transaction count. Generation emits the
full count, so setup time does not shorten the workload; a slower sender takes longer.

The settlement fixture is also a **dummy verifier that always returns true**.
The portal has a zero attestation threshold; only the settlement fixture has a
sequencer role. This benchmarks portal execution and settlement
bookkeeping, including the helper's calls, but excludes zone execution, proof
generation, proof verification, and signature verification. No running zone is
needed. These constructor-seeded fixtures are restricted to chain 1337 and must
never hold real funds.

Each operation transfers one pathUSD base unit. Setup funds withdrawal escrow
for the requested transaction count and approves deposits. Fees and bounce-back
reserves are zero; withdrawals have no callbacks. The fixed synthetic payload has
a valid public key and ciphertext length, but is not intended for decryption by a
zone. Txgen resolves account and deployed contract addresses; the existing Nushell
helper expands setup and templates. Users are distributed across portals with equal
aggregate weight per portal, including when there are more portals than users. All keys are public test material. The portal's
per-block deposit cap still applies; start at 100 TPS. Withdrawal success is
reported by `WithdrawalProcessed(success=true)`, not merely receipt status.

## Portal sizing

`TXGEN_ZONE_COUNT` overrides the portal count. Otherwise the helper calculates:

```
portals = max(1, ceil(target_tps * sizing_window_ms / (210 * 1000)))
```

TIP-1096 permits 230 outstanding deposits, with 20 reserved for withdrawal
bounce-backs, leaving 210 ordinary deposits. `TXGEN_ZONE_SETTLEMENT_WINDOW_MS`
sets the sizing window (default 3000 ms). At 10,000 TPS this selects **143 portals**,
independently of the user count. It conservatively budgets every operation as a
possible deposit, including in mixed and withdrawal-only workloads.

The three-second window is a benchmark planning assumption, not a verified
mainnet settlement interval. TIP-1096 defines an outstanding-work limit, not TPS.
This fixture settles atomically within each operation; the sizing window spreads
load across portal state and does not introduce a settlement delay. Real capacity
planning also needs actual settlement latency and workload composition.

## Rebuild

The artifacts use solc 0.8.30, optimizer 200 runs, Cancun EVM:

```sh
forge build --root contrib/bench/txgen/zones --contracts . \
  --out "$PWD/.bench-tmp/zones-out" --cache-path "$PWD/.bench-tmp/zones-cache" \
  --use 0.8.30 --evm-version cancun --optimize --optimizer-runs 200
for contract in PortalFixture SettlementFixture; do
  jq '{abi, bytecode: {object: .bytecode.object}}' \
    ".bench-tmp/zones-out/PortalFixture.sol/$contract.json" \
    > "contrib/bench/txgen/zones/$contract.json"
done
jq '.abi | map(select(.name == "deposit" or .name == "processWithdrawals"))' \
  .bench-tmp/zones-out/PortalFixture.sol/IPortal.json \
  > contrib/bench/txgen/zones/portal.abi.json
```

Keep fixture storage aligned with `crates/precompiles/src/zone_factory/portal.rs`.
The submitter supports both settlement ABIs, before and after TIP-1096.
