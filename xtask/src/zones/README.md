# `tempo-zone-xtask`

A polyfill to perform various operations on the codebase.

Subcommands currently supported:

- `admin`: read-only checks and guarded operational commands for deployed Zones.
  See the [admin command documentation](admin/README.md).
- `create-zone`: creates a new Zone through Tempo's native TIP-1091 ZoneFactory, either
  signed by `ZONE_FACTORY_OWNER_KEY` or, for a Safe-owned factory, as a Safe Transaction
  Builder proposal (`--safe-address`) finished with `--creation-tx` after execution.
- `enable-token`, `set-access-mode`, `set-gateway-mode`, `set-allowed-account`,
  `set-gateway`: ZonePortal admin calls, signed by `ADMIN_KEY` or written as Safe proposals.
- `generate-zone-genesis`: generates a Zone L2 genesis file.
- `pause-portal`: pauses new deposits, Zone block production, and L1 withdrawal processing for 30 days.

`create-zone` derives Tempo fork activations from its L1 RPC before sending any
transactions. `generate-zone-genesis` requires either `--l1-rpc-url <url>` or an
explicit offline `--hardfork <fork>` cap; there is no implicit all-forks-at-genesis
default.

RPC mode reads `eth_chainId`, `tempo_forkSchedule`, and the latest L1 header. The
RPC chain ID must match the parent encoded in the Zone chain ID. Genesis preserves
activation timestamps, including scheduled future upgrades, and writes absent
supported forks as `null` so node startup cannot inherit a different schedule.
The latest L1 head is used only to validate the reported schedule. The genesis
timestamp comes from the anchor header, and the initialization EVM uses the fork
active at that timestamp. With the same anchor, schedule, and generation parameters,
regeneration produces identical genesis even as the L1 head advances. RPC failures,
unsupported forks, inconsistent schedules, or fork overrides abort generation.
If an upgrade occurs between the schedule and head reads, retry generation.
`--l1-rpc-url` can also be combined with `--tempo-portal` to derive a pre-creation
anchor, or with `--tempo-genesis-header-rlp` to supply the anchor explicitly.

Fork settings are persisted in `genesis.json`; restarting nodes does not fetch
a new schedule. L1 upgrades not present in the snapshot require a coordinated
configuration update. Existing Zone databases are not modified by generation.

For offline development or tests, `--hardfork T11` enables forks through T11 at
timestamp zero and disables T12/T13/T14. Individual `--t*-time` flags still take
precedence in offline mode, but cannot be combined with RPC-derived schedules.
The bundled dev genesis regeneration recipe explicitly selects T14.

- `generate-state-bloat`: generates a TIP20 binary storage dump using Tempo's
  implementation and CLI options.

## Offline Zone state bloat

Generate a dump and initialize a **nonexistent** Zone database:

```bash
cargo zone-xtask generate-state-bloat --size 1 --token 0 --out zone-state-bloat.bin \
  --mnemonic 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about'
cargo run --bin tempo-zone -- init-from-binary-dump \
  --chain zone-genesis.json --datadir zone-data zone-state-bloat.bin \
  --output-genesis bloated-genesis.json --manifest zone-state-bloat.json
# All later init/node commands must use the generated specification:
cargo run --bin tempo-zone -- init --chain bloated-genesis.json --datadir zone-data
```

The example uses a public test-only mnemonic distinct from the default dev
mnemonic. Choose accounts not already funded in your genesis; the benchmark
workflow generates its own private mnemonic.

`--size` is the target dump size in MiB, not the resulting database size; it is
split across every `--token`. The generator and strict dump reader come from
Tempo. The Zone initializer merges storage into the genesis allocation **before**
normal Reth initialization commits the header, trie, and history. It rejects
non-TIP20 addresses, a genesis without pathUSD code, duplicate slots, conflicts
with nonzero genesis storage, malformed dumps, and every existing datadir
(including block zero). Output files are never overwritten. The saved chain
specification must be used on restart; using the original genesis is rejected by
normal genesis validation.

Token `0` is pathUSD, which Zone genesis deploys. Other token IDs (for example
`--token 0 --token 1 --token 2 --token 3`) are seeded as storage-only accounts at
their `0x20C0…{id}` addresses and stay uninitialized until the portal admin
enables the matching L1 token (`just enable-token <token>`). The Zone inbox then
initializes metadata and roles without touching the seeded supply or balances.
Enable every seeded token and wait for the Zone to process `TokenEnabled` before
sending traffic that uses it. Genesis code for those tokens is rejected so they
cannot become usable before the portal enables them.

The manifest includes dump SHA-256, per-token and total entry counts, database
file bytes, import time, configuration digest, genesis hash, and committed/database state roots. A full
hashed-state traversal verifies the root independently of cached trie nodes, and
the stores are reopened before publishing the success manifest. Failed initialization
may leave a partial datadir/output genesis; use a new disposable path when retrying.

This is synthetic benchmark state: generated balances have no corresponding L1
escrow. Use disposable local databases and keep the generated accounts separate
from accounts used for bridge correctness checks.

The importer builds genesis allocations in memory; choose a dump size that fits the
benchmark host. It does not impose a Nitro-specific size limit.
