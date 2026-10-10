# `tempo-zone-xtask`

A polyfill to perform various operations on the codebase.

Subcommands currently supported:

- `admin`: read-only checks and guarded operational commands for deployed Zones.
  See the [admin command documentation](../../xtask/src/zones/admin/README.md).
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
