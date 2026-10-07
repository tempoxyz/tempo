# `tempo-xtask`

A polyfill to perform various operations on the codebase.

Subcommands currently supported:

- `admin`: read-only checks and guarded operational commands for deployed Zones.
  See the [admin command documentation](src/admin/README.md).
- `create-zone`: creates a new Zone through Tempo's native TIP-1091 ZoneFactory, either
  signed by `ZONE_FACTORY_OWNER_KEY` or, for a Safe-owned factory, as a Safe Transaction
  Builder proposal (`--safe-address`) finished with `--creation-tx` after execution.
- `enable-token`, `set-access-mode`, `set-gateway-mode`, `set-allowed-account`,
  `set-gateway`: ZonePortal admin calls, signed by `ADMIN_KEY` or written as Safe proposals.
- `generate-zone-genesis`: generates a Zone L2 genesis file.
- `pause-portal`: pauses new deposits, Zone block production, and L1 withdrawal processing for 30 days.

`create-zone` and `generate-zone-genesis` explicitly write every supported Tempo
fork (T0 through T14, including T1A/T1B/T1C) into Zone genesis, defaulting each
activation timestamp to `0`. Override individual timestamps with `--t0-time`,
`--t1-time`, `--t1a-time`, etc. through `--t14-time` to match the parent L1.
For example, a T12-only devnet can pass `--hardfork T12`, which writes explicit
`null`s for T13 and later forks; explicit `--t*-time` flags still take precedence. Omitting a flag
activates that fork at genesis, even when another fork is delayed explicitly.
These flags configure Zone genesis only; they do not change the parent L1 schedule.
