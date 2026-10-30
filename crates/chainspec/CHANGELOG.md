# Changelog

## `tempo-chainspec@2.0.0`

### Major Changes

- Scheduled T13 activation on Moderato for 29 October 2026 at 15:00 UTC and mainnet for 3 November 2026 at 15:00 UTC. Updated public hardfork timestamp lookups to return the scheduled times. (by @hamdiallam, [#8787](https://github.com/tempoxyz/tempo/pull/8787))

### Minor Changes

- Added `tempo_chainspec::is_valid_native_account`. (by @hamdiallam, [#8787](https://github.com/tempoxyz/tempo/pull/8787))
- Moved EVM execution from revm and alloy-evm to evm2 and removed the `tempo-revm` crate. `tempo-hardfork`, `tempo-primitives` and `tempo-chainspec` expose evm2 types behind their `evm` features in place of their revm and alloy-evm equivalents. `tempo-alloy` drops its `revm` feature and `TempoTransactionRequest::try_into_tempo_tx_env`; its `reth` feature now converts requests into evm2 transaction environments. (by @hamdiallam, [#8787](https://github.com/tempoxyz/tempo/pull/8787))

### Patch Changes

- Added the `T15` hardfork with no public-network activation; dev and test genesis activate it at genesis. (by @hamdiallam, [#8787](https://github.com/tempoxyz/tempo/pull/8787))

## `tempo-chainspec@1.16.0`

### Minor Changes

- Add `TempoHardfork::genesis_key`, derive `TempoGenesisInfo` fork fields from the hardfork list, and add reusable `--hardfork`/`--<fork>-time` genesis generator arguments (`tempo_chainspec::cli::TempoHardforkArgs`). (by @rakita, [#7902](https://github.com/tempoxyz/tempo/pull/7902))
- Add T14 hardfork support with a configurable `t14Time` genesis activation timestamp. T14 remains unscheduled on mainnet and Moderato. (by @rakita, [#7902](https://github.com/tempoxyz/tempo/pull/7902))

## `tempo-chainspec@1.11.0`

### Minor Changes

- Added the T10 hardfork and moved TIP-1091 activation (ZoneFactory precompile and shared Zone runtime installation) from T9 to T10, so the ZonePortal runtime can still change after the audit without reopening T9. (by @HamdiAllam, [#7244](https://github.com/tempoxyz/tempo/pull/7244))
- Implemented TIP-1091 with a native permissioned ZoneFactory, deterministic ZonePortal proxy accounts, and owner-managed runtimes copied from verified source deployments. Activates at T10. (by @HamdiAllam, [#7244](https://github.com/tempoxyz/tempo/pull/7244))

### Patch Changes

- Added the canonical EIP-2935 history storage account to the built-in development genesis. (by @HamdiAllam, [#7244](https://github.com/tempoxyz/tempo/pull/7244))

## `tempo-chainspec@1.10.1`


## `tempo-chainspec@1.10.0`

### Minor Changes

- Bump the Tempo SDK crate set to the `1.10` minor release. (by @DerekCofausper, [#6610](https://github.com/tempoxyz/tempo/pull/6610))

## `tempo-chainspec@1.9.1`


## `tempo-chainspec@1.9.0`

### Minor Changes

- Extracts Tempo hardfork definitions and activation schedules into a new `tempo-hardfork` crate for SDK reuse without chainspec dependencies.
- Updates `tempo-alloy` to depend on and re-export `tempo-hardfork` instead of `tempo-chainspec`. (by @DerekCofausper, [#6480](https://github.com/tempoxyz/tempo/pull/6480))

## `tempo-chainspec@1.8.2`

### Patch Changes

- Release tempo-chainspec with the SDK crate set. (by @DerekCofausper, [#5640](https://github.com/tempoxyz/tempo/pull/5640))

