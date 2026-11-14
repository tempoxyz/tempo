# Changelog

## `tempo-hardfork@2.0.0`

### Major Changes

- Scheduled T13 activation on Moderato for 29 October 2026 at 15:00 UTC and mainnet for 3 November 2026 at 15:00 UTC. Updated public hardfork timestamp lookups to return the scheduled times. (by @decofe, [#8480](https://github.com/tempoxyz/tempo/pull/8480))

### Minor Changes

- A standard EIP-7702 transaction whose gas limit cannot pay for its authorization list keeps the authorizations unrecovered, so execution rejects it without recovering any signature. `gas_params::EIP7702_PER_EMPTY_ACCOUNT_COST_T1` is now public. (by Matthias Seitz, [#9332](https://github.com/tempoxyz/tempo/pull/9332))
- Moved EVM execution from revm and alloy-evm to evm2 and removed the `tempo-revm` crate. `tempo-hardfork`, `tempo-primitives` and `tempo-chainspec` expose evm2 types behind their `evm` features in place of their revm and alloy-evm equivalents. `tempo-alloy` drops its `revm` feature and `TempoTransactionRequest::try_into_tempo_tx_env`; its `reth` feature now converts requests into evm2 transaction environments. (by Arsenii Kulikov, [#7871](https://github.com/tempoxyz/tempo/pull/7871))
- Added the `T15` hardfork with no public-network activation; dev and test genesis activate it at genesis. (by Alexey Shekhirin, [#8706](https://github.com/tempoxyz/tempo/pull/8706))
- Added `L1_COMMITMENT_READ_GAS` (10,000, in `constants::gas`) and `gas_params::apply_zone`, which adds it to a zone's cold account access and access-list address costs from T14, so every load that reads an account's Tempo commitment pays for it (TIP-1154). (by Arsenii Kulikov, [#9050](https://github.com/tempoxyz/tempo/pull/9050))

### Patch Changes

- Moved function-local `use`s to module scope. No public API or behavior changes. (by @joshieDo, [#8920](https://github.com/tempoxyz/tempo/pull/8920))

## `tempo-hardfork@1.16.0`

### Minor Changes

- Add `TempoHardfork::genesis_key`, derive `TempoGenesisInfo` fork fields from the hardfork list, and add reusable `--hardfork`/`--<fork>-time` genesis generator arguments (`tempo_chainspec::cli::TempoHardforkArgs`). (by @rakita, [#7902](https://github.com/tempoxyz/tempo/pull/7902))
- Add T14 hardfork support with a configurable `t14Time` genesis activation timestamp. T14 remains unscheduled on mainnet and Moderato. (by @rakita, [#7902](https://github.com/tempoxyz/tempo/pull/7902))

## `tempo-hardfork@1.11.0`

### Minor Changes

- Added the T10 hardfork and moved TIP-1091 activation (ZoneFactory precompile and shared Zone runtime installation) from T9 to T10, so the ZonePortal runtime can still change after the audit without reopening T9. (by @HamdiAllam, [#7244](https://github.com/tempoxyz/tempo/pull/7244))

## `tempo-hardfork@1.10.1`


## `tempo-hardfork@1.10.0`

### Minor Changes

- Bump the Tempo SDK crate set to the `1.10` minor release. (by @DerekCofausper, [#6610](https://github.com/tempoxyz/tempo/pull/6610))

## `tempo-hardfork@1.9.1`


## `tempo-hardfork@1.9.0`

### Minor Changes

- Extracts Tempo hardfork definitions and activation schedules into a new `tempo-hardfork` crate for SDK reuse without chainspec dependencies.
- Updates `tempo-alloy` to depend on and re-export `tempo-hardfork` instead of `tempo-chainspec`. (by @DerekCofausper, [#6480](https://github.com/tempoxyz/tempo/pull/6480))

