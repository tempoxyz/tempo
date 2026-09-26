# Changelog

## `tempo-hardfork@1.12.0`

### Minor Changes

- Add T14 hardfork support with a configurable `t14Time` genesis activation timestamp. T14 remains unscheduled on mainnet and Moderato. (by @ShanedaSilva, [#7917](https://github.com/tempoxyz/tempo/pull/7917))

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

