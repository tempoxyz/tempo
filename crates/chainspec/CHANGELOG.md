# Changelog

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

