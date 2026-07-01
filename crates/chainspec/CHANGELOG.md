# Changelog

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

