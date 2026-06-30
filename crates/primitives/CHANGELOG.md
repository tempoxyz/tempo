# Changelog

## `tempo-primitives@1.10.0`

### Minor Changes

- Bump the Tempo SDK crate set to the `1.10` minor release. (by @DerekCofausper, [#6610](https://github.com/tempoxyz/tempo/pull/6610))

## `tempo-primitives@1.9.1`

### Patch Changes

- Moved `SYSTEM_PRECOMPILES` from `tempo-precompiles` to `tempo-contracts` and replaced the `is_precompile_address` function with an `is_precompile` method on the `TempoAddressExt` trait in `tempo-primitives`. (by @DerekCofausper, [#6535](https://github.com/tempoxyz/tempo/pull/6535))

## `tempo-primitives@1.9.0`

### Minor Changes

- Extracts Tempo hardfork definitions and activation schedules into a new `tempo-hardfork` crate for SDK reuse without chainspec dependencies.
- Updates `tempo-alloy` to depend on and re-export `tempo-hardfork` instead of `tempo-chainspec`. (by @DerekCofausper, [#6480](https://github.com/tempoxyz/tempo/pull/6480))

## `tempo-primitives@1.8.1`


## `tempo-primitives@1.8.0`

### Minor Changes

- Added T6 admin access key support for account keychain authorization and SDK transaction builders. (by @DerekCofausper, [#4650](https://github.com/tempoxyz/tempo/pull/4650))

### Patch Changes

- Reject channel reserve payment-lane calls with malformed Tempo signature encodings. (by @DerekCofausper, [#4650](https://github.com/tempoxyz/tempo/pull/4650))

## `tempo-primitives@1.7.3`


## `tempo-primitives@1.7.2`

### Patch Changes

- Bumped alloy to `2.0.5` and updated transitive dependencies.
- Dropped constructor helpers in favor of the newly auto-generated ones by the `sol!` macro. (by @ArseniiKulikov, [#4058](https://github.com/tempoxyz/tempo/pull/4058))

## `tempo-primitives@1.7.0`

### Minor Changes

- Enshrined the stricter TIP-1045 payment classifier (`is_payment_v2`) at the T5 hardfork for consensus-level payment lane validation. Relaxed the v2 classifier to allow bounded `key_authorization` (RLP length ≤ 1024 bytes). (by @DerekCofausper, [#4019](https://github.com/tempoxyz/tempo/pull/4019))
- Moved TIP-20 and TIP-1022 virtual-address helpers (`is_tip20_prefix`, `is_virtual_address`, `decode_virtual_address`, `make_virtual_address`, `MasterId`, `UserTag`) from `tempo-precompiles` into a new `TempoAddressExt` trait on `Address` in `tempo-primitives`. Updated all consumers to use the new trait methods (`address.is_tip20()`, `address.is_virtual()`, `Address::new_virtual(...)`, etc.). (by @DerekCofausper, [#4019](https://github.com/tempoxyz/tempo/pull/4019))

## `tempo-primitives@1.6.0`

### Minor Changes

- Store `TempoTransaction.valid_before` and `valid_after` as `Option<NonZeroU64>` so omitted validity bounds remain distinct from zero in RLP and serde handling. Reject zero-valued validity bounds when building AA transactions from `TempoTransactionRequest`. (by @legion2002, [#3501](https://github.com/tempoxyz/tempo/pull/3501))

### Patch Changes

- Bump alloy to 2.0.0, reth to rev `bfb7ab7`, and related dependencies (`reth-codecs` 0.2.0, `reth-primitives-traits` 0.2.0, `alloy-evm` 0.31.0, `revm-inspectors` 0.37.0). Adapt code for upstream API changes including the `TransactionBuilder`/`NetworkTransactionBuilder` trait split, new `BlockHeader` methods (`block_access_list_hash`, `slot_number`), the `slot_number` field on payload builder attributes, the `ExecutionWitnessMode` parameter on `witness`, and `PartialEq` on `TempoBlockEnv`. (by @0xrusowsky, @figtracer, @stevencartavia [#3569](https://github.com/tempoxyz/tempo/pull/3569))

## `tempo-primitives@1.5.1`

### Patch Changes

- Add call-scope support to keychain SDK: `authorize_key`, `revoke_key`, `set_allowed_calls`, `CallScopeBuilder`, and `KeyRestrictions` builders. Extend `TempoTransactionRequest` with key-type, key-data, and key-authorization builder methods. (by @0xrusowsky, [#3495](https://github.com/tempoxyz/tempo/pull/3495))
- Implement TIP-1011 enhanced access key permissions with exact permission matching for keychain operations. (by @0xrusowsky, [#3495](https://github.com/tempoxyz/tempo/pull/3495))
