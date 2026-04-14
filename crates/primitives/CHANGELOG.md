# Changelog

## `tempo-primitives@1.6.0`

### Minor Changes

- Store `TempoTransaction.valid_before` and `valid_after` as `Option<NonZeroU64>` so omitted validity bounds remain distinct from zero in RLP and serde handling. Reject zero-valued validity bounds when building AA transactions from `TempoTransactionRequest`. (by @DerekCofausper, [#3554](https://github.com/tempoxyz/tempo/pull/3554))

## `tempo-primitives@1.5.1`

### Patch Changes

- Add call-scope support to keychain SDK: `authorize_key`, `revoke_key`, `set_allowed_calls`, `CallScopeBuilder`, and `KeyRestrictions` builders. Extend `TempoTransactionRequest` with key-type, key-data, and key-authorization builder methods. (by @0xrusowsky, [#3495](https://github.com/tempoxyz/tempo/pull/3495))
- Implement TIP-1011 enhanced access key permissions with exact permission matching for keychain operations. (by @0xrusowsky, [#3495](https://github.com/tempoxyz/tempo/pull/3495))

