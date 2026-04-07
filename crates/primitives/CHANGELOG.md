# Changelog

## `tempo-primitives@1.6.0`

### Minor Changes

- Implement TIP-1011 enhanced access key permissions with exact permission matching for keychain operations. (by @DerekCofausper, [#3469](https://github.com/tempoxyz/tempo/pull/3469))

### Patch Changes

- Add call-scope support to keychain SDK: `authorize_key`, `revoke_key`, `set_allowed_calls`, `CallScopeBuilder`, and `KeyRestrictions` builders. Extend `TempoTransactionRequest` with key-type, key-data, and key-authorization builder methods. (by @DerekCofausper, [#3469](https://github.com/tempoxyz/tempo/pull/3469))

