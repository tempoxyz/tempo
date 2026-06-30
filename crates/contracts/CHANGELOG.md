# Changelog

## `tempo-contracts@1.10.0`

### Minor Changes

- Bump the Tempo SDK crate set to the `1.10` minor release. (by @DerekCofausper, [#6610](https://github.com/tempoxyz/tempo/pull/6610))

## `tempo-contracts@1.9.1`

### Patch Changes

- Moved `SYSTEM_PRECOMPILES` from `tempo-precompiles` to `tempo-contracts` and replaced the `is_precompile_address` function with an `is_precompile` method on the `TempoAddressExt` trait in `tempo-primitives`. (by @DerekCofausper, [#6535](https://github.com/tempoxyz/tempo/pull/6535))

## `tempo-contracts@1.9.0`

### Minor Changes

- Extracts Tempo hardfork definitions and activation schedules into a new `tempo-hardfork` crate for SDK reuse without chainspec dependencies.
- Updates `tempo-alloy` to depend on and re-export `tempo-hardfork` instead of `tempo-chainspec`. (by @DerekCofausper, [#6480](https://github.com/tempoxyz/tempo/pull/6480))

## `tempo-contracts@1.8.1`


## `tempo-contracts@1.8.0`

### Minor Changes

- Added T6 admin access key support for account keychain authorization and SDK transaction builders. (by @DerekCofausper, [#4650](https://github.com/tempoxyz/tempo/pull/4650))
- Reject channel reserve payment-lane calls with malformed Tempo signature encodings. (by @DerekCofausper, [#4650](https://github.com/tempoxyz/tempo/pull/4650))
- Added the T6 `SignatureVerifier.verifyKeychain` and `SignatureVerifier.verifyKeychainAdmin` selectors for checking account-bound active and admin keychain signatures. (by @DerekCofausper, [#4650](https://github.com/tempoxyz/tempo/pull/4650))

## `tempo-contracts@1.7.3`


## `tempo-contracts@1.7.2`

### Patch Changes

- Bumped alloy to `2.0.5` and updated transitive dependencies.
- Dropped constructor helpers in favor of the newly auto-generated ones by the `sol!` macro. (by @ArseniiKulikov, [#4058](https://github.com/tempoxyz/tempo/pull/4058))

## `tempo-contracts@1.7.0`

### Minor Changes

- Added the TIP-20 channel reserve precompile with channel open, settle, top-up, close, request-close, and withdraw flows gated at T5. (by @DerekCofausper, [#4019](https://github.com/tempoxyz/tempo/pull/4019))

### Patch Changes

- Enshrined the stricter TIP-1045 payment classifier (`is_payment_v2`) at the T5 hardfork for consensus-level payment lane validation. Relaxed the v2 classifier to allow bounded `key_authorization` (RLP length ≤ 1024 bytes). (by @DerekCofausper, [#4019](https://github.com/tempoxyz/tempo/pull/4019))

## `tempo-contracts@1.6.0`


## `tempo-contracts@1.5.1`

### Patch Changes

- Improved gas cap revert detection in BlockGasLimits invariant tests. (by @0xrusowsky, [#3495](https://github.com/tempoxyz/tempo/pull/3495))
- Invariants: fix active order check (by @0xrusowsky, [#3495](https://github.com/tempoxyz/tempo/pull/3495))
- Added TIP-1022 virtual address support: address registry precompile for registering master addresses with deterministic master IDs, TIP-20 recipient resolution that forwards transfers/mints to registered masters, and TIP-403 policy rejection of virtual addresses. (by @0xrusowsky, [#3495](https://github.com/tempoxyz/tempo/pull/3495))
