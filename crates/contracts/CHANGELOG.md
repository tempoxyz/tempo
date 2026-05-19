# Changelog

## `tempo-contracts@1.7.0`

### Minor Changes

- Added the TIP-20 channel escrow precompile with channel open, settle, top-up, close, request-close, and withdraw flows gated at T5. (by @DerekCofausper, [#4019](https://github.com/tempoxyz/tempo/pull/4019))

### Patch Changes

- Enshrined the stricter TIP-1045 payment classifier (`is_payment_v2`) at the T5 hardfork for consensus-level payment lane validation. Relaxed the v2 classifier to allow bounded `key_authorization` (RLP length ≤ 1024 bytes). (by @DerekCofausper, [#4019](https://github.com/tempoxyz/tempo/pull/4019))

## `tempo-contracts@1.6.0`


## `tempo-contracts@1.5.1`

### Patch Changes

- Improved gas cap revert detection in BlockGasLimits invariant tests. (by @0xrusowsky, [#3495](https://github.com/tempoxyz/tempo/pull/3495))
- Invariants: fix active order check (by @0xrusowsky, [#3495](https://github.com/tempoxyz/tempo/pull/3495))
- Added TIP-1022 virtual address support: address registry precompile for registering master addresses with deterministic master IDs, TIP-20 recipient resolution that forwards transfers/mints to registered masters, and TIP-403 policy rejection of virtual addresses. (by @0xrusowsky, [#3495](https://github.com/tempoxyz/tempo/pull/3495))

