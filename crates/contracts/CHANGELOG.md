# Changelog

## `tempo-contracts@1.6.0`

### Minor Changes

- Added TIP-1022 virtual address support: address registry precompile for registering master addresses with deterministic master IDs, TIP-20 recipient resolution that forwards transfers/mints to registered masters, and TIP-403 policy rejection of virtual addresses. (by @0xrusowsky, [#3471](https://github.com/tempoxyz/tempo/pull/3471))

### Patch Changes

- Improved gas cap revert detection in BlockGasLimits invariant tests. (by @0xrusowsky, [#3471](https://github.com/tempoxyz/tempo/pull/3471))
- Invariants: fix active order check (by @0xrusowsky, [#3471](https://github.com/tempoxyz/tempo/pull/3471))

