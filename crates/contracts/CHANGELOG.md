# Changelog

## `tempo-contracts@1.6.0`

### Minor Changes

- Added TIP-1022 virtual address support: address registry precompile for registering master addresses with deterministic master IDs, TIP-20 recipient resolution that forwards transfers/mints to registered masters, and TIP-403 policy rejection of virtual addresses. (by @ArseniiKulikov, [#3463](https://github.com/tempoxyz/tempo/pull/3463))

### Patch Changes

- Improved gas cap revert detection in BlockGasLimits invariant tests. (by @ArseniiKulikov, [#3463](https://github.com/tempoxyz/tempo/pull/3463))
- Invariants: fix active order check (by @ArseniiKulikov, [#3463](https://github.com/tempoxyz/tempo/pull/3463))

