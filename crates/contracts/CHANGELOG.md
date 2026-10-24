# Changelog

## `tempo-contracts@2.0.0`

### Minor Changes

- Added the configurable account precompile interface (`IConfigurableAccount`) and its `CONFIGURABLE_ACCOUNT_ADDRESS`. Nothing registers or calls it yet. (by @DaniPopes, [#8645](https://github.com/tempoxyz/tempo/pull/8645))
- Added the `ConfigurableAccount` account keychain signature type (value 3). From T14, the T3+ `authorizeKey` overloads and `authorizeAdminKey` accept it for a code-free delegate other than the granting account that is not a reserved address (precompile, TIP-20, virtual or zone portal). Earlier forks keep reverting exactly as for an unknown signature type. (by @DaniPopes, [#8645](https://github.com/tempoxyz/tempo/pull/8645))
- Added the `RootKeyRetired(address account)` error to `ITIP20` and `ITIP20ChannelReserve`. From T14, TIP-20 `permit` and channel voucher validation revert with it when the signing account has a config commitment, because a committed account no longer acts through its own root key. (by @DaniPopes, [#8645](https://github.com/tempoxyz/tempo/pull/8645))

## `tempo-contracts@1.16.0`

### Minor Changes

- Added the T12 `burnAt` TIP-20 API, role, and caller-attributed event for authorized burns from unprotected accounts. (by @rakita, [#7902](https://github.com/tempoxyz/tempo/pull/7902))
- Implemented TIP-1098 with a native T11 Zone verifier that validates AWS Nitro attestations and binds them to Zone batch inputs. The verifier remains fail-closed until the canonical T11 PCR measurements are finalized. (by @rakita, [#7902](https://github.com/tempoxyz/tempo/pull/7902))

## `tempo-contracts@1.11.0`

### Minor Changes

- Added a helper for constructing the complete native ZoneFactory state with a specified initial owner. (by @HamdiAllam, [#7244](https://github.com/tempoxyz/tempo/pull/7244))
- Added the `LeaderUpdated` event and updated the ZonePortal runtime with leader transition support. (by @HamdiAllam, [#7244](https://github.com/tempoxyz/tempo/pull/7244))
- Added the T10 hardfork and moved TIP-1091 activation (ZoneFactory precompile and shared Zone runtime installation) from T9 to T10, so the ZonePortal runtime can still change after the audit without reopening T9. (by @HamdiAllam, [#7244](https://github.com/tempoxyz/tempo/pull/7244))
- Implemented TIP-1091 with a native permissioned ZoneFactory, deterministic ZonePortal proxy accounts, and owner-managed runtimes copied from verified source deployments. Activates at T10. (by @HamdiAllam, [#7244](https://github.com/tempoxyz/tempo/pull/7244))
- Updated the canonical Zone Portal, Messenger, and Verifier runtime bytecode installed by the T10 hardfork. (by @HamdiAllam, [#7244](https://github.com/tempoxyz/tempo/pull/7244))

## `tempo-contracts@1.10.1`

### Patch Changes

- Added `IStorageCredits::Mode::as_str` returning the lowercase string label for a storage credit mode. (by @DerekCofausper, [#6734](https://github.com/tempoxyz/tempo/pull/6734))

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
