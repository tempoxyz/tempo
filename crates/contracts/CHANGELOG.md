# Changelog

## `tempo-contracts@1.17.0`

### Minor Changes

- Added `ChannelDescriptor::id` and `id_preimage` in tempo-contracts and `tip20_channel_reserve::voucher_digest` and `voucher_digest_with` in tempo-precompiles, which compute a channel's id and a voucher's EIP-712 digest outside a storage context, matching the precompile. (by @0xrusowsky, [#9366](https://github.com/tempoxyz/tempo/pull/9366))
- Added the configurable account precompile interface (`IConfigurableAccount`) and its `CONFIGURABLE_ACCOUNT_ADDRESS`. Nothing registers or calls it yet. (by @joshieDo, [#8502](https://github.com/tempoxyz/tempo/pull/8502))
- Added the `ConfigurableAccount` account keychain signature type (value 3). From T14, the T3+ `authorizeKey` overloads and `authorizeAdminKey` accept it for a code-free delegate other than the granting account that is not a reserved address (precompile, TIP-20, virtual or zone portal). Earlier forks keep reverting exactly as for an unknown signature type. (by @joshieDo, [#8527](https://github.com/tempoxyz/tempo/pull/8527))
- Registered the configurable account precompile at T14 and stored configuration commitments in the journaled account extension. The first commitment write is priced like account creation and installs the `0xef` account marker (`CONFIGURABLE_ACCOUNT_CODE`, `CONFIGURABLE_ACCOUNT_CODE_HASH`, `valid_account_code`); later writes cost 5,000 gas. `PrecompileStorageProvider::config_commitment` and `set_config_commitment` are now required, `account_config_commitment` decodes a commitment, `CONFIG_COMMITMENT_REGISTRATION_GAS` is removed, and a registered keychain-signed sender is exempt from EIP-3607 from T14. From T14 the handler seeds the upgrade authority, so a root-signed `upgradeAccount` that is the whole transaction registers its sender, and a registered account can be named as a ConfigurableAccount delegate key. (by @joshieDo, [#8743](https://github.com/tempoxyz/tempo/pull/8743))
- Added the `UnsupportedOnZone()` error to `IConfigurableAccount`, which `updateConfig` and `upgradeAccount` revert with on zones (TIP-1154). (by @0xrusowsky, [#9035](https://github.com/tempoxyz/tempo/pull/9035))
- From T14 the signature verifier precompile exposes `verifyConfigurableAccount(account, hash, signature)`: it returns whether a configurable account signature's owner quorum approves `hash` for `account` against its current configuration, and reverts for malformed or invalid approvals. Its calldata is exempt from the primitive signature size cap. (by @joshieDo, [#8750](https://github.com/tempoxyz/tempo/pull/8750))
- Added portal transfer opt-in controls, contract bindings, and the T15 portal runtime. Updated development genesis bytecode and hardened zone transfer admission checks. (by @adityapk00, [#8549](https://github.com/tempoxyz/tempo/pull/8549))
- Added `IAccountKeychain::KeyRestrictions::unrestricted()` with `expiry`, `enforce_limits`, `limit` and `allowed_calls` builders, and `test_util::KeychainSetup`, which sets up an account's keychain in tests. (by @0xrusowsky, [#9365](https://github.com/tempoxyz/tempo/pull/9365))
- Added the `RootKeyRetired(address account)` error to `ITIP20` and `ITIP20ChannelReserve`. From T14, TIP-20 `permit` reverts with it when the owner has a config commitment, because a committed account no longer acts through its own root key. Channel `open` and nonzero `topUp` revert with it when the voucher signer has one; vouchers on already-funded channels stay redeemable after the signer migrates. (by @joshieDo, [#8525](https://github.com/tempoxyz/tempo/pull/8525))
- Added a `requestWithdrawal(..., bytes revealTo, bool revealOrg)` overload and the `OrgRevealRequiresCallback` error to the zone `IZoneOutbox`. A withdrawal commits its sender's org only through this overload with `revealOrg` set, which requires a callback; the existing `requestWithdrawal` always carries `senderOrg = 0`. Because the function is now overloaded, the generated Rust types are `requestWithdrawal_0Call` (the existing signature) and `requestWithdrawal_1Call`. (by Arsenii Kulikov, [#9519](https://github.com/tempoxyz/tempo/pull/9519))
- Added `senderOrg` to the zone `Withdrawal`, the `WithdrawalSenderOrg` outbox event and `callbackSenderOrg()` on `IZonePortal`, which withdrawal receivers call during `onWithdrawalReceived` to read the sender's ZoneIdentity org. Withdrawals in org 0 keep their pre-T15 queue hash; `LegacyWithdrawal` and `LegacyZonePortal` bind that encoding. The T15 `ZonePortal` runtime is regenerated. (by Arsenii Kulikov, [#9432](https://github.com/tempoxyz/tempo/pull/9432))
- Added `IZoneIdentity` bindings and `ZONE_IDENTITY_ADDRESS` for the T15 ZoneIdentity predeploy, and `setIdentityConfig` and `IdentityConfigUpdated` to `IZonePortal`. The T15 `ZonePortal` runtime, and the dev genesis that embeds it, store the ZoneIdentity registrar and enforcement flag. (by Arsenii Kulikov, [#9432](https://github.com/tempoxyz/tempo/pull/9432))
- Added `setReader`, `canRead` and `ReaderUpdated` to the `IZoneIdentity` bindings, which let a ZoneIdentity org's admin and the readers it names read its members' account-scoped state, and replaced `MemberUpdated` with `MemberAdded` and `MemberRemoved`. (by @0xrusowsky, [#9438](https://github.com/tempoxyz/tempo/pull/9438))
- Updated the T15 `ZonePortal` runtime and bindings for the TIP-1171 unbounded deposit queue. Replaced `MAX_UNPROCESSED_DEPOSITS` with `DEPOSITS_PER_BUCKET`, added the checkpoint and congestion-price getters and the `FeeTooHigh` error, bound the `maxFee` overloads of `deposit` and `depositEncrypted` (calls are now suffixed: `deposit_0`/`deposit_1`, `depositEncrypted_0`/`depositEncrypted_1`), and added an optional `max_fee` to `SwapAndDepositRouterCallback` that makes the router call the `maxFee` overload. (by @0xrusowsky, [#9437](https://github.com/tempoxyz/tempo/pull/9437))
- Added TIP-1094 zone deposit addresses to the T15 `ZonePortal` runtime and bindings: `depositVirtual`, `retireAddressVersionsBelow` and `minimumAddressVersion`, the `VirtualDepositMade` and `AddressVersionsRetired` events, and the `InvalidVirtualDeposit`, `AddressVersionRetired` and `InvalidVersionRetirement` errors. Added the zone address registry (`IZoneAddressRegistry`, `MasterRegistered`), the inbox `initializeVirtualAddressKey` call with the `VirtualDepositProcessed`, `VirtualDepositFailed` and `VirtualAddressKeyInitialized` events, and the outbox `InvalidWithdrawalRecipient` error. `TempoAddressExt::is_valid_master` now takes the hardfork and rejects zone deposit addresses from T15. (by @Rjected, [#8864](https://github.com/tempoxyz/tempo/pull/8864))

### Patch Changes

- Moved function-local `use`s to module scope. No public API or behavior changes. (by @joshieDo, [#8920](https://github.com/tempoxyz/tempo/pull/8920))
- The `IZoneIdentity` docs now say org 0 has no edges: nothing moves on the zone to, from or within org 0, and `setEdge` rejects any edge that names it. (by Arsenii Kulikov, [#9520](https://github.com/tempoxyz/tempo/pull/9520))

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
