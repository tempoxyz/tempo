# Changelog

## `tempo-alloy@2.0.0`

### Minor Changes

- From T14 RPC simulation can model configurable account owner quorums. `TempoTransactionRequest` gains `configurableAccountSimulation`, the claimed quorum of the sender or of the `keyId` delegate, and `keyAuthorizationSimulation`, the claimed quorum of the parent or admin signing the attached key authorization. Simulation checks the claimed approvals against the configuration and builds mock owner signatures in their place, verifies the owner quorum of a configurable-signed key authorization sent without one, and refuses to sign a request that carries either field. (by @hamdiallam, [#8787](https://github.com/tempoxyz/tempo/pull/8787))
- Moved EVM execution from revm and alloy-evm to evm2 and removed the `tempo-revm` crate. `tempo-hardfork`, `tempo-primitives` and `tempo-chainspec` expose evm2 types behind their `evm` features in place of their revm and alloy-evm equivalents. `tempo-alloy` drops its `revm` feature and `TempoTransactionRequest::try_into_tempo_tx_env`; its `reth` feature now converts requests into evm2 transaction environments. (by @hamdiallam, [#8787](https://github.com/tempoxyz/tempo/pull/8787))

### Patch Changes

- From T14 a configurable account can act as an access key. A V2 `KeychainSignature` now carries an `AccountSignature`: a primitive approval or the delegate's owner quorum. `SignatureType::ConfigurableAccount` (3) names such a delegate in a key authorization, which is rejected before T14. The handler checks the delegate's account, code and configuration commitment, registers it on first use and charges its account access; a primitive key whose ID has since migrated accepts its owner quorum. Gas estimation rejects a configurable key type without a configuration witness, the signature verifier rejects configurable keychain signatures, and zones reject configurable delegates. (by @hamdiallam, [#8787](https://github.com/tempoxyz/tempo/pull/8787))
- From T14 a configurable account can sign key authorizations. `SignedKeyAuthorization.signature` is now an `AccountSignature`: a primitive root signature or the account's owner quorum, with the same wire encoding. `SignedKeyAuthorization::authorizing_account` returns the named configurable account, and `recover_signer` fails for one. Sender recovery verifies the grant's owner quorum, and the handler checks the grant account's code and configuration commitment and registers it on first use. The Tempo Accounts store persists configurable-signed key authorizations, and zones reject them. (by @hamdiallam, [#8787](https://github.com/tempoxyz/tempo/pull/8787))
- From T14 a primitive key of an account with a configuration commitment can no longer act as the transaction sender, key authorization signer, fee payer or access key: the transaction is rejected with `TempoInvalidTransaction::RootKeyRetired` (role in `RootKeyRole`). Each distinct non-sender role account costs one account access, so a sponsored transaction pays one more cold access; `eth_estimateGas` and `eth_fillTransaction` add it for a request carrying the fee payer marker, `TempoGasFiller` adds it when it fills such a request, and `account_access_gas` is exported. (by @hamdiallam, [#8787](https://github.com/tempoxyz/tempo/pull/8787))
- Fixed `eth_estimateGas` and `eth_fillTransaction` under-estimating gas for WebAuthn senders: the mock signature now prices its authenticator data as nonzero bytes. (by @hamdiallam, [#8787](https://github.com/tempoxyz/tempo/pull/8787))

## `tempo-alloy@1.16.0`


## `tempo-alloy@1.11.0`

### Minor Changes

- Added Accounts-compatible wallets with strict persisted access-key selection, P-256 and secp256k1 signing, pending authorization preparation, and sponsorship-aware transaction filling. (by @HamdiAllam, [#7244](https://github.com/tempoxyz/tempo/pull/7244))

## `tempo-alloy@1.10.1`

### Patch Changes

- Added typed `RecoveryAuthority` selector and `set_receive_policy_for_receiver` helper for building validated TIP-1028 receive-policy calls, rejecting recovery authorities that can never pass `ReceivePolicyGuard.claim()`. (by @DerekCofausper, [#6734](https://github.com/tempoxyz/tempo/pull/6734))

## `tempo-alloy@1.10.0`

### Minor Changes

- Bump the Tempo SDK crate set to the `1.10` minor release. (by @DerekCofausper, [#6610](https://github.com/tempoxyz/tempo/pull/6610))

## `tempo-alloy@1.9.1`


## `tempo-alloy@1.9.0`

### Minor Changes

- Extracts Tempo hardfork definitions and activation schedules into a new `tempo-hardfork` crate for SDK reuse without chainspec dependencies.
- Updates `tempo-alloy` to depend on and re-export `tempo-hardfork` instead of `tempo-chainspec`. (by @DerekCofausper, [#6480](https://github.com/tempoxyz/tempo/pull/6480))

## `tempo-alloy@1.8.1`


## `tempo-alloy@1.8.0`

### Minor Changes

- Added T6 admin access key support for account keychain authorization and SDK transaction builders. (by @DerekCofausper, [#4650](https://github.com/tempoxyz/tempo/pull/4650))

## `tempo-alloy@1.7.3`

### Patch Changes

- Added sponsored transaction support via a new `RelayTransport` that routes `eth_sendRawTransaction` requests through a sponsor service.
- Introduced `SponsorFiller`, `SponsoredProviderBuilder`, and `.sponsor()` / `.sponsor_with_config()` provider builder extensions supporting both sign-and-relay and sign-only modes. (by @DerekCofausper, [#4188](https://github.com/tempoxyz/tempo/pull/4188))

## `tempo-alloy@1.7.2`

### Patch Changes

- Bumped alloy to `2.0.5` and updated transitive dependencies.
- Dropped constructor helpers in favor of the newly auto-generated ones by the `sol!` macro. (by @ArseniiKulikov, [#4058](https://github.com/tempoxyz/tempo/pull/4058))

## `tempo-alloy@1.7.0`

### Minor Changes

- Added the TIP-20 channel reserve precompile with channel open, settle, top-up, close, request-close, and withdraw flows gated at T5. (by @DerekCofausper, [#4019](https://github.com/tempoxyz/tempo/pull/4019))
- Moved TIP-20 and TIP-1022 virtual-address helpers (`is_tip20_prefix`, `is_virtual_address`, `decode_virtual_address`, `make_virtual_address`, `MasterId`, `UserTag`) from `tempo-precompiles` into a new `TempoAddressExt` trait on `Address` in `tempo-primitives`. Updated all consumers to use the new trait methods (`address.is_tip20()`, `address.is_virtual()`, `Address::new_virtual(...)`, etc.). (by @DerekCofausper, [#4019](https://github.com/tempoxyz/tempo/pull/4019))
- Added `is_hardfork_active` helper to `TempoProviderExt` and re-exported `tempo-chainspec` as a non-optional dependency. Updated the crates.io publish pipeline to include `tempo-chainspec` as a published crate. (by @DerekCofausper, [#4019](https://github.com/tempoxyz/tempo/pull/4019))

## `tempo-alloy@1.6.0`

### Patch Changes

- Store `TempoTransaction.valid_before` and `valid_after` as `Option<NonZeroU64>` so omitted validity bounds remain distinct from zero in RLP and serde handling. Reject zero-valued validity bounds when building AA transactions from `TempoTransactionRequest`. (by @legion2002, [#3501](https://github.com/tempoxyz/tempo/pull/3501))
- Bump alloy to 2.0.0, reth to rev `bfb7ab7`, and related dependencies (`reth-codecs` 0.2.0, `reth-primitives-traits` 0.2.0, `alloy-evm` 0.31.0, `revm-inspectors` 0.37.0). Adapt code for upstream API changes including the `TransactionBuilder`/`NetworkTransactionBuilder` trait split, new `BlockHeader` methods (`block_access_list_hash`, `slot_number`), the `slot_number` field on payload builder attributes, the `ExecutionWitnessMode` parameter on `witness`, and `PartialEq` on `TempoBlockEnv`. (by @0xrusowsky, @figtracer, @stevencartavia [#3569](https://github.com/tempoxyz/tempo/pull/3569))

## `tempo-alloy@1.5.1`

### Patch Changes

- Add call-scope support to keychain SDK: `authorize_key`, `revoke_key`, `set_allowed_calls`, `CallScopeBuilder`, and `KeyRestrictions` builders. Extend `TempoTransactionRequest` with key-type, key-data, and key-authorization builder methods. (by @0xrusowsky, [#3495](https://github.com/tempoxyz/tempo/pull/3495))
