# Changelog

## `tempo-alloy@2.0.0`

### Minor Changes

- Added `tempo_alloy::test_utils::CallBuilderExt` behind the `test-utils` feature: `mined()` sends a contract call and returns its receipt without checking its status. (by @0xrusowsky, [#9327](https://github.com/tempoxyz/tempo/pull/9327))
- From T14 RPC simulation can model configurable account owner quorums. `TempoTransactionRequest` gains `configurableAccountSimulation`, the claimed quorum of the sender or of the `keyId` delegate, and `keyAuthorizationSimulation`, the claimed quorum of the parent or admin signing the attached key authorization. Simulation checks the claimed approvals against the configuration and builds mock owner signatures in their place, verifies the owner quorum of a configurable-signed key authorization sent without one, and refuses to sign a request that carries either field. (by @joshieDo, [#8765](https://github.com/tempoxyz/tempo/pull/8765))
- `TempoProviderExt` methods no longer use `async_trait`: they return an opaque `impl Future` (`Send` on native targets) instead of `Pin<Box<dyn Future>>`. The returned futures are not `Unpin`, so callers that store, `select` or `poll_unpin` them must `Box::pin` them first. (by Matthias Seitz, [#9304](https://github.com/tempoxyz/tempo/pull/9304))
- Moved EVM execution from revm and alloy-evm to evm2 and removed the `tempo-revm` crate. `tempo-hardfork`, `tempo-primitives` and `tempo-chainspec` expose evm2 types behind their `evm` features in place of their revm and alloy-evm equivalents. `tempo-alloy` drops its `revm` feature and `TempoTransactionRequest::try_into_tempo_tx_env`; its `reth` feature now converts requests into evm2 transaction environments. (by Arsenii Kulikov, [#7871](https://github.com/tempoxyz/tempo/pull/7871))
- `TempoNetwork`'s recommended fillers now use `TempoNonceFiller`, which fills a transaction with a non-zero `nonce_key` from that nonce key's sequence instead of the protocol pending nonce. `RecommendedFillers` changed from `TempoFillers<NonceFiller>` to `TempoFillers<TempoNonceFiller>`. (by @onbjerg, [#8888](https://github.com/tempoxyz/tempo/pull/8888))

### Patch Changes

- `TempoNetwork::build_unsigned` refuses to build an AA transaction whose `max_priority_fee_per_gas` exceeds its `max_fee_per_gas`, or that fails `TempoTransaction::validate`, so it is never signed. (by @brendanjryan, [#8819](https://github.com/tempoxyz/tempo/pull/8819))
- Used alloy's `encoded_2718` and `alloy_rlp::encode` helpers instead of filling buffers by hand. (by @joshieDo, [#8842](https://github.com/tempoxyz/tempo/pull/8842))
- Used alloy's U256, B256 and Bytes conversion helpers instead of hand-written conversions. (by @joshieDo, [#8844](https://github.com/tempoxyz/tempo/pull/8844))
- Boxed transports with alloy's `Transport::boxed`. (by @joshieDo, [#8846](https://github.com/tempoxyz/tempo/pull/8846))
- From T14 a configurable account can act as an access key. A V2 `KeychainSignature` now carries an `AccountSignature`: a primitive approval or the delegate's owner quorum. `SignatureType::ConfigurableAccount` (3) names such a delegate in a key authorization, which is rejected before T14. The handler checks the delegate's account, code and configuration commitment, registers it on first use and charges its account access; a primitive key whose ID has since migrated accepts its owner quorum. Gas estimation rejects a configurable key type without a configuration witness, the signature verifier rejects configurable keychain signatures, and zones reject configurable delegates. (by @joshieDo, [#8750](https://github.com/tempoxyz/tempo/pull/8750))
- From T14 a configurable account can sign key authorizations. `SignedKeyAuthorization.signature` is now an `AccountSignature`: a primitive root signature or the account's owner quorum, with the same wire encoding. `SignedKeyAuthorization::authorizing_account` returns the named configurable account, and `recover_signer` fails for one. Sender recovery verifies the grant's owner quorum, and the handler checks the grant account's code and configuration commitment and registers it on first use. The Tempo Accounts store persists configurable-signed key authorizations, and zones reject them. (by @joshieDo, [#8755](https://github.com/tempoxyz/tempo/pull/8755))
- From T14 a primitive key of an account with a configuration commitment can no longer act as the transaction sender, key authorization signer, fee payer or access key: the transaction is rejected with `TempoInvalidTransaction::RootKeyRetired` (role in `RootKeyRole`). Each distinct non-sender role account costs one account access, so a sponsored transaction pays one more cold access; `eth_estimateGas` and `eth_fillTransaction` add it for a request carrying the fee payer marker, `TempoGasFiller` adds it when it fills such a request, and `account_access_gas` is exported. (by @joshieDo, [#8746](https://github.com/tempoxyz/tempo/pull/8746))
- Moved function-local `use`s to module scope. No public API or behavior changes. (by @joshieDo, [#8920](https://github.com/tempoxyz/tempo/pull/8920))
- Fixed `eth_simulateV1` rejecting every AA batch with "only one CREATE call is allowed per transaction" by no longer appending the filled-in `Create` destination to the batch's calls. (by Matthias Seitz, [#9062](https://github.com/tempoxyz/tempo/pull/9062))
- `SponsorFiller` marks a request before the other fillers prepare, and `TempoGasFiller` estimates a sponsored request without its fees, so an unfunded sender no longer fails gas estimation when it sets `max_fee_per_gas`.
- Because the marker is now set in `fill_sync`, every filler's `prepare` sees `FEE_PAYER_SIGNATURE_MARKER` on a sponsored request:
- A custom filler that sends the request to a node in `prepare` (such as `eth_call` or `eth_estimateGas`) now sends the marker, which nodes before T14 reject. Strip it in that filler, as `TempoGasFiller` does.
- A sponsored request is treated as a Tempo AA request from the start, so `TempoGasFiller` waits for `chain_id` and `from`, and refuses a legacy `gas_price` in `prepare` with `LegacyGasPriceUnsupported` instead of later. (by @onbjerg, [#9165](https://github.com/tempoxyz/tempo/pull/9165))
- Fixed `eth_estimateGas` and `eth_fillTransaction` under-estimating gas for WebAuthn senders: the mock signature now prices its authenticator data as nonzero bytes. (by @joshieDo, [#8793](https://github.com/tempoxyz/tempo/pull/8793))

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
