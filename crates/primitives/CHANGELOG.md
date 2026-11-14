# Changelog

## `tempo-primitives@2.0.0`

### Minor Changes

- Added `AASigned::configurable_account_signatures`, which returns the configurable account signatures approving a transaction: the outer signature, directly or inside a keychain envelope, then the inline key authorization's. (by Tanishk Goyal, [#9132](https://github.com/tempoxyz/tempo/pull/9132))
- Added `tempo_primitives::account::{encode_config_commitment, decode_config_commitment}`, the TIP-1108 account configuration commitment codec. (by @joshieDo, [#8474](https://github.com/tempoxyz/tempo/pull/8474))
- Added `Call::new(to, input)`, which builds a zero-value `Call`. (by @0xrusowsky, [#9313](https://github.com/tempoxyz/tempo/pull/9313))
- Derived configurable account addresses as the last 20 bytes of the keccak of the initial configuration (TIP-1110), and added `ConfigurableAccountConfig::derivation_gas` for the gas of that hash. (by @joshieDo, [#8741](https://github.com/tempoxyz/tempo/pull/8741))
- From T14 a configurable account can act as an access key. A V2 `KeychainSignature` now carries an `AccountSignature`: a primitive approval or the delegate's owner quorum. `SignatureType::ConfigurableAccount` (3) names such a delegate in a key authorization, which is rejected before T14. The handler checks the delegate's account, code and configuration commitment, registers it on first use and charges its account access; a primitive key whose ID has since migrated accepts its owner quorum. Gas estimation rejects a configurable key type without a configuration witness, the signature verifier rejects configurable keychain signatures, and zones reject configurable delegates. (by @joshieDo, [#8750](https://github.com/tempoxyz/tempo/pull/8750))
- From T14 a configurable account can sign key authorizations. `SignedKeyAuthorization.signature` is now an `AccountSignature`: a primitive root signature or the account's owner quorum, with the same wire encoding. `SignedKeyAuthorization::authorizing_account` returns the named configurable account, and `recover_signer` fails for one. Sender recovery verifies the grant's owner quorum, and the handler checks the grant account's code and configuration commitment and registers it on first use. The Tempo Accounts store persists configurable-signed key authorizations, and zones reject them. (by @joshieDo, [#8755](https://github.com/tempoxyz/tempo/pull/8755))
- Signer recovery now verifies configurable account owner quorums: `TempoSignature::recover_signer` returns a recovery error for invalid approvals. `ConfigurableAccountSignature` caches the last verified digest, so `verify_approvals` of an already recovered signature is free, and gains `recover_account`. (by @joshieDo, [#8750](https://github.com/tempoxyz/tempo/pull/8750))
- From T14 a configurable account can send its own transactions: `TempoSignature::ConfigurableAccount` (type byte `0x05`) carries the owner quorum, the handler checks the account, its code and its configuration commitment, registers the account on first use and verifies the quorum, and a configurable sender can rotate its owners with `updateConfig`. `TempoSignature::signature_type` is now `primitive_signature_type` and returns `None` for a configurable account signature, and `TempoInvalidTransaction::ConfigurableAccount` reports the new `ConfigurableAccountError`. Zones reject configurable account signatures and calls that configure an account. (by @joshieDo, [#8750](https://github.com/tempoxyz/tempo/pull/8750))
- Added `ConfigurableAccountSignature::verify_approvals` and `ConfigurableAccountSignature::validate_account_commitment`, which check owner approvals and the account commitment without reading state, along with `ConfigurableAccountStateError`, `ConfigurableAccountQuorumError::OwnerSignatureRecoveryFailed` and `CONFIGURABLE_ACCOUNT_UPGRADE_DOMAIN`. Transaction signatures do not accept configurable account signatures yet. (by @joshieDo, [#8502](https://github.com/tempoxyz/tempo/pull/8502))
- Added configurable account primitives: `ConfigurableAccountOwner`, `ConfigurableAccountConfig` and `ConfigurableAccountSignature`, with their encoding, account derivation, configuration commitments and owner-quorum weight accounting. Transaction signatures do not accept them yet. (by @joshieDo, [#8502](https://github.com/tempoxyz/tempo/pull/8502))
- Moved EVM execution from revm and alloy-evm to evm2 and removed the `tempo-revm` crate. `tempo-hardfork`, `tempo-primitives` and `tempo-chainspec` expose evm2 types behind their `evm` features in place of their revm and alloy-evm equivalents. `tempo-alloy` drops its `revm` feature and `TempoTransactionRequest::try_into_tempo_tx_env`; its `reth` feature now converts requests into evm2 transaction environments. (by Arsenii Kulikov, [#7871](https://github.com/tempoxyz/tempo/pull/7871))
- Added `tt_signature::p256_keypair` behind the `test-utils` feature: a random P256 signing key with its public key coordinates and derived address. (by @0xrusowsky, [#9327](https://github.com/tempoxyz/tempo/pull/9327))
- Added `tempo_primitives::test_utils` behind the `test-utils` feature: `actors`, `actors_vec` and `amounts`, drawn from a per-thread test RNG seeded from `TEMPO_TEST_SEED` (or randomly, printing the seed on panic so failures replay). (by @0xrusowsky, [#9312](https://github.com/tempoxyz/tempo/pull/9312))
- Added `signers` and `signers_vec` to `tempo_primitives::test_utils`: private-key signers drawn from the same seeded test RNG as `actors` and `amounts`. (by @0xrusowsky, [#9326](https://github.com/tempoxyz/tempo/pull/9326))
- Added `TempoEvmKind`, the kind of Tempo EVM (L1 or zone), which fixes the protocol rules that differ between Tempo and its zones. `TempoEvmExt::new(kind, fee_manager)` replaces `TempoEvmExt::with_fee_manager`, and `PrecompileStorageProvider::kind` replaces `set_revert_blocked_inbound` and `revert_blocked_inbound`. Blocked TIP-1028 inbounds now revert in every storage context over a zone EVM, not only inside zone precompile calls from T15; before T15 no zone path could reach a blocked inbound, so historical execution is unchanged. `TIP20Token::mint_with_role` is removed: TIP-20 mints on zones authorize recipients with TIP-403 `Recipient` from T13 on their own. (by @0xrusowsky, [#8987](https://github.com/tempoxyz/tempo/pull/8987))

### Patch Changes

- Built signed transactions with `SignableTransaction::into_signed` instead of `Signed::new_unhashed` (same lazy hashing). (by @joshieDo, [#8839](https://github.com/tempoxyz/tempo/pull/8839))
- Used `alloy_rlp::encode` and the RLP header length helper instead of hand-rolled encoding, without changing encodings. (by @joshieDo, [#8841](https://github.com/tempoxyz/tempo/pull/8841))
- Used alloy's U256, B256 and Bytes conversion helpers instead of hand-written conversions. (by @joshieDo, [#8844](https://github.com/tempoxyz/tempo/pull/8844))
- `TempoTxEnvelope::size` counts the full inline enum for every transaction type, so legacy, EIP-2930, EIP-1559 and EIP-7702 transactions are no longer reported at about a quarter of their in-memory size. (by Matthias Seitz, [#9330](https://github.com/tempoxyz/tempo/pull/9330))
- Moved function-local `use`s to module scope. No public API or behavior changes. (by @joshieDo, [#8920](https://github.com/tempoxyz/tempo/pull/8920))

## `tempo-primitives@1.16.0`


## `tempo-primitives@1.11.0`

### Minor Changes

- Added the T10 hardfork and moved TIP-1091 activation (ZoneFactory precompile and shared Zone runtime installation) from T9 to T10, so the ZonePortal runtime can still change after the audit without reopening T9. (by @HamdiAllam, [#7244](https://github.com/tempoxyz/tempo/pull/7244))
- Implemented TIP-1093 by extending the expiring nonce validity window to five minutes and the replay-protection ring to 3,000,000 entries at T11 activation. (by @HamdiAllam, [#7244](https://github.com/tempoxyz/tempo/pull/7244))

## `tempo-primitives@1.10.1`


## `tempo-primitives@1.10.0`

### Minor Changes

- Bump the Tempo SDK crate set to the `1.10` minor release. (by @DerekCofausper, [#6610](https://github.com/tempoxyz/tempo/pull/6610))

## `tempo-primitives@1.9.1`

### Patch Changes

- Moved `SYSTEM_PRECOMPILES` from `tempo-precompiles` to `tempo-contracts` and replaced the `is_precompile_address` function with an `is_precompile` method on the `TempoAddressExt` trait in `tempo-primitives`. (by @DerekCofausper, [#6535](https://github.com/tempoxyz/tempo/pull/6535))

## `tempo-primitives@1.9.0`

### Minor Changes

- Extracts Tempo hardfork definitions and activation schedules into a new `tempo-hardfork` crate for SDK reuse without chainspec dependencies.
- Updates `tempo-alloy` to depend on and re-export `tempo-hardfork` instead of `tempo-chainspec`. (by @DerekCofausper, [#6480](https://github.com/tempoxyz/tempo/pull/6480))

## `tempo-primitives@1.8.1`


## `tempo-primitives@1.8.0`

### Minor Changes

- Added T6 admin access key support for account keychain authorization and SDK transaction builders. (by @DerekCofausper, [#4650](https://github.com/tempoxyz/tempo/pull/4650))

### Patch Changes

- Reject channel reserve payment-lane calls with malformed Tempo signature encodings. (by @DerekCofausper, [#4650](https://github.com/tempoxyz/tempo/pull/4650))

## `tempo-primitives@1.7.3`


## `tempo-primitives@1.7.2`

### Patch Changes

- Bumped alloy to `2.0.5` and updated transitive dependencies.
- Dropped constructor helpers in favor of the newly auto-generated ones by the `sol!` macro. (by @ArseniiKulikov, [#4058](https://github.com/tempoxyz/tempo/pull/4058))

## `tempo-primitives@1.7.0`

### Minor Changes

- Enshrined the stricter TIP-1045 payment classifier (`is_payment_v2`) at the T5 hardfork for consensus-level payment lane validation. Relaxed the v2 classifier to allow bounded `key_authorization` (RLP length ≤ 1024 bytes). (by @DerekCofausper, [#4019](https://github.com/tempoxyz/tempo/pull/4019))
- Moved TIP-20 and TIP-1022 virtual-address helpers (`is_tip20_prefix`, `is_virtual_address`, `decode_virtual_address`, `make_virtual_address`, `MasterId`, `UserTag`) from `tempo-precompiles` into a new `TempoAddressExt` trait on `Address` in `tempo-primitives`. Updated all consumers to use the new trait methods (`address.is_tip20()`, `address.is_virtual()`, `Address::new_virtual(...)`, etc.). (by @DerekCofausper, [#4019](https://github.com/tempoxyz/tempo/pull/4019))

## `tempo-primitives@1.6.0`

### Minor Changes

- Store `TempoTransaction.valid_before` and `valid_after` as `Option<NonZeroU64>` so omitted validity bounds remain distinct from zero in RLP and serde handling. Reject zero-valued validity bounds when building AA transactions from `TempoTransactionRequest`. (by @legion2002, [#3501](https://github.com/tempoxyz/tempo/pull/3501))

### Patch Changes

- Bump alloy to 2.0.0, reth to rev `bfb7ab7`, and related dependencies (`reth-codecs` 0.2.0, `reth-primitives-traits` 0.2.0, `alloy-evm` 0.31.0, `revm-inspectors` 0.37.0). Adapt code for upstream API changes including the `TransactionBuilder`/`NetworkTransactionBuilder` trait split, new `BlockHeader` methods (`block_access_list_hash`, `slot_number`), the `slot_number` field on payload builder attributes, the `ExecutionWitnessMode` parameter on `witness`, and `PartialEq` on `TempoBlockEnv`. (by @0xrusowsky, @figtracer, @stevencartavia [#3569](https://github.com/tempoxyz/tempo/pull/3569))

## `tempo-primitives@1.5.1`

### Patch Changes

- Add call-scope support to keychain SDK: `authorize_key`, `revoke_key`, `set_allowed_calls`, `CallScopeBuilder`, and `KeyRestrictions` builders. Extend `TempoTransactionRequest` with key-type, key-data, and key-authorization builder methods. (by @0xrusowsky, [#3495](https://github.com/tempoxyz/tempo/pull/3495))
- Implement TIP-1011 enhanced access key permissions with exact permission matching for keychain operations. (by @0xrusowsky, [#3495](https://github.com/tempoxyz/tempo/pull/3495))
