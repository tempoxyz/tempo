# Changelog

## `tempo-primitives@2.0.0`

### Minor Changes

- Added `tempo_primitives::account::{encode_config_commitment, decode_config_commitment}`, the TIP-1108 account configuration commitment codec. (by @hamdiallam, [#8787](https://github.com/tempoxyz/tempo/pull/8787))
- Derived configurable account addresses as the last 20 bytes of the keccak of the initial configuration (TIP-1110), and added `ConfigurableAccountConfig::derivation_gas` for the gas of that hash. (by @hamdiallam, [#8787](https://github.com/tempoxyz/tempo/pull/8787))
- From T14 a configurable account can act as an access key. A V2 `KeychainSignature` now carries an `AccountSignature`: a primitive approval or the delegate's owner quorum. `SignatureType::ConfigurableAccount` (3) names such a delegate in a key authorization, which is rejected before T14. The handler checks the delegate's account, code and configuration commitment, registers it on first use and charges its account access; a primitive key whose ID has since migrated accepts its owner quorum. Gas estimation rejects a configurable key type without a configuration witness, the signature verifier rejects configurable keychain signatures, and zones reject configurable delegates. (by @hamdiallam, [#8787](https://github.com/tempoxyz/tempo/pull/8787))
- From T14 a configurable account can sign key authorizations. `SignedKeyAuthorization.signature` is now an `AccountSignature`: a primitive root signature or the account's owner quorum, with the same wire encoding. `SignedKeyAuthorization::authorizing_account` returns the named configurable account, and `recover_signer` fails for one. Sender recovery verifies the grant's owner quorum, and the handler checks the grant account's code and configuration commitment and registers it on first use. The Tempo Accounts store persists configurable-signed key authorizations, and zones reject them. (by @hamdiallam, [#8787](https://github.com/tempoxyz/tempo/pull/8787))
- Signer recovery now verifies configurable account owner quorums: `TempoSignature::recover_signer` returns a recovery error for invalid approvals. `ConfigurableAccountSignature` caches the last verified digest, so `verify_approvals` of an already recovered signature is free, and gains `recover_account`. (by @hamdiallam, [#8787](https://github.com/tempoxyz/tempo/pull/8787))
- From T14 a configurable account can send its own transactions: `TempoSignature::ConfigurableAccount` (type byte `0x05`) carries the owner quorum, the handler checks the account, its code and its configuration commitment, registers the account on first use and verifies the quorum, and a configurable sender can rotate its owners with `updateConfig`. `TempoSignature::signature_type` is now `primitive_signature_type` and returns `None` for a configurable account signature, and `TempoInvalidTransaction::ConfigurableAccount` reports the new `ConfigurableAccountError`. Zones reject configurable account signatures and calls that configure an account. (by @hamdiallam, [#8787](https://github.com/tempoxyz/tempo/pull/8787))
- Added `ConfigurableAccountSignature::verify_approvals` and `ConfigurableAccountSignature::validate_account_commitment`, which check owner approvals and the account commitment without reading state, along with `ConfigurableAccountStateError`, `ConfigurableAccountQuorumError::OwnerSignatureRecoveryFailed` and `CONFIGURABLE_ACCOUNT_UPGRADE_DOMAIN`. Transaction signatures do not accept configurable account signatures yet. (by @hamdiallam, [#8787](https://github.com/tempoxyz/tempo/pull/8787))
- Added configurable account primitives: `ConfigurableAccountOwner`, `ConfigurableAccountConfig` and `ConfigurableAccountSignature`, with their encoding, account derivation, configuration commitments and owner-quorum weight accounting. Transaction signatures do not accept them yet. (by @hamdiallam, [#8787](https://github.com/tempoxyz/tempo/pull/8787))
- Moved EVM execution from revm and alloy-evm to evm2 and removed the `tempo-revm` crate. `tempo-hardfork`, `tempo-primitives` and `tempo-chainspec` expose evm2 types behind their `evm` features in place of their revm and alloy-evm equivalents. `tempo-alloy` drops its `revm` feature and `TempoTransactionRequest::try_into_tempo_tx_env`; its `reth` feature now converts requests into evm2 transaction environments. (by @hamdiallam, [#8787](https://github.com/tempoxyz/tempo/pull/8787))

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
