use super::*;
use crate::{
    TempoBlockEnv, TempoEvm, TempoEvmExt, build_tempo_evm, signature_gas::calldata_tokens,
};
use alloy_consensus::transaction::Recovered;
use alloy_primitives::{Bytes, Signature};
use alloy_signer::SignerSync;
use alloy_signer_local::PrivateKeySigner;
use evm2::{
    evm::{InMemoryDB, precompile::NoPrecompiles},
    interpreter::gas::STANDARD_TOKEN_COST,
};
use reth_primitives_traits::SignedTransaction as _;
use std::iter::repeat_with;
use tempo_precompiles::{
    signature_verifier::configurable_account_verification_gas, storage::keccak_cost,
};
use tempo_primitives::{
    TempoTxEnvelope,
    account::encode_config_commitment,
    transaction::{
        AccountSignature, CONFIGURABLE_ACCOUNT_CONFIG_DOMAIN, CONFIGURABLE_ACCOUNT_DOMAIN,
        CONFIGURABLE_ACCOUNT_SIGNATURE_DOMAIN, Call, ConfigurableAccountConfig,
        ConfigurableAccountOwner, ConfigurableAccountQuorumError, KeyAuthorization,
        MAX_CONFIGURABLE_ACCOUNT_OWNERS, PrimitiveSignature, TEMPO_EXPIRING_NONCE_KEY,
        TempoTransaction, configurable_account_digest,
    },
};

mod cost;
mod native_access;
mod registration;

const FACTORY: Address = Address::repeat_byte(0x71);

/// A one-owner, threshold-one account configuration and its owner key.
struct Native {
    key: PrivateKeySigner,
    config: ConfigurableAccountConfig,
}

impl Native {
    fn new(key: PrivateKeySigner) -> Self {
        let config = ConfigurableAccountConfig {
            salt: B256::ZERO,
            version: 0,
            threshold: 1,
            owners: vec![ConfigurableAccountOwner {
                owner: key.address(),
                weight: 1,
            }],
        };
        Self { key, config }
    }

    fn random() -> Self {
        Self::new(PrivateKeySigner::random())
    }

    fn account(&self) -> Address {
        self.config.derive_account(FACTORY).unwrap()
    }

    /// Signs `inner_digest` with the owner key under this account's domain separation.
    fn sign(&self, inner_digest: B256) -> ConfigurableAccountSignature {
        let account = self.account();
        let approval = self
            .key
            .sign_hash_sync(&configurable_account_digest(
                inner_digest,
                account,
                self.config.version,
            ))
            .unwrap();
        ConfigurableAccountSignature::try_new(
            account,
            self.config.clone(),
            vec![PrimitiveSignature::Secp256k1(approval)],
        )
        .unwrap()
    }

    /// Builds an environment whose outer signature is this account, signed over the final
    /// transaction digest.
    fn env(&self, tx: TempoTransaction) -> TempoTxEnv {
        self.env_for(self.account(), tx)
    }

    /// Builds an environment for `caller` whose outer signature is this account over `tx`.
    fn env_for(&self, caller: Address, tx: TempoTransaction) -> TempoTxEnv {
        let signature = self.sign(tx.signature_hash());
        env(caller, tx, TempoSignature::ConfigurableAccount(signature))
    }
}

fn base_tx() -> TempoTransaction {
    TempoTransaction {
        chain_id: 1,
        gas_limit: 1_000_000,
        calls: vec![Call {
            to: TxKind::Call(Address::repeat_byte(0x44)),
            value: U256::ZERO,
            input: Bytes::new(),
        }],
        ..Default::default()
    }
}

fn env(caller: Address, tx: TempoTransaction, signature: TempoSignature) -> TempoTxEnv {
    TempoTxEnvelope::AA(tx.into_signed(signature))
        .with_signer(caller)
        .into()
}

fn primitive_signature() -> TempoSignature {
    TempoSignature::from(Signature::test_signature())
}

/// A fresh EVM at `spec` with `factory` configured in the block and `accounts` in the database.
fn evm_with(
    spec: TempoHardfork,
    factory: Option<Address>,
    accounts: &[(Address, AccountInfo)],
) -> TempoEvm<'static> {
    let mut block = TempoBlockEnv::default();
    block.ext.configurable_account_recovery_factory = factory;
    evm_with_block(spec, block, accounts)
}

/// A fresh EVM at `spec` running `block`, with `accounts` in the database.
///
/// The configurable-account hardfork (T14) has no EIP-8037 state gas schedule, so state-gas
/// terms below are `new_account_state_gas()` of the EVM's own gas parameters, zero at T14.
fn evm_with_block(
    spec: TempoHardfork,
    block: TempoBlockEnv,
    accounts: &[(Address, AccountInfo)],
) -> TempoEvm<'static> {
    let mut evm = build_tempo_evm(
        spec,
        1,
        block,
        InMemoryDB::default(),
        NoPrecompiles::default(),
        TempoEvmExt::default(),
    );
    for (address, info) in accounts {
        evm.overlay_db_mut()
            .insert_account_info(address, info.clone());
    }
    evm
}

fn evm(spec: TempoHardfork) -> TempoEvm<'static> {
    evm_with(spec, Some(FACTORY), &[])
}

fn committed(commitment: B256) -> AccountInfo {
    AccountInfo {
        extension: encode_config_commitment(commitment).into(),
        ..Default::default()
    }
}

fn gas_params(evm: &TempoEvm<'_>) -> GasParams {
    evm.version().gas_params
}

fn native_error(error: &HandlerError) -> Option<&ConfigurableAccountError> {
    error
        .external_ref::<TempoInvalidTransaction>()
        .and_then(transaction_native_error)
}

fn transaction_native_error(error: &TempoInvalidTransaction) -> Option<&ConfigurableAccountError> {
    if let TempoInvalidTransaction::ConfigurableAccount(error) = error {
        Some(error)
    } else {
        None
    }
}

#[test]
fn native_hash_gas_layout_matches_all_owner_counts() {
    assert_eq!(CONFIGURABLE_ACCOUNT_DOMAIN.len(), 34);
    assert_eq!(CONFIGURABLE_ACCOUNT_CONFIG_DOMAIN.len(), 33);
    assert_eq!(CONFIGURABLE_ACCOUNT_SIGNATURE_DOMAIN.len(), 36);
    for (count, version) in (1..=MAX_CONFIGURABLE_ACCOUNT_OWNERS)
        .flat_map(|count| [0, 127, 128, 255, 256, u64::MAX].map(|version| (count, version)))
    {
        let config = ConfigurableAccountConfig {
            salt: B256::ZERO,
            version,
            threshold: 1,
            owners: (1..=count)
                .map(|index| ConfigurableAccountOwner {
                    owner: Address::repeat_byte(u8::try_from(index).unwrap()),
                    weight: 1,
                })
                .collect(),
        };
        assert_eq!(config.account_salt_preimage_len(), 68 + 21 * count);
        assert_eq!(config.commitment_preimage_len(), 75 + 21 * count);
        assert_eq!(
            config.account_salt_preimage_len(),
            config.account_salt_preimage().unwrap().len()
        );
        assert_eq!(
            config.commitment_preimage_len(),
            config.commitment_preimage().unwrap().len()
        );
        assert_eq!(
            initial_account_proof_gas(&config).unwrap(),
            keccak_cost(68 + 21 * count).unwrap() + keccak_cost(85).unwrap(),
            "derivation gas for {count} owners"
        );
        let signature = ConfigurableAccountSignature::try_new(
            config.derive_account(FACTORY).unwrap(),
            config.clone(),
            vec![PrimitiveSignature::default()],
        )
        .unwrap();
        let mut witness = alloy_rlp::encode(signature.account());
        witness.extend(alloy_rlp::encode(&config));
        let calldata = calldata_tokens(&witness) * u64::from(STANDARD_TOKEN_COST);
        assert_eq!(
            CONFIGURABLE_ACCOUNT_SIGNATURE_DOMAIN.len() + 32 + 20 + 8,
            96
        );
        assert_eq!(
            configurable_account_verification_gas(&signature).unwrap(),
            calldata + keccak_cost(75 + 21 * count).unwrap() + keccak_cost(96).unwrap() + 3_000,
            "verification gas for {count} owners"
        );
    }
}

#[test]
fn native_authorization_roles_preserve_order_and_duplicate_accounts() {
    // Primitive outer signature and no grant: no native role.
    let primitive = env(Address::repeat_byte(0x11), base_tx(), primitive_signature());
    assert!(
        primitive
            .as_aa()
            .unwrap()
            .native_authorizations()
            .iter()
            .all(Option::is_none)
    );

    // Native outer role only.
    let native = Native::random();
    let caller = native.account();
    let outer_only = native.env(base_tx());
    let roles = outer_only.as_aa().unwrap().native_authorizations();
    assert!(roles[0].is_some());
    assert!(roles[1].is_none());

    // The same account signs the outer role and the inline grant: two separately signed roles.
    let grant = KeyAuthorization::unrestricted(1, SignatureType::ConfigurableAccount, caller);
    let grant_digest = grant.signature_hash();
    let grant_signature = native.sign(grant_digest);
    let mut tx = base_tx();
    tx.nonce_key = TEMPO_EXPIRING_NONCE_KEY;
    tx.key_authorization = Some(grant.into_signed(AccountSignature::ConfigurableAccount(
        grant_signature.clone(),
    )));
    let outer_digest = tx.signature_hash();
    let both = native.env(tx.clone());
    let roles = both.as_aa().unwrap().native_authorizations();
    let outer = roles[0].as_ref().unwrap();
    let grant = roles[1].as_ref().unwrap();
    assert_eq!(outer.signature.account(), grant.signature.account());
    assert_eq!(outer.inner_digest, outer_digest);
    assert_eq!(grant.inner_digest, grant_digest);
    assert_ne!(outer.inner_digest, grant.inner_digest);
    outer.verify().unwrap();
    grant.verify().unwrap();
    let mut evm = evm(TempoHardfork::T14);
    assert_eq!(
        validate_state(&mut evm, &both, TempoHardfork::T14)
            .unwrap()
            .1,
        gas_params(&evm).new_account_state_gas(),
        "two roles for one account create only one leaf"
    );

    // A keychain wrapper signs over the user-bound digest.
    let keychain = env(
        caller,
        tx.clone(),
        TempoSignature::Keychain(KeychainSignature::new(
            caller,
            AccountSignature::ConfigurableAccount(grant_signature),
        )),
    );
    assert_eq!(
        keychain.as_aa().unwrap().native_authorizations()[0]
            .as_ref()
            .unwrap()
            .inner_digest,
        KeychainSignature::signing_hash(outer_digest, caller)
    );

    // Primitive outer signature with a native grant leaves only the grant role.
    let grant_only = env(caller, tx.clone(), primitive_signature());
    let roles = grant_only.as_aa().unwrap().native_authorizations();
    assert!(roles[0].is_none());
    assert!(roles[1].is_some());

    tx.key_authorization = None;
    let none = env(caller, tx, primitive_signature());
    assert!(
        none.as_aa()
            .unwrap()
            .native_authorizations()
            .iter()
            .all(Option::is_none)
    );
}

#[test]
fn native_state_registration_gas_and_registered_v0() {
    let native = Native::random();
    let env = native.env(base_tx());
    let aa = env.as_aa().unwrap();
    let spec = TempoHardfork::T14;

    let mut evm = evm(spec);
    assert_eq!(
        validate_state(&mut evm, &env, spec).unwrap(),
        (
            20_000 + keccak_cost(89).unwrap() + keccak_cost(85).unwrap(),
            0
        )
    );
    verify(env.execution_context(), aa).unwrap();

    let hash = aa.native_authorizations()[0]
        .as_ref()
        .unwrap()
        .signature
        .config_commitment();
    let mut evm = evm_with(spec, Some(FACTORY), &[(native.account(), committed(hash))]);
    assert_eq!(validate_state(&mut evm, &env, spec).unwrap(), (0, 0));

    let mut evm = evm_with(
        spec,
        Some(FACTORY),
        &[(native.account(), committed(B256::repeat_byte(0x99)))],
    );
    let error = validate_state(&mut evm, &env, spec).unwrap_err();
    assert!(
        matches!(
            native_error(&error),
            Some(ConfigurableAccountError::ConfigurationCommitmentMismatch { expected, actual })
                if *expected == B256::repeat_byte(0x99) && *actual == hash
        ),
        "{error:?}"
    );
}

#[test]
fn native_transaction_accepts_threshold_above_eight_with_eight_approvals() {
    let mut owners = repeat_with(PrivateKeySigner::random)
        .take(9)
        .collect::<Vec<_>>();
    owners.sort_by_key(PrivateKeySigner::address);
    let config = ConfigurableAccountConfig {
        salt: B256::ZERO,
        version: 0,
        threshold: 9,
        owners: owners
            .iter()
            .enumerate()
            .map(|(index, signer)| ConfigurableAccountOwner {
                owner: signer.address(),
                weight: if index == 0 { 2 } else { 1 },
            })
            .collect(),
    };
    let account = config.derive_account(FACTORY).unwrap();
    let tx = base_tx();
    let digest = configurable_account_digest(tx.signature_hash(), account, 0);
    let approvals = owners[..8]
        .iter()
        .map(|signer| PrimitiveSignature::Secp256k1(signer.sign_hash_sync(&digest).unwrap()))
        .collect();
    let signature = ConfigurableAccountSignature::try_new(account, config, approvals).unwrap();
    let env = env(account, tx, TempoSignature::ConfigurableAccount(signature));

    validate_state(&mut evm(TempoHardfork::T14), &env, TempoHardfork::T14).unwrap();
    verify(env.execution_context(), env.as_aa().unwrap()).unwrap();
}

#[test]
fn native_contexts_fail_closed_and_simulation_is_explicit() {
    let native = Native::random();
    let account = native.account();
    let env = native.env(base_tx());

    // Before T14 the native signature is rejected before any account is read.
    for spec in [TempoHardfork::T12, TempoHardfork::T13] {
        let mut evm = evm(spec);
        let error = validate_state(&mut evm, &env, spec).unwrap_err();
        assert!(
            matches!(
                native_error(&error),
                Some(ConfigurableAccountError::UnsupportedContext)
            ),
            "{spec:?}: {error:?}"
        );
        assert!(
            !evm.state_mut().account(&account).unwrap().is_warm(),
            "context checks must precede account reads"
        );
    }

    // The signature must name the sender before the factory is consulted.
    let other = Address::repeat_byte(0x99);
    let mismatched = native.env_for(other, base_tx());
    let mut evm = evm_with(TempoHardfork::T14, None, &[]);
    let error = validate_state(&mut evm, &mismatched, TempoHardfork::T14).unwrap_err();
    assert!(
        matches!(
            native_error(&error),
            Some(ConfigurableAccountError::AccountMismatch { expected, actual })
                if *expected == other && *actual == account
        ),
        "{error:?}"
    );

    let error = validate_state(&mut evm, &env, TempoHardfork::T14).unwrap_err();
    assert!(
        matches!(
            native_error(&error),
            Some(ConfigurableAccountError::FactoryNotConfigured)
        ),
        "{error:?}"
    );

    // A quorum over the wrong digest fails in a transaction and is skipped in simulation.
    let tx = base_tx();
    let wrong = env_signed_over(&native, tx, B256::repeat_byte(0x99));
    let error = verify(wrong.execution_context(), wrong.as_aa().unwrap()).unwrap_err();
    assert!(
        matches!(
            transaction_native_error(&error),
            Some(ConfigurableAccountError::Quorum(
                ConfigurableAccountQuorumError::SignerNotOwner
            ))
        ),
        "{error:?}"
    );
    let simulated = wrong.with_simulation_overrides(B256::ZERO, None, None);
    verify(simulated.execution_context(), simulated.as_aa().unwrap()).unwrap();
}

/// Builds an environment signed over `digest` instead of the transaction's own digest.
fn env_signed_over(native: &Native, tx: TempoTransaction, digest: B256) -> TempoTxEnv {
    env(
        native.account(),
        tx,
        TempoSignature::ConfigurableAccount(native.sign(digest)),
    )
}

#[test]
fn native_error_classification_preserves_state_dependent_errors() {
    let address = Address::repeat_byte(0x22);
    for (error, bad) in [
        (
            ConfigurableAccountError::AccountMismatch {
                expected: address,
                actual: Address::ZERO,
            },
            true,
        ),
        (ConfigurableAccountError::InvalidSignatureContext, true),
        (
            ConfigurableAccountError::OwnerSignatureRecoveryFailed { approval_index: 0 },
            true,
        ),
        (ConfigurableAccountError::UnsupportedContext, false),
        (ConfigurableAccountError::FactoryNotConfigured, false),
        (
            ConfigurableAccountError::InvalidAccount { account: address },
            false,
        ),
        (
            ConfigurableAccountError::ConfigurationCommitmentMismatch {
                expected: B256::ZERO,
                actual: B256::repeat_byte(1),
            },
            false,
        ),
    ] {
        let error = TempoInvalidTransaction::ConfigurableAccount(error);
        assert_eq!(error.is_bad_transaction(), bad, "{error}");
    }
}

#[test_case::test_case(8; "invalid_final_signature")]
#[test_case::test_case(1; "excess_valid_approval")]
fn native_approvals_reject_invalid_quorums(threshold: u8) {
    let mut owners = repeat_with(PrivateKeySigner::random)
        .take(if threshold == 1 { 2 } else { 8 })
        .collect::<Vec<_>>();
    owners.sort_by_key(PrivateKeySigner::address);
    let config = ConfigurableAccountConfig {
        salt: B256::ZERO,
        version: 0,
        threshold,
        owners: owners
            .iter()
            .map(|signer| ConfigurableAccountOwner {
                owner: signer.address(),
                weight: 1,
            })
            .collect(),
    };
    let account = config.derive_account(FACTORY).unwrap();
    let inner_digest = B256::repeat_byte(0x42);
    let digest = configurable_account_digest(inner_digest, account, 0);
    let mut signatures = owners
        .iter()
        .map(|signer| PrimitiveSignature::Secp256k1(signer.sign_hash_sync(&digest).unwrap()))
        .collect::<Vec<_>>();
    let signature = ConfigurableAccountSignature::try_new(
        account,
        config.clone(),
        signatures[..threshold as usize].to_vec(),
    )
    .unwrap();
    NativeAuthorization {
        signature: &signature,
        inner_digest,
    }
    .verify()
    .unwrap();
    if threshold == 1 {
        // Both approvals recover ordered configured owners; only the extra
        // approval after the first owner's quorum makes this witness invalid.
        for (approval, owner) in signatures.iter().zip(&owners) {
            assert_eq!(approval.recover_signer(&digest).unwrap(), owner.address());
        }
    } else {
        signatures[7] =
            PrimitiveSignature::Secp256k1(owners[7].sign_hash_sync(&B256::ZERO).unwrap());
    }
    let signature = ConfigurableAccountSignature::try_new(account, config, signatures).unwrap();
    let result = NativeAuthorization {
        signature: &signature,
        inner_digest,
    }
    .verify();
    if threshold == 1 {
        assert!(
            matches!(
                result,
                Err(ConfigurableAccountError::Quorum(
                    ConfigurableAccountQuorumError::ExcessSignatures
                ))
            ),
            "{result:?}"
        );
    } else {
        assert!(result.is_err(), "{result:?}");
    }
}
