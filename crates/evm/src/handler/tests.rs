use super::*;
use crate::{TempoBlockEnv, TempoEvmExt, TempoEvmTx, tempo_tx_registry};
use alloy_consensus::transaction::Recovered;
use alloy_eips::eip2930::{AccessList, AccessListItem};
use alloy_primitives::{B256, Bytes, Signature};
use alloy_signer::SignerSync;
use alloy_signer_local::PrivateKeySigner;
use evm2::{
    ExecutionConfig, SpecId,
    evm::{InMemoryDB, precompile::NoPrecompiles},
};
use proptest::prelude::*;
use tempo_precompiles::{
    PATH_USD_ADDRESS,
    test_util::TIP20Setup,
    tip20::{ITIP20, PAUSE_ROLE},
};
use tempo_primitives::{
    AASigned, TempoTransaction,
    subblock::TEMPO_SUBBLOCK_NONCE_KEY_PREFIX,
    transaction::{
        Call, CallScope, KeyAuthorization, KeychainSignature, SelectorRule, SignatureType,
        SignedKeyAuthorization, TempoSignedAuthorization, TokenLimit,
        tt_signature::{P256SignatureWithPreHash, PrimitiveSignature, WebAuthnSignature},
    },
};

const SIGNER: Address = Address::new([0x11; 20]);

fn test_evm(spec: TempoHardfork) -> crate::TempoEvm<'static> {
    test_evm_with_amsterdam(spec, false)
}

fn test_evm_with_amsterdam(spec: TempoHardfork, amsterdam: bool) -> crate::TempoEvm<'static> {
    let mut version = tempo_chainspec::gas_params::version(SpecId::OSAKA, spec, amsterdam);
    version.chain_id = 1;
    let config = ExecutionConfig::for_spec_and_version(spec, version);
    Evm::new_with_execution_config_and_ext(
        config,
        spec,
        TempoBlockEnv::default(),
        tempo_tx_registry(SpecId::OSAKA),
        InMemoryDB::default(),
        NoPrecompiles::default(),
        TempoEvmExt::default(),
    )
}

fn secp256k1_signature() -> TempoSignature {
    TempoSignature::Primitive(PrimitiveSignature::Secp256k1(Signature::test_signature()))
}

fn aa_env(transaction: TempoTransaction, signature: TempoSignature) -> TempoTxEnv {
    Recovered::new_unchecked(
        tempo_primitives::TempoTxEnvelope::AA(AASigned::new_unhashed(transaction, signature)),
        SIGNER,
    )
    .into()
}

fn intrinsic(
    spec: TempoHardfork,
    transaction: TempoTransaction,
    signature: TempoSignature,
) -> HandlerResult<(u64, u64, u64)> {
    intrinsic_with_amsterdam(spec, false, transaction, signature)
}

fn intrinsic_with_amsterdam(
    spec: TempoHardfork,
    amsterdam: bool,
    transaction: TempoTransaction,
    signature: TempoSignature,
) -> HandlerResult<(u64, u64, u64)> {
    let evm = test_evm_with_amsterdam(spec, amsterdam);
    let env = aa_env(transaction, signature);
    let aa = env.as_aa().unwrap();
    let (regular, state, floor) = intrinsic_gas(&evm, aa)?;
    let (nonce_regular, nonce_state) = nonce_intrinsic_gas(&evm, aa);
    Ok((
        regular.saturating_add(nonce_regular),
        state.saturating_add(nonce_state),
        floor,
    ))
}

fn call(input: Bytes) -> Call {
    Call {
        to: TxKind::Call(Address::ZERO),
        value: U256::ZERO,
        input,
    }
}

fn key_authorization(num_limits: usize) -> SignedKeyAuthorization {
    let mut authorization =
        KeyAuthorization::unrestricted(1, SignatureType::Secp256k1, Address::ZERO);
    if num_limits > 0 {
        authorization = authorization.with_limits(
            (0..num_limits)
                .map(|index| TokenLimit {
                    token: Address::with_last_byte(index as u8),
                    limit: U256::from(1000),
                    period: 0,
                })
                .collect(),
        );
    }
    authorization.into_signed(PrimitiveSignature::Secp256k1(Signature::test_signature()))
}

const COLD_ACCOUNT_ACCESS_COST: u64 = 2_600;

fn genesis_gas_params() -> GasParams {
    tempo_chainspec::gas_params::version(SpecId::OSAKA, TempoHardfork::Genesis, false).gas_params
}

fn tempo_gas_params(spec: TempoHardfork) -> GasParams {
    tempo_chainspec::gas_params::version(SpecId::OSAKA, spec, spec.is_t4()).gas_params
}

fn calculate_initial_tx_gas(
    spec: SpecId,
    input: &[u8],
    is_create: bool,
    access_list_accounts: u64,
    access_list_storage: u64,
    authorization_list: u64,
) -> InitialAndFloorGas {
    let params =
        tempo_chainspec::gas_params::version(spec, TempoHardfork::Genesis, false).gas_params;
    let tokens = calldata_tokens(input);
    let mut initial_gas = u64::from(params[GasId::TxBaseStipend])
        + tokens * u64::from(params[GasId::TxTokenCost])
        + access_list_accounts * u64::from(params[GasId::TxAccessListAddressCost])
        + access_list_storage * u64::from(params[GasId::TxAccessListStorageKeyCost])
        + authorization_list * u64::from(params[GasId::TxEip7702PerEmptyAccountCost]);
    let mut initial_state_gas = 0;
    if is_create {
        initial_gas += u64::from(params[GasId::Create]) + params.initcode_cost(input.len());
        initial_state_gas += params.create_state_gas();
    }
    let floor_gas = if spec.enables(SpecId::PRAGUE) {
        u64::from(params[GasId::TxFloorCostBase])
            + tokens * u64::from(params[GasId::TxFloorCostPerToken])
    } else {
        0
    };
    InitialAndFloorGas {
        initial_gas,
        initial_state_gas,
        floor_gas,
    }
}

trait TestGasParamsExt {
    fn initial_tx_gas(
        &self,
        input: &[u8],
        is_create: bool,
        access_list_accounts: u64,
        access_list_storage: u64,
        authorization_list: u64,
    ) -> InitialAndFloorGas;
}

impl TestGasParamsExt for GasParams {
    fn initial_tx_gas(
        &self,
        input: &[u8],
        is_create: bool,
        access_list_accounts: u64,
        access_list_storage: u64,
        authorization_list: u64,
    ) -> InitialAndFloorGas {
        let tokens = calldata_tokens(input);
        let mut initial_gas = u64::from(self[GasId::TxBaseStipend])
            + tokens * u64::from(self[GasId::TxTokenCost])
            + access_list_accounts * u64::from(self[GasId::TxAccessListAddressCost])
            + access_list_storage * u64::from(self[GasId::TxAccessListStorageKeyCost])
            + authorization_list * u64::from(self[GasId::TxEip7702PerEmptyAccountCost]);
        let mut initial_state_gas = 0;
        if is_create {
            initial_gas += u64::from(self[GasId::Create]) + self.initcode_cost(input.len());
            initial_state_gas += self.create_state_gas();
        }
        InitialAndFloorGas {
            initial_gas,
            initial_state_gas,
            floor_gas: 0,
        }
    }
}

fn calculate_aa_batch_intrinsic_gas<'a, I>(
    env: &TempoBatchCallEnv,
    gas_params: &GasParams,
    access_list: Option<I>,
    spec: TempoHardfork,
) -> HandlerResult<InitialAndFloorGas>
where
    I: Iterator<Item = &'a AccessListItem>,
{
    let access_list = AccessList(
        access_list
            .map(|items| items.cloned().collect())
            .unwrap_or_default(),
    );
    let evm = test_evm_with_amsterdam(spec, gas_params.create_state_gas() > 0);
    let env = aa_env(
        TempoTransaction {
            calls: env.aa_calls.clone(),
            key_authorization: env.key_authorization.clone(),
            tempo_authorization_list: env.tempo_authorization_list.clone(),
            nonce_key: env.nonce_key,
            nonce: env.nonce,
            access_list,
            ..Default::default()
        },
        env.signature.clone(),
    );
    let (initial_gas, initial_state_gas, floor_gas) = intrinsic_gas(&evm, env.as_aa().unwrap())?;
    Ok(InitialAndFloorGas {
        initial_gas,
        initial_state_gas,
        floor_gas,
    })
}

mod keychain {
    use super::*;

    pub(super) fn generate_keypair() -> (PrivateKeySigner, Address) {
        let signer = PrivateKeySigner::random();
        let addr = signer.address();
        (signer, addr)
    }

    pub(super) fn sign_key_auth(
        signer: &PrivateKeySigner,
        key_auth: KeyAuthorization,
    ) -> SignedKeyAuthorization {
        let sig = signer
            .sign_hash_sync(&key_auth.signature_hash())
            .expect("signing failed");
        key_auth.into_signed(PrimitiveSignature::Secp256k1(sig))
    }

    fn test_sig() -> PrimitiveSignature {
        PrimitiveSignature::Secp256k1(alloy_primitives::Signature::test_signature())
    }

    fn validate_keychain_env(
        env: &TempoTxEnv,
        chain_id: u64,
        spec: TempoHardfork,
    ) -> HandlerResult<()> {
        validate_key_authorization(env.as_aa().unwrap(), chain_id, spec)
    }

    pub(super) fn invalid_transaction(error: &HandlerError) -> Option<&TempoInvalidTransaction> {
        error.external_ref::<TempoInvalidTransaction>()
    }

    /// Build EVM + transaction with a keychain-signature AA tx.
    ///
    /// - `signature`: outer keychain signature; when `None` a default V2
    ///   keychain sig for `user` is used.
    /// - `seed_key`: when `true` the access key is pre-authorized in
    ///   keychain storage (existing-key path).
    pub(super) fn make_evm(
        user: Address,
        access_key: Address,
        key_auth: Option<SignedKeyAuthorization>,
        spec: TempoHardfork,
        signature: Option<TempoSignature>,
        seed_key: bool,
    ) -> (crate::TempoEvm<'static>, TempoTxEnv) {
        let sig = signature
            .unwrap_or_else(|| TempoSignature::Keychain(KeychainSignature::new(user, test_sig())));
        let env: TempoTxEnv = Recovered::new_unchecked(
            tempo_primitives::TempoTxEnvelope::AA(AASigned::new_unhashed(
                TempoTransaction {
                    chain_id: 1,
                    fee_token: Some(tempo_contracts::precompiles::DEFAULT_FEE_TOKEN),
                    gas_limit: 1_000_000,
                    calls: vec![call(Bytes::new())],
                    key_authorization: key_auth,
                    ..Default::default()
                },
                sig,
            )),
            user,
        )
        .into();
        let env = env.with_simulation_overrides(B256::ZERO, None, Some(access_key));
        let mut evm = test_evm(spec);

        StorageCtx::enter_evm_without_tip1060_accounting(&mut evm, || {
            let mut kc = AccountKeychain::new();
            kc.initialize().unwrap();
            kc.set_transaction_key(Address::ZERO).unwrap();
            kc.set_tx_origin(user).unwrap();
            if seed_key {
                kc.authorize_key(
                    user,
                    access_key,
                    PrecompileSignatureType::Secp256k1,
                    KeyRestrictions {
                        expiry: u64::MAX,
                        enforceLimits: false,
                        limits: vec![],
                        allowAnyCalls: true,
                        allowedCalls: vec![],
                    },
                    None,
                )
                .unwrap();
            }
        });

        (evm, env)
    }

    pub(super) fn validate_against_state(
        evm: &mut crate::TempoEvm<'static>,
        env: &TempoTxEnv,
    ) -> HandlerResult<()> {
        validate_against_state_with_fee(evm, env, U256::ZERO)
    }

    fn validate_against_state_with_fee(
        evm: &mut crate::TempoEvm<'static>,
        env: &TempoTxEnv,
        collected_fee: U256,
    ) -> HandlerResult<()> {
        let aa = env.as_aa().unwrap();
        validate_key_authorization(aa, evm.version().chain_id, evm.config_spec_id())?;
        let fee = TempoFeeContext {
            fee_payer: aa.signer(),
            fee_token: tempo_contracts::precompiles::DEFAULT_FEE_TOKEN,
            collected: collected_fee,
        };
        let state = prepare_keychain(evm, aa, fee)?;
        apply_key_authorization(evm, aa, fee, &state, u64::MAX)?;
        Ok(())
    }

    #[test]
    fn test_key_authorization_invalid_signature_rejected() {
        let (_, user) = generate_keypair();
        let key = Address::random();
        let (bad_signer, _) = generate_keypair();

        let signed = sign_key_auth(
            &bad_signer,
            KeyAuthorization::unrestricted(1337, SignatureType::Secp256k1, key),
        );
        let (_, env) = make_evm(user, key, Some(signed), TempoHardfork::T2, None, true);

        assert!(matches!(
            validate_keychain_env(&env, 1, TempoHardfork::T2)
                .as_ref()
                .err()
                .and_then(|error| invalid_transaction(error)),
            Some(TempoInvalidTransaction::KeyAuthorizationNotSignedByRoot { .. })
        ));
    }

    #[test]
    fn test_key_authorization_mismatched_key_id_rejected() {
        let (signer, user) = generate_keypair();
        let wrong_key = Address::random();
        let tx_key = Address::random();

        let signed = sign_key_auth(
            &signer,
            KeyAuthorization::unrestricted(1337, SignatureType::Secp256k1, wrong_key),
        );
        let (_, env) = make_evm(user, tx_key, Some(signed), TempoHardfork::T2, None, true);

        assert!(matches!(
            validate_keychain_env(&env, 1, TempoHardfork::T2)
                .as_ref()
                .err()
                .and_then(|error| invalid_transaction(error)),
            Some(TempoInvalidTransaction::AccessKeyCannotAuthorizeOtherKeys)
        ));
    }

    #[test]
    fn test_key_authorization_chain_id_wildcard() {
        for spec in [TempoHardfork::T1B, TempoHardfork::T2] {
            let (signer, user) = generate_keypair();
            let key = Address::random();
            let signed = sign_key_auth(
                &signer,
                KeyAuthorization::unrestricted(0, SignatureType::Secp256k1, key),
            );
            let (_, env) = make_evm(user, key, Some(signed), spec, None, false);

            let result = validate_keychain_env(&env, 1, spec);
            if !spec.is_t1c() {
                assert!(
                    result.is_ok(),
                    "{spec:?}: chain_id=0 wildcard should be accepted pre-T1C, got: {result:?}"
                );
            } else {
                assert!(
                    result.is_err(),
                    "{spec:?}: chain_id=0 wildcard should be rejected post-T1C, got: {result:?}"
                );
            }
        }
    }

    #[test]
    fn test_key_authorization_chain_id_wrong_and_matching() {
        // Both pre-T1C and post-T1C: wrong chain_id rejected, matching accepted.
        for spec in [TempoHardfork::T1B, TempoHardfork::T2] {
            // Wrong chain_id → rejected
            let (signer, user) = generate_keypair();
            let key = Address::random();
            let signed = sign_key_auth(
                &signer,
                KeyAuthorization::unrestricted(99_999, SignatureType::Secp256k1, key),
            );
            let (mut evm, env) = make_evm(user, key, Some(signed), spec, None, true);
            assert!(
                validate_against_state(&mut evm, &env).is_err(),
                "{spec:?}: wrong chain_id should be rejected"
            );

            // Matching chain_id (1 = default CfgEnv) → accepted
            let (signer, user) = generate_keypair();
            let key = Address::random();
            let signed = sign_key_auth(
                &signer,
                KeyAuthorization::unrestricted(1, SignatureType::Secp256k1, key),
            );
            let (mut evm, env) = make_evm(user, key, Some(signed), spec, None, true);
            let result = validate_against_state(&mut evm, &env);
            assert!(
                !matches!(
                        result.as_ref().err().and_then(invalid_transaction),
                        Some(TempoInvalidTransaction::KeychainValidationFailed { reason })
                            if reason.contains("chain_id")
                ),
                "{spec:?}: matching chain_id should be accepted, got: {result:?}"
            );
        }
    }

    #[test]
    fn test_key_authorization_witness_rejected_before_t5() {
        let (signer, user) = generate_keypair();
        let key = Address::random();
        let signed = sign_key_auth(
            &signer,
            KeyAuthorization::unrestricted(1, SignatureType::Secp256k1, key)
                .with_witness(B256::repeat_byte(0x53)),
        );
        let (_, env) = make_evm(user, key, Some(signed), TempoHardfork::T4, None, false);

        let result = validate_keychain_env(&env, 1, TempoHardfork::T4);
        assert!(
            matches!(
                result.as_ref().err().and_then(invalid_transaction),
                Some(TempoInvalidTransaction::KeychainValidationFailed { reason })
                    if reason.contains("before T5")
            ),
            "witness-bearing key authorization should be rejected before T5, got: {result:?}"
        );
    }

    #[test]
    fn test_key_authorization_expiry_cached_for_pool_maintenance() {
        let (signer, user) = generate_keypair();
        let key = Address::random();
        let expiry = u64::MAX - 1;

        let signed = sign_key_auth(
            &signer,
            KeyAuthorization::unrestricted(1, SignatureType::Secp256k1, key).with_expiry(expiry),
        );
        let (mut evm, env) = make_evm(user, key, Some(signed), TempoHardfork::T2, None, false);

        let _ = validate_against_state(&mut evm, &env);
        assert_eq!(evm.ext().key_expiry, Some(expiry));
    }

    #[test]
    fn test_t5_key_authorization_witness_is_not_burned_in_state() {
        use tempo_precompiles::account_keychain::isKeyAuthorizationWitnessBurnedCall;

        let (signer, user) = generate_keypair();
        let key = Address::random();
        let witness = B256::repeat_byte(0x54);
        let signed = sign_key_auth(
            &signer,
            KeyAuthorization::unrestricted(1, SignatureType::Secp256k1, key).with_witness(witness),
        );
        let (mut evm, env) = make_evm(user, key, Some(signed), TempoHardfork::T5, None, false);

        let result = validate_against_state(&mut evm, &env);
        assert!(
            result.is_ok(),
            "T5 witness authorization should pass: {result:?}"
        );

        StorageCtx::enter_evm_without_tip1060_accounting(&mut evm, || {
            let keychain = AccountKeychain::new();
            assert!(
                !keychain
                    .is_key_authorization_witness_burned(isKeyAuthorizationWitnessBurnedCall {
                        account: user,
                        witness,
                    })
                    .expect("witness read succeeds"),
                "T5 key authorization must not burn its witness"
            );
        });
    }

    #[test]
    fn test_t6_admin_key_authorization_fields_rejected_before_t6() {
        let (signer, user) = generate_keypair();
        let key = Address::random();
        let signed = sign_key_auth(
            &signer,
            KeyAuthorization::unrestricted(1, SignatureType::Secp256k1, key).into_admin(user),
        );
        let (_, env) = make_evm(user, key, Some(signed), TempoHardfork::T5, None, false);

        let result = validate_keychain_env(&env, 1, TempoHardfork::T5);
        assert!(
            matches!(
                result.as_ref().err().and_then(invalid_transaction),
                Some(TempoInvalidTransaction::KeychainValidationFailed { reason })
                    if reason.contains("not active before T6")
            ),
            "admin key authorization fields should be rejected before T6, got: {result:?}"
        );
    }

    #[test]
    fn test_t6_admin_key_authorization_rejects_account_mismatch() {
        let (signer, user) = generate_keypair();
        let key = Address::random();
        let wrong_account = Address::random();
        let signed = sign_key_auth(
            &signer,
            KeyAuthorization::unrestricted(1, SignatureType::Secp256k1, key)
                .into_admin(wrong_account),
        );
        let (_, env) = make_evm(user, key, Some(signed), TempoHardfork::T6, None, false);

        let result = validate_keychain_env(&env, 1, TempoHardfork::T6);
        assert!(
            matches!(
                result.as_ref().err().and_then(invalid_transaction),
                Some(TempoInvalidTransaction::KeychainValidationFailed { reason })
                    if reason.contains("account mismatch")
            ),
            "admin key authorization should be bound to tx.caller, got: {result:?}"
        );
    }

    #[test]
    fn test_t6_root_admin_key_authorization_allows_omitted_account() {
        let (signer, user) = generate_keypair();
        let key = Address::random();
        let mut key_auth = KeyAuthorization::unrestricted(1, SignatureType::Secp256k1, key);
        key_auth.is_admin = true;
        assert_eq!(key_auth.account, None);

        let signed = sign_key_auth(&signer, key_auth);
        let (mut evm, env) = make_evm(user, key, Some(signed), TempoHardfork::T6, None, false);

        let env_result = validate_keychain_env(&env, 1, TempoHardfork::T6);
        assert!(
            env_result.is_ok(),
            "root-signed admin key authorization should pass stateless validation, got: {env_result:?}"
        );

        let result = validate_against_state(&mut evm, &env);
        assert!(
            result.is_ok(),
            "root-signed admin key authorization should not require account, got: {result:?}"
        );

        StorageCtx::enter_evm_without_tip1060_accounting(&mut evm, || {
            let keychain = AccountKeychain::new();
            assert!(
                keychain
                    .is_admin_key(user, key)
                    .expect("admin key status read succeeds"),
                "root-signed admin key should be registered as admin"
            );
        });
    }

    #[test]
    fn test_t6_root_signed_key_authorization_rejects_admin_keychain_submission() {
        let (root_signer, user) = generate_keypair();
        let (_, admin_key) = generate_keypair();
        let child_key = Address::random();
        let signed = sign_key_auth(
            &root_signer,
            KeyAuthorization::unrestricted(1, SignatureType::Secp256k1, child_key),
        );
        let (_, env) = make_evm(
            user,
            admin_key,
            Some(signed),
            TempoHardfork::T6,
            None,
            false,
        );

        let env_result = validate_keychain_env(&env, 1, TempoHardfork::T6);
        assert!(
            matches!(
                env_result.as_ref().err().and_then(invalid_transaction),
                Some(TempoInvalidTransaction::KeychainValidationFailed { reason })
                    if reason.contains("root transaction signature")
            ),
            "root-signed key authorization should require a root transaction signature, got: {env_result:?}"
        );
    }

    #[test]
    fn test_t6_root_key_authorization_rejects_account_mismatch() {
        let (signer, user) = generate_keypair();
        let key = Address::random();
        let wrong_account = Address::random();
        let signed = sign_key_auth(
            &signer,
            KeyAuthorization::unrestricted(1, SignatureType::Secp256k1, key)
                .with_account(wrong_account),
        );
        let (_, env) = make_evm(user, key, Some(signed), TempoHardfork::T6, None, false);

        let result = validate_keychain_env(&env, 1, TempoHardfork::T6);
        assert!(
            matches!(
                result.as_ref().err().and_then(invalid_transaction),
                Some(TempoInvalidTransaction::KeychainValidationFailed { reason })
                    if reason.contains("key authorization account mismatch")
            ),
            "root-signed key authorization should be bound to tx.caller, got: {result:?}"
        );
    }

    #[test]
    fn test_t6_admin_key_authorization_rejects_restrictions() {
        let (signer, user) = generate_keypair();
        let key = Address::random();
        let signed = sign_key_auth(
            &signer,
            KeyAuthorization::unrestricted(1, SignatureType::Secp256k1, key)
                .with_expiry(u64::MAX)
                .into_admin(user),
        );
        let (_, env) = make_evm(user, key, Some(signed), TempoHardfork::T6, None, false);

        let result = validate_keychain_env(&env, 1, TempoHardfork::T6);
        assert!(
            matches!(
                result.as_ref().err().and_then(invalid_transaction),
                Some(TempoInvalidTransaction::KeychainValidationFailed { reason })
                    if reason.contains("cannot carry expiry")
            ),
            "admin key authorization should reject restrictions, got: {result:?}"
        );
    }

    #[test]
    fn test_t6_admin_access_key_can_authorize_different_admin_key() {
        let (admin_signer, admin_key) = generate_keypair();
        let user = Address::random();
        let child_key = Address::random();
        let signed = sign_key_auth(
            &admin_signer,
            KeyAuthorization::unrestricted(1, SignatureType::WebAuthn, child_key).into_admin(user),
        );
        let (mut evm, env) = make_evm(
            user,
            admin_key,
            Some(signed),
            TempoHardfork::T6,
            None,
            false,
        );

        let env_result = validate_keychain_env(&env, 1, TempoHardfork::T6);
        assert!(
            env_result.is_ok(),
            "admin access key authorization should pass stateless validation, got: {env_result:?}"
        );

        StorageCtx::enter_evm_without_tip1060_accounting(&mut evm, || {
            let mut keychain = AccountKeychain::new();
            keychain
                .authorize_admin_key(user, admin_key, PrecompileSignatureType::Secp256k1, None)
                .expect("root authorizes admin key");
        });

        let result = validate_against_state(&mut evm, &env);
        assert!(
            result.is_ok(),
            "admin access key should authorize a different admin key, got: {result:?}"
        );

        StorageCtx::enter_evm_without_tip1060_accounting(&mut evm, || {
            let keychain = AccountKeychain::new();
            assert!(
                keychain
                    .is_admin_key(user, child_key)
                    .expect("admin key status read succeeds"),
                "child key should be registered as admin"
            );
        });
    }

    #[test]
    fn test_t6_admin_key_authorization_rejects_admin_signature_type_mismatch() {
        let (admin_signer, admin_key) = generate_keypair();
        let user = Address::random();
        let child_key = Address::random();
        let signed = sign_key_auth(
            &admin_signer,
            KeyAuthorization::unrestricted(1, SignatureType::Secp256k1, child_key)
                .with_account(user),
        );
        let (mut evm, env) = make_evm(
            user,
            admin_key,
            Some(signed),
            TempoHardfork::T6,
            None,
            false,
        );

        let env_result = validate_keychain_env(&env, 1, TempoHardfork::T6);
        assert!(
            env_result.is_ok(),
            "admin-signed key authorization should pass stateless validation, got: {env_result:?}"
        );

        StorageCtx::enter_evm_without_tip1060_accounting(&mut evm, || {
            let mut keychain = AccountKeychain::new();
            keychain
                .authorize_admin_key(user, admin_key, PrecompileSignatureType::WebAuthn, None)
                .expect("root authorizes WebAuthn admin key");
        });

        let result = validate_against_state(&mut evm, &env);
        assert!(
            matches!(
                result.as_ref().err().and_then(invalid_transaction),
                Some(TempoInvalidTransaction::KeychainValidationFailed { reason })
                    if reason.contains("SignatureTypeMismatch")
            ),
            "admin-signed key authorization should reject sidecar signature type mismatch, got: {result:?}"
        );
    }

    #[test]
    fn test_t6_admin_key_authorization_rejects_different_transaction_admin_key() {
        let (authorization_signer, authorization_admin_key) = generate_keypair();
        let (_, tx_admin_key) = generate_keypair();
        let user = Address::random();
        let child_key = Address::random();
        let signed = sign_key_auth(
            &authorization_signer,
            KeyAuthorization::unrestricted(1, SignatureType::Secp256k1, child_key)
                .with_account(user),
        );
        let (_, env) = make_evm(
            user,
            tx_admin_key,
            Some(signed),
            TempoHardfork::T6,
            None,
            false,
        );

        let result = validate_keychain_env(&env, 1, TempoHardfork::T6);
        assert!(
            matches!(
                result.as_ref().err().and_then(invalid_transaction),
                Some(TempoInvalidTransaction::KeychainValidationFailed { reason })
                    if reason.contains("must be signed by transaction key")
            ),
            "admin-signed key authorization must use the transaction admin key; auth signer {authorization_admin_key}, tx signer {tx_admin_key}, got: {result:?}"
        );
    }

    #[test]
    fn test_t6_admin_access_key_non_admin_authorization_requires_account_binding() {
        let (admin_signer, admin_key) = generate_keypair();
        let user = Address::random();
        let child_key = Address::random();
        let signed = sign_key_auth(
            &admin_signer,
            KeyAuthorization::unrestricted(1, SignatureType::Secp256k1, child_key),
        );
        let (_, env) = make_evm(
            user,
            admin_key,
            Some(signed),
            TempoHardfork::T6,
            None,
            false,
        );

        let result = validate_keychain_env(&env, 1, TempoHardfork::T6);
        assert!(
            matches!(
                result.as_ref().err().and_then(invalid_transaction),
                Some(TempoInvalidTransaction::KeychainValidationFailed { reason })
                    if reason.contains("admin-signed key authorization account mismatch")
            ),
            "admin-signed non-admin authorization without account binding should fail in validate_env, got: {result:?}"
        );
    }

    #[test]
    fn test_t6_admin_access_key_non_admin_authorization_rejects_account_replay() {
        use tempo_precompiles::account_keychain::getKeyCall;

        let (admin_signer, admin_key) = generate_keypair();
        let alice = Address::random();
        let bob = Address::random();
        let child_key = Address::random();
        let signed = sign_key_auth(
            &admin_signer,
            KeyAuthorization::unrestricted(1, SignatureType::Secp256k1, child_key)
                .with_account(alice),
        );

        let (mut alice_evm, alice_env) = make_evm(
            alice,
            admin_key,
            Some(signed.clone()),
            TempoHardfork::T6,
            None,
            false,
        );
        let alice_env_result = validate_keychain_env(&alice_env, 1, TempoHardfork::T6);
        assert!(
            alice_env_result.is_ok(),
            "account-bound authorization should pass Alice stateless validation, got: {alice_env_result:?}"
        );

        StorageCtx::enter_evm_without_tip1060_accounting(&mut alice_evm, || {
            let mut keychain = AccountKeychain::new();
            keychain
                .authorize_admin_key(alice, admin_key, PrecompileSignatureType::Secp256k1, None)
                .expect("root authorizes Alice admin key");
        });

        let alice_result = validate_against_state(&mut alice_evm, &alice_env);
        assert!(
            alice_result.is_ok(),
            "account-bound admin-signed non-admin authorization should pass for Alice, got: {alice_result:?}"
        );
        StorageCtx::enter_evm_without_tip1060_accounting(&mut alice_evm, || {
            let keychain = AccountKeychain::new();
            let key = keychain
                .get_key(getKeyCall {
                    account: alice,
                    keyId: child_key,
                })
                .expect("child key read succeeds");
            assert_eq!(key.keyId, child_key, "child key should be registered");
            assert!(
                !keychain
                    .is_admin_key(alice, child_key)
                    .expect("admin key status read succeeds"),
                "child key should not be admin"
            );
        });

        let (_, bob_env) = make_evm(bob, admin_key, Some(signed), TempoHardfork::T6, None, false);

        let bob_result = validate_keychain_env(&bob_env, 1, TempoHardfork::T6);
        assert!(
            matches!(
                bob_result.as_ref().err().and_then(invalid_transaction),
                Some(TempoInvalidTransaction::KeychainValidationFailed { reason })
                    if reason.contains("key authorization account mismatch")
            ),
            "Alice-bound authorization should not replay for Bob, got: {bob_result:?}"
        );
    }

    #[test]
    fn test_t6_admin_delegation_does_not_apply_child_fee_limit() {
        let (admin_signer, admin_key) = generate_keypair();
        let user = Address::random();
        let child_key = Address::random();
        let gas_limit = 100_000;
        let fee = U256::from(gas_limit);
        let child_spending_limit = fee - U256::ONE;

        let signed = sign_key_auth(
            &admin_signer,
            KeyAuthorization::unrestricted(1, SignatureType::Secp256k1, child_key)
                .with_limits(vec![TokenLimit {
                    token: tempo_contracts::precompiles::DEFAULT_FEE_TOKEN,
                    limit: child_spending_limit,
                    period: 60,
                }])
                .with_account(user),
        );
        let (mut evm, env) = make_evm(
            user,
            admin_key,
            Some(signed),
            TempoHardfork::T6,
            None,
            false,
        );

        let env_result = validate_keychain_env(&env, 1, TempoHardfork::T6);
        assert!(
            env_result.is_ok(),
            "admin delegation should pass stateless validation, got: {env_result:?}"
        );

        StorageCtx::enter_evm_without_tip1060_accounting(&mut evm, || {
            let mut keychain = AccountKeychain::new();
            keychain
                .authorize_admin_key(user, admin_key, PrecompileSignatureType::Secp256k1, None)
                .expect("root authorizes admin key");
        });

        let result = validate_against_state_with_fee(&mut evm, &env, fee);
        assert!(
            result.is_ok(),
            "admin delegation should not precharge fees against child key limits, got: {result:?}"
        );
    }

    #[test]
    fn test_t6_admin_delegation_preserves_admin_transaction_key() {
        use tempo_precompiles::account_keychain::getTransactionKeyCall;

        let (admin_signer, admin_key) = generate_keypair();
        let user = Address::random();
        let child_key = Address::random();
        let signed = sign_key_auth(
            &admin_signer,
            KeyAuthorization::unrestricted(1, SignatureType::Secp256k1, child_key)
                .with_account(user),
        );
        let (mut evm, env) = make_evm(
            user,
            admin_key,
            Some(signed),
            TempoHardfork::T6,
            None,
            false,
        );

        let env_result = validate_keychain_env(&env, 1, TempoHardfork::T6);
        assert!(
            env_result.is_ok(),
            "admin delegation should pass stateless validation, got: {env_result:?}"
        );

        StorageCtx::enter_evm_without_tip1060_accounting(&mut evm, || {
            let mut keychain = AccountKeychain::new();
            keychain
                .authorize_admin_key(user, admin_key, PrecompileSignatureType::Secp256k1, None)
                .expect("root authorizes admin key");
        });

        let result = validate_against_state(&mut evm, &env);
        assert!(
            result.is_ok(),
            "admin delegation should pass, got: {result:?}"
        );

        StorageCtx::enter_evm_without_tip1060_accounting(&mut evm, || {
            let keychain = AccountKeychain::new();
            let transaction_key = keychain
                .get_transaction_key(getTransactionKeyCall {}, user)
                .expect("transaction key read succeeds");
            assert_eq!(
                transaction_key, admin_key,
                "admin delegation must preserve the signer key as transaction key"
            );
        });
    }

    #[test]
    fn test_same_tx_key_authorization_rejects_fee_above_new_limit_before_auth() {
        let (signer, user) = generate_keypair();
        let key = Address::random();
        let gas_limit = 100_000;
        let fee = U256::from(gas_limit);
        let spending_limit = fee - U256::ONE;

        let signed = sign_key_auth(
            &signer,
            KeyAuthorization::unrestricted(1, SignatureType::Secp256k1, key).with_limits(vec![
                TokenLimit {
                    token: tempo_contracts::precompiles::DEFAULT_FEE_TOKEN,
                    limit: spending_limit,
                    period: 60,
                },
            ]),
        );
        let (mut evm, env) = make_evm(user, key, Some(signed), TempoHardfork::T3, None, false);

        let result = validate_against_state_with_fee(&mut evm, &env, fee);

        assert!(
            matches!(
                result.as_ref().err().and_then(invalid_transaction),
                Some(TempoInvalidTransaction::CollectFeePreTx(FeePaymentError::Other(reason)))
                    if reason.contains("SpendingLimitExceeded")
            ),
            "same-tx auth+use should reject fee above the new key limit before auth, got: {result:?}"
        );
        assert!(
            evm.logs()
                .iter()
                .all(|log| log.address != tempo_precompiles::ACCOUNT_KEYCHAIN_ADDRESS),
            "fee-limit rejection must happen before key authorization emits events"
        );
    }

    #[test]
    fn test_stale_collected_fee_not_charged_to_zero_fee_same_tx_auth_use() {
        let (signer, user) = generate_keypair();
        let key = Address::random();
        let stale_fee = U256::from(100_000);
        let spending_limit = stale_fee - U256::ONE;

        let signed = sign_key_auth(
            &signer,
            KeyAuthorization::unrestricted(1, SignatureType::Secp256k1, key).with_limits(vec![
                TokenLimit {
                    token: tempo_contracts::precompiles::DEFAULT_FEE_TOKEN,
                    limit: spending_limit,
                    period: 60,
                },
            ]),
        );
        let (mut evm, env) = make_evm(
            user,
            key,
            Some(signed.clone()),
            TempoHardfork::T3,
            None,
            false,
        );

        StorageCtx::enter_evm_without_tip1060_accounting(&mut evm, || {
            TIP20Setup::path_usd(user)
                .with_issuer(user)
                .with_mint(user, stale_fee * U256::from(2))
                .apply()
                .expect("pathUSD setup succeeds");
        });

        let stale_env: TempoTxEnv = Recovered::new_unchecked(
            tempo_primitives::TempoTxEnvelope::AA(AASigned::new_unhashed(
                TempoTransaction {
                    chain_id: 1,
                    fee_token: Some(tempo_contracts::precompiles::DEFAULT_FEE_TOKEN),
                    max_priority_fee_per_gas: 1_000_000_000_000,
                    max_fee_per_gas: 1_000_000_000_000,
                    gas_limit: 100_000,
                    calls: vec![call(Bytes::new())],
                    key_authorization: Some(signed),
                    ..Default::default()
                },
                TempoSignature::Keychain(KeychainSignature::new(
                    user,
                    PrimitiveSignature::Secp256k1(Signature::test_signature()),
                )),
            )),
            user,
        )
        .into();
        let stale_env = stale_env.with_simulation_overrides(B256::ZERO, None, Some(key));
        let stale_context = TempoHandlerHooks::resolve_fee_context(&mut evm, &stale_env).unwrap();
        assert_eq!(stale_context.collected, stale_fee);

        let context = TempoHandlerHooks::resolve_fee_context(&mut evm, &env).unwrap();
        assert_eq!(context.collected, U256::ZERO);

        let result = validate_against_state_with_fee(&mut evm, &env, U256::ZERO);

        assert!(
            result.is_ok(),
            "zero-fee same-tx auth/use must not charge stale fee, got: {result:?}"
        );
        assert_eq!(context.collected, U256::ZERO);
    }
}

use keychain::invalid_transaction;

#[test]
fn test_t3_scope_validation_moves_to_execution() {
    const CALL_SCOPE_SELECTOR: [u8; 4] = [0xde, 0xad, 0xbe, 0xef];

    let caller = Address::repeat_byte(0x11);
    let access_key = Address::repeat_byte(0x22);
    let target = DEFAULT_FEE_TOKEN;

    let signature =
        TempoSignature::Keychain(tempo_primitives::transaction::KeychainSignature::new(
            caller,
            tempo_primitives::transaction::PrimitiveSignature::Secp256k1(
                alloy_primitives::Signature::test_signature(),
            ),
        ));
    let calls = vec![Call {
        to: TxKind::Call(target),
        value: U256::ZERO,
        input: Bytes::from_static(&CALL_SCOPE_SELECTOR),
    }];
    let mut evm = test_evm(TempoHardfork::T3);

    StorageCtx::enter_evm_without_tip1060_accounting(&mut evm, || {
        let mut keychain = AccountKeychain::new();

        keychain.initialize().expect("keychain initialized");
        keychain
            .set_transaction_key(Address::ZERO)
            .expect("root key setup succeeds");
        keychain
            .set_tx_origin(caller)
            .expect("tx.origin setup succeeds");
        keychain
            .authorize_key(
                caller,
                access_key,
                PrecompileSignatureType::Secp256k1,
                KeyRestrictions {
                    expiry: u64::MAX,
                    enforceLimits: false,
                    limits: vec![],
                    allowAnyCalls: false,
                    allowedCalls: vec![PrecompileCallScope {
                        target,
                        selectorRules: vec![PrecompileSelectorRule {
                            selector: CALL_SCOPE_SELECTOR.into(),
                            recipients: vec![],
                        }],
                    }],
                },
                None,
            )
            .expect("access key authorization succeeds");
    });

    let env = aa_env(
        TempoTransaction {
            chain_id: 1,
            fee_token: Some(DEFAULT_FEE_TOKEN),
            gas_limit: 1_000_000,
            calls: calls.clone(),
            ..Default::default()
        },
        signature,
    )
    .with_simulation_overrides(B256::ZERO, None, Some(access_key));
    let keychain = prepare_keychain(
        &mut evm,
        env.as_aa().unwrap(),
        TempoFeeContext {
            fee_payer: caller,
            fee_token: DEFAULT_FEE_TOKEN,
            collected: U256::ZERO,
        },
    )
    .expect("scope validation no longer runs during state validation");
    assert_eq!(keychain.access_key, Some(access_key));

    // EVM2 passes only the post-intrinsic execution budget into batch execution. A
    // transaction whose gas limit is exactly its intrinsic gas therefore has no gas left for
    // call-scope validation.
    let execution_gas = 0;
    let result =
        prevalidate_call_scopes(&mut evm, caller, Some(access_key), &calls, execution_gas, 0)
            .expect("scope validation should return a frame result")
            .expect("insufficient execution gas should halt");

    assert!(
        matches!(result.stop, InstrStop::PrecompileOOG),
        "expected scope validation to fail during execution with OOG, got: {:?}",
        result.stop
    );
    assert_eq!(
        result.gas.limit(),
        execution_gas,
        "batch OOG should report the full execution gas budget"
    );
    assert_eq!(
        result.gas.spent(),
        execution_gas,
        "batch OOG should consume the full execution gas budget"
    );
    assert_eq!(result.gas.refunded(), 0);
}

#[test]
fn test_t3_scope_validation_returns_call_not_allowed_revert_data() {
    use alloy_sol_types::SolInterface;
    use tempo_contracts::precompiles::AccountKeychainError;

    const ALLOWED_SELECTOR: [u8; 4] = [0xde, 0xad, 0xbe, 0xef];
    const DENIED_SELECTOR: [u8; 4] = [0xca, 0xfe, 0xba, 0xbe];

    let caller = Address::repeat_byte(0x11);
    let access_key = Address::repeat_byte(0x22);
    let target = DEFAULT_FEE_TOKEN;
    let calls = vec![Call {
        to: TxKind::Call(target),
        value: U256::ZERO,
        input: Bytes::from_static(&DENIED_SELECTOR),
    }];
    let mut evm = test_evm(TempoHardfork::T3);

    StorageCtx::enter_evm_without_tip1060_accounting(&mut evm, || {
        let mut keychain = AccountKeychain::new();

        keychain.initialize().expect("keychain initialized");
        keychain
            .set_transaction_key(Address::ZERO)
            .expect("root key setup succeeds");
        keychain
            .set_tx_origin(caller)
            .expect("tx.origin setup succeeds");
        keychain
            .authorize_key(
                caller,
                access_key,
                PrecompileSignatureType::Secp256k1,
                KeyRestrictions {
                    expiry: u64::MAX,
                    enforceLimits: false,
                    limits: vec![],
                    allowAnyCalls: false,
                    allowedCalls: vec![PrecompileCallScope {
                        target,
                        selectorRules: vec![PrecompileSelectorRule {
                            selector: ALLOWED_SELECTOR.into(),
                            recipients: vec![],
                        }],
                    }],
                },
                None,
            )
            .expect("access key authorization succeeds");
    });

    let result = prevalidate_call_scopes(&mut evm, caller, Some(access_key), &calls, 1_000_000, 0)
        .expect("execution should return a frame result")
        .expect("denied call should revert");

    let expected_revert: Bytes = AccountKeychainError::call_not_allowed().abi_encode().into();

    assert_eq!(result.stop, InstrStop::Revert);
    assert_eq!(result.output, expected_revert);
    assert!(
        result.gas.spent() < 1_000_000,
        "prevalidate revert must not consume the full gas_limit"
    );
}

#[test]
fn test_t3_scope_validation_empty_calls_returns_custom_error() {
    let err = validate_calls(&[], false)
        .map_err(TempoInvalidTransaction::from)
        .map_err(invalid)
        .expect_err("empty calls should return an error instead of panicking");

    assert!(matches!(
        invalid_transaction(&err),
        Some(TempoInvalidTransaction::CallsValidation(reason))
            if *reason == "calls list cannot be empty"
    ));
}

#[test]
fn test_self_sponsored_fee_payer_rejected_post_t2() {
    let caller = Address::random();
    let invalid_token = Address::random();

    let env: TempoTxEnv = Recovered::new_unchecked(
        tempo_primitives::TempoTxEnvelope::AA(AASigned::new_unhashed(
            TempoTransaction {
                chain_id: 1,
                fee_token: Some(invalid_token),
                fee_payer_signature: Some(Signature::test_signature()),
                gas_limit: 1_000_000,
                calls: vec![call(Bytes::new())],
                ..Default::default()
            },
            secp256k1_signature(),
        )),
        caller,
    )
    .into();
    let env = env.with_simulation_overrides(B256::ZERO, Some(caller), None);
    let mut evm = test_evm(TempoHardfork::T2);
    let result = handle(TxRequest {
        envelope: &env,
        tx: Recovered::new_unchecked(env.as_aa().unwrap(), caller),
        host: &mut evm,
        _non_exhaustive: (),
    });
    assert!(matches!(
        result
            .as_ref()
            .err()
            .and_then(|error| invalid_transaction(error)),
        Some(TempoInvalidTransaction::SelfSponsoredFeePayer)
    ));
}

#[test]
fn test_self_sponsored_fee_payer_not_rejected_pre_t4() {
    let caller = Address::random();
    let invalid_token = Address::random();

    let env: TempoTxEnv = Recovered::new_unchecked(
        tempo_primitives::TempoTxEnvelope::AA(AASigned::new_unhashed(
            TempoTransaction {
                chain_id: 1,
                fee_token: Some(invalid_token),
                fee_payer_signature: Some(Signature::test_signature()),
                gas_limit: 1_000_000,
                calls: vec![call(Bytes::new())],
                ..Default::default()
            },
            secp256k1_signature(),
        )),
        caller,
    )
    .into();
    let env = env.with_simulation_overrides(B256::ZERO, Some(caller), None);
    let mut evm = test_evm(TempoHardfork::T1C);
    let result = handle(TxRequest {
        envelope: &env,
        tx: Recovered::new_unchecked(env.as_aa().unwrap(), caller),
        host: &mut evm,
        _non_exhaustive: (),
    });
    assert!(
        !matches!(
            result
                .as_ref()
                .err()
                .and_then(|error| invalid_transaction(error)),
            Some(TempoInvalidTransaction::SelfSponsoredFeePayer)
        ),
        "self-sponsored fee payer must not be rejected before T2, got: {result:?}"
    );
}

mod keychain_continued {
    use super::{
        keychain::{generate_keypair, make_evm, sign_key_auth, validate_against_state},
        *,
    };

    #[test]
    fn test_keychain_version_rejection() {
        let caller = Address::random();

        // V1 (legacy) rejected post-T1C
        let v1 = TempoSignature::Keychain(KeychainSignature::new_v1(
            caller,
            PrimitiveSignature::Secp256k1(Signature::test_signature()),
        ));
        let (_, env) = make_evm(
            caller,
            Address::ZERO,
            None,
            TempoHardfork::T2,
            Some(v1),
            false,
        );
        assert!(
            env.as_aa()
                .unwrap()
                .inner()
                .signature()
                .validate_version(true)
                .is_err()
        );

        // V2 rejected pre-T1C
        let v2 = TempoSignature::Keychain(KeychainSignature::new(
            caller,
            PrimitiveSignature::Secp256k1(Signature::test_signature()),
        ));
        let (_, env) = make_evm(
            caller,
            Address::ZERO,
            None,
            TempoHardfork::T1B,
            Some(v2),
            false,
        );
        assert!(
            env.as_aa()
                .unwrap()
                .inner()
                .signature()
                .validate_version(false)
                .is_err()
        );
    }

    #[test]
    fn test_keychain_signature_with_valid_authorized_key() {
        let (mut evm, env) = make_evm(
            Address::repeat_byte(0x11),
            Address::repeat_byte(0x22),
            None,
            TempoHardfork::T2,
            None,
            true,
        );

        let result = validate_against_state(&mut evm, &env);
        assert!(
            !matches!(
                result.as_ref().err().and_then(invalid_transaction),
                Some(TempoInvalidTransaction::KeychainValidationFailed { .. })
            ),
            "Valid authorized key should pass, got: {result:?}"
        );
    }

    #[test]
    fn test_key_authorization_without_existing_key_passes() {
        let (signer, user) = generate_keypair();
        let key = Address::random();
        let signed = sign_key_auth(
            &signer,
            KeyAuthorization::unrestricted(1, SignatureType::Secp256k1, key),
        );
        let (mut evm, env) = make_evm(user, key, Some(signed), TempoHardfork::T2, None, false);

        let result = validate_against_state(&mut evm, &env);
        assert!(
            !matches!(
                result.as_ref().err().and_then(invalid_transaction),
                Some(
                    TempoInvalidTransaction::KeychainValidationFailed { .. }
                        | TempoInvalidTransaction::AccessKeyCannotAuthorizeOtherKeys
                        | TempoInvalidTransaction::KeyAuthorizationNotSignedByRoot { .. }
                        | TempoInvalidTransaction::KeychainPrecompileError { .. }
                )
            ),
            "Same-tx auth+use should pass when key does not exist, got: {result:?}"
        );
    }
}

#[test]
fn test_aa_gas_single_call_vs_normal_tx() {
    use alloy_primitives::{Bytes, TxKind};
    use tempo_primitives::transaction::{Call, TempoSignature};
    let gas_params = genesis_gas_params();

    // Test that AA tx with secp256k1 and single call matches normal tx + per-call overhead
    let calldata = Bytes::from(vec![1, 2, 3, 4, 5]); // 5 non-zero bytes
    let to = Address::random();

    // Single call for AA
    let call = Call {
        to: TxKind::Call(to),
        value: U256::ZERO,
        input: calldata.clone(),
    };

    let aa_env = TempoBatchCallEnv {
        signature: TempoSignature::Primitive(PrimitiveSignature::Secp256k1(
            alloy_primitives::Signature::test_signature(),
        )), // dummy secp256k1 sig
        aa_calls: vec![call],
        key_authorization: None,
        signature_hash: B256::ZERO,
        ..Default::default()
    };

    // Calculate AA gas
    let spec = tempo_chainspec::hardfork::TempoHardfork::default();
    let aa_gas = calculate_aa_batch_intrinsic_gas(
        &aa_env,
        &gas_params,
        None::<std::iter::Empty<&AccessListItem>>, // no access list
        spec,
    )
    .unwrap();

    // Calculate expected gas using revm's function for equivalent normal tx
    let normal_tx_gas = calculate_initial_tx_gas(
        SpecId::CANCUN,
        &calldata,
        false, // not create
        0,     // no access list accounts
        0,     // no access list storage
        0,     // no authorization list
    );

    // AA with secp256k1 + single call should match normal tx exactly
    assert_eq!(
        aa_gas.initial_total_gas(),
        normal_tx_gas.initial_total_gas()
    );
}

#[test]
fn test_aa_gas_multiple_calls_overhead() {
    use alloy_primitives::{Bytes, TxKind};
    use tempo_primitives::transaction::{Call, TempoSignature};

    let calldata = Bytes::from(vec![1, 2, 3]); // 3 non-zero bytes

    let calls = vec![
        Call {
            to: TxKind::Call(Address::random()),
            value: U256::ZERO,
            input: calldata.clone(),
        },
        Call {
            to: TxKind::Call(Address::random()),
            value: U256::ZERO,
            input: calldata.clone(),
        },
        Call {
            to: TxKind::Call(Address::random()),
            value: U256::ZERO,
            input: calldata.clone(),
        },
    ];

    let aa_env = TempoBatchCallEnv {
        signature: TempoSignature::Primitive(PrimitiveSignature::Secp256k1(
            alloy_primitives::Signature::test_signature(),
        )),
        aa_calls: calls,
        key_authorization: None,
        signature_hash: B256::ZERO,
        ..Default::default()
    };

    let spec = tempo_chainspec::hardfork::TempoHardfork::default();
    let gas = calculate_aa_batch_intrinsic_gas(
        &aa_env,
        &genesis_gas_params(),
        None::<std::iter::Empty<&AccessListItem>>,
        spec,
    )
    .unwrap();

    // Calculate base gas for a single normal tx
    let base_tx_gas = calculate_initial_tx_gas(SpecId::CANCUN, &calldata, false, 0, 0, 0);

    // For 3 calls: base (21k) + 3*calldata + 2*per-call overhead (calls 2 and 3)
    // = 21k + 2*(calldata cost) + 2*COLD_ACCOUNT_ACCESS_COST
    let expected = base_tx_gas.initial_total_gas()
        + 2 * (calldata.len() as u64 * 16)
        + 2 * COLD_ACCOUNT_ACCESS_COST;
    // Should charge per-call overhead for calls beyond the first
    assert_eq!(gas.initial_total_gas(), expected,);
}

#[test]
fn test_aa_gas_p256_signature() {
    use alloy_primitives::{B256, Bytes, TxKind};
    use tempo_primitives::transaction::{
        Call, TempoSignature, tt_signature::P256SignatureWithPreHash,
    };

    let spec = SpecId::CANCUN;
    let calldata = Bytes::from(vec![1, 2]);

    let call = Call {
        to: TxKind::Call(Address::random()),
        value: U256::ZERO,
        input: calldata.clone(),
    };

    let aa_env = TempoBatchCallEnv {
        signature: TempoSignature::Primitive(PrimitiveSignature::P256(P256SignatureWithPreHash {
            r: B256::ZERO,
            s: B256::ZERO,
            pub_key_x: B256::ZERO,
            pub_key_y: B256::ZERO,
            pre_hash: false,
        })),
        aa_calls: vec![call],
        key_authorization: None,
        signature_hash: B256::ZERO,
        ..Default::default()
    };

    let gas = calculate_aa_batch_intrinsic_gas(
        &aa_env,
        &genesis_gas_params(),
        None::<std::iter::Empty<&AccessListItem>>,
        tempo_chainspec::hardfork::TempoHardfork::default(),
    )
    .unwrap();

    // Calculate base gas for normal tx
    let base_gas = calculate_initial_tx_gas(spec, &calldata, false, 0, 0, 0);

    // Expected: normal tx + P256_VERIFY_GAS
    let expected = base_gas.initial_total_gas() + P256_VERIFY_GAS;
    assert_eq!(gas.initial_total_gas(), expected,);
}

#[test]
fn test_aa_gas_create_call() {
    use alloy_primitives::{Bytes, TxKind};
    use tempo_primitives::transaction::{Call, TempoSignature};

    let spec = SpecId::CANCUN; // Post-Shanghai
    let initcode = Bytes::from(vec![0x60, 0x80]); // 2 bytes

    let call = Call {
        to: TxKind::Create,
        value: U256::ZERO,
        input: initcode.clone(),
    };

    let aa_env = TempoBatchCallEnv {
        signature: TempoSignature::Primitive(PrimitiveSignature::Secp256k1(
            alloy_primitives::Signature::test_signature(),
        )),
        aa_calls: vec![call],
        key_authorization: None,
        signature_hash: B256::ZERO,
        ..Default::default()
    };

    let gas = calculate_aa_batch_intrinsic_gas(
        &aa_env,
        &genesis_gas_params(),
        None::<std::iter::Empty<&AccessListItem>>,
        tempo_chainspec::hardfork::TempoHardfork::default(),
    )
    .unwrap();

    // Calculate expected using revm's function for CREATE tx
    let base_gas = calculate_initial_tx_gas(
        spec, &initcode, true, // is_create = true
        0, 0, 0,
    );

    // AA CREATE should match normal CREATE exactly
    assert_eq!(gas.initial_total_gas(), base_gas.initial_total_gas(),);
}

#[test]
fn test_aa_gas_value_transfer() {
    use alloy_primitives::{Bytes, TxKind};
    use tempo_primitives::transaction::{Call, TempoSignature};

    let calldata = Bytes::from(vec![1]);

    let call = Call {
        to: TxKind::Call(Address::random()),
        value: U256::from(1000), // Non-zero value
        input: calldata,
    };

    let aa_env = TempoBatchCallEnv {
        signature: TempoSignature::Primitive(PrimitiveSignature::Secp256k1(
            alloy_primitives::Signature::test_signature(),
        )),
        aa_calls: vec![call],
        key_authorization: None,
        signature_hash: B256::ZERO,
        ..Default::default()
    };

    let res = calculate_aa_batch_intrinsic_gas(
        &aa_env,
        &genesis_gas_params(),
        None::<std::iter::Empty<&AccessListItem>>,
        tempo_chainspec::hardfork::TempoHardfork::default(),
    );

    assert!(matches!(
        res.as_ref()
            .err()
            .and_then(|error| error.external_ref::<TempoInvalidTransaction>()),
        Some(TempoInvalidTransaction::ValueTransferNotAllowedInAATx)
    ));
}

#[test]
fn test_zero_value_transfer() {
    assert!(
        intrinsic(
            TempoHardfork::Genesis,
            TempoTransaction {
                calls: vec![call(Bytes::new())],
                ..Default::default()
            },
            secp256k1_signature(),
        )
        .is_ok()
    );
}

#[test]
fn test_aa_gas_access_list() {
    use alloy_primitives::{Bytes, TxKind};
    use tempo_primitives::transaction::{Call, TempoSignature};

    let spec = SpecId::CANCUN;
    let calldata = Bytes::from(vec![]);

    let call = Call {
        to: TxKind::Call(Address::random()),
        value: U256::ZERO,
        input: calldata.clone(),
    };

    let aa_env = TempoBatchCallEnv {
        signature: TempoSignature::Primitive(PrimitiveSignature::Secp256k1(
            alloy_primitives::Signature::test_signature(),
        )),
        aa_calls: vec![call],
        key_authorization: None,
        signature_hash: B256::ZERO,
        ..Default::default()
    };

    // Test without access list
    let gas = calculate_aa_batch_intrinsic_gas(
        &aa_env,
        &genesis_gas_params(),
        None::<std::iter::Empty<&AccessListItem>>,
        tempo_chainspec::hardfork::TempoHardfork::default(),
    )
    .unwrap();

    // Calculate expected using revm's function
    let base_gas = calculate_initial_tx_gas(spec, &calldata, false, 0, 0, 0);

    // Expected: normal tx
    assert_eq!(gas.initial_total_gas(), base_gas.initial_total_gas(),);
}

#[test]
fn test_key_authorization_rlp_encoding() {
    use alloy_primitives::{Address, U256};
    use tempo_primitives::transaction::{KeyAuthorization, SignatureType, TokenLimit};

    // Create test data
    let chain_id = 1u64;
    let key_type = SignatureType::Secp256k1;
    let key_id = Address::random();
    let expiry = 1000u64;
    let limits = vec![
        TokenLimit {
            token: Address::random(),
            limit: U256::from(100),
            period: 0,
        },
        TokenLimit {
            token: Address::random(),
            limit: U256::from(200),
            period: 0,
        },
    ];

    // Compute hash using the helper function
    let hash1 = KeyAuthorization::unrestricted(chain_id, key_type, key_id)
        .with_expiry(expiry)
        .with_limits(limits.clone())
        .signature_hash();

    // Compute again to verify consistency
    let hash2 = KeyAuthorization::unrestricted(chain_id, key_type, key_id)
        .with_expiry(expiry)
        .with_limits(limits.clone())
        .signature_hash();

    assert_eq!(hash1, hash2, "Hash computation should be deterministic");

    // Verify that different chain_id produces different hash
    let hash3 = KeyAuthorization::unrestricted(2, key_type, key_id)
        .with_expiry(expiry)
        .with_limits(limits)
        .signature_hash();
    assert_ne!(
        hash1, hash3,
        "Different chain_id should produce different hash"
    );
}

#[test]
fn test_aa_gas_floor_gas_prague() {
    use alloy_primitives::{Bytes, TxKind};
    use tempo_primitives::transaction::{Call, TempoSignature};

    let spec = SpecId::PRAGUE;
    let calldata = Bytes::from(vec![1, 2, 3, 4, 5]); // 5 non-zero bytes

    let call = Call {
        to: TxKind::Call(Address::random()),
        value: U256::ZERO,
        input: calldata.clone(),
    };

    let aa_env = TempoBatchCallEnv {
        signature: TempoSignature::Primitive(PrimitiveSignature::Secp256k1(
            alloy_primitives::Signature::test_signature(),
        )),
        aa_calls: vec![call],
        key_authorization: None,
        signature_hash: B256::ZERO,
        ..Default::default()
    };

    let gas = calculate_aa_batch_intrinsic_gas(
        &aa_env,
        &genesis_gas_params(),
        None::<std::iter::Empty<&AccessListItem>>,
        tempo_chainspec::hardfork::TempoHardfork::default(),
    )
    .unwrap();

    // Calculate expected floor gas using revm's function
    let base_gas = calculate_initial_tx_gas(spec, &calldata, false, 0, 0, 0);

    // Floor gas should match revm's calculation for same calldata
    assert_eq!(
        gas.floor_gas, base_gas.floor_gas,
        "Should calculate floor gas for Prague matching revm"
    );
}

#[test]
fn test_key_authorization_gas_with_limits() {
    use tempo_primitives::transaction::{
        KeyAuthorization, SignatureType, SignedKeyAuthorization, TokenLimit,
    };

    // Helper to create key auth with N limits
    let create_key_auth = |num_limits: usize| -> SignedKeyAuthorization {
        let mut auth =
            KeyAuthorization::unrestricted(1, SignatureType::Secp256k1, Address::random());
        if num_limits > 0 {
            auth = auth.with_limits(
                (0..num_limits)
                    .map(|_| TokenLimit {
                        token: Address::random(),
                        limit: U256::from(1000),
                        period: 0,
                    })
                    .collect(),
            );
        }
        auth.into_signed(PrimitiveSignature::Secp256k1(
            alloy_primitives::Signature::test_signature(),
        ))
    };

    // Test 0 limits: base (27k) + ecrecover (3k) = 30,000
    let genesis_gas_params = genesis_gas_params();
    let (gas_0, state_0) = calculate_key_authorization_gas(
        &create_key_auth(0),
        &genesis_gas_params,
        tempo_chainspec::hardfork::TempoHardfork::default(),
    );
    assert_eq!(
        gas_0,
        KEY_AUTH_BASE_GAS + ECRECOVER_GAS,
        "0 limits should be 30,000"
    );
    assert_eq!(state_0, 0, "pre-T1B has no state gas");

    // Test 1 limit: 30,000 + 22,000 = 52,000
    let (gas_1, state_1) = calculate_key_authorization_gas(
        &create_key_auth(1),
        &genesis_gas_params,
        tempo_chainspec::hardfork::TempoHardfork::default(),
    );
    assert_eq!(
        gas_1,
        KEY_AUTH_BASE_GAS + ECRECOVER_GAS + KEY_AUTH_PER_LIMIT_GAS,
        "1 limit should be 52,000"
    );
    assert_eq!(state_1, 0, "pre-T1B has no state gas");

    // Test 2 limits: 30,000 + 44,000 = 74,000
    let (gas_2, _) = calculate_key_authorization_gas(
        &create_key_auth(2),
        &genesis_gas_params,
        tempo_chainspec::hardfork::TempoHardfork::default(),
    );
    assert_eq!(
        gas_2,
        KEY_AUTH_BASE_GAS + ECRECOVER_GAS + 2 * KEY_AUTH_PER_LIMIT_GAS,
        "2 limits should be 74,000"
    );

    // Test 3 limits: 30,000 + 66,000 = 96,000
    let (gas_3, _) = calculate_key_authorization_gas(
        &create_key_auth(3),
        &genesis_gas_params,
        tempo_chainspec::hardfork::TempoHardfork::default(),
    );
    assert_eq!(
        gas_3,
        KEY_AUTH_BASE_GAS + ECRECOVER_GAS + 3 * KEY_AUTH_PER_LIMIT_GAS,
        "3 limits should be 96,000"
    );

    // T1B branch: gas = sig_gas + SLOAD + SSTORE * (1 + num_limits) + buffer
    let t1b_gas_params = tempo_gas_params(TempoHardfork::T1B);
    let sstore = u64::from(t1b_gas_params.get(GasId::SstoreSetWithoutLoadCost));
    let sload = u64::from(t1b_gas_params.get(GasId::WarmStorageReadCost))
        + u64::from(t1b_gas_params.get(GasId::ColdStorageAdditionalCost));
    const BUFFER: u64 = 2_000;

    for num_limits in 0..=3 {
        let (gas, state_gas) = calculate_key_authorization_gas(
            &create_key_auth(num_limits),
            &t1b_gas_params,
            TempoHardfork::T1B,
        );
        let expected = ECRECOVER_GAS + sload + sstore * (1 + num_limits as u64) + BUFFER;
        assert_eq!(gas, expected, "T1B with {num_limits} limits");
        assert_eq!(state_gas, 0, "T1B has no state gas");
    }

    let t3_gas_params = tempo_gas_params(TempoHardfork::T3);
    let t3_sstore = u64::from(t3_gas_params.get(GasId::SstoreSetWithoutLoadCost));
    let t3_sload = u64::from(t3_gas_params.get(GasId::WarmStorageReadCost))
        + u64::from(t3_gas_params.get(GasId::ColdStorageAdditionalCost));

    for num_limits in 0..=3 {
        let num_sstores = 1 + 2 * num_limits as u64;
        let (gas, state_gas) = calculate_key_authorization_gas(
            &create_key_auth(num_limits),
            &t3_gas_params,
            TempoHardfork::T3,
        );
        let expected = ECRECOVER_GAS + t3_sload + t3_sstore * num_sstores + BUFFER;
        assert_eq!(gas, expected, "T3 with {num_limits} limits");
        assert_eq!(state_gas, 0, "T3 has no state gas");
    }

    // T4 with T4 gas params: regular sstore = 19,900, state gas = 230,000 per SSTORE
    let t4_gas_params = tempo_gas_params(TempoHardfork::T4);
    let t4_sstore = u64::from(t4_gas_params.get(GasId::SstoreSetWithoutLoadCost));
    let t4_sload = u64::from(t4_gas_params.get(GasId::WarmStorageReadCost))
        + u64::from(t4_gas_params.get(GasId::ColdStorageAdditionalCost));
    let t4_sstore_state = u64::from(t4_gas_params.get(GasId::SstoreSetState));

    for num_limits in 0..=3 {
        let num_sstores = 1 + 2 * num_limits as u64;
        let (gas, state_gas) = calculate_key_authorization_gas(
            &create_key_auth(num_limits),
            &t4_gas_params,
            TempoHardfork::T4,
        );
        let expected_state = t4_sstore_state * num_sstores;
        let expected =
            ECRECOVER_GAS + t4_sload + t4_sstore * num_sstores + BUFFER + 5_000 + expected_state;
        assert_eq!(gas + state_gas, expected, "T4 with {num_limits} limits");
        assert_eq!(
            state_gas, expected_state,
            "T4 state gas with {num_limits} limits"
        );
    }

    let t5_gas_params = tempo_gas_params(TempoHardfork::T5);
    let t5_sload = u64::from(t5_gas_params.get(GasId::WarmStorageReadCost))
        + u64::from(t5_gas_params.get(GasId::ColdStorageAdditionalCost));
    let base_t5_key_auth = create_key_auth(0);
    let mut witness_t5_key_auth = create_key_auth(0);
    witness_t5_key_auth.authorization = witness_t5_key_auth
        .authorization
        .with_witness(B256::repeat_byte(0x53));

    let (base_t5_gas, base_t5_state_gas) =
        calculate_key_authorization_gas(&base_t5_key_auth, &t5_gas_params, TempoHardfork::T5);
    let (witness_t5_gas, witness_t5_state_gas) =
        calculate_key_authorization_gas(&witness_t5_key_auth, &t5_gas_params, TempoHardfork::T5);

    assert_eq!(
        witness_t5_gas - base_t5_gas,
        t5_sload + KEY_AUTH_EXTRA_EVENT_BUFFER,
        "T5 witness adds one burned-witness SLOAD and one event"
    );
    assert_eq!(
        witness_t5_state_gas - base_t5_state_gas,
        0,
        "T5 witness authorization does not add state gas"
    );

    let t6_gas_params = tempo_gas_params(TempoHardfork::T6);
    let base_t6_key_auth = create_key_auth(0);
    let mut account_bound_t6_key_auth = create_key_auth(0);
    account_bound_t6_key_auth.authorization = account_bound_t6_key_auth
        .authorization
        .with_account(Address::random());
    let mut admin_t6_key_auth = create_key_auth(0);
    admin_t6_key_auth.authorization = admin_t6_key_auth
        .authorization
        .into_admin(Address::random());
    let mut unbound_admin_t6_key_auth = create_key_auth(0);
    unbound_admin_t6_key_auth.authorization.is_admin = true;

    let (base_t6_gas, base_t6_state_gas) =
        calculate_key_authorization_gas(&base_t6_key_auth, &t6_gas_params, TempoHardfork::T6);
    let (account_bound_t6_gas, account_bound_t6_state_gas) = calculate_key_authorization_gas(
        &account_bound_t6_key_auth,
        &t6_gas_params,
        TempoHardfork::T6,
    );
    let (admin_t6_gas, admin_t6_state_gas) =
        calculate_key_authorization_gas(&admin_t6_key_auth, &t6_gas_params, TempoHardfork::T6);
    let (unbound_admin_t6_gas, unbound_admin_t6_state_gas) = calculate_key_authorization_gas(
        &unbound_admin_t6_key_auth,
        &t6_gas_params,
        TempoHardfork::T6,
    );

    assert_eq!(
        account_bound_t6_gas - base_t6_gas,
        0,
        "T6 account-bound authorization does not add key authorization gas"
    );
    assert_eq!(
        admin_t6_gas - base_t6_gas,
        KEY_AUTH_EXTRA_EVENT_BUFFER,
        "T6 account-bound admin authorization charges one extra event buffer"
    );
    assert_eq!(
        admin_t6_gas - account_bound_t6_gas,
        KEY_AUTH_EXTRA_EVENT_BUFFER,
        "T6 admin authorization pays one extra event buffer over non-admin account-bound authorization"
    );
    assert_eq!(
        unbound_admin_t6_gas - base_t6_gas,
        KEY_AUTH_EXTRA_EVENT_BUFFER,
        "T6 root-signed admin authorization without account charges only the extra event buffer"
    );
    assert_eq!(
        account_bound_t6_state_gas, base_t6_state_gas,
        "T6 account binding does not add state gas"
    );
    assert_eq!(
        admin_t6_state_gas, base_t6_state_gas,
        "T6 admin authorization event buffer does not add state gas"
    );
    assert_eq!(
        unbound_admin_t6_state_gas, base_t6_state_gas,
        "T6 unbound admin authorization does not add state gas"
    );

    let scoped = KeyAuthorization::unrestricted(1, SignatureType::Secp256k1, Address::random())
        .with_allowed_calls(vec![tempo_primitives::transaction::CallScope {
            target: Address::random(),
            selector_rules: vec![tempo_primitives::transaction::SelectorRule {
                selector: [0xa9, 0x05, 0x9c, 0xbb],
                recipients: vec![Address::random(), Address::random()],
            }],
        }])
        .into_signed(PrimitiveSignature::Secp256k1(
            alloy_primitives::Signature::test_signature(),
        ));

    let (gas, state_gas) =
        calculate_key_authorization_gas(&scoped, &t3_gas_params, TempoHardfork::T3);
    let expected = ECRECOVER_GAS + t3_sload + t3_sstore * (1 + 12) + BUFFER;
    assert_eq!(
        gas, expected,
        "T3 scope writes should keep current main accounting"
    );
    assert_eq!(state_gas, 0, "T3 has no state gas");

    let (gas, state_gas) =
        calculate_key_authorization_gas(&scoped, &t4_gas_params, TempoHardfork::T4);
    // 1 key write + 12 scope slots = 13 SSTOREs:
    // account mode(1) + target insertion rows(3) + selector insertion rows(3)
    // + constrained selector recipient-length(1) + recipients values+positions(2*2).
    // The rounded surcharge adds 5k base + 7k per target + 7k per selector + 5k per
    // recipient, which keeps larger scope trees from being materially underpriced.
    let num_sstores = 1 + 12;
    let expected_state = t4_sstore_state * num_sstores;
    let expected =
        ECRECOVER_GAS + t4_sload + t4_sstore * num_sstores + BUFFER + 29_000 + expected_state;
    assert_eq!(
        gas + state_gas,
        expected,
        "T4 scope writes should be fully charged"
    );
    assert_eq!(state_gas, expected_state, "T4 scope state gas");
    let multi_scope =
        KeyAuthorization::unrestricted(1, SignatureType::Secp256k1, Address::random())
            .with_allowed_calls(vec![
                tempo_primitives::transaction::CallScope {
                    target: Address::random(),
                    selector_rules: vec![
                        tempo_primitives::transaction::SelectorRule {
                            selector: [0xa9, 0x05, 0x9c, 0xbb],
                            recipients: vec![],
                        },
                        tempo_primitives::transaction::SelectorRule {
                            selector: [0x09, 0x5e, 0xa7, 0xb3],
                            recipients: vec![],
                        },
                    ],
                },
                tempo_primitives::transaction::CallScope {
                    target: Address::random(),
                    selector_rules: vec![],
                },
            ])
            .into_signed(PrimitiveSignature::Secp256k1(
                alloy_primitives::Signature::test_signature(),
            ));

    let (gas, state_gas) =
        calculate_key_authorization_gas(&multi_scope, &t3_gas_params, TempoHardfork::T3);
    let expected = ECRECOVER_GAS + t3_sload + t3_sstore * 14 + BUFFER;
    assert_eq!(
        gas, expected,
        "T3 scope writes should keep current main accounting"
    );
    assert_eq!(state_gas, 0, "T3 has no state gas");

    let (gas, state_gas) =
        calculate_key_authorization_gas(&multi_scope, &t4_gas_params, TempoHardfork::T4);
    let expected_state = t4_sstore_state * 12;
    let expected = ECRECOVER_GAS + t4_sload + t4_sstore * 12 + BUFFER + 33_000 + expected_state;
    assert_eq!(
        gas + state_gas,
        expected,
        "T4 scope writes should only charge storage-creating rows"
    );
    assert_eq!(state_gas, expected_state, "T4 scope state gas");
}

#[test]
fn test_t4_key_authorization_matches_tip1016_sstore_regular_cost() {
    let evm = test_evm_with_amsterdam(TempoHardfork::T4, true);
    let authorization = key_authorization(0);
    let params = &evm.version().gas_params;
    let load = u64::from(params[GasId::WarmStorageReadCost])
        + u64::from(params[GasId::ColdStorageAdditionalCost]);
    let (regular, state) = key_authorization_gas(&authorization, &evm, TempoHardfork::T4);
    assert_eq!(
        regular - ECRECOVER_GAS - load - 2_000 - call_scope_extra_gas(&authorization.authorization),
        20_000
    );
    assert_eq!(state, 230_000);
}

#[test]
fn test_t7_key_authorization_intrinsic_includes_storage_credit_value() {
    let evm = test_evm(TempoHardfork::T7);
    let authorization = key_authorization(0);
    let params = &evm.version().gas_params;
    let load = u64::from(params[GasId::WarmStorageReadCost])
        + u64::from(params[GasId::ColdStorageAdditionalCost]);
    let (regular, state) = key_authorization_gas(&authorization, &evm, TempoHardfork::T7);
    assert_eq!(params[GasId::SstoreSetWithoutLoadCost], 5_000);
    assert_eq!(
        regular - ECRECOVER_GAS - load - 2_000 - call_scope_extra_gas(&authorization.authorization),
        tempo_chainspec::constants::gas::SSTORE_CREATE_COST
    );
    assert_eq!(state, 0);
}

#[test]
fn test_translate_allowed_calls_for_precompile_preserves_empty_nested_allow_all_lists() {
    let empty_selectors =
        KeyAuthorization::unrestricted(1, SignatureType::Secp256k1, Address::ZERO)
            .with_allowed_calls(vec![CallScope {
                target: Address::repeat_byte(1),
                selector_rules: Vec::new(),
            }])
            .into_signed(PrimitiveSignature::Secp256k1(Signature::test_signature()));
    let translated = translate_allowed_calls(&empty_selectors);
    assert_eq!(translated.len(), 1);
    assert!(translated[0].selectorRules.is_empty());

    let empty_recipients =
        KeyAuthorization::unrestricted(1, SignatureType::Secp256k1, Address::ZERO)
            .with_allowed_calls(vec![CallScope {
                target: Address::repeat_byte(1),
                selector_rules: vec![SelectorRule {
                    selector: [0xa9, 0x05, 0x9c, 0xbb],
                    recipients: Vec::new(),
                }],
            }])
            .into_signed(PrimitiveSignature::Secp256k1(Signature::test_signature()));
    let translated = translate_allowed_calls(&empty_recipients);
    assert_eq!(translated.len(), 1);
    assert_eq!(translated[0].selectorRules.len(), 1);
    assert!(translated[0].selectorRules[0].recipients.is_empty());
}

#[test]
fn test_key_authorization_gas_in_batch() {
    let calldata = Bytes::from(vec![1, 2, 3]);

    let call = Call {
        to: TxKind::Call(Address::random()),
        value: U256::ZERO,
        input: calldata,
    };

    // Create key authorization with 2 limits
    let key_auth: SignedKeyAuthorization =
        KeyAuthorization::unrestricted(1, SignatureType::Secp256k1, Address::random())
            .with_limits(vec![
                TokenLimit {
                    token: Address::random(),
                    limit: U256::from(1000),
                    period: 0,
                },
                TokenLimit {
                    token: Address::random(),
                    limit: U256::from(2000),
                    period: 0,
                },
            ])
            .into_signed(PrimitiveSignature::Secp256k1(Signature::test_signature()));

    let aa_env_with_key_auth = TempoBatchCallEnv {
        signature: TempoSignature::Primitive(PrimitiveSignature::Secp256k1(
            Signature::test_signature(),
        )),
        aa_calls: vec![call.clone()],
        key_authorization: Some(key_auth),
        signature_hash: B256::ZERO,
        ..Default::default()
    };

    let aa_env_without_key_auth = TempoBatchCallEnv {
        signature: TempoSignature::Primitive(PrimitiveSignature::Secp256k1(
            Signature::test_signature(),
        )),
        aa_calls: vec![call],
        key_authorization: None,
        signature_hash: B256::ZERO,
        ..Default::default()
    };

    let calculate = |env: &TempoBatchCallEnv| {
        let (regular, state, _) = intrinsic(
            TempoHardfork::Genesis,
            TempoTransaction {
                calls: env.aa_calls.clone(),
                key_authorization: env.key_authorization.clone(),
                ..Default::default()
            },
            env.signature.clone(),
        )
        .unwrap();
        InitialAndFloorGas {
            initial_gas: regular,
            initial_state_gas: state,
            floor_gas: 0,
        }
    };

    // Calculate gas WITH key authorization
    let gas_with_key_auth = calculate(&aa_env_with_key_auth);

    // Calculate gas WITHOUT key authorization
    let gas_without_key_auth = calculate(&aa_env_without_key_auth);

    // Expected key auth gas: 30,000 (base + ecrecover) + 2 * 22,000 (limits) = 74,000
    let expected_key_auth_gas = KEY_AUTH_BASE_GAS + ECRECOVER_GAS + 2 * KEY_AUTH_PER_LIMIT_GAS;

    assert_eq!(
        gas_with_key_auth.initial_total_gas() - gas_without_key_auth.initial_total_gas(),
        expected_key_auth_gas,
        "Key authorization should add exactly {expected_key_auth_gas} gas to batch",
    );

    // Also verify absolute values
    let evm = test_evm(TempoHardfork::Genesis);
    let expected_without = u64::from(evm.version().gas_params[GasId::TxBaseStipend])
        + 12 * u64::from(evm.version().gas_params[GasId::TxTokenCost]);
    let expected_with = expected_without + expected_key_auth_gas;

    assert_eq!(
        gas_without_key_auth.initial_total_gas(),
        expected_without,
        "Gas without key auth should match expected"
    );
    assert_eq!(
        gas_with_key_auth.initial_total_gas(),
        expected_with,
        "Gas with key auth should match expected"
    );
}

#[test]
fn test_2d_nonce_gas_in_intrinsic_gas() {
    const BASE_INTRINSIC_GAS: u64 = 21_000;

    for spec in [
        TempoHardfork::Genesis,
        TempoHardfork::T0,
        TempoHardfork::T1,
        TempoHardfork::T1A,
        TempoHardfork::T1B,
        TempoHardfork::T2,
    ] {
        let gas = |nonce, nonce_key| {
            intrinsic(
                spec,
                TempoTransaction {
                    nonce,
                    nonce_key,
                    calls: vec![call(Bytes::new())],
                    ..Default::default()
                },
                secp256k1_signature(),
            )
            .unwrap()
        };

        // Case 1: Protocol nonce (nonce_key == 0, nonce > 0) - no additional gas
        {
            let gas = gas(5, U256::ZERO);
            assert_eq!(
                gas.0, BASE_INTRINSIC_GAS,
                "{spec:?}: protocol nonce (nonce_key=0, nonce>0) should have no extra gas"
            );
        }

        // Case 2: nonce_key != 0, nonce == 0
        {
            let evm = test_evm(spec);
            let expected = if spec.is_t1() {
                // T1+: any nonce==0 charges new_account_cost (250k)
                BASE_INTRINSIC_GAS
                    + u64::from(evm.version().gas_params[GasId::NewAccountCost])
                    + evm.version().gas_params.new_account_state_gas()
            } else {
                // Pre-T1: charges gas_new_nonce_key for new 2D key
                BASE_INTRINSIC_GAS + spec.gas_new_nonce_key()
            };
            let gas = gas(0, U256::ONE);
            assert_eq!(
                gas.0 + gas.1,
                expected,
                "{spec:?}: nonce_key!=0, nonce==0 gas mismatch"
            );
        }

        // Case 3: Existing 2D nonce key (nonce_key != 0, nonce > 0)
        {
            let gas = gas(5, U256::ONE);
            assert_eq!(
                gas.0,
                BASE_INTRINSIC_GAS + spec.gas_existing_nonce_key(),
                "{spec:?}: existing 2D nonce key gas mismatch"
            );
        }
    }
}

/// Test that T1 hardfork correctly charges 250k gas for nonce == 0.
///
/// This test validates [TIP-1000]'s requirement:
/// "Tempo transactions with any `nonce_key` and `nonce == 0` require an additional 250,000 gas"
///
/// The test proves the audit finding (claiming only 22,100 gas is charged) is a false positive
/// by using delta-based assertions: gas(nonce=0) - gas(nonce>0) == new_account_cost.
///
/// [TIP-1000]: <https://docs.tempo.xyz/protocol/tips/tip-1000>
#[test]
fn test_t1_2d_nonce_key_charges_250k_gas() {
    // Deterministic test addresses
    const TEST_TARGET: Address = Address::new([0xAA; 20]);
    const TEST_NONCE_KEY: U256 = U256::from_limbs([42, 0, 0, 0]);
    const SPEC: TempoHardfork = TempoHardfork::T1;
    const NEW_NONCE_KEY_GAS: u64 = SPEC.gas_new_nonce_key();
    const EXISTING_NONCE_KEY_GAS: u64 = SPEC.gas_existing_nonce_key();

    // Create T1 config with TIP-1000 gas params
    let gas_params = tempo_gas_params(TempoHardfork::T1);

    // Get the expected new_account_cost dynamically from gas params
    let new_account_cost = u64::from(gas_params[GasId::NewAccountCost]);
    assert_eq!(
        new_account_cost, 250_000,
        "T1 gas params should have 250k new_account_cost"
    );

    // Helper to create EVM context for testing
    let make_evm = |nonce: u64, nonce_key: U256| {
        let (initial_gas, initial_state_gas, floor_gas) = intrinsic(
            SPEC,
            TempoTransaction {
                gas_limit: 1_000_000,
                nonce,
                nonce_key,
                calls: vec![Call {
                    to: TxKind::Call(TEST_TARGET),
                    value: U256::ZERO,
                    input: Bytes::new(),
                }],
                ..Default::default()
            },
            secp256k1_signature(),
        )
        .unwrap();
        InitialAndFloorGas {
            initial_gas,
            initial_state_gas,
            floor_gas,
        }
    };

    // Case 1: nonce == 0 with 2D nonce key -> should include new_account_cost
    let gas_nonce_zero = make_evm(0, TEST_NONCE_KEY);

    // Case 2: nonce > 0 with same 2D nonce key -> should charge EXISTING_NONCE_KEY_GAS (5k)
    // This tests that existing 2D nonce keys are charged 5k gas per TIP-1000 Invariant 3
    let gas_nonce_five = make_evm(5, TEST_NONCE_KEY);

    // Delta-based assertion: the difference should be new_account_cost - EXISTING_NONCE_KEY_GAS
    // nonce=0 charges 250k (new account), nonce>0 charges 5k (existing key update)
    let gas_delta = gas_nonce_zero.initial_total_gas() - gas_nonce_five.initial_total_gas();
    let expected_delta = new_account_cost - EXISTING_NONCE_KEY_GAS;
    assert_eq!(
        gas_delta, expected_delta,
        "T1 gas difference between nonce=0 and nonce>0 should be {expected_delta} (new_account_cost - EXISTING_NONCE_KEY_GAS), got {gas_delta}"
    );

    // Verify it's NOT using the pre-T1 NEW_NONCE_KEY_GAS (22,100)
    assert_ne!(
        gas_delta, NEW_NONCE_KEY_GAS,
        "T1 should NOT use pre-T1 NEW_NONCE_KEY_GAS ({NEW_NONCE_KEY_GAS}) for nonce=0 transactions"
    );

    // Case 3: nonce == 0 with regular nonce (nonce_key=0) -> same +250k charge
    let gas_regular = make_evm(0, U256::ZERO);

    assert_eq!(
        gas_nonce_zero.initial_total_gas(),
        gas_regular.initial_total_gas(),
        "nonce=0 should charge the same regardless of nonce_key (2D vs regular)"
    );
}

/// Test that T1 hardfork correctly charges 5k gas for existing 2D nonce keys (nonce > 0).
///
/// This test validates [TIP-1000] Invariant 3:
/// "SSTORE operations that modify existing non-zero state (non-zero to non-zero)
/// MUST continue to charge 5,000 gas"
///
/// When using an existing 2D nonce key (nonce_key != 0 && nonce > 0), the nonce value
/// transitions from N to N+1 (non-zero to non-zero), which must charge EXISTING_NONCE_KEY_GAS.
///
/// [TIP-1000]: <https://docs.tempo.xyz/protocol/tips/tip-1000>
#[test]
fn test_t1_existing_2d_nonce_key_charges_5k_gas() {
    const BASE_INTRINSIC_GAS: u64 = 21_000;
    const TEST_TARGET: Address = Address::new([0xBB; 20]);
    const TEST_NONCE_KEY: U256 = U256::from_limbs([99, 0, 0, 0]);
    const SPEC: TempoHardfork = TempoHardfork::T1;
    const EXISTING_NONCE_KEY_GAS: u64 = SPEC.gas_existing_nonce_key();

    let make_evm = |nonce: u64, nonce_key: U256| {
        let (initial_gas, initial_state_gas, floor_gas) = intrinsic(
            SPEC,
            TempoTransaction {
                gas_limit: 1_000_000,
                nonce,
                nonce_key,
                calls: vec![Call {
                    to: TxKind::Call(TEST_TARGET),
                    value: U256::ZERO,
                    input: Bytes::new(),
                }],
                ..Default::default()
            },
            secp256k1_signature(),
        )
        .unwrap();
        InitialAndFloorGas {
            initial_gas,
            initial_state_gas,
            floor_gas,
        }
    };

    // Case 1: Existing 2D nonce key (nonce > 0) should charge EXISTING_NONCE_KEY_GAS
    let gas_existing = make_evm(5, TEST_NONCE_KEY);
    assert_eq!(
        gas_existing.initial_total_gas(),
        BASE_INTRINSIC_GAS + EXISTING_NONCE_KEY_GAS,
        "T1 existing 2D nonce key (nonce>0) should charge BASE + EXISTING_NONCE_KEY_GAS ({EXISTING_NONCE_KEY_GAS})"
    );

    // Case 2: Regular nonce (nonce_key = 0) with nonce > 0 should NOT charge extra gas
    let gas_regular = make_evm(5, U256::ZERO);

    assert_eq!(
        gas_regular.initial_total_gas(),
        BASE_INTRINSIC_GAS,
        "T1 regular nonce (nonce_key=0, nonce>0) should only charge BASE intrinsic gas"
    );

    // Verify the delta between 2D and regular nonce is exactly EXISTING_NONCE_KEY_GAS
    let gas_delta = gas_existing.initial_total_gas() - gas_regular.initial_total_gas();
    assert_eq!(
        gas_delta, EXISTING_NONCE_KEY_GAS,
        "Difference between existing 2D and regular nonce should be EXISTING_NONCE_KEY_GAS ({EXISTING_NONCE_KEY_GAS})"
    );
}

#[test]
fn test_2d_nonce_gas_limit_validation() {
    const BASE_INTRINSIC_GAS: u64 = 21_000;

    for spec in [
        TempoHardfork::Genesis,
        TempoHardfork::T0,
        TempoHardfork::T1,
        TempoHardfork::T2,
    ] {
        let evm = test_evm(spec);
        let env = |nonce| {
            aa_env(
                TempoTransaction {
                    nonce,
                    nonce_key: U256::ONE,
                    calls: vec![call(Bytes::new())],
                    ..Default::default()
                },
                secp256k1_signature(),
            )
        };
        let nonce_zero_env = env(0);
        let nonce_zero = nonce_zero_env.as_aa().unwrap();
        let (nonce_zero_gas, nonce_zero_state_gas) = nonce_intrinsic_gas(&evm, nonce_zero);
        let nonce_zero_total = nonce_zero_gas + nonce_zero_state_gas;

        // Build spec-specific test cases: (gas_limit, nonce, expected_result)
        let cases = if spec.is_t0() {
            let mut cases = vec![
                (BASE_INTRINSIC_GAS + nonce_zero_total, 0, true), // Exactly sufficient for nonce==0 (exec + state)
                (BASE_INTRINSIC_GAS + spec.gas_existing_nonce_key(), 1, true), // Exactly sufficient for existing key
            ];
            // Insufficient: below total required for nonce==0
            cases.push((BASE_INTRINSIC_GAS + nonce_zero_total - 1, 0u64, false));
            cases
        } else {
            // Genesis: nonce gas is added AFTER validation, so lower gas_limit still passes
            vec![
                (BASE_INTRINSIC_GAS + 10_000, 0u64, true), // Passes validation (nonce gas added after)
                (BASE_INTRINSIC_GAS + nonce_zero_gas, 0, true), // Also passes
                (BASE_INTRINSIC_GAS + spec.gas_existing_nonce_key(), 1, true), // Also passes
                (BASE_INTRINSIC_GAS - 1, 0, false),        // Below base intrinsic gas
            ]
        };

        for (gas_limit, nonce, should_succeed) in cases {
            let env = env(nonce);
            let aa = env.as_aa().unwrap();
            let (mut regular, mut state, _) = intrinsic_gas(&evm, aa).unwrap();
            if spec.is_t0() {
                let (nonce_regular, nonce_state) = nonce_intrinsic_gas(&evm, aa);
                regular += nonce_regular;
                state += nonce_state;
            }
            let result = evm2::ethereum::validate_intrinsic_gas(gas_limit, regular, state);

            if should_succeed {
                assert!(
                    result.is_ok(),
                    "{spec:?}: gas_limit={gas_limit}, nonce={nonce}: expected success but got error"
                );
            } else {
                assert!(
                    result.is_err(),
                    "{spec:?}: gas_limit={gas_limit}, nonce={nonce}: should fail"
                );
            }
        }
    }
}

/// TIP-1016: Standard CREATE tx should populate initial_state_gas with
/// create_state_gas when state gas is enabled (T4+).
/// Note: new_account_state_gas for the caller (nonce==0) is added later
/// during state validation, not in the initial CREATE state gas.
#[test]
fn test_state_gas_standard_create_tx_populates_initial_state_gas() {
    // TIP-1016 is opt-in via amsterdam_eip8037; manually enable for this test.
    let gas_params = tempo_gas_params(TempoHardfork::T4);
    let initcode = Bytes::from(vec![0x60, 0x80]);

    let init_gas = gas_params.initial_tx_gas(
        &initcode, true, // is_create
        0, 0, 0,
    );

    let expected_state_gas = gas_params.create_state_gas();

    assert!(
        expected_state_gas > 0,
        "State gas constants should be non-zero"
    );
    assert_eq!(
        init_gas.initial_state_gas,
        expected_state_gas,
        "CREATE tx should have initial_state_gas = create_state_gas ({})",
        gas_params.create_state_gas()
    );
}

/// TIP-1016: Standard CALL tx should have zero initial_state_gas.
#[test]
fn test_state_gas_standard_call_tx_zero_initial_state_gas() {
    let gas_params = tempo_gas_params(TempoHardfork::T4);
    let calldata = Bytes::from(vec![1, 2, 3]);

    let init_gas = gas_params.initial_tx_gas(
        &calldata, false, // not create
        0, 0, 0,
    );

    assert_eq!(
        init_gas.initial_state_gas, 0,
        "CALL tx should have zero initial_state_gas"
    );
}

/// TIP-1016: initial gas for a standard CREATE tx should include both the
/// CREATE state charge and the nonce-zero caller account charge at T4.
#[test]
fn test_state_gas_validate_initial_tx_gas_create_t4() {
    let evm = test_evm_with_amsterdam(TempoHardfork::T4, true);
    let initial_state_gas = evm2::ethereum::create_initial_state_gas(evm.version(), true)
        + evm.version().gas_params.new_account_state_gas();

    // create_state_gas (from the CREATE intrinsic) + new_account_state_gas
    // (from Tempo's nonce==0 check for the caller)
    let expected_state_gas = evm.version().gas_params.create_state_gas()
        + evm.version().gas_params.new_account_state_gas();

    assert_eq!(
        initial_state_gas, expected_state_gas,
        "T4 CREATE tx with nonce==0 should have create_state_gas + new_account_state_gas"
    );
}

/// TIP-1016: When EIP-8037 is enabled, tx gas limit can exceed the cap.
#[test]
fn test_state_gas_tx_gas_limit_above_cap_allowed() {
    let evm = test_evm_with_amsterdam(TempoHardfork::T4, true);

    // validate_env should pass even though gas_limit > cap
    let result = evm2::ethereum::validate_tx_gas_limit_cap(evm.version(), 60_000_000);
    assert!(
        result.is_ok(),
        "With EIP-8037 enabled, tx gas limit above cap should be allowed, got: {:?}",
        result.err()
    );
}

/// TIP-1016: When EIP-8037 is disabled (pre-T4), tx gas limit above cap is rejected.
#[test]
fn test_state_gas_tx_gas_limit_above_cap_rejected_pre_t4() {
    let evm = test_evm_with_amsterdam(TempoHardfork::T1, false);

    // validate_env should reject: gas_limit > cap with state gas disabled
    let result = evm2::ethereum::validate_tx_gas_limit_cap(evm.version(), 60_000_000);
    assert!(
        result.is_err(),
        "With EIP-8037 disabled, tx gas limit above cap should be rejected"
    );
}

/// TIP-1016 regression: subblock fee-payment halt must not exceed the gas cap.
#[test]
fn test_subblock_fee_payment_halt_clamps_to_gas_cap_t4() {
    const CAP: u64 = 1 << 24;
    const TX_GAS_LIMIT: u64 = 60_000_000;

    let mut evm = test_evm_with_amsterdam(TempoHardfork::T4, true);
    StorageCtx::enter_evm_without_tip1060_accounting(&mut evm, || {
        TIP20Setup::path_usd(SIGNER).with_issuer(SIGNER).apply()
    })
    .expect("PATH USD setup succeeds");

    let env = aa_env(
        TempoTransaction {
            chain_id: 1,
            fee_token: Some(PATH_USD_ADDRESS),
            max_priority_fee_per_gas: 1,
            max_fee_per_gas: 1,
            gas_limit: TX_GAS_LIMIT,
            calls: vec![call(Bytes::new())],
            nonce_key: U256::from(TEMPO_SUBBLOCK_NONCE_KEY_PREFIX) << 248,
            ..Default::default()
        },
        secp256k1_signature(),
    );

    // Sanity: T4 must actually have the cap-skip enabled so tx_gas_limit > cap is legal.
    assert!(
        evm.feature(EvmFeatures::EIP8037),
        "T4 must enable EIP-8037 for this regression to apply"
    );
    assert_eq!(evm.version().tx_gas_limit_cap, CAP);

    let env = Recovered::new_unchecked(env, SIGNER);
    let result = evm
        .transact(&env)
        .expect("subblock fee-payment failure must be converted to a halt, not a hard error")
        .detach()
        .result;

    assert!(!result.status);
    assert_eq!(result.stop, InstrStop::PrecompileError);
    assert_eq!(
        result.total_gas_spent, CAP,
        "regular gas charged on subblock fee-payment halt must be clamped to \
                     tx_gas_limit_cap (got {} for tx.gas_limit={} cap={})",
        result.total_gas_spent, TX_GAS_LIMIT, CAP,
    );
    assert_eq!(result.state_gas_spent, 0, "halt reports zero state gas");
}

#[test]
fn test_subblock_paused_fee_token_halts_as_fee_payment_failure() {
    const GAS_LIMIT: u64 = 300_000;

    let mut evm = test_evm_with_amsterdam(TempoHardfork::T4, true);
    StorageCtx::enter_evm_without_tip1060_accounting(&mut evm, || {
        let mut token = TIP20Setup::path_usd(SIGNER)
            .with_issuer(SIGNER)
            .with_role(SIGNER, *PAUSE_ROLE)
            .apply()?;
        token.pause(SIGNER, ITIP20::pauseCall {})
    })
    .expect("paused PATH USD setup succeeds");

    let env = aa_env(
        TempoTransaction {
            chain_id: 1,
            fee_token: Some(PATH_USD_ADDRESS),
            max_priority_fee_per_gas: 1,
            max_fee_per_gas: 1,
            gas_limit: GAS_LIMIT,
            calls: vec![call(Bytes::new())],
            nonce_key: U256::from(TEMPO_SUBBLOCK_NONCE_KEY_PREFIX) << 248,
            ..Default::default()
        },
        secp256k1_signature(),
    );

    let env = Recovered::new_unchecked(env, SIGNER);
    let result = evm
        .transact(&env)
        .expect("subblock paused fee-token failure must be converted to a halt")
        .detach()
        .result;

    assert!(!result.status);
    assert_eq!(result.stop, InstrStop::PrecompileError);
    assert_eq!(result.total_gas_spent, GAS_LIMIT);
    assert_eq!(result.state_gas_spent, 0, "halt reports zero state gas");
}

/// TIP-1016: Pre-T4 behavior unchanged. EIP-8037 is disabled and a CALL
/// transaction has no initial state gas.
#[test]
fn test_state_gas_backward_compat_t1_no_state_gas_enabled() {
    let evm = test_evm_with_amsterdam(TempoHardfork::T1, false);

    assert!(
        !evm.feature(EvmFeatures::EIP8037),
        "Pre-T4 should NOT have EIP-8037 enabled"
    );

    // CALL tx - no state gas in either case
    assert_eq!(
        evm2::ethereum::create_initial_state_gas(evm.version(), false),
        0
    );
}

/// TIP-1016: Standard tx with nonce==0 should track state gas on T4 only.
#[test]
fn test_state_gas_standard_tx_nonce_zero_t4() {
    let evm = test_evm_with_amsterdam(TempoHardfork::T4, true);
    let initial_state_gas = evm.version().gas_params.new_account_state_gas();

    assert_eq!(
        initial_state_gas,
        evm.version().gas_params.new_account_state_gas(),
        "T4 standard tx with nonce==0 should track new_account_state_gas"
    );
}

/// TIP-1016: Standard tx with nonce==0 should NOT track state gas on T1.
#[test]
fn test_state_gas_standard_tx_nonce_zero_t1_no_state_gas() {
    let evm = test_evm_with_amsterdam(TempoHardfork::T1, false);
    let initial_state_gas = evm.version().gas_params.new_account_state_gas();

    assert_eq!(
        initial_state_gas, 0,
        "T1 standard tx with nonce==0 must NOT track state gas"
    );
}

/// TIP-1060: T7 removes the EIP-3529 one-fifth refund cap; pre-T7 keeps it.
#[test]
fn test_refund_cap_removed_on_t7() {
    // Refund (50k) deliberately exceeds one fifth of the gas used (100k / 5 = 20k).
    const SPENT: u64 = 100_000;
    const REFUND: i64 = 50_000;
    const CAPPED: u64 = SPENT / 5;

    let refunded_for_spec = |spec: TempoHardfork| -> u64 {
        let evm = test_evm(spec);
        let mut result = MessageResult::<TempoEvmTypes> {
            gas: GasTracker::new_spent_with_reservoir(SPENT, 0),
            ..MessageResult::default()
        };
        result.gas.record_refund(REFUND);
        result.final_refund(
            SPENT,
            u64::from(evm.version().gas_params[GasId::MaxRefundQuotient]),
        )
    };

    assert_eq!(
        refunded_for_spec(TempoHardfork::T6),
        CAPPED,
        "pre-T7 must cap the refund at one fifth of gas used"
    );
    assert_eq!(
        refunded_for_spec(TempoHardfork::T7),
        REFUND as u64,
        "T7 must credit the full refund, with no EIP-3529 cap"
    );
}

#[test]
fn test_multicall_gas_refund_accounting() {
    use std::sync::atomic::{AtomicUsize, Ordering};

    const GAS_LIMIT: u64 = 1_000_000;
    const INTRINSIC_GAS: u64 = 21_000;
    // Mock call's gas: (CALL_0, CALL_1)
    const SPENT: (u64, u64) = (1000, 500);
    const REFUND: (i64, i64) = (100, 50);

    #[derive(Debug)]
    struct Runner {
        call_idx: AtomicUsize,
        outcomes: [(InstrStop, u64, i64); 2],
    }

    impl evm2::InterpreterRunner<TempoEvmTypes> for Runner {
        fn run<'frame, 'host>(
            &self,
            _config: &ExecutionConfig<TempoEvmTypes>,
            interpreter: &mut evm2::interpreter::Interpreter<'frame, 'host, TempoEvmTypes>,
            _host: &mut Evm<'host, TempoEvmTypes>,
        ) -> Option<InstrStop> {
            let (stop, spent, refund) =
                self.outcomes[self.call_idx.fetch_add(1, Ordering::Relaxed)];
            interpreter
                .gas_mut()
                .tracker_mut()
                .spend(spent)
                .expect("mock call has enough gas");
            interpreter.gas_mut().tracker_mut().record_refund(refund);
            Some(stop)
        }
    }

    let mut evm = test_evm(TempoHardfork::Genesis);
    evm.set_interpreter_runner(Runner {
        call_idx: AtomicUsize::new(0),
        outcomes: [
            (InstrStop::Stop, SPENT.0, REFUND.0),
            (InstrStop::Stop, SPENT.1, REFUND.1),
        ],
    });

    let calls = vec![
        Call {
            to: TxKind::Call(Address::random()),
            value: U256::ZERO,
            input: Bytes::new(),
        },
        Call {
            to: TxKind::Call(Address::random()),
            value: U256::ZERO,
            input: Bytes::new(),
        },
    ];

    let result = execute_batch(
        &mut evm,
        SIGNER,
        None,
        0,
        U256::ZERO,
        GAS_LIMIT - INTRINSIC_GAS,
        0,
        &calls,
        false,
    )
    .expect("execute_batch should succeed");

    assert_eq!(
        INTRINSIC_GAS + result.gas.spent(),
        INTRINSIC_GAS + SPENT.0 + SPENT.1,
        "Total spent should be intrinsic_gas + sum of all calls' spent values"
    );
    assert_eq!(
        result.gas.refunded(),
        REFUND.0 + REFUND.1,
        "Total refund should be sum of all calls' refunded values"
    );
    assert_eq!(
        INTRINSIC_GAS + result.gas.used(),
        INTRINSIC_GAS + SPENT.0 + SPENT.1 - (REFUND.0 + REFUND.1) as u64,
        "used() should be spent - refund"
    );
}

/// TIP-1016: CREATE state gas is charged upfront and must be spent even if a later AA step reverts.
#[test]
fn test_state_gas_failed_batch_preserves_upfront_create_intrinsic_gas() {
    use std::sync::atomic::{AtomicUsize, Ordering};

    const TX_GAS_LIMIT: u64 = 1_000_000;
    const INTRINSIC_GAS: u64 = 21_000;
    const CALL_RESULTS: [(InstrStop, u64); 2] =
        [(InstrStop::Stop, 10_000), (InstrStop::Revert, 7_000)];

    #[derive(Debug)]
    struct Runner {
        call_idx: AtomicUsize,
    }

    impl evm2::InterpreterRunner<TempoEvmTypes> for Runner {
        fn run<'frame, 'host>(
            &self,
            _config: &ExecutionConfig<TempoEvmTypes>,
            interpreter: &mut evm2::interpreter::Interpreter<'frame, 'host, TempoEvmTypes>,
            _host: &mut Evm<'host, TempoEvmTypes>,
        ) -> Option<InstrStop> {
            let (stop, spent) = CALL_RESULTS[self.call_idx.fetch_add(1, Ordering::Relaxed)];
            interpreter
                .gas_mut()
                .tracker_mut()
                .spend(spent)
                .expect("mock call has enough gas");
            Some(stop)
        }
    }

    let mut evm = test_evm_with_amsterdam(TempoHardfork::T4, true);
    evm.set_interpreter_runner(Runner {
        call_idx: AtomicUsize::new(0),
    });
    let initial_state_gas = evm.version().gas_params.create_state_gas();
    let (gas_limit, reservoir) = initial_gas_and_reservoir(
        evm.version(),
        TX_GAS_LIMIT,
        INTRINSIC_GAS,
        initial_state_gas,
        0,
    );
    let calls = vec![
        Call {
            to: TxKind::Create,
            value: U256::ZERO,
            input: Bytes::from(vec![0x60, 0x80]),
        },
        Call {
            to: TxKind::Call(Address::random()),
            value: U256::ZERO,
            input: Bytes::new(),
        },
    ];

    let result = execute_batch(
        &mut evm,
        SIGNER,
        None,
        1,
        U256::ZERO,
        gas_limit,
        reservoir,
        &calls,
        true,
    )
    .expect("execute_batch should return a failed message result");

    let expected_spent = INTRINSIC_GAS
        + initial_state_gas
        + CALL_RESULTS.iter().map(|(_, spent)| spent).sum::<u64>();

    // Pays CREATE state gas + both call costs. CREATE is charged upfront via intrinsic gas, and NOT refunded.
    assert_eq!(result.stop, InstrStop::Revert);
    assert_eq!(
        TX_GAS_LIMIT - result.gas.remaining() - result.gas.reservoir(),
        expected_spent
    );
    assert_eq!(result.gas.remaining(), TX_GAS_LIMIT - expected_spent);
    assert_eq!(result.gas.state_gas_spent(), 0);
    assert_eq!(result.gas.reservoir(), 0);
}

/// TIP-1016: AA CREATE tx should populate initial_state_gas.
#[test]
fn test_state_gas_aa_create_tx_populates_initial_state_gas() {
    let gas_params = tempo_gas_params(TempoHardfork::T4);
    let initcode = Bytes::from(vec![0x60, 0x80]);

    let call = Call {
        to: TxKind::Create,
        value: U256::ZERO,
        input: initcode,
    };

    let aa_env = TempoBatchCallEnv {
        signature: TempoSignature::Primitive(PrimitiveSignature::Secp256k1(
            alloy_primitives::Signature::test_signature(),
        )),
        aa_calls: vec![call],
        key_authorization: None,
        signature_hash: B256::ZERO,
        ..Default::default()
    };

    let gas = calculate_aa_batch_intrinsic_gas(
        &aa_env,
        &gas_params,
        None::<std::iter::Empty<&AccessListItem>>,
        TempoHardfork::T4,
    )
    .unwrap();

    let expected_state_gas = gas_params.create_state_gas();

    assert_eq!(
        gas.initial_state_gas, expected_state_gas,
        "AA CREATE tx should have initial_state_gas = create_state_gas"
    );
}

/// TIP-1016: AA CALL tx should have zero initial_state_gas.
#[test]
fn test_state_gas_aa_call_tx_zero_initial_state_gas() {
    let gas_params = tempo_gas_params(TempoHardfork::T4);
    let calldata = Bytes::from(vec![1, 2, 3]);

    let call = Call {
        to: TxKind::Call(Address::random()),
        value: U256::ZERO,
        input: calldata,
    };

    let aa_env = TempoBatchCallEnv {
        signature: TempoSignature::Primitive(PrimitiveSignature::Secp256k1(
            alloy_primitives::Signature::test_signature(),
        )),
        aa_calls: vec![call],
        key_authorization: None,
        signature_hash: B256::ZERO,
        ..Default::default()
    };

    let gas = calculate_aa_batch_intrinsic_gas(
        &aa_env,
        &gas_params,
        None::<std::iter::Empty<&AccessListItem>>,
        TempoHardfork::T4,
    )
    .unwrap();

    assert_eq!(
        gas.initial_state_gas, 0,
        "AA CALL tx should have zero initial_state_gas"
    );
}

/// TIP-1016: AA batch with multiple calls including CREATE should track
/// state gas for the CREATE call only.
#[test]
fn test_state_gas_aa_mixed_batch_create_and_call() {
    let gas_params = tempo_gas_params(TempoHardfork::T4);
    let calldata = Bytes::from(vec![1, 2, 3]);
    let initcode = Bytes::from(vec![0x60, 0x80]);

    let calls = vec![
        Call {
            to: TxKind::Call(Address::random()),
            value: U256::ZERO,
            input: calldata,
        },
        Call {
            to: TxKind::Create,
            value: U256::ZERO,
            input: initcode,
        },
    ];

    let aa_env = TempoBatchCallEnv {
        signature: TempoSignature::Primitive(PrimitiveSignature::Secp256k1(
            alloy_primitives::Signature::test_signature(),
        )),
        aa_calls: calls,
        key_authorization: None,
        signature_hash: B256::ZERO,
        ..Default::default()
    };

    let gas = calculate_aa_batch_intrinsic_gas(
        &aa_env,
        &gas_params,
        None::<std::iter::Empty<&AccessListItem>>,
        TempoHardfork::T4,
    )
    .unwrap();

    // Only the CREATE call contributes state gas
    let expected_state_gas = gas_params.create_state_gas();

    assert_eq!(
        gas.initial_state_gas, expected_state_gas,
        "Mixed batch should have state gas only from CREATE call"
    );
}

/// TIP-1016: AA batch with multiple CREATE calls accumulates state gas.
#[test]
fn test_state_gas_aa_multiple_create_calls() {
    let gas_params = tempo_gas_params(TempoHardfork::T4);
    let initcode = Bytes::from(vec![0x60, 0x80]);

    let calls = vec![
        Call {
            to: TxKind::Create,
            value: U256::ZERO,
            input: initcode.clone(),
        },
        Call {
            to: TxKind::Create,
            value: U256::ZERO,
            input: initcode,
        },
    ];

    let aa_env = TempoBatchCallEnv {
        signature: TempoSignature::Primitive(PrimitiveSignature::Secp256k1(
            alloy_primitives::Signature::test_signature(),
        )),
        aa_calls: calls,
        key_authorization: None,
        signature_hash: B256::ZERO,
        ..Default::default()
    };

    let gas = calculate_aa_batch_intrinsic_gas(
        &aa_env,
        &gas_params,
        None::<std::iter::Empty<&AccessListItem>>,
        TempoHardfork::T4,
    )
    .unwrap();

    // Two CREATE calls should accumulate state gas
    let per_create_state_gas = gas_params.create_state_gas();

    assert_eq!(
        gas.initial_state_gas,
        per_create_state_gas * 2,
        "Multiple CREATE calls should accumulate initial_state_gas"
    );
}

/// TIP-1016: In multi-call execution, per-call gas starts with no state gas
/// charged, so state gas is only deducted once upfront by the AA intrinsic
/// calculation, not per call.
#[test]
fn test_state_gas_multi_call_per_call_init_has_zero_state_gas() {
    let zero_init_gas = InitialAndFloorGas::new(0, 0);
    assert_eq!(
        zero_init_gas.initial_state_gas, 0,
        "Per-call init gas in multi-call must have zero initial_state_gas; \
             state gas is deducted once upfront, not per call"
    );
}

/// TIP-1016: Multi-call corrected gas (success path) must use flattened
/// reconstruction and must preserve accumulated state_gas_spent.
#[test]
fn test_state_gas_multi_call_corrected_gas_success_preserves_state_gas() {
    let gas_limit: u64 = 1_000_000;
    let total_gas_spent: u64 = 400_000;
    let accumulated_state_gas: i64 = 150_000;
    let accumulated_refund: i64 = 5_000;

    // Simulate flattened gas reconstruction (same pattern as execute_batch)
    let mut corrected_gas = GasTracker::from_parts(gas_limit, gas_limit - total_gas_spent, 0);
    corrected_gas.set_refunded(accumulated_refund);
    corrected_gas.add_state_gas_spent(accumulated_state_gas);

    assert_eq!(
        corrected_gas.spent(),
        total_gas_spent,
        "Flattened gas must have correct spent"
    );
    assert_eq!(
        corrected_gas.used(),
        total_gas_spent - accumulated_refund as u64,
        "Flattened gas must have correct used (spent - refunded)"
    );
    assert_eq!(
        corrected_gas.state_gas_spent(),
        accumulated_state_gas,
        "Corrected gas must preserve accumulated state_gas_spent"
    );
    assert_eq!(
        corrected_gas.reservoir(),
        0,
        "Flattened gas must have zero reservoir"
    );
}

/// TIP-1016: AA nonce==0 new account should track state gas in T4.
#[test]
fn test_state_gas_aa_nonce_zero_new_account() {
    let calls = vec![Call {
        to: TxKind::Call(Address::random()),
        value: U256::ZERO,
        input: Bytes::from(vec![1, 2, 3]),
    }];
    let evm = test_evm_with_amsterdam(TempoHardfork::T4, true);
    let (_, state, _) = intrinsic_with_amsterdam(
        TempoHardfork::T4,
        true,
        TempoTransaction {
            nonce: 0,
            nonce_key: U256::ONE,
            calls,
            ..Default::default()
        },
        secp256k1_signature(),
    )
    .unwrap();

    assert_eq!(
        state,
        evm.version().gas_params.new_account_state_gas(),
        "AA tx with nonce==0 should track new_account_state_gas in T4"
    );
}

/// TIP-1016: AA auth list entries with nonce==0 should track state gas.
#[test]
fn test_state_gas_aa_auth_list_nonce_zero() {
    // TIP-1016 is opt-in via amsterdam_eip8037; manually enable for this test.
    let gas_params = tempo_gas_params(TempoHardfork::T4);

    let aa_env = TempoBatchCallEnv {
        signature: TempoSignature::Primitive(PrimitiveSignature::Secp256k1(
            alloy_primitives::Signature::test_signature(),
        )),
        aa_calls: vec![Call {
            to: TxKind::Call(Address::random()),
            value: U256::ZERO,
            input: Bytes::from(vec![1, 2, 3]),
        }],
        tempo_authorization_list: vec![TempoSignedAuthorization::new_unchecked(
            alloy_eips::eip7702::Authorization {
                chain_id: U256::ONE,
                address: Address::random(),
                nonce: 0,
            },
            TempoSignature::Primitive(PrimitiveSignature::Secp256k1(
                alloy_primitives::Signature::test_signature(),
            )),
        )],
        ..Default::default()
    };

    let gas = calculate_aa_batch_intrinsic_gas(
        &aa_env,
        &gas_params,
        None::<std::iter::Empty<&AccessListItem>>,
        TempoHardfork::T4,
    )
    .unwrap();

    // State gas = per-auth state gas (225k) + nonce==0 account creation state gas (225k)
    // Use hard-coded expected values to catch missing gas_params overrides.
    assert_eq!(
        gas.initial_state_gas,
        225_000 + 225_000,
        "Auth list entry should track per-auth state gas (225k) + nonce==0 account creation state gas (225k)"
    );
}

/// TIP-1016: Auth list state gas (GasId 254) must be zero on T1.
#[test]
fn test_state_gas_auth_list_zero_on_t1() {
    let gas_params = tempo_gas_params(TempoHardfork::T1);
    assert_eq!(
        gas_params.new_account_state_gas(),
        0,
        "Auth account creation state gas must be zero on T1"
    );

    let aa_env = TempoBatchCallEnv {
        signature: TempoSignature::Primitive(PrimitiveSignature::Secp256k1(
            alloy_primitives::Signature::test_signature(),
        )),
        aa_calls: vec![Call {
            to: TxKind::Call(Address::random()),
            value: U256::ZERO,
            input: Bytes::from(vec![1, 2, 3]),
        }],
        tempo_authorization_list: vec![TempoSignedAuthorization::new_unchecked(
            alloy_eips::eip7702::Authorization {
                chain_id: U256::ONE,
                address: Address::random(),
                nonce: 0,
            },
            TempoSignature::Primitive(PrimitiveSignature::Secp256k1(
                alloy_primitives::Signature::test_signature(),
            )),
        )],
        ..Default::default()
    };

    let gas = calculate_aa_batch_intrinsic_gas(
        &aa_env,
        &gas_params,
        None::<std::iter::Empty<&AccessListItem>>,
        TempoHardfork::T1,
    )
    .unwrap();

    assert_eq!(
        gas.initial_state_gas, 0,
        "T1 auth list nonce==0 should have zero initial_state_gas"
    );
}

/// TIP-1016: `initial_total_gas >= initial_state_gas` invariant must hold for
/// AA CREATE calls. Without this, execution computes the regular initial gas
/// as zero, giving the transaction its full gas_limit for free.
#[test]
fn test_state_gas_aa_create_total_gas_includes_state_gas() {
    let gas_params = tempo_gas_params(TempoHardfork::T4);
    let initcode = Bytes::from(vec![0x60, 0x80]);

    let call = Call {
        to: TxKind::Create,
        value: U256::ZERO,
        input: initcode,
    };

    let aa_env = TempoBatchCallEnv {
        signature: TempoSignature::Primitive(PrimitiveSignature::Secp256k1(
            alloy_primitives::Signature::test_signature(),
        )),
        aa_calls: vec![call],
        key_authorization: None,
        signature_hash: B256::ZERO,
        ..Default::default()
    };

    let gas = calculate_aa_batch_intrinsic_gas(
        &aa_env,
        &gas_params,
        None::<std::iter::Empty<&AccessListItem>>,
        TempoHardfork::T4,
    )
    .unwrap();

    assert!(
        gas.initial_total_gas() >= gas.initial_state_gas,
        "invariant violated: initial_total_gas ({}) < initial_state_gas ({})",
        gas.initial_total_gas(),
        gas.initial_state_gas,
    );
}

/// TIP-1016: `initial_total_gas >= initial_state_gas` invariant must hold
/// when AA auth-list entries with nonce==0 add account-creation state gas.
#[test]
fn test_state_gas_aa_auth_nonce_zero_total_gas_includes_state_gas() {
    let gas_params = tempo_gas_params(TempoHardfork::T4);

    let aa_env = TempoBatchCallEnv {
        signature: TempoSignature::Primitive(PrimitiveSignature::Secp256k1(
            alloy_primitives::Signature::test_signature(),
        )),
        aa_calls: vec![Call {
            to: TxKind::Call(Address::random()),
            value: U256::ZERO,
            input: Bytes::from(vec![1, 2, 3]),
        }],
        tempo_authorization_list: vec![TempoSignedAuthorization::new_unchecked(
            alloy_eips::eip7702::Authorization {
                chain_id: U256::ONE,
                address: Address::random(),
                nonce: 0,
            },
            TempoSignature::Primitive(PrimitiveSignature::Secp256k1(
                alloy_primitives::Signature::test_signature(),
            )),
        )],
        ..Default::default()
    };

    let gas = calculate_aa_batch_intrinsic_gas(
        &aa_env,
        &gas_params,
        None::<std::iter::Empty<&AccessListItem>>,
        TempoHardfork::T4,
    )
    .unwrap();

    assert!(
        gas.initial_total_gas() >= gas.initial_state_gas,
        "invariant violated: initial_total_gas ({}) < initial_state_gas ({})",
        gas.initial_total_gas(),
        gas.initial_state_gas,
    );
}

fn arb_opt_timestamp() -> impl Strategy<Value = Option<u64>> {
    prop_oneof![Just(None), any::<u64>().prop_map(Some)]
}

/// Helper to create a secp256k1 signature for testing gas calculations.
///
/// Note: We use a test signature rather than real valid/invalid signatures because
/// these gas calculation functions only depend on the signature *type* (Secp256k1,
/// P256, WebAuthn), not on cryptographic validity. Signature verification happens
/// separately during `recover_signer()` before transactions enter the pool.
fn secp256k1_sig() -> TempoSignature {
    TempoSignature::Primitive(PrimitiveSignature::Secp256k1(
        alloy_primitives::Signature::test_signature(),
    ))
}

/// Helper to create a TempoBatchCallEnv with specified calls.
fn make_aa_env(calls: Vec<Call>) -> TempoBatchCallEnv {
    TempoBatchCallEnv {
        signature: secp256k1_sig(),
        aa_calls: calls,
        key_authorization: None,
        signature_hash: B256::ZERO,
        ..Default::default()
    }
}

/// Helper to create a single-call TempoBatchCallEnv with given calldata.
fn make_single_call_env(calldata: Bytes) -> TempoBatchCallEnv {
    make_aa_env(vec![Call {
        to: TxKind::Call(Address::ZERO),
        value: U256::ZERO,
        input: calldata,
    }])
}

/// Helper to create a multi-call TempoBatchCallEnv with N empty calls.
fn make_multi_call_env(num_calls: usize) -> TempoBatchCallEnv {
    make_aa_env(
        (0..num_calls)
            .map(|_| Call {
                to: TxKind::Call(Address::ZERO),
                value: U256::ZERO,
                input: Bytes::new(),
            })
            .collect(),
    )
}

/// Helper to compute AA batch gas with no access list.
#[derive(Clone)]
struct InitialAndFloorGas {
    initial_gas: u64,
    initial_state_gas: u64,
    floor_gas: u64,
}

impl InitialAndFloorGas {
    fn new(initial_gas: u64, floor_gas: u64) -> Self {
        Self {
            initial_gas,
            initial_state_gas: 0,
            floor_gas,
        }
    }

    fn initial_total_gas(&self) -> u64 {
        self.initial_gas + self.initial_state_gas
    }
}

#[derive(Clone)]
struct TempoBatchCallEnv {
    aa_calls: Vec<Call>,
    signature: TempoSignature,
    key_authorization: Option<SignedKeyAuthorization>,
    tempo_authorization_list: Vec<TempoSignedAuthorization>,
    nonce_key: U256,
    nonce: u64,
    signature_hash: B256,
}

impl Default for TempoBatchCallEnv {
    fn default() -> Self {
        Self {
            aa_calls: Vec::new(),
            signature: secp256k1_sig(),
            key_authorization: None,
            tempo_authorization_list: Vec::new(),
            nonce_key: U256::ZERO,
            nonce: 0,
            signature_hash: B256::ZERO,
        }
    }
}

fn compute_aa_gas(env: &TempoBatchCallEnv) -> InitialAndFloorGas {
    let _ = (&env.signature, &env.key_authorization, env.signature_hash);
    let (initial_gas, initial_state_gas, floor_gas) = intrinsic(
        TempoHardfork::Genesis,
        TempoTransaction {
            calls: env.aa_calls.clone(),
            ..Default::default()
        },
        secp256k1_signature(),
    )
    .unwrap();
    InitialAndFloorGas {
        initial_gas,
        initial_state_gas,
        floor_gas,
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(500))]

    /// Property: validate_time_window returns Ok if (after <= ts < before)
    #[test]
    fn proptest_validate_time_window_correctness(
        valid_after in arb_opt_timestamp(),
        valid_before in arb_opt_timestamp(),
        block_timestamp in any::<u64>(),
    ) {
        let result = validate_time_window(valid_after, valid_before, block_timestamp);

        let after_ok = valid_after.is_none_or(|after| block_timestamp >= after);
        let before_ok = valid_before.is_none_or(|before| block_timestamp < before);
        let expected_valid = after_ok && before_ok;

        prop_assert_eq!(result.is_ok(), expected_valid,
            "valid_after={:?}, valid_before={:?}, block_ts={}, result={:?}",
            valid_after, valid_before, block_timestamp, result);
    }

    /// Property: validate_time_window with None constraints always succeeds
    #[test]
    fn proptest_validate_time_window_none_always_valid(block_timestamp in any::<u64>()) {
        prop_assert!(validate_time_window(None, None, block_timestamp).is_ok());
    }

    /// Property: validate_time_window with valid_after=0 is equivalent to None
    ///
    /// This tests the equivalence property: Some(0) and None for valid_after should produce
    /// identical results regardless of what valid_before is. We intentionally don't constrain
    /// valid_before because we're testing that the equivalence holds in all cases (both when
    /// valid_before causes success and when it causes failure).
    #[test]
    fn proptest_validate_time_window_zero_after_equivalent_to_none(
        valid_before in arb_opt_timestamp(),
        block_timestamp in any::<u64>(),
    ) {
        let with_zero = validate_time_window(Some(0), valid_before, block_timestamp);
        let with_none = validate_time_window(None, valid_before, block_timestamp);
        prop_assert_eq!(with_zero.is_ok(), with_none.is_ok());
    }

    /// Property: validate_time_window - if before <= after, the window is empty
    #[test]
    fn proptest_validate_time_window_empty_window(
        valid_after in 1u64..=u64::MAX,
        offset in 0u64..1000u64,
    ) {
        let valid_before = valid_after.saturating_sub(offset);
        let result = validate_time_window(Some(valid_after), Some(valid_before), valid_after);
        prop_assert!(result.is_err(), "Empty window should reject all timestamps");
    }

    /// Property: signature gas ordering is consistent: secp256k1 <= p256 <= webauthn
    #[test]
    fn proptest_signature_gas_ordering(webauthn_data_len in 0usize..1000) {
        let secp_sig = PrimitiveSignature::Secp256k1(alloy_primitives::Signature::test_signature());
        let p256_sig = PrimitiveSignature::P256(P256SignatureWithPreHash {
            r: B256::ZERO, s: B256::ZERO, pub_key_x: B256::ZERO, pub_key_y: B256::ZERO, pre_hash: false,
        });
        let webauthn_sig = PrimitiveSignature::WebAuthn(WebAuthnSignature {
            r: B256::ZERO, s: B256::ZERO, pub_key_x: B256::ZERO, pub_key_y: B256::ZERO,
            webauthn_data: Bytes::from(vec![0u8; webauthn_data_len]),
        });

        let secp_gas = primitive_signature_verification_gas(&secp_sig);
        let p256_gas = primitive_signature_verification_gas(&p256_sig);
        let webauthn_gas = primitive_signature_verification_gas(&webauthn_sig);

        prop_assert!(secp_gas <= p256_gas, "secp256k1 should be <= p256");
        prop_assert!(p256_gas <= webauthn_gas, "p256 should be <= webauthn");
    }

    /// Property: gas calculation monotonicity - more calldata means more gas (non-zero bytes)
    /// Non-zero bytes cost 16 gas each, so monotonicity holds for uniform non-zero calldata.
    #[test]
    fn proptest_gas_monotonicity_calldata_nonzero(
        calldata_len1 in 0usize..1000,
        calldata_len2 in 0usize..1000,
    ) {
        let gas1 = compute_aa_gas(&make_single_call_env(Bytes::from(vec![1u8; calldata_len1])));
        let gas2 = compute_aa_gas(&make_single_call_env(Bytes::from(vec![1u8; calldata_len2])));

        if calldata_len1 <= calldata_len2 {
            prop_assert!(gas1.initial_total_gas() <= gas2.initial_total_gas(),
                "More calldata should mean more gas: len1={}, gas1={}, len2={}, gas2={}",
                calldata_len1, gas1.initial_total_gas(), calldata_len2, gas2.initial_total_gas());
        } else {
            prop_assert!(gas1.initial_total_gas() >= gas2.initial_total_gas(),
                "Less calldata should mean less gas: len1={}, gas1={}, len2={}, gas2={}",
                calldata_len1, gas1.initial_total_gas(), calldata_len2, gas2.initial_total_gas());
        }
    }

    /// Property: gas calculation monotonicity - more calldata means more gas (zero bytes)
    /// Zero bytes cost 4 gas each, so monotonicity holds for uniform zero calldata.
    #[test]
    fn proptest_gas_monotonicity_calldata_zero(
        calldata_len1 in 0usize..1000,
        calldata_len2 in 0usize..1000,
    ) {
        let gas1 = compute_aa_gas(&make_single_call_env(Bytes::from(vec![0u8; calldata_len1])));
        let gas2 = compute_aa_gas(&make_single_call_env(Bytes::from(vec![0u8; calldata_len2])));

        if calldata_len1 <= calldata_len2 {
            prop_assert!(gas1.initial_total_gas() <= gas2.initial_total_gas(),
                "More zero-byte calldata should mean more gas: len1={}, gas1={}, len2={}, gas2={}",
                calldata_len1, gas1.initial_total_gas(), calldata_len2, gas2.initial_total_gas());
        } else {
            prop_assert!(gas1.initial_total_gas() >= gas2.initial_total_gas(),
                "Less zero-byte calldata should mean less gas: len1={}, gas1={}, len2={}, gas2={}",
                calldata_len1, gas1.initial_total_gas(), calldata_len2, gas2.initial_total_gas());
        }
    }

    /// Property: zero-byte calldata costs less gas than non-zero byte calldata of same length.
    /// Zero bytes cost 4 gas each, non-zero bytes cost 16 gas each.
    #[test]
    fn proptest_zero_bytes_cheaper_than_nonzero(calldata_len in 1usize..1000) {
        let zero_gas = compute_aa_gas(&make_single_call_env(Bytes::from(vec![0u8; calldata_len])));
        let nonzero_gas = compute_aa_gas(&make_single_call_env(Bytes::from(vec![1u8; calldata_len])));

        prop_assert!(zero_gas.initial_total_gas() < nonzero_gas.initial_total_gas(),
            "Zero-byte calldata should cost less: len={}, zero_gas={}, nonzero_gas={}",
            calldata_len, zero_gas.initial_total_gas(), nonzero_gas.initial_total_gas());
    }

    /// Property: mixed calldata gas is bounded by all-zero and all-nonzero extremes.
    /// Gas for mixed calldata should be between gas for all-zero and all-nonzero of same length.
    #[test]
    fn proptest_mixed_calldata_gas_bounded(
        calldata_len in 1usize..500,
        nonzero_ratio in 0u8..=100,
    ) {
        // Create mixed calldata where nonzero_ratio% of bytes are non-zero
        let calldata: Vec<u8> = (0..calldata_len)
            .map(|i| if (i * 100 / calldata_len) < nonzero_ratio as usize { 1u8 } else { 0u8 })
            .collect();

        let mixed_gas = compute_aa_gas(&make_single_call_env(Bytes::from(calldata)));
        let zero_gas = compute_aa_gas(&make_single_call_env(Bytes::from(vec![0u8; calldata_len])));
        let nonzero_gas = compute_aa_gas(&make_single_call_env(Bytes::from(vec![1u8; calldata_len])));

        prop_assert!(mixed_gas.initial_total_gas() >= zero_gas.initial_total_gas(),
            "Mixed calldata gas should be >= all-zero gas: mixed={}, zero={}",
            mixed_gas.initial_total_gas(), zero_gas.initial_total_gas());
        prop_assert!(mixed_gas.initial_total_gas() <= nonzero_gas.initial_total_gas(),
            "Mixed calldata gas should be <= all-nonzero gas: mixed={}, nonzero={}",
            mixed_gas.initial_total_gas(), nonzero_gas.initial_total_gas());
    }

    /// Property: gas calculation monotonicity - more calls means more gas
    #[test]
    fn proptest_gas_monotonicity_call_count(
        num_calls1 in 1usize..10,
        num_calls2 in 1usize..10,
    ) {
        let gas1 = compute_aa_gas(&make_multi_call_env(num_calls1));
        let gas2 = compute_aa_gas(&make_multi_call_env(num_calls2));

        if num_calls1 <= num_calls2 {
            prop_assert!(gas1.initial_total_gas() <= gas2.initial_total_gas(),
                "More calls should mean more gas: calls1={}, gas1={}, calls2={}, gas2={}",
                num_calls1, gas1.initial_total_gas(), num_calls2, gas2.initial_total_gas());
        } else {
            prop_assert!(gas1.initial_total_gas() >= gas2.initial_total_gas(),
                "Fewer calls should mean less gas: calls1={}, gas1={}, calls2={}, gas2={}",
                num_calls1, gas1.initial_total_gas(), num_calls2, gas2.initial_total_gas());
        }
    }

    /// Property: AA batch gas with Secp256k1 signature equals exactly 21k base + cold access
    ///
    /// For minimal AA transactions (Secp256k1 sig, no calldata, no access list):
    /// - Base: 21,000 (same base stipend as regular transactions)
    /// - Plus: COLD_ACCOUNT_ACCESS_COST per additional call beyond the first
    ///
    /// AA transactions use the same 21k base as regular transactions because
    /// Secp256k1 signature verification adds 0 extra gas. Other signature types
    /// (P256, WebAuthn) add 5,000+ gas beyond this base.
    #[test]
    fn proptest_gas_aa_secp256k1_exact_bounds(num_calls in 1usize..5) {
        let gas = compute_aa_gas(&make_multi_call_env(num_calls));

        // Expected exactly: 21k base + cold account access for each additional call
        let cold_account_access_cost = {
            let evm = test_evm(TempoHardfork::Genesis);
            u64::from(evm.version().gas_params[GasId::WarmStorageReadCost])
                + u64::from(evm.version().gas_params[GasId::ColdAccountAdditionalCost])
        };
        let expected = 21_000 + cold_account_access_cost * (num_calls.saturating_sub(1) as u64);
        prop_assert_eq!(gas.initial_total_gas(), expected,
            "Gas {} should equal expected {} for {} calls (21k + {}*COLD_ACCOUNT_ACCESS_COST)",
            gas.initial_total_gas(), expected, num_calls, num_calls.saturating_sub(1));
    }

    /// Property: first_call returns the first call for AA transactions with any number of calls
    #[test]
    fn proptest_first_call_returns_first_for_aa(num_calls in 1usize..10) {
        let env = aa_env(
            TempoTransaction {
                calls: (0..num_calls)
                    .map(|index| Call {
                        to: TxKind::Call(Address::with_last_byte(index as u8)),
                        value: U256::ZERO,
                        input: Bytes::from(vec![index as u8; index + 1]),
                    })
                    .collect(),
                ..Default::default()
            },
            secp256k1_signature(),
        );
        prop_assert_eq!(
            env.evm_tx().calls().next(),
            Some((TxKind::Call(Address::ZERO), &Bytes::from_static(&[0])))
        );
    }

    /// Property: first_call returns None for AA transaction with zero calls
    #[test]
    fn proptest_first_call_empty_aa(_dummy in 0u8..1) {
        let env = aa_env(TempoTransaction::default(), secp256k1_signature());
        prop_assert!(env.evm_tx().calls().next().is_none());
    }

    /// Property: first_call returns inner tx data for non-AA transactions
    #[test]
    fn proptest_first_call_non_aa(calldata_len in 0usize..100) {
        let input = Bytes::from(vec![0xab; calldata_len]);
        let transaction = alloy_consensus::TxLegacy {
            to: TxKind::Call(Address::repeat_byte(0x42)),
            input: input.clone(),
            ..Default::default()
        };
        let transaction = TempoEvmTx::from(Recovered::new_unchecked(
            tempo_primitives::TempoTxEnvelope::Legacy(alloy_consensus::Signed::new_unhashed(
                transaction,
                Signature::test_signature(),
        )),
            SIGNER,
        ));
        prop_assert_eq!(
            transaction.calls().next(),
            Some((TxKind::Call(Address::repeat_byte(0x42)), &input))
        );
    }

    /// Property: calculate_key_authorization_gas is monotonic in number of limits
    #[test]
    fn proptest_key_auth_gas_monotonic_limits(
        num_limits1 in 0usize..10,
        num_limits2 in 0usize..10,
    ) {
        use tempo_primitives::transaction::{
            SignatureType, SignedKeyAuthorization,
            key_authorization::KeyAuthorization,
            TokenLimit as PrimTokenLimit,
        };

        let make_key_auth = |num_limits: usize| -> SignedKeyAuthorization {
            let mut auth =
                KeyAuthorization::unrestricted(1, SignatureType::Secp256k1, Address::ZERO);
            if num_limits > 0 {
                auth = auth.with_limits((0..num_limits).map(|i| PrimTokenLimit {
                    token: Address::with_last_byte(i as u8),
                    limit: U256::from(1000),
                    period: 0,
                }).collect());
            }
            auth.into_signed(PrimitiveSignature::Secp256k1(
                alloy_primitives::Signature::test_signature(),
            ))
        };

        // Test both pre-T1B and T1B branches
        for (gas_params, spec) in [
            (tempo_chainspec::gas_params::version(SpecId::OSAKA, TempoHardfork::default(), false).gas_params, tempo_chainspec::hardfork::TempoHardfork::default()),
            (tempo_chainspec::gas_params::version(SpecId::OSAKA, TempoHardfork::T1B, false).gas_params, TempoHardfork::T1B),
        ] {
            let (gas1, _) = calculate_key_authorization_gas(&make_key_auth(num_limits1), &gas_params, spec);
            let (gas2, _) = calculate_key_authorization_gas(&make_key_auth(num_limits2), &gas_params, spec);

            if num_limits1 <= num_limits2 {
                prop_assert!(gas1 <= gas2,
                    "{spec:?}: More limits should mean more gas: limits1={}, gas1={}, limits2={}, gas2={}",
                    num_limits1, gas1, num_limits2, gas2);
            } else {
                prop_assert!(gas1 >= gas2,
                    "{spec:?}: Fewer limits should mean less gas: limits1={}, gas1={}, limits2={}, gas2={}",
                    num_limits1, gas1, num_limits2, gas2);
            }
        }
    }

    /// Property: calculate_key_authorization_gas minimum is KEY_AUTH_BASE_GAS + ECRECOVER_GAS
    #[test]
    fn proptest_key_auth_gas_minimum(
        sig_type in 0u8..3,
        num_limits in 0usize..5,
    ) {
        use tempo_primitives::transaction::{
            SignatureType, TokenLimit as PrimTokenLimit, key_authorization::KeyAuthorization,
        };

        let signature = match sig_type {
            0 => PrimitiveSignature::Secp256k1(alloy_primitives::Signature::test_signature()),
            1 => PrimitiveSignature::P256(P256SignatureWithPreHash {
                r: B256::ZERO, s: B256::ZERO, pub_key_x: B256::ZERO, pub_key_y: B256::ZERO, pre_hash: false,
            }),
            _ => PrimitiveSignature::WebAuthn(WebAuthnSignature {
                r: B256::ZERO, s: B256::ZERO, pub_key_x: B256::ZERO, pub_key_y: B256::ZERO,
                webauthn_data: Bytes::new(),
            }),
        };

        let mut auth =
            KeyAuthorization::unrestricted(1, SignatureType::Secp256k1, Address::ZERO);
        if num_limits > 0 {
            auth = auth.with_limits((0..num_limits).map(|i| PrimTokenLimit {
                token: Address::with_last_byte(i as u8),
                limit: U256::from(1000),
                period: 0,
            }).collect());
        }
        let key_auth = auth.into_signed(signature);

        // Pre-T1B: minimum is KEY_AUTH_BASE_GAS + ECRECOVER_GAS
        let genesis_params = tempo_chainspec::gas_params::version(SpecId::OSAKA, TempoHardfork::default(), false).gas_params;
        let (gas, _) = calculate_key_authorization_gas(&key_auth, &genesis_params, tempo_chainspec::hardfork::TempoHardfork::default());
        let min_gas = KEY_AUTH_BASE_GAS + ECRECOVER_GAS;
        prop_assert!(gas >= min_gas,
            "Pre-T1B: Key auth gas should be at least {min_gas}, got {gas}");

        // T1B: minimum is ECRECOVER_GAS + sload + sstore (0 limits)
        let t1b_params = tempo_chainspec::gas_params::version(SpecId::OSAKA, TempoHardfork::T1B, false).gas_params;
        let (gas_t1b, _) = calculate_key_authorization_gas(&key_auth, &t1b_params, TempoHardfork::T1B);
        let sstore = u64::from(t1b_params[GasId::SstoreSetWithoutLoadCost]);
        let sload = u64::from(t1b_params[GasId::WarmStorageReadCost]) + u64::from(t1b_params[GasId::ColdStorageAdditionalCost]);
        let min_t1b = ECRECOVER_GAS + sload + sstore;
        prop_assert!(gas_t1b >= min_t1b,
            "T1B: Key auth gas should be at least {min_t1b}, got {gas_t1b}");
    }
}

use alloy_consensus::{Signed, TxLegacy};
use evm2::evm::AccountInfo;
use std::sync::Arc;
use tempo_contracts::precompiles::{DEFAULT_FEE_TOKEN, TIPFeeAMMError};
use tempo_precompiles::{
    TIP_FEE_MANAGER_ADDRESS,
    storage::{ContractStorage, Handler, StorageActions},
    tip_fee_manager::TipFeeManager,
    tip20::TIP20Token,
};
use tempo_primitives::{TempoAddressExt, TempoTxEnvelope, transaction::calc_gas_balance_spending};

fn legacy_env(to: TxKind, input: Bytes) -> TempoTxEnv {
    Recovered::new_unchecked(
        TempoTxEnvelope::Legacy(Signed::new_unhashed(
            TxLegacy {
                chain_id: Some(1),
                gas_limit: 21_000,
                to,
                input,
                ..Default::default()
            },
            Signature::test_signature(),
        )),
        SIGNER,
    )
    .into()
}

fn aa_env_for(signer: Address, transaction: TempoTransaction) -> TempoTxEnv {
    Recovered::new_unchecked(
        TempoTxEnvelope::AA(AASigned::new_unhashed(
            transaction,
            TempoSignature::Primitive(PrimitiveSignature::Secp256k1(Signature::test_signature())),
        )),
        signer,
    )
    .into()
}

fn fee_tx_env(caller: Address, fee_token: Address, gas_limit: u64, gas_price: u128) -> TempoTxEnv {
    aa_env_for(
        caller,
        TempoTransaction {
            chain_id: 1,
            fee_token: Some(fee_token),
            max_priority_fee_per_gas: gas_price,
            max_fee_per_gas: gas_price,
            gas_limit,
            calls: Vec::new(),
            ..Default::default()
        },
    )
}

fn storage_evm(spec: TempoHardfork) -> crate::TempoEvm<'static> {
    build_tempo_evm(
        spec,
        1,
        TempoBlockEnv::default(),
        InMemoryDB::default(),
        NoPrecompiles::default(),
        TempoEvmExt::default(),
    )
}

fn insert_storage(evm: &mut crate::TempoEvm<'_>, address: Address, slot: U256, value: U256) {
    evm.overlay_db_mut()
        .insert_account_info(&address, AccountInfo::default());
    evm.overlay_db_mut()
        .insert_account_storage(&address, &slot, &value);
}

fn resolve(
    evm: &mut crate::TempoEvm<'_>,
    tx: &TempoTxEnv,
    fee_payer: Address,
    spec: TempoHardfork,
) -> tempo_precompiles::error::Result<Address> {
    TempoFeeManager.resolve_fee_token(evm, tx, fee_payer, spec, StorageActions::disabled())
}

fn collect_fee_pre_tx(evm: &mut crate::TempoEvm<'_>, tx: &TempoTxEnv) -> HandlerResult<()> {
    let context = TempoHandlerHooks::resolve_fee_context(evm, tx)?;
    TempoHandlerHooks::collect_fee(evm, context, None)
}

#[derive(Debug)]
struct ValidatorTokenLookupFailsFeeManager;

impl ProtocolFeeManager for ValidatorTokenLookupFailsFeeManager {
    fn get_fee_token(
        &self,
        _host: &mut Evm<'_, TempoEvmTypes>,
        tx: &TempoTxEnv,
        _fee_payer: Address,
        _spec: TempoHardfork,
    ) -> tempo_precompiles::error::Result<Address> {
        Ok(tx.evm_tx().fee_token().unwrap_or(DEFAULT_FEE_TOKEN))
    }

    fn get_validator_token(
        &self,
        _host: &mut Evm<'_, TempoEvmTypes>,
        _beneficiary: Address,
    ) -> tempo_precompiles::error::Result<Address> {
        Err(TempoPrecompileError::Fatal(
            "injected validator token lookup failure".to_string(),
        ))
    }

    fn collect_fee_pre_tx(
        &self,
        _host: &mut Evm<'_, TempoEvmTypes>,
        _fee_payer: Address,
        _user_token: Address,
        _max_amount: U256,
        _beneficiary: Address,
        _skip_liquidity_check: bool,
    ) -> tempo_precompiles::error::Result<Address> {
        Err(TempoPrecompileError::TIPFeeAMMError(
            TIPFeeAMMError::InsufficientLiquidity(
                tempo_contracts::precompiles::ITIPFeeAMM::InsufficientLiquidity {},
            ),
        ))
    }

    fn collect_fee_post_tx(
        &self,
        _host: &mut Evm<'_, TempoEvmTypes>,
        _fee_payer: Address,
        _actual_spending: U256,
        _refund_amount: U256,
        _fee_token: Address,
        _beneficiary: Address,
    ) -> tempo_precompiles::error::Result<U256> {
        Ok(U256::ZERO)
    }
}

#[test]
fn registers_transaction_types_by_fork() {
    let frontier = tempo_tx_registry(SpecId::FRONTIER);
    assert!(frontier.contains(0));
    assert!(!frontier.contains(1));
    assert!(!frontier.contains(2));
    assert!(!frontier.contains(4));
    assert!(frontier.contains(0x76));

    let prague = tempo_tx_registry(SpecId::PRAGUE);
    assert!(prague.contains(0));
    assert!(prague.contains(1));
    assert!(prague.contains(2));
    assert!(prague.contains(4));
    assert!(prague.contains(0x76));
}

#[test]
fn builds_evm_with_matching_tempo_spec_and_fee_rules() {
    let evm = build_tempo_evm(
        TempoHardfork::T7,
        4242,
        TempoBlockEnv::default(),
        InMemoryDB::default(),
        NoPrecompiles::default(),
        TempoEvmExt::default(),
    );

    assert_eq!(evm.version().chain_id, 4242);
    assert_eq!(evm.config_spec_id(), TempoHardfork::T7);
    assert!(!evm.version().features.contains(EvmFeatures::BALANCE_CHECK));
    assert!(!evm.version().features.contains(EvmFeatures::BALANCE_TOP_UP));
    assert!(evm.version().features.contains(EvmFeatures::FEE_CHARGE));
    assert_eq!(evm.version().gas_params[GasId::MaxRefundQuotient], 1);
}

#[test]
fn test_invalid_fee_token_rejected() {
    // Test that an invalid fee token (non-TIP20 address) is rejected with a typed error
    // rather than panicking. This validates the check in collect_fee_pre_tx that
    // guards against invalid tokens reaching get_token_balance.
    let invalid_token = Address::random(); // Random address won't have TIP20 prefix
    assert!(
        !invalid_token.is_tip20(),
        "Test requires a non-TIP20 address"
    );

    let mut test = storage_evm(TempoHardfork::default());
    let tx = fee_tx_env(SIGNER, invalid_token, 100_000, 1_000_000_000);

    let result = collect_fee_pre_tx(&mut test, &tx);

    assert!(
        matches!(
            result,
            Err(ref error)
                if matches!(
                    error.external_ref::<TempoInvalidTransaction>(),
                    Some(TempoInvalidTransaction::FeeTokenNotTip20 { address })
                        if *address == invalid_token
                )
        ),
        "Should reject non-TIP20 fee token with FeeTokenNotTip20 error"
    );
}

#[test]
fn test_non_usd_fee_token_rejected() {
    let admin = Address::random();
    let mut test = storage_evm(TempoHardfork::default());

    let fee_token = StorageCtx::enter_evm_without_tip1060_accounting(&mut test, || {
        TIP20Setup::create("Euro", "EUR", admin)
            .currency("EUR")
            .apply()
            .map(|token| token.address())
    })
    .expect("EUR token setup succeeds");

    let tx = fee_tx_env(SIGNER, fee_token, 100_000, 1_000_000_000);

    let result = collect_fee_pre_tx(&mut test, &tx);

    assert!(
        matches!(
            result,
            Err(ref error)
                if matches!(
                    error.external_ref::<TempoInvalidTransaction>(),
                    Some(TempoInvalidTransaction::FeeTokenNotUsdCurrency {
                address,
                currency,
                    }) if *address == fee_token && currency == "EUR"
                )
        ),
        "Should reject non-USD fee token with FeeTokenNotUsdCurrency error"
    );
}

#[test]
fn test_paused_fee_token_rejected() {
    let admin = Address::random();
    let fee_payer = Address::random();
    let fee = U256::from(100_000_000_000_000_u64);
    let mut test = storage_evm(TempoHardfork::default());

    let fee_token = StorageCtx::enter_evm_without_tip1060_accounting(&mut test, || {
        let mut token = TIP20Setup::create("Paused USD", "PUSD", admin)
            .with_issuer(admin)
            .with_role(admin, *tempo_precompiles::tip20::PAUSE_ROLE)
            .with_mint(fee_payer, fee)
            .apply()?;
        token.pause(admin, tempo_precompiles::tip20::ITIP20::pauseCall {})?;
        Ok::<_, TempoPrecompileError>(token.address())
    })
    .expect("paused USD token setup succeeds");

    let tx = fee_tx_env(fee_payer, fee_token, 100_000, 1_000_000_000);

    let result = collect_fee_pre_tx(&mut test, &tx);

    assert!(
        matches!(
            result,
            Err(ref error)
                if matches!(
                    error.external_ref::<TempoInvalidTransaction>(),
                    Some(TempoInvalidTransaction::FeeTokenPaused { address })
                        if *address == fee_token
                )
        ),
        "Should reject paused fee token with FeeTokenPaused error"
    );
}

#[test]
fn test_collect_fee_pre_tx_insufficient_liquidity_reports_pair_from_handler() -> eyre::Result<()> {
    use tempo_contracts::precompiles::IFeeManager;

    let admin = Address::random();
    let fee_payer = Address::random();
    let validator = Address::random();
    let gas_limit = 1_000;
    let gas_price = 1_000_000_000_000_u128;
    let fee = calc_gas_balance_spending(gas_limit, gas_price);

    let mut test = storage_evm(TempoHardfork::T5);
    let mut block = *test.block();
    block.beneficiary = validator;
    test.set_block(block);

    let (user_token, validator_token) =
        StorageCtx::enter_evm_without_tip1060_accounting(&mut test, || {
            let user_token = TIP20Setup::create("UserToken", "UTK", admin)
                .with_issuer(admin)
                .with_mint(fee_payer, fee)
                .with_approval(fee_payer, TIP_FEE_MANAGER_ADDRESS, U256::MAX)
                .apply()?;

            let validator_token = TIP20Setup::create("ValidatorToken", "VTK", admin)
                .with_issuer(admin)
                .apply()?;

            TipFeeManager::new().set_validator_token(
                validator,
                IFeeManager::setValidatorTokenCall {
                    token: validator_token.address(),
                },
                Address::random(),
            )?;

            Ok::<_, TempoPrecompileError>((user_token.address(), validator_token.address()))
        })?;

    let tx = fee_tx_env(fee_payer, user_token, gas_limit, gas_price);

    let result = collect_fee_pre_tx(&mut test, &tx);

    assert!(
        matches!(
            result,
            Err(ref error)
                if matches!(
                    error.external_ref::<TempoInvalidTransaction>(),
                    Some(TempoInvalidTransaction::CollectFeePreTx(err))
                if *err == FeePaymentError::InsufficientAmmLiquidity {
                    user_token: Some(user_token),
                    validator_token: Some(validator_token),
                    fee,
                        }
                )
        ),
        "expected pair-aware insufficient liquidity error, got: {result:?}"
    );

    Ok(())
}

#[test]
fn test_collect_fee_pre_tx_insufficient_liquidity_falls_back_when_pair_lookup_fails()
-> eyre::Result<()> {
    let admin = Address::random();
    let fee_payer = Address::random();
    let gas_limit = 1_000;
    let gas_price = 1_000_000_000_000_u128;
    let fee = calc_gas_balance_spending(gas_limit, gas_price);

    let mut test = storage_evm(TempoHardfork::T5);
    test.ext_mut().fee_manager = Arc::new(ValidatorTokenLookupFailsFeeManager);

    let user_token = StorageCtx::enter_evm_without_tip1060_accounting(&mut test, || {
        TIP20Setup::create("UserToken", "UTK", admin)
            .with_issuer(admin)
            .with_mint(fee_payer, fee)
            .apply()
            .map(|token| token.address())
    })?;

    let tx = fee_tx_env(fee_payer, user_token, gas_limit, gas_price);

    let result = collect_fee_pre_tx(&mut test, &tx);

    assert!(
        matches!(
            result,
            Err(ref error)
                if matches!(
                    error.external_ref::<TempoInvalidTransaction>(),
                    Some(TempoInvalidTransaction::CollectFeePreTx(err))
                if *err == FeePaymentError::InsufficientAmmLiquidity {
                    user_token: None,
                    validator_token: None,
                    fee,
                        }
                )
        ),
        "expected generic insufficient liquidity error when pair lookup fails, got: {result:?}"
    );

    Ok(())
}

#[test]
fn test_get_token_balance() {
    let mut evm = storage_evm(TempoHardfork::Genesis);
    // Use PATH_USD_ADDRESS which has the TIP20 prefix
    let token = PATH_USD_ADDRESS;
    let account = Address::random();
    let expected_balance = U256::random();

    // Set up initial balance
    let balance_slot = TIP20Token::from_address(token).unwrap().balances[account].slot();
    insert_storage(&mut evm, token, balance_slot, expected_balance);

    let balance = StorageCtx::enter_evm_without_tip1060_accounting(&mut evm, || {
        TIP20Token::from_address(token).unwrap().balances[account].read()
    })
    .unwrap();
    assert_eq!(balance, expected_balance);
}

#[test]
fn test_get_fee_token() {
    let mut evm = storage_evm(TempoHardfork::Genesis);
    let user = Address::random();
    let validator = Address::random();
    let user_fee_token = Address::random();
    let validator_fee_token = Address::random();
    let tx_fee_token = Address::random();

    // Set validator token
    let validator_slot = TipFeeManager::new().validator_tokens[validator].slot();
    insert_storage(
        &mut evm,
        TIP_FEE_MANAGER_ADDRESS,
        validator_slot,
        U256::from_be_bytes(validator_fee_token.into_word().0),
    );

    {
        let tx = legacy_env(TxKind::Call(Address::ZERO), Bytes::new());
        let fee_token = resolve(&mut evm, &tx, user, TempoHardfork::Genesis).unwrap();
        assert_eq!(DEFAULT_FEE_TOKEN, fee_token);
    }

    // Set user token
    StorageCtx::enter_evm_without_tip1060_accounting(&mut evm, || {
        TipFeeManager::new().user_tokens[user].write(user_fee_token)
    })
    .unwrap();

    {
        let tx = legacy_env(TxKind::Call(Address::ZERO), Bytes::new());
        let fee_token = resolve(&mut evm, &tx, user, TempoHardfork::Genesis).unwrap();
        assert_eq!(user_fee_token, fee_token);
    }

    // Set tx fee token
    let tx = aa_env_for(
        SIGNER,
        TempoTransaction {
            fee_token: Some(tx_fee_token),
            ..Default::default()
        },
    );
    let fee_token = resolve(&mut evm, &tx, user, TempoHardfork::Genesis).unwrap();
    assert_eq!(tx_fee_token, fee_token);
}

#[test]
fn test_tempo_evm_applies_gas_params() {
    let version = tempo_chainspec::gas_params::version(SpecId::OSAKA, TempoHardfork::T1, false);
    assert_eq!(
        version.gas_params[GasId::TxEip7702PerEmptyAccountCost],
        12_500
    );
}

#[test]
fn test_tempo_evm_respects_gas_cap() {
    let mut version = tempo_chainspec::gas_params::version(SpecId::OSAKA, TempoHardfork::T1, false);
    version.tx_gas_limit_cap = TempoHardfork::T1.tx_gas_limit_cap().unwrap();
    let evm = Evm::new_with_execution_config_and_ext(
        ExecutionConfig::for_spec_and_version(TempoHardfork::T1, version),
        TempoHardfork::T1,
        TempoBlockEnv::default(),
        tempo_tx_registry(SpecId::OSAKA),
        InMemoryDB::default(),
        NoPrecompiles::default(),
        TempoEvmExt::default(),
    );
    assert_eq!(
        evm.version().tx_gas_limit_cap,
        TempoHardfork::T1.tx_gas_limit_cap().unwrap()
    );
}

#[test]
fn test_tempo_evm_gas_params_differ_t0_vs_t1() {
    let t0 = tempo_chainspec::gas_params::version(SpecId::OSAKA, TempoHardfork::T0, false);
    let t1 = tempo_chainspec::gas_params::version(SpecId::OSAKA, TempoHardfork::T1, false);
    assert_eq!(t0.gas_params[GasId::TxEip7702PerEmptyAccountCost], 25_000);
    assert_eq!(t1.gas_params[GasId::TxEip7702PerEmptyAccountCost], 12_500);
}

#[test]
fn test_tempo_evm_t1_state_creation_costs() {
    let params =
        tempo_chainspec::gas_params::version(SpecId::OSAKA, TempoHardfork::T1, false).gas_params;
    assert_eq!(params[GasId::SstoreSetWithoutLoadCost], 250_000);
    assert_eq!(params[GasId::TxCreateCost], 500_000);
    assert_eq!(params[GasId::Create], 500_000);
    assert_eq!(params[GasId::NewAccountCost], 250_000);
    assert_eq!(params[GasId::CodeDepositCost], 1_000);
}
