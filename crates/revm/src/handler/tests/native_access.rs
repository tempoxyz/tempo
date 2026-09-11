use super::*;
use alloy_eips::eip2930::{AccessList, AccessListItem};
use alloy_evm::FromRecoveredTx;
use alloy_signer::SignerSync;
use alloy_signer_local::PrivateKeySigner;
use revm::DatabaseCommit;
use tempo_primitives::transaction::{
    KeyAuthorization, KeychainSignature, MultisigConfig, MultisigOwner, MultisigSignature,
    SignatureType, SignedKeyAuthorization, TempoTransaction, multisig_digest,
};

struct NativeAccessFixture {
    parent_key: PrivateKeySigner,
    parent_config: MultisigConfig,
    delegate_key: PrivateKeySigner,
    delegate_config: MultisigConfig,
}

impl NativeAccessFixture {
    const FACTORY: Address = Address::repeat_byte(0x71);

    fn new() -> Self {
        let parent_key = PrivateKeySigner::from_bytes(&B256::repeat_byte(1)).unwrap();
        let delegate_key = PrivateKeySigner::from_bytes(&B256::repeat_byte(2)).unwrap();
        let config = |owner| MultisigConfig {
            salt: B256::ZERO,
            version: 0,
            threshold: 1,
            owners: vec![MultisigOwner { owner, weight: 1 }],
        };
        Self {
            parent_config: config(parent_key.address()),
            delegate_config: config(delegate_key.address()),
            parent_key,
            delegate_key,
        }
    }

    fn delegate(&self) -> Address {
        self.delegate_config.derive_account(Self::FACTORY).unwrap()
    }

    fn sign(
        key: &PrivateKeySigner,
        config: Option<&MultisigConfig>,
        digest: B256,
    ) -> TempoSignature {
        if let Some(config) = config {
            let account = config.derive_account(Self::FACTORY).unwrap();
            let approval = key
                .sign_hash_sync(&multisig_digest(digest, account, 0))
                .unwrap();
            TempoSignature::Multisig(
                MultisigSignature::try_new(
                    account,
                    config.clone(),
                    vec![PrimitiveSignature::Secp256k1(approval)],
                )
                .unwrap(),
            )
        } else {
            PrimitiveSignature::Secp256k1(key.sign_hash_sync(&digest).unwrap()).into()
        }
    }

    fn evm(&self, case: GrantCase, warmth: Warmth, gas_limit: u64) -> TestHandlerEvm {
        let native_parent = matches!(case, GrantCase::NativeGrant | GrantCase::NativeGrantAndUse);
        let parent_config = native_parent.then_some(&self.parent_config);
        let grant = KeyAuthorization::unrestricted(1, SignatureType::Multisig, self.delegate());
        let grant_signature = Self::sign(&self.parent_key, parent_config, grant.signature_hash());
        self.evm_with_authorization(case, warmth, gas_limit, grant.into_signed(grant_signature))
    }

    fn evm_with_authorization(
        &self,
        case: GrantCase,
        warmth: Warmth,
        gas_limit: u64,
        authorization: SignedKeyAuthorization,
    ) -> TestHandlerEvm {
        let native_parent = matches!(case, GrantCase::NativeGrant | GrantCase::NativeGrantAndUse);
        let parent_config = native_parent.then_some(&self.parent_config);
        let parent = parent_config.map_or(self.parent_key.address(), |config| {
            config.derive_account(Self::FACTORY).unwrap()
        });
        let tx = TempoTransaction {
            chain_id: 1,
            nonce: 3,
            gas_limit,
            fee_token: Some(PATH_USD_ADDRESS),
            calls: vec![Call {
                to: TxKind::Call(Address::repeat_byte(0x44)),
                value: U256::ZERO,
                input: Bytes::new(),
            }],
            access_list: if matches!(warmth, Warmth::AccessList) {
                AccessList(vec![AccessListItem {
                    address: self.delegate(),
                    storage_keys: vec![],
                }])
            } else {
                Default::default()
            },
            key_authorization: Some(authorization),
            ..Default::default()
        };
        let signature = if matches!(
            case,
            GrantCase::PrimitiveGrantAndUse | GrantCase::NativeGrantAndUse
        ) {
            let inner = KeychainSignature::signing_hash(tx.signature_hash(), parent);
            let signature = Self::sign(&self.delegate_key, Some(&self.delegate_config), inner);
            TempoSignature::Keychain(KeychainSignature::new(
                parent,
                signature.as_multisig().unwrap().clone(),
            ))
        } else {
            Self::sign(&self.parent_key, parent_config, tx.signature_hash())
        };
        let signed = tx.into_signed(signature);
        let env = TempoTxEnv::from_recovered_tx(&signed, parent);
        let mut test = TestHandlerEvm::new(TempoHardfork::T12, env);
        test.evm.ctx.block.multisig_recovery_factory = Some(Self::FACTORY);
        test.evm.ctx.journaled_state.database.insert_account_info(
            parent,
            revm::state::AccountInfo {
                nonce: 3,
                ..Default::default()
            },
        );
        StorageCtx::enter_ctx(test.evm.ctx_mut(), StorageActions::disabled(), || {
            TIP20Setup::path_usd(self.parent_key.address()).apply()
        })
        .unwrap();
        let state = test.evm.ctx.journaled_state.finalize();
        test.evm.ctx.journaled_state.database.commit(state);
        match warmth {
            Warmth::Cold | Warmth::AccessList => {}
            Warmth::Loaded => {
                test.evm
                    .ctx
                    .journaled_state
                    .load_account(self.delegate())
                    .unwrap();
            }
            Warmth::Coinbase => {
                test.evm.ctx.block.beneficiary = self.delegate();
            }
        }
        test
    }
}

#[derive(Clone, Copy, Debug)]
enum GrantCase {
    PrimitiveGrant,
    NativeGrant,
    PrimitiveGrantAndUse,
    NativeGrantAndUse,
}

#[derive(Clone, Copy, Debug)]
enum Warmth {
    Cold,
    Loaded,
    AccessList,
    Coinbase,
}

#[derive(Clone, Copy, Debug)]
enum GrantBindingCase {
    Matching,
    WrongTarget,
    WrongType,
    UnrelatedSigner,
}

#[test_case::test_case(TempoHardfork::T11; "primitive_grant_before_t12")]
#[test_case::test_case(TempoHardfork::T12; "primitive_grant_at_t12")]
fn native_grant_type_is_gated_in_handler(spec: TempoHardfork) {
    let fixture = NativeAccessFixture::new();
    let mut test = fixture.evm(GrantCase::PrimitiveGrant, Warmth::Cold, 1_000_000);
    test.evm.ctx.cfg.spec = spec;
    test.evm.ctx.cfg.gas_params = tempo_gas_params(spec);
    let result = test.handler.validate_env(&mut test.evm);
    if spec.is_t12() {
        result.unwrap();
        assert!(test.handler.run(&mut test.evm).unwrap().is_success());
    } else {
        assert!(
            matches!(
                result,
                Err(EVMError::Transaction(
                    TempoInvalidTransaction::NativeMultisig(
                        crate::native_multisig::NativeMultisigError::UnsupportedContext
                    )
                ))
            ),
            "{result:?}"
        );
    }
}

#[test_case::test_case(GrantCase::NativeGrant; "native_signer")]
#[test_case::test_case(GrantCase::PrimitiveGrantAndUse; "committed_keychain_parent")]
fn native_handler_rejects_account_code(case: GrantCase) {
    let fixture = NativeAccessFixture::new();
    // The positive committed-parent control also proves T12 retains primitive
    // root authority; only adding account code changes the expected outcome.
    for code in [
        None,
        Some(revm::state::Bytecode::new_legacy(Bytes::from_static(&[
            0x00,
        ]))),
    ] {
        let mut test = fixture.evm(case, Warmth::Cold, 1_000_000);
        let account = test.evm.ctx.tx.caller;
        let info = &mut test
            .evm
            .ctx
            .journaled_state
            .database
            .cache
            .accounts
            .get_mut(&account)
            .unwrap()
            .info;
        if matches!(case, GrantCase::PrimitiveGrantAndUse) {
            info.extension =
                tempo_primitives::account::encode_config_commitment(B256::repeat_byte(0x77)).into();
        }
        if let Some(code) = &code {
            info.code_hash = code.hash_slow();
            info.code = Some(code.clone());
        }
        let result = test.handler.run(&mut test.evm);
        if code.is_some() {
            assert!(
                matches!(
                    result,
                    Err(EVMError::Transaction(TempoInvalidTransaction::NativeMultisig(
                        crate::native_multisig::NativeMultisigError::InvalidAccount { account: actual }
                    ))) if actual == account
                ),
                "{case:?}: {result:?}"
            );
        } else {
            assert!(result.unwrap().is_success(), "{case:?}");
        }
    }
}

#[test_case::test_case(GrantBindingCase::Matching; "matching_grant")]
#[test_case::test_case(GrantBindingCase::WrongTarget; "wrong_grant_target")]
#[test_case::test_case(GrantBindingCase::WrongType; "wrong_grant_type")]
#[test_case::test_case(GrantBindingCase::UnrelatedSigner; "unrelated_grant_signer")]
fn native_handler_binds_grant_roles(case: GrantBindingCase) {
    let fixture = NativeAccessFixture::new();
    let other = PrivateKeySigner::from_bytes(&B256::repeat_byte(3)).unwrap();
    let grant = KeyAuthorization::unrestricted(
        1,
        if matches!(case, GrantBindingCase::WrongType) {
            SignatureType::Secp256k1
        } else {
            SignatureType::Multisig
        },
        if matches!(case, GrantBindingCase::WrongTarget) {
            other.address()
        } else {
            fixture.delegate()
        },
    )
    .with_account(fixture.parent_key.address());
    let signer = if matches!(case, GrantBindingCase::UnrelatedSigner) {
        &other
    } else {
        &fixture.parent_key
    };
    let signature = NativeAccessFixture::sign(signer, None, grant.signature_hash());
    let authorization = grant.into_signed(signature);
    assert_eq!(authorization.recover_account().unwrap(), signer.address());
    let mut test = fixture.evm_with_authorization(
        GrantCase::PrimitiveGrantAndUse,
        Warmth::Cold,
        1_000_000,
        authorization,
    );
    // All quorums are genuinely signed over this transaction, including the
    // changed grant. Failures below must be role binding, not bad cryptography.
    for role in crate::native_multisig::authorizations(&test.evm.ctx.tx)
        .into_iter()
        .flatten()
    {
        role.verify().unwrap();
    }
    let result = test.handler.run(&mut test.evm);
    let expected_reason = match case {
        GrantBindingCase::Matching => None,
        GrantBindingCase::WrongTarget => {
            Some("root-signed key authorization must use root transaction signature")
        }
        GrantBindingCase::WrongType => {
            Some("key authorization key_type does not match the keychain signature type")
        }
        GrantBindingCase::UnrelatedSigner => {
            Some("admin-signed key authorization must match transaction key and parent account")
        }
    };
    if let Some(expected) = expected_reason {
        assert!(
            matches!(
                &result,
                Err(EVMError::Transaction(TempoInvalidTransaction::KeychainValidationFailed { reason }))
                    if reason == expected
            ),
            "expected {expected}, got {result:?}"
        );
    } else {
        assert!(result.unwrap().is_success());
    }
}

#[test_case::test_case(GrantCase::PrimitiveGrant; "primitive_parent_grant_only")]
#[test_case::test_case(GrantCase::NativeGrant; "native_parent_grant_only")]
#[test_case::test_case(GrantCase::PrimitiveGrantAndUse; "primitive_parent_grant_and_use")]
#[test_case::test_case(GrantCase::NativeGrantAndUse; "native_parent_grant_and_use")]
fn native_delegate_access_is_intrinsic_once(case: GrantCase) {
    let fixture = NativeAccessFixture::new();
    for warmth in [
        Warmth::Cold,
        Warmth::Loaded,
        Warmth::AccessList,
        Warmth::Coinbase,
    ] {
        let mut test = fixture.evm(case, warmth, 1_000_000);
        let base = validate_aa_initial_tx_gas(&test.evm).unwrap();
        let gas_params = tempo_gas_params(TempoHardfork::T12);
        let access = gas_params.warm_storage_read_cost()
            + if matches!(warmth, Warmth::Cold) {
                gas_params.cold_account_additional_cost()
            } else {
                0
            };
        let roles = crate::native_multisig::authorizations(&test.evm.ctx.tx);
        let mut registered = Vec::new();
        let mut expected = access;
        for role in roles.into_iter().flatten() {
            expected += tempo_precompiles::native_multisig::keccak_cost(
                role.signature.config().account_salt_preimage_len(),
            ) + tempo_precompiles::native_multisig::keccak_cost(85);
            if !registered.contains(&role.signature.account()) {
                expected += 20_000;
                registered.push(role.signature.account());
            }
        }
        let actual = test.validate_initial_tx_gas();
        assert_eq!(
            actual.initial_total_gas() - base.initial_total_gas(),
            expected,
            "{case:?}, {warmth:?}"
        );
        assert!(
            !test
                .evm
                .ctx
                .journaled_state
                .load_account(fixture.delegate())
                .unwrap()
                .is_cold
        );
        assert!(
            test.evm.ctx.journaled_state.state[&fixture.delegate()]
                .info
                .extension
                .is_empty()
        );

        // Recreate the journal for each check: validation itself warms the delegate account.
        for (limit, valid) in [
            (actual.initial_total_gas() - 1, false),
            (actual.initial_total_gas(), true),
        ] {
            let mut boundary = fixture.evm(case, warmth, limit);
            assert_eq!(
                boundary
                    .handler
                    .validate_initial_tx_gas(&mut boundary.evm)
                    .is_ok(),
                valid,
                "{case:?}, {warmth:?}, gas={limit}"
            );
        }
        let mut execution = fixture.evm(case, warmth, 1_000_000);
        let result = execution
            .handler
            .run(&mut execution.evm)
            .unwrap_or_else(|error| panic!("{case:?}, {warmth:?}: {error:?}"));
        assert!(result.is_success(), "{case:?}, {warmth:?}: {result:?}");
        assert_eq!(
            execution.evm.ctx.journaled_state.state[&fixture.delegate()]
                .info
                .extension
                .is_empty(),
            matches!(case, GrantCase::PrimitiveGrant | GrantCase::NativeGrant),
            "only an authorizing delegate is registered: {case:?}, {warmth:?}",
        );
    }
}
