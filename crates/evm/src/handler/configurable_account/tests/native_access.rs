//! Key-authorization grants and delegate access for configurable accounts.

use super::*;
use crate::handler::{PreparedAa, prepare_aa};
use alloy_eips::eip2930::{AccessList, AccessListItem};
use evm2::{
    bytecode::Bytecode,
    ethereum::{warm_access_list, warm_base_accounts},
    registry::TxRequest,
};
use tempo_precompiles::{
    PATH_USD_ADDRESS,
    account_keychain::{AccountKeychain, SignatureType as KeychainSignatureType, getKeyCall},
    test_util::TIP20Setup,
};
use tempo_primitives::transaction::{KeychainSignature, SignatureType, SignedKeyAuthorization};

/// A parent account (primitive or configurable) granting access to a configurable delegate.
struct Access {
    parent: Native,
    delegate: Native,
}

impl Access {
    fn new() -> Self {
        let key = |byte| PrivateKeySigner::from_bytes(&B256::repeat_byte(byte)).unwrap();
        Self {
            parent: Native::new(key(1)),
            delegate: Native::new(key(2)),
        }
    }

    fn delegate(&self) -> Address {
        self.delegate.account()
    }

    fn delegate_config(&self) -> &ConfigurableAccountConfig {
        &self.delegate.config
    }

    fn parent_config(&self) -> &ConfigurableAccountConfig {
        &self.parent.config
    }

    /// Signs `digest` as the parent: its configurable account when `native`, else its primitive
    /// root key.
    fn parent_signature(&self, native: bool, digest: B256) -> AccountSignature {
        if native {
            self.parent.sign(digest).into()
        } else {
            AccountSignature::from(self.parent.key.sign_hash_sync(&digest).unwrap())
        }
    }

    /// The grant of the delegate by the parent, signed by the parent.
    fn grant(&self, native_parent: bool) -> SignedKeyAuthorization {
        let grant =
            KeyAuthorization::unrestricted(1, SignatureType::ConfigurableAccount, self.delegate());
        let signature = self.parent_signature(native_parent, grant.signature_hash());
        grant.into_signed(signature)
    }

    fn setup(&self, scenario: Scenario) -> Setup {
        let Scenario {
            spec,
            case,
            warmth,
            gas_limit,
            nonce_key,
            nonce,
            first_call_create,
            authorization,
        } = scenario;
        let native_parent = matches!(
            case,
            GrantCase::NativeGrant | GrantCase::NativeGrantAndUse | GrantCase::NativeAdminGrant
        );
        let admin_delegate = matches!(
            case,
            GrantCase::PrimitiveAdminGrant | GrantCase::NativeAdminGrant
        );
        let delegate_acts = admin_delegate
            || matches!(
                case,
                GrantCase::PrimitiveGrantAndUse | GrantCase::NativeGrantAndUse
            );
        let parent = if native_parent {
            self.parent.account()
        } else {
            self.parent.key.address()
        };
        let authorization = authorization.unwrap_or_else(|| self.grant(native_parent));
        let mut call = base_tx().calls.remove(0);
        if first_call_create {
            call.to = TxKind::Create;
        }
        let tx = TempoTransaction {
            nonce,
            nonce_key,
            gas_limit,
            fee_token: Some(PATH_USD_ADDRESS),
            calls: vec![call],
            access_list: if matches!(warmth, Warmth::AccessList) {
                AccessList(vec![AccessListItem {
                    address: self.delegate(),
                    storage_keys: vec![],
                }])
            } else {
                AccessList::default()
            },
            key_authorization: Some(authorization),
            ..base_tx()
        };
        let signature = if delegate_acts {
            let inner = KeychainSignature::signing_hash(tx.signature_hash(), parent);
            TempoSignature::Keychain(KeychainSignature::new(parent, self.delegate.sign(inner)))
        } else {
            match self.parent_signature(native_parent, tx.signature_hash()) {
                AccountSignature::Primitive(signature) => TempoSignature::Primitive(signature),
                AccountSignature::ConfigurableAccount(signature) => {
                    TempoSignature::ConfigurableAccount(signature)
                }
            }
        };
        let env = env(parent, tx, signature);

        let mut block = TempoBlockEnv::default();
        block.ext.configurable_account_recovery_factory = Some(FACTORY);
        if matches!(warmth, Warmth::Coinbase) {
            block.beneficiary = self.delegate();
        }
        let mut parent_info =
            AccountInfo::default().with_nonce(if nonce_key.is_zero() { nonce } else { 0 });
        if native_parent && admin_delegate {
            parent_info.extension =
                encode_config_commitment(self.parent.config.commitment().unwrap()).into();
        }
        let mut evm = evm_with_block(spec, block, &[(parent, parent_info)]);
        let admin_grant = admin_delegate && spec.is_t14();
        if admin_grant {
            // The admin grant stands for the parent's own earlier transaction, whose caller the
            // handler warms before any keychain call.
            evm.state_mut().prewarm(&parent);
        }
        StorageCtx::enter_evm_without_tip1060_accounting(&mut evm, || {
            TIP20Setup::path_usd(self.parent.key.address())
                .apply()
                .unwrap();
            if admin_grant {
                let mut keychain = AccountKeychain::new();
                keychain.initialize().unwrap();
                keychain.set_tx_origin(parent).unwrap();
                keychain
                    .authorize_admin_key(
                        parent,
                        self.delegate(),
                        KeychainSignatureType::ConfigurableAccount,
                        None,
                    )
                    .unwrap();
            }
        });
        if matches!(warmth, Warmth::Loaded) {
            evm.state_mut().prewarm(&self.delegate());
        }
        Setup {
            evm,
            env,
            caller: parent,
        }
    }
}

/// A ready-to-run scenario.
pub(super) struct Setup {
    pub(super) evm: TempoEvm<'static>,
    pub(super) env: TempoTxEnv,
    pub(super) caller: Address,
}

impl Setup {
    /// Runs the transaction and commits it, returning `(success, tx_gas_used)`.
    pub(super) fn run(&mut self) -> HandlerResult<(bool, u64)> {
        self.evm
            .transact(&Recovered::new_unchecked(self.env.clone(), self.caller))
            .map(|executed| {
                let result = executed.commit();
                (result.status, result.tx_gas_used())
            })
    }

    /// Runs `prepare_aa` only, without executing the calls.
    pub(super) fn prepare(&mut self) -> HandlerResult<PreparedAa> {
        prepare_aa(&mut TxRequest {
            envelope: &self.env,
            tx: Recovered::new_unchecked(self.env.as_aa().unwrap(), self.caller),
            host: &mut self.evm,
            _non_exhaustive: (),
        })
    }

    /// Warms the transaction's base accounts and access list, then returns the configurable
    /// account gas and state gas that `prepare_aa` adds to the intrinsic cost.
    fn native_gas(&mut self) -> HandlerResult<(u64, u64)> {
        let tx = self.env.as_aa().unwrap().inner().tx();
        warm_base_accounts(&mut self.evm, self.caller, tx.calls[0].to);
        warm_access_list(&mut self.evm, &tx.access_list);
        let spec = self.evm.config_spec_id();
        validate_state(&mut self.evm, &self.env, spec)
    }

    pub(super) fn account(&mut self, address: Address) -> Option<AccountInfo> {
        self.evm
            .state_mut()
            .account_info_untracked(&address)
            .unwrap()
    }
}

/// Everything that varies between the grant scenarios.
#[derive(Clone)]
struct Scenario {
    spec: TempoHardfork,
    case: GrantCase,
    warmth: Warmth,
    gas_limit: u64,
    nonce_key: U256,
    nonce: u64,
    first_call_create: bool,
    authorization: Option<SignedKeyAuthorization>,
}

impl Scenario {
    fn new(case: GrantCase, warmth: Warmth) -> Self {
        Self {
            spec: TempoHardfork::T14,
            case,
            warmth,
            gas_limit: 1_000_000,
            nonce_key: U256::ZERO,
            nonce: 3,
            first_call_create: false,
            authorization: None,
        }
    }

    fn with_gas_limit(mut self, gas_limit: u64) -> Self {
        self.gas_limit = gas_limit;
        self
    }

    fn with_nonce(mut self, nonce_key: U256, nonce: u64) -> Self {
        self.nonce_key = nonce_key;
        self.nonce = nonce;
        self
    }

    fn with_spec(mut self, spec: TempoHardfork) -> Self {
        self.spec = spec;
        self
    }

    fn with_first_call_create(mut self) -> Self {
        self.first_call_create = true;
        self
    }

    fn with_authorization(mut self, authorization: SignedKeyAuthorization) -> Self {
        self.authorization = Some(authorization);
        self
    }
}

#[derive(Clone, Copy, Debug)]
enum GrantCase {
    PrimitiveGrant,
    NativeGrant,
    PrimitiveGrantAndUse,
    NativeGrantAndUse,
    PrimitiveAdminGrant,
    NativeAdminGrant,
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

fn assert_native_error(error: &HandlerError, expected: &ConfigurableAccountError, context: &str) {
    assert_eq!(native_error(error), Some(expected), "{context}: {error:?}");
}

#[test_case::test_case(TempoHardfork::T12; "primitive_grant_before_t14_at_t12")]
#[test_case::test_case(TempoHardfork::T13; "primitive_grant_before_t14_at_t13")]
#[test_case::test_case(TempoHardfork::T14; "primitive_grant_at_t14")]
fn native_grant_type_is_gated_in_handler(spec: TempoHardfork) {
    let access = Access::new();
    let mut setup =
        access.setup(Scenario::new(GrantCase::PrimitiveGrant, Warmth::Cold).with_spec(spec));
    let result = setup.run();
    if spec.is_t14() {
        assert!(result.unwrap().0);
    } else {
        let error = result.unwrap_err();
        assert_native_error(
            &error,
            &ConfigurableAccountError::UnsupportedContext,
            "gate",
        );
    }
}

#[test_case::test_case(GrantCase::NativeGrant; "native_signer")]
#[test_case::test_case(GrantCase::PrimitiveGrantAndUse; "committed_keychain_parent")]
fn native_handler_rejects_account_code(case: GrantCase) {
    let access = Access::new();
    // A committed parent no longer signs a grant with its primitive root key (TIP-1112), and
    // account code is rejected before that.
    for code in [
        None,
        Some(Bytecode::new_legacy(Bytes::from_static(&[0x00]))),
    ] {
        let mut setup = access.setup(Scenario::new(case, Warmth::Cold));
        let account = setup.caller;
        let mut info = setup.account(account).unwrap();
        if matches!(case, GrantCase::PrimitiveGrantAndUse) {
            info.extension = encode_config_commitment(B256::repeat_byte(0x77)).into();
        }
        if let Some(code) = &code {
            info = info.with_code(code.clone());
        }
        setup
            .evm
            .overlay_db_mut()
            .insert_account_info(&account, info);
        let result = setup.run();
        if code.is_some() {
            let error = result.unwrap_err();
            assert_native_error(
                &error,
                &ConfigurableAccountError::InvalidAccount { account },
                &format!("{case:?}"),
            );
        } else if matches!(case, GrantCase::PrimitiveGrantAndUse) {
            let error = result.unwrap_err();
            assert!(
                matches!(
                    error.external_ref::<TempoInvalidTransaction>(),
                    Some(TempoInvalidTransaction::RootKeyRetired {
                        account: actual,
                        role: RootKeyRole::KeyAuthorizationSigner,
                    }) if *actual == account
                ),
                "{case:?}: {error:?}"
            );
        } else {
            assert!(result.unwrap().0, "{case:?}");
        }
    }
}

#[test_case::test_case(GrantBindingCase::Matching; "matching_grant")]
#[test_case::test_case(GrantBindingCase::WrongTarget; "wrong_grant_target")]
#[test_case::test_case(GrantBindingCase::WrongType; "wrong_grant_type")]
#[test_case::test_case(GrantBindingCase::UnrelatedSigner; "unrelated_grant_signer")]
fn native_handler_binds_grant_roles(case: GrantBindingCase) {
    let access = Access::new();
    let other = PrivateKeySigner::from_bytes(&B256::repeat_byte(3)).unwrap();
    let grant = KeyAuthorization::unrestricted(
        1,
        if matches!(case, GrantBindingCase::WrongType) {
            SignatureType::Secp256k1
        } else {
            SignatureType::ConfigurableAccount
        },
        if matches!(case, GrantBindingCase::WrongTarget) {
            other.address()
        } else {
            access.delegate()
        },
    )
    .with_account(access.parent.key.address());
    let signer = if matches!(case, GrantBindingCase::UnrelatedSigner) {
        &other
    } else {
        &access.parent.key
    };
    let signature = AccountSignature::from(signer.sign_hash_sync(&grant.signature_hash()).unwrap());
    let authorization = grant.into_signed(signature);
    assert_eq!(authorization.recover_account().unwrap(), signer.address());
    let mut setup = access.setup(
        Scenario::new(GrantCase::PrimitiveGrantAndUse, Warmth::Cold)
            .with_authorization(authorization),
    );
    // All quorums are genuinely signed over this transaction, including the
    // changed grant. Failures below must be role binding, not bad cryptography.
    for role in setup
        .env
        .as_aa()
        .unwrap()
        .native_authorizations()
        .into_iter()
        .flatten()
    {
        role.verify().unwrap();
    }
    let result = setup.run();
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
        let error = result.unwrap_err();
        assert!(
            matches!(
                error.external_ref::<TempoInvalidTransaction>(),
                Some(TempoInvalidTransaction::KeychainValidationFailed { reason })
                    if reason == expected
            ),
            "expected {expected}, got {error:?}"
        );
    } else {
        assert!(result.unwrap().0);
    }
}

#[test_case::test_case(GrantCase::PrimitiveAdminGrant; "primitive_parent")]
#[test_case::test_case(GrantCase::NativeAdminGrant; "configurable_parent")]
fn configurable_account_admin_can_sign_inline_grant(case: GrantCase) {
    let access = Access::new();
    let parent = if matches!(case, GrantCase::NativeAdminGrant) {
        access.parent.account()
    } else {
        access.parent.key.address()
    };
    let child = PrivateKeySigner::from_bytes(&B256::repeat_byte(3))
        .unwrap()
        .address();
    let grant =
        KeyAuthorization::unrestricted(1, SignatureType::Secp256k1, child).with_account(parent);
    let signature = access.delegate.sign(grant.signature_hash());
    let authorization = grant.into_signed(signature);
    let mut setup =
        access.setup(Scenario::new(case, Warmth::Cold).with_authorization(authorization));

    assert!(setup.run().unwrap().0);
    StorageCtx::enter_evm_without_tip1060_accounting(&mut setup.evm, || {
        let info = AccountKeychain::new()
            .get_key(getKeyCall {
                account: parent,
                keyId: child,
            })
            .unwrap();
        assert!(info.expiry != 0 && !info.isRevoked);
    });
}

#[test_case::test_case(GrantCase::PrimitiveGrant; "primitive_parent_grant_only")]
#[test_case::test_case(GrantCase::NativeGrant; "native_parent_grant_only")]
#[test_case::test_case(GrantCase::PrimitiveGrantAndUse; "primitive_parent_grant_and_use")]
#[test_case::test_case(GrantCase::NativeGrantAndUse; "native_parent_grant_and_use")]
fn native_delegate_access_is_intrinsic_once(case: GrantCase) {
    let access = Access::new();
    for warmth in [
        Warmth::Cold,
        Warmth::Loaded,
        Warmth::AccessList,
        Warmth::Coinbase,
    ] {
        let mut setup = access.setup(Scenario::new(case, warmth));
        let params = gas_params(&setup.evm);
        let mut expected = account_access_gas(&params, matches!(warmth, Warmth::Cold));
        let mut registered = Vec::new();
        for role in setup
            .env
            .as_aa()
            .unwrap()
            .native_authorizations()
            .into_iter()
            .flatten()
        {
            expected += keccak_cost(role.signature.config().account_salt_preimage_len()).unwrap()
                + keccak_cost(85).unwrap();
            if !registered.contains(&role.signature.account()) {
                expected += 20_000;
                registered.push(role.signature.account());
            }
        }
        let creates_delegate = matches!(
            case,
            GrantCase::PrimitiveGrantAndUse | GrantCase::NativeGrantAndUse
        );
        if creates_delegate {
            expected +=
                u64::from(params.get(GasId::NewAccountCost)) + params.new_account_state_gas();
        }
        let (extra_gas, extra_state_gas) = setup.native_gas().unwrap();
        assert_eq!(extra_gas, expected, "{case:?}, {warmth:?}");
        assert_eq!(
            extra_state_gas,
            if creates_delegate {
                params.new_account_state_gas()
            } else {
                0
            },
            "{case:?}, {warmth:?}"
        );
        assert!(
            setup
                .evm
                .state_mut()
                .account(&access.delegate())
                .unwrap()
                .is_warm()
        );
        assert!(
            setup
                .account(access.delegate())
                .is_none_or(|info| info.extension.is_empty())
        );

        // The full preparation charges the same gas: it is exactly sufficient, and one less is
        // not. Recreate the EVM for each check, since validation itself warms the delegate.
        let prepared = access.setup(Scenario::new(case, warmth)).prepare().unwrap();
        let total = prepared.intrinsic + prepared.initial_state_gas;
        for (limit, valid) in [(total - 1, false), (total, true)] {
            let mut boundary = access.setup(Scenario::new(case, warmth).with_gas_limit(limit));
            assert_eq!(
                boundary.prepare().is_ok(),
                valid,
                "{case:?}, {warmth:?}, gas={limit}"
            );
        }
        let mut execution = access.setup(Scenario::new(case, warmth));
        let (success, _) = execution
            .run()
            .unwrap_or_else(|error| panic!("{case:?}, {warmth:?}: {error:?}"));
        assert!(success, "{case:?}, {warmth:?}");
        assert_eq!(
            execution
                .account(access.delegate())
                .is_none_or(|info| info.extension.is_empty()),
            matches!(case, GrantCase::PrimitiveGrant | GrantCase::NativeGrant),
            "only an authorizing delegate is registered: {case:?}, {warmth:?}",
        );
    }
}

#[test]
fn native_delegate_creation_gas_covers_all_nonce_types() {
    let access = Access::new();
    // The sender's first-call `CREATE` charge never pays for the delegate's creation.
    for nonce_key in [U256::ZERO, U256::ONE, TEMPO_EXPIRING_NONCE_KEY] {
        for first_call_create in [false, true] {
            for funded in [false, true] {
                let mut scenario = Scenario::new(GrantCase::PrimitiveGrantAndUse, Warmth::Cold)
                    .with_gas_limit(1_500_000)
                    .with_nonce(nonce_key, 0);
                if first_call_create {
                    scenario = scenario.with_first_call_create();
                }
                let mut setup = access.setup(scenario);
                if funded {
                    setup.evm.overlay_db_mut().insert_account_info(
                        &access.delegate(),
                        AccountInfo::default().with_balance(U256::ONE),
                    );
                }
                let params = gas_params(&setup.evm);
                let (extra_gas, extra_state_gas) = setup.native_gas().unwrap();
                let proof_and_access = initial_account_proof_gas(access.delegate_config()).unwrap()
                    + 20_000
                    + u64::from(params.get(GasId::WarmStorageReadCost))
                    + params.cold_account_additional_cost();
                assert_eq!(
                    extra_gas,
                    proof_and_access
                        + if funded {
                            0
                        } else {
                            u64::from(params.get(GasId::NewAccountCost))
                        },
                    "nonce_key={nonce_key}, first_call_create={first_call_create}, funded={funded}"
                );
                assert_eq!(
                    extra_state_gas,
                    if funded {
                        0
                    } else {
                        params.new_account_state_gas()
                    },
                    "nonce_key={nonce_key}, first_call_create={first_call_create}, funded={funded}"
                );
            }
        }
    }
}

#[test]
fn native_delegate_creation_gas_survives_revert() {
    let access = Access::new();
    let mut used = [0; 2];
    for (index, funded) in [true, false].into_iter().enumerate() {
        let mut setup = access.setup(Scenario::new(GrantCase::PrimitiveGrantAndUse, Warmth::Cold));
        if funded {
            setup.evm.overlay_db_mut().insert_account_info(
                &access.delegate(),
                AccountInfo::default().with_balance(U256::ONE),
            );
        }
        let code = Bytecode::new_legacy(Bytes::from_static(&[0x60, 0, 0x60, 0, 0xfd]));
        setup.evm.overlay_db_mut().insert_account_info(
            &Address::repeat_byte(0x44),
            AccountInfo::default().with_code(code),
        );
        let (success, gas_used) = setup.run().unwrap();
        assert!(!success);
        assert!(
            !setup
                .account(access.delegate())
                .unwrap()
                .extension
                .is_empty()
        );
        used[index] = gas_used;
    }
    let params = gas_params(&evm(TempoHardfork::T14));
    assert_eq!(
        used[1] - used[0],
        u64::from(params.get(GasId::NewAccountCost)) + params.new_account_state_gas()
    );
}

#[test]
fn native_sender_and_delegate_creation_are_charged_separately() {
    let access = Access::new();
    let mut setup = access.setup(
        Scenario::new(GrantCase::NativeGrantAndUse, Warmth::Cold)
            .with_gas_limit(1_500_000)
            .with_nonce(TEMPO_EXPIRING_NONCE_KEY, 0),
    );
    let params = gas_params(&setup.evm);
    let (extra_gas, extra_state_gas) = setup.native_gas().unwrap();
    let proof_and_writes = [access.parent_config(), access.delegate_config()]
        .iter()
        .map(|config| initial_account_proof_gas(config).unwrap() + 20_000)
        .sum::<u64>();
    assert_eq!(
        extra_gas,
        proof_and_writes
            + u64::from(params.get(GasId::WarmStorageReadCost))
            + params.cold_account_additional_cost()
            + 2 * u64::from(params.get(GasId::NewAccountCost))
    );
    assert_eq!(extra_state_gas, 2 * params.new_account_state_gas());
}
