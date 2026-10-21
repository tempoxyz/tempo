//! First-use commitment registration: gas, failure atomicity and visibility during execution.

use super::{native_access::Setup, *};
use crate::handler::{intrinsic_gas, nonce_intrinsic_gas, prepare_aa};
use alloy_eips::eip7702::Authorization;
use alloy_sol_types::SolCall;
use commonware_utils::NZU64;
use evm2::{bytecode::Bytecode, registry::TxRequest};
use tempo_contracts::precompiles::{CONFIGURABLE_ACCOUNT_ADDRESS, IConfigurableAccount};
use tempo_precompiles::{PATH_USD_ADDRESS, TempoPrecompiles, test_util::TIP20Setup};
use tempo_primitives::{account::decode_config_commitment, transaction::TempoSignedAuthorization};

const TARGET: Address = Address::repeat_byte(0x33);

/// A T14 EVM and a simulated transaction from a fresh configurable-account sender.
struct Sender {
    native: Native,
    setup: Setup,
}

impl Sender {
    fn new(nonce_key: U256, nonce: u64, gas_limit: u64, calls: Vec<Call>) -> Self {
        Self::for_native(Native::random(), nonce_key, nonce, gas_limit, calls)
    }

    fn for_native(
        native: Native,
        nonce_key: U256,
        nonce: u64,
        gas_limit: u64,
        calls: Vec<Call>,
    ) -> Self {
        let account = native.account();
        let expiring = nonce_key == TEMPO_EXPIRING_NONCE_KEY;
        let mut tx = TempoTransaction {
            nonce,
            nonce_key,
            gas_limit,
            calls,
            valid_before: expiring.then_some(NZU64!(10)),
            ..base_tx()
        };
        // An expiring-nonce transaction is sponsored: the fee payer is a role account.
        if expiring {
            let fee_payer = PrivateKeySigner::from_bytes(&B256::repeat_byte(0x45)).unwrap();
            tx.fee_payer_signature = Some(
                fee_payer
                    .sign_hash_sync(&tx.fee_payer_signature_hash(account))
                    .unwrap(),
            );
        }
        let env = native
            .env(tx)
            .with_simulation_overrides(B256::repeat_byte(0x46), None, None);
        let mut evm = evm(TempoHardfork::T14);
        StorageCtx::enter_evm_without_tip1060_accounting(&mut evm, || {
            TIP20Setup::path_usd(Address::repeat_byte(0x99))
                .apply()
                .unwrap();
        });
        Self {
            native,
            setup: Setup {
                evm,
                env,
                caller: account,
            },
        }
    }

    fn account(&self) -> Address {
        self.native.account()
    }

    /// The commitment stored on the sender, zero when none is registered.
    fn commitment(&mut self) -> B256 {
        let account = self.account();
        match self.setup.account(account) {
            Some(info) => decode_config_commitment(&info.extension, TempoHardfork::T14).unwrap(),
            None => B256::ZERO,
        }
    }

    fn expected_commitment(&self) -> B256 {
        self.setup.env.as_aa().unwrap().native_authorizations()[0]
            .as_ref()
            .unwrap()
            .signature
            .config_commitment()
    }
}

fn call_to(to: TxKind) -> Call {
    Call {
        to,
        value: U256::ZERO,
        input: Bytes::new(),
    }
}

#[test]
fn native_registration_charges_empty_sender_creation_once() {
    struct Row {
        nonce_key: U256,
        first_call_create: bool,
        funded: bool,
        sender_nonce: u64,
        creation_charges: u64,
    }
    // Each row charges TIP-1000's new-account cost exactly once, except where the nonce write
    // of `nonce_key == 0` creates the account or the sender already exists.
    for Row {
        nonce_key,
        first_call_create,
        funded,
        sender_nonce,
        creation_charges,
    } in [
        Row {
            nonce_key: U256::ZERO,
            first_call_create: false,
            funded: false,
            sender_nonce: 0,
            creation_charges: 0,
        },
        Row {
            nonce_key: U256::ZERO,
            first_call_create: true,
            funded: false,
            sender_nonce: 0,
            creation_charges: 0,
        },
        Row {
            nonce_key: U256::ONE,
            first_call_create: false,
            funded: false,
            sender_nonce: 0,
            creation_charges: 1,
        },
        Row {
            nonce_key: U256::ONE,
            first_call_create: true,
            funded: false,
            sender_nonce: 0,
            creation_charges: 1,
        },
        Row {
            nonce_key: U256::ONE,
            first_call_create: true,
            funded: false,
            sender_nonce: 1,
            creation_charges: 0,
        },
        Row {
            nonce_key: TEMPO_EXPIRING_NONCE_KEY,
            first_call_create: false,
            funded: false,
            sender_nonce: 0,
            creation_charges: 1,
        },
        Row {
            nonce_key: TEMPO_EXPIRING_NONCE_KEY,
            first_call_create: true,
            funded: false,
            sender_nonce: 0,
            creation_charges: 1,
        },
        Row {
            nonce_key: TEMPO_EXPIRING_NONCE_KEY,
            first_call_create: false,
            funded: true,
            sender_nonce: 0,
            creation_charges: 0,
        },
    ] {
        let case = format!(
            "nonce_key={nonce_key}, first_call_create={first_call_create}, funded={funded}, sender_nonce={sender_nonce}"
        );
        // Room for the intrinsic `CREATE` and new-account charges.
        let mut sender = Sender::new(
            nonce_key,
            0,
            5_000_000,
            vec![call_to(if first_call_create {
                TxKind::Create
            } else {
                TxKind::Call(TARGET)
            })],
        );
        let account = sender.account();
        if funded || sender_nonce != 0 {
            let balance = if funded { U256::ONE } else { U256::ZERO };
            sender.setup.evm.overlay_db_mut().insert_account_info(
                &account,
                AccountInfo::default()
                    .with_balance(balance)
                    .with_nonce(sender_nonce),
            );
        }
        let params = gas_params(&sender.setup.evm);
        let aa = sender.setup.env.as_aa().unwrap();
        // The cost of the same transaction without any configurable-account charge.
        let (base_regular, base_state, _) = intrinsic_gas(&sender.setup.evm, aa).unwrap();
        let (nonce_regular, nonce_state) = nonce_intrinsic_gas(&sender.setup.evm, aa);
        let config = aa.native_authorizations()[0]
            .as_ref()
            .unwrap()
            .signature
            .config();
        let proof_and_write = initial_account_proof_gas(config).unwrap() + 20_000;
        // The fee payer is a role account, charged one cold access.
        let fee_payer_access = if nonce_key == TEMPO_EXPIRING_NONCE_KEY {
            u64::from(params.get(GasId::WarmStorageReadCost))
                + params.cold_account_additional_cost()
        } else {
            0
        };
        // Full preparation: the sender's first-call `CREATE` charge lands in state validation.
        let prepared = sender.setup.prepare().unwrap();
        assert_eq!(
            prepared.intrinsic - base_regular - nonce_regular,
            proof_and_write
                + fee_payer_access
                + creation_charges * u64::from(params.get(GasId::NewAccountCost)),
            "{case}"
        );
        assert_eq!(
            prepared.initial_state_gas - base_state - nonce_state,
            creation_charges * params.new_account_state_gas(),
            "{case}"
        );
    }
}

#[test_case::test_case(&[0x60, 0, 0x60, 0, 0xfd]; "revert")]
#[test_case::test_case(&[0xfe]; "halt")]
fn native_registration_first_call_failure_and_retry(failing_code: &'static [u8]) {
    let mut sender = Sender::new(U256::ZERO, 0, 600_000, vec![call_to(TxKind::Call(TARGET))]);
    let expected = sender.expected_commitment();
    assert_ne!(expected, B256::ZERO);
    assert_eq!(sender.commitment(), B256::ZERO);
    for (nonce, (code, succeeds)) in (0..).zip([(failing_code, false), (&[0x00][..], true)]) {
        sender.setup.evm.overlay_db_mut().insert_account_info(
            &TARGET,
            AccountInfo::default().with_code(Bytecode::new_legacy(Bytes::copy_from_slice(code))),
        );
        let tx = TempoTransaction {
            nonce,
            gas_limit: 600_000,
            calls: vec![call_to(TxKind::Call(TARGET))],
            ..base_tx()
        };
        sender.setup.env =
            sender
                .native
                .env(tx)
                .with_simulation_overrides(B256::repeat_byte(0x46), None, None);
        let (success, _) = sender.setup.run().unwrap();
        assert_eq!(success, succeeds, "nonce {nonce}");
        // The first-use registration survives the failed first call and the retry.
        assert_eq!(sender.commitment(), expected, "nonce {nonce}");
    }
}

#[test]
fn native_invalid_intrinsic_gas_does_not_register() {
    let mut sender = Sender::new(U256::ZERO, 0, 1, vec![call_to(TxKind::Call(TARGET))]);
    let error = sender.setup.run().unwrap_err();
    assert!(
        matches!(error, HandlerError::IntrinsicGasTooLow { got: 1, .. }),
        "{error:?}"
    );
    assert_eq!(sender.commitment(), B256::ZERO);
}

#[test]
fn native_failed_fee_collection_does_not_register() {
    let gas_limit = 1_000_000;
    let mut sender = Sender::new(
        U256::ZERO,
        0,
        gas_limit,
        vec![call_to(TxKind::Call(TARGET))],
    );
    // The sender holds no fee token, so charging the fee fails after validation.
    let tx = TempoTransaction {
        max_fee_per_gas: 1_000_000_000_000,
        fee_token: Some(PATH_USD_ADDRESS),
        gas_limit,
        calls: vec![call_to(TxKind::Call(TARGET))],
        ..base_tx()
    };
    sender.setup.env =
        sender
            .native
            .env(tx)
            .with_simulation_overrides(B256::repeat_byte(0x46), None, None);
    let error = sender.setup.run().unwrap_err();
    assert!(
        matches!(
            error.external_ref::<TempoInvalidTransaction>(),
            Some(TempoInvalidTransaction::CollectFeePreTx(_))
        ),
        "{error:?}"
    );
    assert_eq!(sender.commitment(), B256::ZERO);
}

#[test]
fn native_getter_observes_first_registration_during_execution() {
    let native = Native::random();
    let account = native.account();
    let calls = vec![Call {
        to: TxKind::Call(CONFIGURABLE_ACCOUNT_ADDRESS),
        value: U256::ZERO,
        input: IConfigurableAccount::getConfigCommitmentCall { account }
            .abi_encode()
            .into(),
    }];
    let mut sender = Sender::for_native(native, U256::ZERO, 0, 1_000_000, calls);
    let expected = sender.expected_commitment();
    let precompiles = TempoPrecompiles::<TempoEvmTypes>::new(
        TempoHardfork::T14,
        sender.setup.evm.ext().actions.clone(),
        sender.setup.evm.ext().non_creditable_slots.clone(),
    );
    sender.setup.evm.set_precompiles(precompiles);
    let output = sender
        .setup
        .evm
        .transact(&Recovered::new_unchecked(
            sender.setup.env.clone(),
            sender.setup.caller,
        ))
        .unwrap()
        .commit();
    assert!(output.status, "{output:?}");
    assert_eq!(output.output, Bytes::from(expected));
}

#[test]
fn configurable_account_authorization_list_entries_are_rejected() {
    let parent = Address::repeat_byte(1);
    let native = Native::random();
    for spec in [TempoHardfork::T13, TempoHardfork::T14] {
        for signature in [
            TempoSignature::ConfigurableAccount(native.sign(B256::ZERO)),
            TempoSignature::Keychain(KeychainSignature::new(parent, native.sign(B256::ZERO))),
        ] {
            let tx = TempoTransaction {
                tempo_authorization_list: vec![TempoSignedAuthorization::new_unchecked(
                    Authorization {
                        chain_id: U256::ONE,
                        address: Address::repeat_byte(5),
                        nonce: 0,
                    },
                    signature,
                )],
                ..base_tx()
            };
            let env = env(parent, tx, primitive_signature());
            let mut evm = evm(spec);
            let error = prepare_aa(&mut TxRequest {
                envelope: &env,
                tx: Recovered::new_unchecked(env.as_aa().unwrap(), parent),
                host: &mut evm,
                _non_exhaustive: (),
            })
            .err()
            .expect("a configurable-account authorization-list entry is rejected");
            assert_eq!(
                native_error(&error),
                Some(&ConfigurableAccountError::InvalidSignatureContext),
                "{spec:?}: {error:?}"
            );
        }
    }
}
