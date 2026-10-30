#![cfg(feature = "reth")]

use alloy_primitives::{Address, B256, Bytes, Signature, TxKind, U256};
use alloy_rpc_types_eth::TransactionRequest;
use reth_rpc_convert::{TryIntoSimTx, TryIntoTxEnv};
use reth_rpc_eth_types::EthApiError;
use tempo_alloy::rpc::{
    ConfigurableAccountSimulationApproval, ConfigurableAccountSimulationSpec,
    PrimitiveSignatureType, TempoTransactionRequest,
};
use tempo_evm::TempoEvmEnv;
use tempo_primitives::{
    SignatureType, TempoSignature, TempoTxEnvelope,
    transaction::{
        ConfigurableAccountConfig, ConfigurableAccountOwner, ConfigurableAccountSignature,
        KeyAuthorization, PrimitiveSignature,
    },
};
use test_case::test_case;

fn aa_request(key_type: SignatureType) -> TempoTransactionRequest {
    TempoTransactionRequest {
        inner: TransactionRequest {
            from: Some(Address::repeat_byte(0xaa)),
            to: Some(TxKind::Call(Address::repeat_byte(1))),
            nonce: Some(0),
            gas: Some(100_000),
            max_fee_per_gas: Some(1_000_000_000),
            max_priority_fee_per_gas: Some(1_000_000),
            chain_id: Some(4217),
            ..Default::default()
        },
        key_type: Some(key_type),
        ..Default::default()
    }
}

/// Two of three owners, each of weight one.
fn config() -> ConfigurableAccountConfig {
    ConfigurableAccountConfig {
        salt: B256::ZERO,
        version: 1,
        threshold: 2,
        owners: [1, 2, 3]
            .map(|byte| ConfigurableAccountOwner {
                owner: Address::repeat_byte(byte),
                weight: 1,
            })
            .into(),
    }
}

fn approval(owner: u8) -> ConfigurableAccountSimulationApproval {
    ConfigurableAccountSimulationApproval {
        owner: Address::repeat_byte(owner),
        key_type: Some(PrimitiveSignatureType::Secp256k1),
        key_data: None,
    }
}

fn spec(
    approvals: Vec<ConfigurableAccountSimulationApproval>,
) -> ConfigurableAccountSimulationSpec {
    ConfigurableAccountSimulationSpec {
        signer: None,
        config: config(),
        approvals,
    }
}

fn grant() -> KeyAuthorization {
    KeyAuthorization::unrestricted(4217, SignatureType::Secp256k1, Address::repeat_byte(8))
}

/// Simulation skips owner recovery, so the claimed approvals are checked before the mock is built.
#[test_case(vec![approval(1)], "configurable account signature weight below threshold"; "below threshold")]
#[test_case(vec![approval(2), approval(1)], "configurable account recovered owners must be strictly ascending"; "unordered")]
#[test_case(vec![approval(1), approval(9)], "configurable account signer is not an owner"; "non-owner")]
fn simulation_rejects_invalid_claimed_approvals(
    approvals: Vec<ConfigurableAccountSimulationApproval>,
    message: &str,
) {
    let mut request = aa_request(SignatureType::ConfigurableAccount);
    request.configurable_account_simulation = Some(spec(approvals));

    let error = request
        .try_into_tx_env(&TempoEvmEnv::default())
        .expect_err("invalid claimed approvals are rejected");
    assert!(matches!(error, EthApiError::InvalidParams(actual) if actual == message));
}

/// An owner's `WebAuthn` hint is clamped to what an owner signature can carry, and every mock
/// approval is non-zero, so it costs as much calldata gas as a real one.
#[test_case(None, None, 1920; "default")]
#[test_case(Some(PrimitiveSignatureType::WebAuthn), None, 800; "no hint")]
#[test_case(Some(PrimitiveSignatureType::WebAuthn), Some(500), 500; "under the cap")]
#[test_case(Some(PrimitiveSignatureType::WebAuthn), Some(1921), 1920; "over the cap")]
#[test_case(Some(PrimitiveSignatureType::WebAuthn), Some(8192), 1920; "transaction cap")]
fn simulation_models_owner_webauthn_approvals(
    key_type: Option<PrimitiveSignatureType>,
    hint: Option<u16>,
    expected_len: usize,
) {
    let mut request = aa_request(SignatureType::ConfigurableAccount);
    request.configurable_account_simulation = Some(spec(vec![
        ConfigurableAccountSimulationApproval {
            key_type,
            key_data: hint.map(|hint| Bytes::from(hint.to_be_bytes())),
            ..approval(1)
        },
        approval(2),
    ]));

    let env = request
        .try_into_tx_env(&TempoEvmEnv::default())
        .expect("a valid claimed quorum converts");
    let signature = env
        .as_aa()
        .expect("AA expected")
        .signature()
        .as_configurable_account()
        .expect("the mock quorum signs the transaction");
    let PrimitiveSignature::WebAuthn(approval) = &signature.signatures()[0] else {
        panic!("expected a WebAuthn approval");
    };
    assert_eq!(approval.webauthn_data.len(), expected_len);
    assert!(approval.webauthn_data.iter().all(|byte| *byte != 0));
}

/// The transaction's own `WebAuthn` mock is non-zero too.
#[test]
fn webauthn_transaction_mock_is_non_zero() {
    let env = aa_request(SignatureType::WebAuthn)
        .try_into_tx_env(&TempoEvmEnv::default())
        .expect("a WebAuthn request converts");
    let TempoSignature::Primitive(PrimitiveSignature::WebAuthn(signature)) =
        env.as_aa().expect("AA expected").signature()
    else {
        panic!("expected a WebAuthn signature");
    };
    assert_eq!(signature.webauthn_data.len(), 800);
    assert!(signature.webauthn_data.iter().all(|byte| *byte != 0));
}

/// Owner approvals take primitive key types only.
#[test]
fn approval_rejects_configurable_key_type() {
    let approval = |key_type: &str| {
        serde_json::from_value::<ConfigurableAccountSimulationApproval>(serde_json::json!({
            "owner": Address::repeat_byte(1),
            "keyType": key_type,
        }))
    };
    assert_eq!(
        approval("webAuthn")
            .expect("a primitive key type parses")
            .key_type,
        Some(PrimitiveSignatureType::WebAuthn)
    );
    assert!(approval("configurableAccount").is_err());
}

/// The mock grant is signed by the admin named as `signer`.
#[test]
fn grant_simulation_signs_the_grant_with_mock_owner_approvals() {
    let admin = Address::repeat_byte(0xbb);
    let mut request = aa_request(SignatureType::Secp256k1);
    request.set_key_authorization(grant().into_signed(Signature::test_signature()));
    // An unsupported `keyData` length falls back to the default size, as for ordinary requests.
    let webauthn = ConfigurableAccountSimulationApproval {
        key_type: Some(PrimitiveSignatureType::WebAuthn),
        key_data: Some(Bytes::from_static(&[0, 0, 1])),
        ..approval(2)
    };
    request.key_authorization_simulation = Some(ConfigurableAccountSimulationSpec {
        signer: Some(admin),
        ..spec(vec![approval(1), webauthn])
    });

    let env = request
        .try_into_tx_env(&TempoEvmEnv::default())
        .expect("a valid claimed quorum converts");
    let tx = env.as_aa().expect("AA expected");
    let signed = tx
        .tx()
        .key_authorization
        .as_ref()
        .expect("the grant is kept");
    assert_eq!(signed.authorization, grant());
    let signature = signed
        .signature
        .as_configurable_account()
        .expect("the grant carries the mock quorum");
    assert_eq!(signature.account(), admin);
    assert_eq!(signature.config(), &config());
    assert_eq!(signature.signatures().len(), 2);
}

/// Fillers drop a grant whose key is already live but keep its simulated quorum, which is then
/// ignored.
#[test]
fn grant_simulation_without_a_grant_is_ignored() {
    let mut request = aa_request(SignatureType::Secp256k1);
    request.key_authorization_simulation = Some(spec(vec![approval(1), approval(2)]));

    TryIntoSimTx::<TempoTxEnvelope>::try_into_sim_tx(request.clone())
        .expect("eth_simulateV1 ignores the simulated quorum");
    let env = request
        .try_into_tx_env(&TempoEvmEnv::default())
        .expect("eth_call ignores the simulated quorum");
    assert!(
        env.as_aa()
            .expect("AA expected")
            .tx()
            .key_authorization
            .is_none()
    );
}

/// `eth_simulateV1` and `eth_call` reject an inconsistent simulated role alike. Simulation skips
/// owner cryptography, so they also verify a real configurable grant first.
#[test_case(
    |request| request.set_key_type(SignatureType::ConfigurableAccount),
    "configurable account simulation requires a configuration witness";
    "missing witness"
)]
#[test_case(
    |request| {
        request.configurable_account_simulation = Some(spec(vec![approval(1), approval(2)]));
        request.set_key_id(Address::repeat_byte(0xaa));
    },
    "a configurable delegate cannot be its own parent";
    "own parent"
)]
#[test_case(
    |request| {
        request.configurable_account_simulation = Some(ConfigurableAccountSimulationSpec {
            signer: Some(Address::repeat_byte(0xbb)),
            ..spec(vec![approval(1), approval(2)])
        });
    },
    "configurable account simulation signer does not match the role account";
    "signer mismatch"
)]
#[test_case(
    |request| request.set_key_authorization(grant().into_signed(
        ConfigurableAccountSignature::try_new(
            Address::repeat_byte(0xaa),
            config(),
            vec![PrimitiveSignature::Secp256k1(Signature::new(U256::ZERO, U256::ZERO, false)); 2],
        )
        .unwrap(),
    )),
    "invalid configurable account owner signature";
    "configurable grant with invalid approvals"
)]
#[test_case(
    |request| {
        request.configurable_account_simulation = Some(spec(vec![approval(1), approval(2)]));
        request.inner.from = None;
    },
    "configurable account simulation requires `from`";
    "outer quorum without from"
)]
#[test_case(
    |request| {
        request.set_key_authorization(grant().into_signed(Signature::test_signature()));
        request.key_authorization_simulation = Some(spec(vec![approval(1), approval(2)]));
        request.inner.from = None;
    },
    "configurable account simulation requires `from`";
    "grant quorum without from"
)]
#[test_case(
    |request| {
        request.configurable_account_simulation = Some(spec(vec![approval(1), approval(2)]));
        request.inner.from = Some(Address::ZERO);
    },
    "configurable account simulation requires `from`";
    "outer quorum with the zero from eth_simulateV1 defaults to"
)]
fn simulation_rejects_invalid_roles(configure: fn(&mut TempoTransactionRequest), message: &str) {
    let mut request = aa_request(SignatureType::Secp256k1);
    configure(&mut request);

    let error = TryIntoSimTx::<TempoTxEnvelope>::try_into_sim_tx(request.clone())
        .expect_err("eth_simulateV1 rejects the role");
    assert_eq!(error.to_string(), message);
    let error = request
        .try_into_tx_env(&TempoEvmEnv::default())
        .expect_err("eth_call rejects the role");
    assert!(matches!(error, EthApiError::InvalidParams(actual) if actual == message));
}
