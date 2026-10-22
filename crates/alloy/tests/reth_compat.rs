#![cfg(feature = "reth")]

use alloy_primitives::{Address, B256, Bytes, Signature, TxKind, U256};
use alloy_rpc_types_eth::TransactionRequest;
use reth_rpc_convert::{TryIntoSimTx, TryIntoTxEnv};
use reth_rpc_eth_types::EthApiError;
use tempo_alloy::rpc::{
    ConfigurableAccountSimulationApproval, ConfigurableAccountSimulationSpec,
    TempoTransactionRequest,
};
use tempo_evm::TempoEvmEnv;
use tempo_primitives::{
    SignatureType, TempoTxEnvelope,
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

#[test]
fn configurable_account_key_type_cannot_fabricate_a_primitive_simulation_signature() {
    let env = TempoEvmEnv::default();

    aa_request(SignatureType::Secp256k1)
        .try_into_tx_env(&env)
        .expect("a primitive key type converts");

    let error = aa_request(SignatureType::ConfigurableAccount)
        .try_into_tx_env(&env)
        .expect_err("a configurable account key type has no primitive stand-in");
    assert!(matches!(error, EthApiError::InvalidParams(_)));
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
        key_type: Some(SignatureType::Secp256k1),
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
#[test_case(
    vec![
        ConfigurableAccountSimulationApproval {
            key_type: Some(SignatureType::WebAuthn),
            key_data: Some(Bytes::from(1921u16.to_be_bytes())),
            ..approval(1)
        },
        approval(2),
    ],
    "configurable account owner signature too large";
    "oversized webauthn"
)]
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

#[test]
fn grant_simulation_signs_the_grant_with_mock_owner_approvals() {
    let mut request = aa_request(SignatureType::Secp256k1);
    request.set_key_authorization(grant().into_signed(Signature::test_signature()));
    // An unsupported `keyData` length falls back to the default size, as for ordinary requests.
    let webauthn = ConfigurableAccountSimulationApproval {
        key_type: Some(SignatureType::WebAuthn),
        key_data: Some(Bytes::from_static(&[0, 0, 1])),
        ..approval(2)
    };
    request.key_authorization_simulation = Some(spec(vec![approval(1), webauthn]));

    let env = request
        .try_into_tx_env(&TempoEvmEnv::default())
        .expect("a valid claimed quorum converts");
    let TempoTxEnvelope::AA(tx) = env.inner().transaction() else {
        panic!("AA expected");
    };
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
    assert_eq!(signature.account(), Address::repeat_byte(0xaa));
    assert_eq!(signature.config(), &config());
    assert_eq!(signature.signatures().len(), 2);
}

/// Simulated blocks skip owner cryptography, so a real configurable grant is verified first.
#[test]
fn block_simulation_rejects_a_configurable_grant_with_invalid_approvals() {
    let unrecoverable =
        PrimitiveSignature::Secp256k1(Signature::new(U256::ZERO, U256::ZERO, false));
    let signature = ConfigurableAccountSignature::try_new(
        Address::repeat_byte(0xaa),
        config(),
        vec![unrecoverable; 2],
    )
    .unwrap();
    let mut request = aa_request(SignatureType::Secp256k1);
    request.set_key_authorization(grant().into_signed(signature));

    let error = TryIntoSimTx::<TempoTxEnvelope>::try_into_sim_tx(request)
        .expect_err("dummy owner approvals must not authorize a grant");
    assert_eq!(
        error.to_string(),
        "invalid configurable account owner signature"
    );
}
