#![cfg(feature = "reth")]

use alloy_primitives::{Address, B256, TxKind};
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
    transaction::{ConfigurableAccountConfig, ConfigurableAccountOwner, KeyAuthorization},
};

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

/// Simulated blocks skip owner cryptography, so a real configurable grant is verified first.
#[test]
fn block_simulation_rejects_a_configurable_grant_with_invalid_approvals() {
    let owner = Address::repeat_byte(1);
    let spec = ConfigurableAccountSimulationSpec {
        signer: None,
        config: ConfigurableAccountConfig {
            salt: B256::ZERO,
            version: 1,
            threshold: 1,
            owners: vec![ConfigurableAccountOwner { owner, weight: 1 }],
        },
        approvals: vec![ConfigurableAccountSimulationApproval {
            owner,
            key_type: Some(SignatureType::Secp256k1),
            key_data: None,
        }],
    };
    let mut request = aa_request(SignatureType::Secp256k1);
    request.set_key_authorization(
        KeyAuthorization::unrestricted(4217, SignatureType::Secp256k1, Address::repeat_byte(8))
            .into_signed(spec.mock_signature(Address::repeat_byte(0xaa)).unwrap()),
    );

    let error = TryIntoSimTx::<TempoTxEnvelope>::try_into_sim_tx(request)
        .expect_err("dummy owner approvals must not authorize a grant");
    assert_eq!(
        error.to_string(),
        "invalid configurable account owner signature at approval 0"
    );
}
