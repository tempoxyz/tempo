#![cfg(feature = "reth")]

use alloy_primitives::{Address, TxKind};
use alloy_rpc_types_eth::TransactionRequest;
use reth_rpc_convert::TryIntoTxEnv;
use reth_rpc_eth_types::EthApiError;
use tempo_alloy::rpc::TempoTransactionRequest;
use tempo_evm::TempoEvmEnv;
use tempo_primitives::SignatureType;

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
