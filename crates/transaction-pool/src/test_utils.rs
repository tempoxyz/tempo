//! Shared test utilities for the transaction-pool crate.
//!
//! This module provides common helpers for creating test transactions,
//! wrapping them in pool structures, and setting up mock providers.

use crate::transaction::TempoPooledTransaction;
use alloy_consensus::{Transaction, TxEip1559};
use alloy_primitives::{Address, B256, Signature, TxKind, U256};
use reth_primitives_traits::Recovered;
use reth_provider::test_utils::MockEthProvider;
use reth_transaction_pool::{TransactionOrigin, ValidPoolTransaction};
use std::time::Instant;
use tempo_chainspec::{TempoChainSpec, spec::MODERATO};
use tempo_primitives::{
    TempoTxEnvelope,
    transaction::{
        TempoTransaction,
        tempo_transaction::Call,
        tt_signature::{PrimitiveSignature, TempoSignature},
        tt_signed::AASigned,
    },
};

/// Helper to create a non-AA (EIP-1559) transaction.
pub(crate) fn create_eip1559_tx(
    to: Address,
    gas_limit: u64,
    value: U256,
) -> TempoPooledTransaction {
    let tx = TxEip1559 {
        to: TxKind::Call(to),
        gas_limit,
        value,
        max_fee_per_gas: 2_000_000_000,
        max_priority_fee_per_gas: 1_000_000_000,
        ..Default::default()
    };

    let envelope = TempoTxEnvelope::Eip1559(alloy_consensus::Signed::new_unchecked(
        tx,
        Signature::test_signature(),
        B256::ZERO,
    ));

    let recovered = Recovered::new_unchecked(envelope, Address::random());
    TempoPooledTransaction::new(recovered)
}

/// Helper to create an AA transaction with custom nonce_key and nonce.
///
/// Uses default gas parameters (gas_limit=100_000, value=0).
pub(crate) fn create_aa_tx(sender: Address, nonce_key: U256, nonce: u64) -> TempoPooledTransaction {
    create_aa_tx_full(
        sender,
        nonce_key,
        nonce,
        100_000,
        U256::ZERO,
        1_000_000_000,
        2_000_000_000,
    )
}

/// Helper to create an AA transaction with custom gas limit and value.
///
/// Uses default fee parameters.
pub(crate) fn create_aa_tx_with_values(
    sender: Address,
    nonce_key: U256,
    nonce: u64,
    gas_limit: u64,
    value: U256,
) -> TempoPooledTransaction {
    create_aa_tx_full(
        sender,
        nonce_key,
        nonce,
        gas_limit,
        value,
        1_000_000_000,
        2_000_000_000,
    )
}

/// Helper to create an AA transaction with custom gas prices.
///
/// Uses default gas_limit=100_000 and value=1000.
pub(crate) fn create_aa_tx_with_gas(
    sender: Address,
    nonce_key: U256,
    nonce: u64,
    max_priority_fee: u128,
    max_fee: u128,
) -> TempoPooledTransaction {
    create_aa_tx_full(
        sender,
        nonce_key,
        nonce,
        100_000,
        U256::from(1000),
        max_priority_fee,
        max_fee,
    )
}

/// Full helper to create an AA transaction with all customizable parameters.
pub(crate) fn create_aa_tx_full(
    sender: Address,
    nonce_key: U256,
    nonce: u64,
    gas_limit: u64,
    value: U256,
    max_priority_fee_per_gas: u128,
    max_fee_per_gas: u128,
) -> TempoPooledTransaction {
    let tx = TempoTransaction {
        chain_id: 1,
        max_priority_fee_per_gas,
        max_fee_per_gas,
        gas_limit,
        calls: vec![Call {
            to: TxKind::Call(Address::random()),
            value,
            input: Default::default(),
        }],
        nonce_key,
        nonce,
        fee_token: None,
        fee_payer_signature: None,
        valid_after: None,
        valid_before: None,
        access_list: Default::default(),
        tempo_authorization_list: vec![],
        key_authorization: None,
    };

    let signature =
        TempoSignature::Primitive(PrimitiveSignature::Secp256k1(Signature::test_signature()));
    let aa_signed = AASigned::new_unhashed(tx, signature);
    let envelope: TempoTxEnvelope = aa_signed.into();

    let recovered = Recovered::new_unchecked(envelope, sender);
    TempoPooledTransaction::new(recovered)
}

/// Helper to wrap a transaction in ValidPoolTransaction.
///
/// Note: Creates a dummy SenderId for testing since the AA2dPool doesn't use it.
pub(crate) fn wrap_valid_tx(
    tx: TempoPooledTransaction,
    origin: TransactionOrigin,
) -> ValidPoolTransaction<TempoPooledTransaction> {
    let tx_id = reth_transaction_pool::identifier::TransactionId::new(0u64.into(), tx.nonce());
    ValidPoolTransaction {
        transaction: tx,
        transaction_id: tx_id,
        propagate: true,
        timestamp: Instant::now(),
        origin,
        authority_ids: None,
    }
}

/// Creates a mock provider configured with the MODERATO chain spec.
pub(crate) fn create_mock_provider()
-> MockEthProvider<reth_ethereum_primitives::EthPrimitives, TempoChainSpec> {
    MockEthProvider::default().with_chain_spec(std::sync::Arc::unwrap_or_clone(MODERATO.clone()))
}
