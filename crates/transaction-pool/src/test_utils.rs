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

/// Builder for creating test transactions.
///
/// Supports building both EIP-1559 and AA transactions with a fluent API.
///
/// # Examples
///
/// ```ignore
/// // Create a simple AA transaction
/// let tx = TxBuilder::aa(sender).build();
///
/// // Create an AA transaction with custom nonce key and nonce
/// let tx = TxBuilder::aa(sender)
///     .nonce_key(U256::from(1))
///     .nonce(5)
///     .build();
///
/// // Create an EIP-1559 transaction
/// let tx = TxBuilder::eip1559(to_address).build();
/// ```
#[derive(Debug, Clone)]
pub(crate) struct TxBuilder {
    kind: TxKind,
    sender: Address,
    nonce_key: U256,
    nonce: u64,
    gas_limit: u64,
    value: U256,
    max_priority_fee_per_gas: u128,
    max_fee_per_gas: u128,
    fee_token: Option<Address>,
    valid_after: Option<u64>,
    valid_before: Option<u64>,
    chain_id: u64,
    /// Custom calls for AA transactions. If None, a default call is created from `kind` and `value`.
    calls: Option<Vec<Call>>,
}

impl Default for TxBuilder {
    fn default() -> Self {
        Self {
            kind: TxKind::Call(Address::random()),
            sender: Address::random(),
            nonce_key: U256::ZERO,
            nonce: 0,
            gas_limit: 1_000_000,
            value: U256::ZERO,
            max_priority_fee_per_gas: 1_000_000_000,
            max_fee_per_gas: 2_000_000_000,
            fee_token: None,
            valid_after: None,
            valid_before: None,
            chain_id: 42431, // MODERATO chain_id
            calls: None,
        }
    }
}

impl TxBuilder {
    /// Create a builder for an AA transaction with the given sender.
    pub(crate) fn aa(sender: Address) -> Self {
        Self {
            sender,
            ..Default::default()
        }
    }

    /// Create a builder for an EIP-1559 transaction to the given address.
    pub(crate) fn eip1559(to: Address) -> Self {
        Self {
            kind: TxKind::Call(to),
            ..Default::default()
        }
    }

    /// Set the nonce key (AA transactions only).
    pub(crate) fn nonce_key(mut self, nonce_key: U256) -> Self {
        self.nonce_key = nonce_key;
        self
    }

    /// Set the transaction nonce.
    pub(crate) fn nonce(mut self, nonce: u64) -> Self {
        self.nonce = nonce;
        self
    }

    /// Set the gas limit.
    pub(crate) fn gas_limit(mut self, gas_limit: u64) -> Self {
        self.gas_limit = gas_limit;
        self
    }

    /// Set the transaction value.
    pub(crate) fn value(mut self, value: U256) -> Self {
        self.value = value;
        self
    }

    /// Set the max priority fee per gas.
    pub(crate) fn max_priority_fee(mut self, fee: u128) -> Self {
        self.max_priority_fee_per_gas = fee;
        self
    }

    /// Set the max fee per gas.
    pub(crate) fn max_fee(mut self, fee: u128) -> Self {
        self.max_fee_per_gas = fee;
        self
    }

    /// Set the fee token (AA transactions only).
    pub(crate) fn fee_token(mut self, fee_token: Address) -> Self {
        self.fee_token = Some(fee_token);
        self
    }

    /// Set the valid_after timestamp (AA transactions only).
    pub(crate) fn valid_after(mut self, valid_after: u64) -> Self {
        self.valid_after = Some(valid_after);
        self
    }

    /// Set the valid_before timestamp (AA transactions only).
    pub(crate) fn valid_before(mut self, valid_before: u64) -> Self {
        self.valid_before = Some(valid_before);
        self
    }

    /// Set custom calls for the AA transaction.
    /// If not set, a default call is created from `kind` and `value`.
    pub(crate) fn calls(mut self, calls: Vec<Call>) -> Self {
        self.calls = Some(calls);
        self
    }

    /// Build an AA transaction.
    pub(crate) fn build(self) -> TempoPooledTransaction {
        let calls = self.calls.unwrap_or_else(|| {
            vec![Call {
                to: self.kind,
                value: self.value,
                input: Default::default(),
            }]
        });

        let tx = TempoTransaction {
            chain_id: 1,
            max_priority_fee_per_gas: self.max_priority_fee_per_gas,
            max_fee_per_gas: self.max_fee_per_gas,
            gas_limit: self.gas_limit,
            calls,
            nonce_key: self.nonce_key,
            nonce: self.nonce,
            fee_token: self.fee_token,
            fee_payer_signature: None,
            valid_after: self.valid_after,
            valid_before: self.valid_before,
            access_list: Default::default(),
            tempo_authorization_list: vec![],
            key_authorization: None,
        };

        let signature =
            TempoSignature::Primitive(PrimitiveSignature::Secp256k1(Signature::test_signature()));
        let aa_signed = AASigned::new_unhashed(tx, signature);
        let envelope: TempoTxEnvelope = aa_signed.into();

        let recovered = Recovered::new_unchecked(envelope, self.sender);
        TempoPooledTransaction::new(recovered)
    }

    /// Build an EIP-1559 transaction.
    pub(crate) fn build_eip1559(self) -> TempoPooledTransaction {
        let tx = TxEip1559 {
            chain_id: self.chain_id,
            to: self.kind,
            gas_limit: self.gas_limit,
            value: self.value,
            max_fee_per_gas: self.max_fee_per_gas,
            max_priority_fee_per_gas: self.max_priority_fee_per_gas,
            ..Default::default()
        };

        let envelope = TempoTxEnvelope::Eip1559(alloy_consensus::Signed::new_unchecked(
            tx,
            Signature::test_signature(),
            B256::ZERO,
        ));

        let recovered = Recovered::new_unchecked(envelope, self.sender);
        TempoPooledTransaction::new(recovered)
    }
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
