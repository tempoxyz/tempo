//! Normalized finalized-block facts owned by the tempo monitor.

use alloy_consensus::Transaction;
pub use alloy_eips::{BlockNumHash, eip1898::BlockWithParent};
use alloy_primitives::{Address, B256, Bytes, TxKind, U256};
use serde::{Deserialize, Serialize};
use std::num::NonZeroU64;
use tempo_contracts::precompiles::ITIP20;
use tempo_hardfork::TempoHardfork;
use tempo_primitives::{
    TempoConsensusContext, TempoHeader, TempoReceipt, TempoTxEnvelope, TempoTxType,
    transaction::TEMPO_EXPIRING_NONCE_KEY,
};

/// A normalized fact value that may be unavailable or not applicable.
///
/// `Missing`: unable to derive a trusted value for this field. Checks that require a missing fact
///  must NOT pass. Instead, they should produce inconclusive, degraded, or error coverage.
///
/// `NotNeeded`: the field is intentionally not applicable for this record or check input.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum FactValue<T> {
    /// The value was derived and is trusted for check evaluation.
    Available(T),
    /// The value is required or relevant but could not be derived reliably.
    Missing { reason: String },
    /// The value is intentionally not applicable in this context.
    NotNeeded,
}

/// Normalized finalized-block facts used by invariant checks and store commits.
///
/// This contains only monitor-owned projections plus canonical Alloy/Tempo primitive values.
/// It must not contain Reth provider, notification, block, or receipt types.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlockFacts {
    pub reference: BlockWithParent,
    pub hardfork: TempoHardfork,
    pub header: HeaderFacts,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct HeaderFacts {
    pub timestamp: u64,
    pub timestamp_millis: u64,
    pub gas_used: u64,
    pub gas_limit: u64,
    pub general_gas_limit: u64,
    pub shared_gas_limit: u64,
    pub base_fee_per_gas: Option<u64>,
    pub beneficiary: Address,
    pub consensus_context: Option<TempoConsensusContext>,
}

impl From<&TempoHeader> for HeaderFacts {
    fn from(header: &TempoHeader) -> Self {
        Self {
            timestamp: header.inner.timestamp,
            timestamp_millis: header.timestamp_millis(),
            gas_used: header.inner.gas_used,
            gas_limit: header.inner.gas_limit,
            general_gas_limit: header.general_gas_limit,
            shared_gas_limit: header.shared_gas_limit,
            base_fee_per_gas: header.inner.base_fee_per_gas,
            beneficiary: header.inner.beneficiary,
            consensus_context: header.consensus_context,
        }
    }
}

/// Pure projection from a canonical `TempoTxEnvelope`.
///
/// `primary_action` is the transaction kind exposed by the canonical transaction trait.
/// For Tempo transactions represents the first call kind, not a complete list of all calls.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TxEnvelopeFacts {
    pub tx_type: TempoTxType,
    pub action: TxKind,
    pub gas_limit: u64,
    pub nonce: u64,
    pub value: U256,
    pub nonce_key: Option<U256>,
    pub valid_before: Option<NonZeroU64>,
    pub valid_after: Option<NonZeroU64>,
    pub fee_token: Option<Address>,
}

impl From<&TempoTxEnvelope> for TxEnvelopeFacts {
    fn from(tx: &TempoTxEnvelope) -> Self {
        let tempo_tx = tx.as_aa();

        Self {
            tx_type: tx.tx_type(),
            action: match tx.to() {
                Some(to) => TxKind::Call(to),
                None => TxKind::Create,
            },
            gas_limit: tx.gas_limit(),
            nonce: tx.nonce(),
            value: tx.value(),
            nonce_key: tempo_tx.map(|signed| signed.tx().nonce_key),
            valid_before: tempo_tx.and_then(|signed| signed.tx().valid_before),
            valid_after: tempo_tx.and_then(|signed| signed.tx().valid_after),
            fee_token: tempo_tx.and_then(|signed| signed.tx().fee_token),
        }
    }
}

impl TxEnvelopeFacts {
    pub fn is_expiring_nonce(&self) -> bool {
        self.nonce_key == Some(TEMPO_EXPIRING_NONCE_KEY)
    }
}

/// Contextual transaction facts for a transaction included in a finalized block.
///
/// `sender`, `fee_payer`, and `unique_intent` are `FactValue`s because recovery can fail or inputs
/// can be unavailable. Checks that depend on them must fail closed when they are `Missing`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TxFacts {
    pub block: BlockNumHash,
    pub tx_index: u64,
    pub tx_hash: B256,
    pub is_system: bool,
    pub envelope: TxEnvelopeFacts,
    pub sender: FactValue<Address>,
    pub fee_payer: FactValue<Address>,
    pub unique_intent: FactValue<B256>,
}

/// Contextual receipt facts for a finalized transaction.
///
/// `gas_used` is fallible because it is derived from cumulative gas. If cumulative gas is
/// non-monotonic, the value is recorded as `Missing` instead of being saturated or trusted.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReceiptFacts {
    pub block: BlockNumHash,
    pub tx_hash: B256,
    pub tx_index: u64,
    pub success: bool,
    pub gas_used: FactValue<u64>,
    pub cumulative_gas_used: u64,
}

impl ReceiptFacts {
    pub fn from_tempo_receipt(
        block: BlockNumHash,
        tx_hash: B256,
        tx_index: u64,
        receipt: &TempoReceipt,
        previous_cumulative_gas_used: u64,
    ) -> Self {
        let gas_used = receipt
            .cumulative_gas_used
            .checked_sub(previous_cumulative_gas_used)
            .map_or_else(
                || FactValue::Missing {
                    reason: format!(
                        "receipt cumulative gas regressed: previous={previous_cumulative_gas_used} current={}",
                        receipt.cumulative_gas_used
                    ),
                },
                FactValue::Available,
            );

        Self {
            block,
            tx_hash,
            tx_index,
            success: receipt.success,
            gas_used,
            cumulative_gas_used: receipt.cumulative_gas_used,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OrderedLog {
    pub block: BlockNumHash,
    pub tx_hash: B256,
    pub tx_index: u64,
    pub log_index: u64,
    pub emitter: Address,
    pub topics: Vec<B256>,
    pub data: Bytes,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum DecodedEventKind {
    Tip20Transfer(ITIP20::Transfer),
    Unknown { topic0: Option<B256> },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DecodedEvent {
    pub source: OrderedLog,
    pub kind: DecodedEventKind,
}
