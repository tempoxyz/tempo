//! Evidence references, values, and structured check evidence.

use alloy_primitives::{Address, B256, Bytes, U256};
use serde::{Deserialize, Serialize};

use crate::{
    diagnostics::coverage::CoverageRecord,
    entity::EntityKey,
    input::{
        facts::{BlockNumHash, BlockWithParent},
        state_view::StateReadKey,
    },
    invariants::meta::InvariantId,
};

/// Reference to chain data supporting a check result.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum EvidenceRef {
    /// Whole-block reference.
    Block(BlockNumHash),
    /// Transaction reference.
    Tx {
        /// Block containing the transaction.
        block: BlockNumHash,
        /// Transaction hash.
        tx_hash: B256,
        /// Transaction index in the block.
        tx_index: u64,
    },
    /// Log reference.
    Log {
        /// Block containing the log.
        block: BlockNumHash,
        /// Transaction hash containing the log.
        tx_hash: B256,
        /// Log index in the transaction/block context.
        log_index: u64,
    },
}

/// Serializable value captured as evidence.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum EvidenceValue {
    /// Boolean value.
    Bool(bool),
    /// String value.
    String(String),
    /// Address value.
    Address(Address),
    /// 256-bit hash value.
    Hash(B256),
    /// Unsigned integer value.
    Uint(U256),
    /// Signed integer value.
    Int(i128),
    /// Byte string value.
    Bytes(Bytes),
    /// Structured JSON value.
    Json(serde_json::Value),
}

/// Named observed value used in violation reports.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ObservedValue {
    pub label: String,
    pub value: EvidenceValue,
}

/// Expected invariant condition used in violation reports.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExpectedValue {
    pub label: String,
    pub condition: String,
}

/// Structured evidence item attached to a check result.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum EvidenceItem {
    /// State read used by the check.
    StateRead(StateReadKey),
    /// Chain object reference.
    ChainRef(EvidenceRef),
    /// Human-readable note.
    Note(String),
    /// Standalone typed value.
    Value(EvidenceValue),
    /// Additional structured evidence.
    Json(serde_json::Value),
}

/// Structured evidence for an invariant violation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ViolationEvidence {
    pub invariant_id: InvariantId,
    pub block: BlockWithParent,
    pub entity: Option<EntityKey>,
    pub expected: ExpectedValue,
    pub observed: Vec<ObservedValue>,
    pub items: Vec<EvidenceItem>,
    pub coverage: CoverageRecord,
}
