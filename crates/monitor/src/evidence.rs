//! Evidence references, values, and structured check evidence.

use alloy_primitives::{Address, B256, Bytes, U256};
use serde::{Deserialize, Serialize};

use crate::{
    coverage::CoverageRecord,
    entity::EntityKey,
    facts::{BlockNumHash, BlockWithParent},
    invariants::meta::InvariantId,
    state_view::StateReadKey,
};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum EvidenceRef {
    Block(BlockNumHash),
    Tx {
        block: BlockNumHash,
        tx_hash: B256,
        tx_index: u64,
    },
    Log {
        block: BlockNumHash,
        tx_hash: B256,
        log_index: u64,
    },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum EvidenceValue {
    Bool(bool),
    String(String),
    Address(Address),
    Hash(B256),
    Uint(U256),
    Int(i128),
    Bytes(Bytes),
    Json(serde_json::Value),
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ObservedValue {
    pub label: String,
    pub value: EvidenceValue,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExpectedValue {
    pub label: String,
    pub condition: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum EvidenceItem {
    StateRead(StateReadKey),
    ChainRef(EvidenceRef),
    Note(String),
    Value(EvidenceValue),
    Json(serde_json::Value),
}

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
