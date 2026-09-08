//! State and history read views consumed by invariant checks.

use serde::{Deserialize, Serialize};

use crate::{
    diagnostics::evidence::EvidenceValue,
    input::facts::{BlockNumHash, FactValue},
};

/// State boundary used for a monitor state read.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum StateBoundary {
    /// Parent state before the current block.
    Parent,
    /// Current state after applying the current block.
    Current,
}

/// Key for one state read consumed by an invariant check.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct StateReadKey {
    pub boundary: StateBoundary,
    pub table: String,
    pub key: String,
}

/// Value returned by a monitor state read.
pub type StateReadValue = FactValue<EvidenceValue>;

/// Collection of state reads for a block/boundary.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct StateReadView {
    pub boundary: StateBoundary,
    pub block: BlockNumHash,
    pub reads: Vec<(StateReadKey, StateReadValue)>,
    pub complete: bool,
    pub notes: Vec<String>,
}

/// Key for one historical monitor read.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct HistoryKey {
    pub namespace: String,
    pub key: String,
}

/// Value returned by a historical monitor read.
pub type HistoryValue = FactValue<EvidenceValue>;

/// Collection of historical reads for a block.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct HistoryView {
    pub block: BlockNumHash,
    pub reads: Vec<(HistoryKey, HistoryValue)>,
    pub complete: bool,
    pub notes: Vec<String>,
}
