//! State and history read views consumed by invariant checks.

use serde::{Deserialize, Serialize};

use crate::{
    evidence::EvidenceValue,
    facts::{BlockNumHash, FactValue},
};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum StateBoundary {
    Parent,
    Current,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct StateReadKey {
    pub boundary: StateBoundary,
    pub table: String,
    pub key: String,
}

pub type StateReadValue = FactValue<EvidenceValue>;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct StateReadView {
    pub boundary: StateBoundary,
    pub block: BlockNumHash,
    pub reads: Vec<(StateReadKey, StateReadValue)>,
    pub complete: bool,
    pub notes: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct HistoryKey {
    pub namespace: String,
    pub key: String,
}

pub type HistoryValue = FactValue<EvidenceValue>;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct HistoryView {
    pub block: BlockNumHash,
    pub reads: Vec<(HistoryKey, HistoryValue)>,
    pub complete: bool,
    pub notes: Vec<String>,
}
