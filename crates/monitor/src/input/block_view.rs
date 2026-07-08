//! Immutable monitor-facing view consumed by invariant checks.

use crate::{
    diagnostics::coverage::CoverageRecord,
    entity::DirtyEntity,
    input::{
        facts::{BlockFacts, DecodedEvent, OrderedLog, ReceiptFacts, TxFacts},
        state_view::{HistoryView, StateReadView},
    },
};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReplayFacts {
    pub available: bool,
    pub notes: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlockView {
    pub block: BlockFacts,
    pub txs: Vec<TxFacts>,
    pub receipts: Vec<ReceiptFacts>,
    pub logs: Vec<OrderedLog>,
    pub decoded_events: Vec<DecodedEvent>,
    pub dirty_entities: Vec<DirtyEntity>,
    pub current_state: StateReadView,
    pub parent_state: StateReadView,
    pub history: HistoryView,
    pub coverage: Vec<CoverageRecord>,
    pub replay: Option<ReplayFacts>,
}
