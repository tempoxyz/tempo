//! Semantic action log and resolver types.

pub mod fee_manager;
pub mod nonce;
pub mod production;
pub mod resolver;
pub mod semantic_read;
pub mod slots;
pub mod tip20;

use crate::blockstm::{
    action::{
        fee_manager::CollectedFeesDelta, nonce::ExpiringNonceUse,
        semantic_read::SemanticPrefixRead, tip20::Tip20FeeEscrowDelta, tip20::Tip20TransferDelta,
    },
    rw_set::BlockStmAccessKey,
};

/// Resource touched by a semantic action.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum BlockStmResource {
    ExpiringNonce,
    Tip20Balance,
    Tip20FeeEscrow,
    CollectedFees,
    SemanticRead,
    Unknown,
}

/// One ordered semantic action captured from real validation/execution.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlockStmAction {
    pub tx_index: usize,
    pub op_index: u32,
    pub resource: BlockStmResource,
    pub kind: BlockStmActionKind,
    pub covered_storage_slots: Vec<BlockStmAccessKey>,
}

/// Typed semantic action payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BlockStmActionKind {
    ExpiringNonceUse(ExpiringNonceUse),
    Tip20FeeEscrowDelta(Tip20FeeEscrowDelta),
    Tip20TransferDelta(Tip20TransferDelta),
    CollectedFeesDelta(CollectedFeesDelta),
    SemanticPrefixRead(SemanticPrefixRead),
    Barrier,
}

impl BlockStmAction {
    /// Creates an action with the canonical resource for `kind`.
    pub fn new(
        tx_index: usize,
        op_index: u32,
        kind: BlockStmActionKind,
        covered_storage_slots: Vec<BlockStmAccessKey>,
    ) -> Self {
        let resource = kind.resource();
        Self {
            tx_index,
            op_index,
            resource,
            kind,
            covered_storage_slots,
        }
    }
}

impl BlockStmActionKind {
    /// Returns the canonical resource touched by this action.
    pub const fn resource(&self) -> BlockStmResource {
        match self {
            Self::ExpiringNonceUse(_) => BlockStmResource::ExpiringNonce,
            Self::Tip20FeeEscrowDelta(_) => BlockStmResource::Tip20FeeEscrow,
            Self::Tip20TransferDelta(_) => BlockStmResource::Tip20Balance,
            Self::CollectedFeesDelta(_) => BlockStmResource::CollectedFees,
            Self::SemanticPrefixRead(_) => BlockStmResource::SemanticRead,
            Self::Barrier => BlockStmResource::Unknown,
        }
    }
}

/// Ordered action log for one block.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct BlockStmActionLog {
    actions: Vec<BlockStmAction>,
}

impl BlockStmActionLog {
    /// Appends an action.
    pub fn push(&mut self, action: BlockStmAction) {
        self.actions.push(action);
    }

    /// Returns actions in recorded order.
    pub fn actions(&self) -> &[BlockStmAction] {
        &self.actions
    }

    /// Counts actions for a resource.
    pub fn count_resource(&self, resource: BlockStmResource) -> usize {
        self.actions
            .iter()
            .filter(|action| action.resource == resource)
            .count()
    }

    /// Returns true when `key` is covered by at least one semantic action.
    pub fn covers_storage_key(&self, key: &BlockStmAccessKey) -> bool {
        self.actions.iter().any(|action| {
            action
                .covered_storage_slots
                .iter()
                .any(|covered| covered == key)
        })
    }
}
