//! Explicit trie-task operation stream. Only `Commit` ends a block.

use crate::model::{random_address, random_slot, Update};
use alloy_primitives::{Address, U256};
use rand_09::{seq::SliceRandom, Rng};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct StorageHint {
    pub address: Address,
    pub slot: U256,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub(crate) enum Operation {
    UpdateBatch {
        updates: Vec<Update>,
    },
    PrewarmBatch {
        accounts: Vec<Address>,
        storages: Vec<StorageHint>,
    },
    /// End the block; the driver finishes its update stream and checks the resulting root.
    Commit,
}

/// One block's operations: the updates in order, in batches of 1 to 16, interleaved with prewarm
/// hints.
pub(crate) fn operations(rng: &mut impl Rng, updates: Vec<Update>) -> Vec<Operation> {
    // Hint only a subset of writes, then add unrelated reads. This exercises both
    // warmed and cold trie paths rather than making every hint predict a write.
    let mut targets = updates
        .iter()
        .map(|update| match update {
            Update::Account { address, .. } => (*address, None),
            Update::Storage { address, slot, .. } => (*address, Some(*slot)),
        })
        .collect::<Vec<_>>();
    targets.shuffle(rng);
    let count = if targets.len() > 1 { rng.random_range(1..targets.len()) } else { targets.len() };
    targets.truncate(count);
    for _ in 0..rng.random_range(1..=8) {
        let address = random_address(rng);
        let slot = rng.random_bool(0.5).then(|| random_slot(rng));
        targets.push((address, slot));
    }
    targets.shuffle(rng);
    let mut operations = Vec::new();
    let mut targets = targets.into_iter().peekable();
    let mut updates = updates.into_iter().peekable();
    // Keep write order intact while interleaving independently sized hint batches.
    while targets.peek().is_some() || updates.peek().is_some() {
        if targets.peek().is_some() && (updates.peek().is_none() || rng.random_bool(0.5)) {
            let size = rng.random_range(1..=targets.len().min(16));
            let mut accounts = Vec::new();
            let mut storages = Vec::new();
            for (address, slot) in targets.by_ref().take(size) {
                match slot {
                    Some(slot) => storages.push(StorageHint { address, slot }),
                    None => accounts.push(address),
                }
            }
            operations.push(Operation::PrewarmBatch { accounts, storages });
        } else {
            let size = rng.random_range(1..=updates.len().min(16));
            operations
                .push(Operation::UpdateBatch { updates: updates.by_ref().take(size).collect() });
        }
    }
    operations.push(Operation::Commit);
    operations
}
