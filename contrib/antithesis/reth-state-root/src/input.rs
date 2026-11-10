//! Explicit trie-task operation stream. Only `Commit` ends a block.

use crate::model::{apply, generate, random_address, random_slot, Model, Update};
use alloy_primitives::{Address, KECCAK256_EMPTY, U256};
use antithesis_sdk::random::AntithesisRng;
use antithesis_trie_shapes::Collider;
use eyre::{ensure, Result};
use rand_09::{seq::SliceRandom, Rng};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Input {
    pub operations: Vec<Operation>,
}

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

impl Input {
    pub(crate) fn generate(blocks: u64, updates: usize) -> Self {
        let mut state = Model::default();
        let mut collider = Collider::default();
        let mut operations = Vec::new();
        for number in 1..=blocks {
            // Draw from Antithesis directly so each explored branch can choose different work.
            let mut rng = AntithesisRng;
            let generated = generate(&mut rng, &state, &mut collider, updates);
            apply(&mut state, number, &generated);
            // Hint only a subset of writes, then add unrelated reads. This exercises both
            // warmed and cold trie paths rather than making every hint predict a write.
            let mut targets = generated
                .iter()
                .map(|update| match update {
                    Update::Account { address, .. } => (*address, None),
                    Update::Storage { address, slot, .. } => (*address, Some(*slot)),
                })
                .collect::<Vec<_>>();
            targets.shuffle(&mut rng);
            let count =
                if targets.len() > 1 { rng.random_range(1..targets.len()) } else { targets.len() };
            targets.truncate(count);
            for _ in 0..rng.random_range(1..=8) {
                let address = random_address(&mut rng);
                let slot = rng.random_bool(0.5).then(|| random_slot(&mut rng));
                targets.push((address, slot));
            }
            targets.shuffle(&mut rng);
            let mut targets = targets.into_iter().peekable();
            let mut updates = generated.into_iter().peekable();
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
                    operations.push(Operation::UpdateBatch {
                        updates: updates.by_ref().take(size).collect(),
                    });
                }
            }
            operations.push(Operation::Commit);
        }
        Self { operations }
    }

    pub(crate) fn validate(&self) -> Result<()> {
        // Account existence survives commits; the update budget resets per block.
        // Validate before any operation reaches production trie workers.
        let mut accounts = BTreeSet::new();
        let mut blocks = 0;
        let mut block_updates = 0;
        for operation in &self.operations {
            match operation {
                Operation::UpdateBatch { updates } => {
                    ensure!(!updates.is_empty(), "empty update batch");
                    block_updates += updates.len();
                    ensure!(block_updates <= 4096, "block needs at most 4096 updates");
                    for update in updates {
                        match update {
                            Update::Account { address, account } => {
                                ensure!(!account.is_empty(), "empty account: {address}");
                                ensure!(
                                    account.bytecode_hash != Some(KECCAK256_EMPTY),
                                    "noncanonical empty code hash: {address}"
                                );
                                accounts.insert(*address);
                            }
                            Update::Storage { address, .. } => {
                                ensure!(
                                    accounts.contains(address),
                                    "storage before account creation: {address}"
                                );
                            }
                        }
                    }
                }
                Operation::PrewarmBatch { accounts, storages } => {
                    ensure!(!accounts.is_empty() || !storages.is_empty(), "empty prewarm batch");
                }
                Operation::Commit => {
                    ensure!(block_updates > 0, "commit without updates");
                    blocks += 1;
                    ensure!(blocks <= 1024, "input needs at most 1024 commits");
                    block_updates = 0;
                }
            }
        }
        ensure!(
            matches!(self.operations.last(), Some(Operation::Commit)),
            "input must end with a commit"
        );
        Ok(())
    }
}
