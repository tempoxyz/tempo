use crate::{
    db::{MdbxPageStore, Watermark},
    page::{PageIndex, page_offset},
    recovery::{PageStateRecoverySource, recover_from_plain_state},
    sentinel,
    smt::{PageSmt, empty_page_root},
    store::{MemoryPageStore, OverlayPageStore, PageStoreError, PageStoreRead},
    updates::PageStateUpdates,
};
use alloy_primitives::{Address, B256, U256, keccak256, map::B256Set};
use reth_revm::db::BundleState;
use reth_trie::HashedPostState;
use std::{
    collections::{BTreeMap, HashMap},
    fmt,
    sync::Arc,
};
use tempo_chainspec::PageAccountPredicate;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum PageStateError {
    #[error(transparent)]
    Store(#[from] PageStoreError),
    #[error("page-state recovery error: {0}")]
    Recovery(String),
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PageBlockOutput {
    pub updates: PageStateUpdates,
    pub trie_input: HashedPostState,
}

#[derive(Clone)]
pub struct PageStateManager {
    base: Arc<dyn PageStoreRead>,
    canonical: Option<MdbxPageStore>,
    in_memory: Arc<std::sync::RwLock<HashMap<B256, InMemoryPageBlock>>>,
    predicate: Option<PageAccountPredicate>,
}

#[derive(Clone, Debug)]
struct InMemoryPageBlock {
    #[allow(dead_code)]
    number: u64,
    #[allow(dead_code)]
    parent_hash: B256,
    #[allow(dead_code)]
    updates: Arc<PageStateUpdates>,
}

impl fmt::Debug for PageStateManager {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PageStateManager")
            .field("canonical", &self.canonical.is_some())
            .field("predicate", &self.predicate)
            .finish_non_exhaustive()
    }
}

impl Default for PageStateManager {
    fn default() -> Self {
        Self {
            base: Arc::new(MemoryPageStore::default()),
            canonical: None,
            in_memory: Arc::default(),
            predicate: None,
        }
    }
}

impl PageStateManager {
    pub fn new_for_tests(db: MemoryPageStore) -> Self {
        Self {
            base: Arc::new(db),
            canonical: None,
            in_memory: Arc::default(),
            predicate: None,
        }
    }

    pub fn new(db: MdbxPageStore, predicate: PageAccountPredicate) -> Self {
        Self {
            base: Arc::new(db.clone()),
            canonical: Some(db),
            in_memory: Arc::default(),
            predicate: Some(predicate),
        }
    }

    pub fn new_ephemeral(db: MemoryPageStore, predicate: PageAccountPredicate) -> Self {
        Self {
            base: Arc::new(db),
            canonical: None,
            in_memory: Arc::default(),
            predicate: Some(predicate),
        }
    }

    pub fn new_with_store(base: Arc<dyn PageStoreRead>, predicate: PageAccountPredicate) -> Self {
        Self {
            base,
            canonical: None,
            in_memory: Arc::default(),
            predicate: Some(predicate),
        }
    }

    pub fn is_active(&self, timestamp: u64) -> bool {
        self.predicate
            .as_ref()
            .is_some_and(|predicate| predicate.is_active(timestamp))
    }

    pub fn store_at(&self, parent_hash: B256) -> OverlayPageStore<'_> {
        let in_memory = self
            .in_memory
            .read()
            .expect("page-state in-memory lock poisoned");
        let mut deltas = Vec::new();
        let mut cursor = parent_hash;
        while let Some(block) = in_memory.get(&cursor) {
            deltas.push(block.updates.clone());
            cursor = block.parent_hash;
        }
        OverlayPageStore::new(self.base.as_ref(), deltas)
    }

    pub fn process_block(
        &self,
        timestamp: u64,
        parent_hash: B256,
        bundle: &BundleState,
        hashed_state: &HashedPostState,
    ) -> Result<PageBlockOutput, PageStateError> {
        let Some(predicate) = &self.predicate else {
            return Ok(PageBlockOutput {
                updates: PageStateUpdates::default(),
                trie_input: hashed_state.clone(),
            });
        };

        let mut dirty_words = BTreeMap::<Address, BTreeMap<PageIndex, BTreeMap<u8, U256>>>::new();
        for (address, account) in &bundle.state {
            if !predicate.is_page_account(timestamp, address) {
                continue;
            }
            for (&slot, value) in &account.storage {
                if slot == U256::from_be_bytes(sentinel::sentinel_slot().0) {
                    continue;
                }
                dirty_words
                    .entry(*address)
                    .or_default()
                    .entry(PageIndex::of_slot(slot))
                    .or_default()
                    .insert(page_offset(slot), value.present_value);
            }
        }

        if dirty_words.is_empty() {
            return Ok(PageBlockOutput {
                updates: PageStateUpdates::default(),
                trie_input: hashed_state.clone(),
            });
        }

        let store = self.store_at(parent_hash);
        let mut updates = PageStateUpdates::default();
        for (address, account_words) in dirty_words {
            let mut dirty_pages = BTreeMap::new();
            for (index, words) in account_words {
                let mut page = store.page(address, index)?.unwrap_or_default();
                for (offset, value) in words {
                    page.set_word(offset, value);
                }
                dirty_pages.insert(index, (!page.is_empty()).then_some(page));
            }

            let account_updates = PageSmt::new(&store, address).update(&dirty_pages)?;
            updates.accounts.insert(address, account_updates);
        }

        let trie_input = build_trie_input(hashed_state, &updates);
        Ok(PageBlockOutput {
            updates,
            trie_input,
        })
    }

    pub fn insert_block(
        &self,
        hash: B256,
        number: u64,
        parent_hash: B256,
        updates: PageStateUpdates,
    ) -> Result<(), PageStoreError> {
        self.in_memory
            .write()
            .expect("page-state in-memory lock poisoned")
            .insert(
                hash,
                InMemoryPageBlock {
                    number,
                    parent_hash,
                    updates: Arc::new(updates),
                },
            );
        Ok(())
    }

    pub fn on_canonical_commit(&self, blocks: &[(u64, B256)]) -> Result<(), PageStoreError> {
        if blocks.is_empty() {
            return Ok(());
        }

        if let Some(db) = &self.canonical {
            for &(number, hash) in blocks {
                let updates = self
                    .in_memory
                    .read()
                    .expect("page-state in-memory lock poisoned")
                    .get(&hash)
                    .map(|block| block.updates.clone())
                    .ok_or(PageStoreError::MissingBlockDelta { number, hash })?;
                db.commit_block(
                    Watermark {
                        block_number: number,
                        block_hash: hash,
                    },
                    &updates,
                )?;
            }
        }

        let watermark = blocks
            .last()
            .map(|(number, _)| *number)
            .expect("blocks is not empty");
        self.in_memory
            .write()
            .expect("page-state in-memory lock poisoned")
            .retain(|_, block| block.number > watermark);
        Ok(())
    }

    pub fn on_reorg(&self, orphaned: &[B256]) {
        let mut in_memory = self
            .in_memory
            .write()
            .expect("page-state in-memory lock poisoned");
        for hash in orphaned {
            in_memory.remove(hash);
        }
    }

    pub fn recover<R>(&self, source: &R) -> Result<crate::RecoveryReport, PageStateError>
    where
        R: PageStateRecoverySource + ?Sized,
    {
        let Some(db) = &self.canonical else {
            return Ok(crate::RecoveryReport::default());
        };

        let tip = source.best_block()?;
        let watermark = db.watermark()?;
        let sidecar_page_keys = if watermark.is_some_and(|wm| wm.block_number > tip.block_number) {
            db.changelog_page_keys_after(tip.block_number)?
        } else {
            Vec::new()
        };
        let (updates, report) =
            recover_from_plain_state(db, source, tip, watermark, sidecar_page_keys)?;
        db.commit_block(tip, &updates)?;
        self.in_memory
            .write()
            .expect("page-state in-memory lock poisoned")
            .clear();
        Ok(report)
    }

    pub fn prove_page(
        &self,
        parent_hash: B256,
        address: Address,
        index: PageIndex,
    ) -> Result<(B256, crate::PageProof), PageStateError> {
        let store = self.store_at(parent_hash);
        let root = store.root(address)?.unwrap_or_else(empty_page_root);
        let proof = PageSmt::new(&store, address).prove(index)?;
        Ok((root, proof))
    }
}

fn build_trie_input(hashed_state: &HashedPostState, updates: &PageStateUpdates) -> HashedPostState {
    if updates.accounts.is_empty() {
        return hashed_state.clone();
    }

    let page_accounts = updates.accounts.keys().map(keccak256).collect::<B256Set>();
    let mut trie_input = HashedPostState {
        accounts: hashed_state.accounts.clone(),
        storages: hashed_state
            .storages
            .iter()
            .filter_map(|(&hashed_address, storage)| {
                (!page_accounts.contains(&hashed_address))
                    .then(|| (hashed_address, storage.clone()))
            })
            .collect(),
    };
    sentinel::apply(&mut trie_input, updates);
    trie_input
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sentinel::sentinel_slot_hashed;
    use alloy_primitives::{B256, U256, address};
    use reth_revm::{db::BundleState, primitives::HashMap};
    use reth_trie::{HashedPostState, KeccakKeyHasher};
    use tempo_chainspec::spec::DEV;

    fn bundle_with_storage(
        address: Address,
        slots: impl IntoIterator<Item = (U256, U256)>,
    ) -> BundleState {
        BundleState::new(
            [(
                address,
                None,
                None,
                HashMap::from_iter(
                    slots
                        .into_iter()
                        .map(|(slot, value)| (slot, (U256::ZERO, value))),
                ),
            )],
            std::iter::empty::<[(Address, Option<Option<_>>, [(U256, U256); 0]); 0]>(),
            std::iter::empty::<(B256, _)>(),
        )
    }

    #[test]
    fn process_block_rewrites_page_account_to_sentinel() {
        let address = address!("0x20c0000000000000000000000000000000000001");
        let bundle = bundle_with_storage(address, [(U256::from(7), U256::from(42))]);
        let hashed_state =
            HashedPostState::from_bundle_state::<KeccakKeyHasher>(bundle.state.iter());
        let original_hashed = hashed_state.clone();
        let manager = PageStateManager::new_ephemeral(
            MemoryPageStore::default(),
            PageAccountPredicate::new(DEV.clone()),
        );

        let output = manager
            .process_block(0, B256::ZERO, &bundle, &hashed_state)
            .unwrap();

        assert_eq!(output.updates.accounts.len(), 1);
        assert_eq!(hashed_state, original_hashed);
        let hashed_address = alloy_primitives::keccak256(address);
        let original_storage = hashed_state.storages.get(&hashed_address).unwrap();
        assert!(original_storage.storage.len() > 1 || !original_storage.wiped);
        let storage = output.trie_input.storages.get(&hashed_address).unwrap();
        assert!(storage.wiped);
        assert_eq!(storage.storage.len(), 1);
        assert!(storage.storage.contains_key(&sentinel_slot_hashed()));
        assert!(
            !bundle.state[&address]
                .storage
                .contains_key(&U256::from_be_bytes(sentinel::sentinel_slot().0))
        );
    }

    #[test]
    fn process_block_leaves_non_page_account_storage_untouched() {
        let address = address!("0x1111111111111111111111111111111111111111");
        let bundle = bundle_with_storage(address, [(U256::from(7), U256::from(42))]);
        let original_hashed =
            HashedPostState::from_bundle_state::<KeccakKeyHasher>(bundle.state.iter());
        let hashed_state = original_hashed.clone();
        let manager = PageStateManager::new_ephemeral(
            MemoryPageStore::default(),
            PageAccountPredicate::new(DEV.clone()),
        );

        let output = manager
            .process_block(0, B256::ZERO, &bundle, &hashed_state)
            .unwrap();

        assert!(output.updates.is_empty());
        assert_eq!(hashed_state, original_hashed);
        assert_eq!(output.trie_input, original_hashed);
    }
}
