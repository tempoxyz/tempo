use crate::{
    db::Watermark,
    manager::PageStateError,
    page::{Page, PageIndex},
    sentinel,
    smt::PageSmt,
    store::{PageStoreRead, PageStoreScan},
    updates::PageStateUpdates,
};
use alloy_primitives::{Address, B256};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RecoveryPageKey {
    pub address: Address,
    pub index: PageIndex,
}

impl RecoveryPageKey {
    pub const fn new(address: Address, index: PageIndex) -> Self {
        Self { address, index }
    }
}

/// Plain-state read view used to rebuild the derived page-state sidecar.
pub trait PageStateRecoverySource {
    fn best_block(&self) -> Result<Watermark, PageStateError>;

    /// Returns page keys touched by reth storage changesets over `(from_exclusive, to_inclusive]`.
    fn changed_page_keys(
        &self,
        from_exclusive: u64,
        to_inclusive: u64,
    ) -> Result<Vec<RecoveryPageKey>, PageStateError>;

    /// Returns every page account with plain storage at the current provider tip.
    fn page_accounts(&self) -> Result<Vec<Address>, PageStateError>;

    /// Rebuilds one page from plain storage at the current provider tip.
    fn page(&self, address: Address, index: PageIndex) -> Result<Option<Page>, PageStateError>;

    /// Rebuilds all non-empty pages for one page account from plain storage at the current
    /// provider tip.
    fn account_pages(&self, address: Address) -> Result<BTreeMap<PageIndex, Page>, PageStateError>;

    /// Reads the sentinel root from plain storage for self-checking. A missing sentinel is allowed
    /// only for pre-activation/bootstrap callers that have not written the anchor yet.
    fn sentinel_root(&self, address: Address) -> Result<Option<B256>, PageStateError>;
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct RecoveryReport {
    pub pages_rebuilt: usize,
    pub accounts_rebuilt_full: usize,
}

pub fn recover_from_plain_state<S, R>(
    store: &S,
    source: &R,
    tip: Watermark,
    watermark: Option<Watermark>,
    sidecar_page_keys: impl IntoIterator<Item = RecoveryPageKey>,
) -> Result<(PageStateUpdates, RecoveryReport), PageStateError>
where
    S: PageStoreRead + PageStoreScan + ?Sized,
    R: PageStateRecoverySource + ?Sized,
{
    let mut updates = PageStateUpdates::default();
    let mut report = RecoveryReport::default();

    if watermark.is_none() {
        for address in sorted_addresses(source.page_accounts()?) {
            rebuild_full_account(store, source, address, &mut updates, &mut report)?;
        }
        return Ok((updates, report));
    }

    let watermark = watermark.expect("watermark checked above");
    let mut suspect_keys = BTreeSet::new();
    if watermark.block_number < tip.block_number {
        suspect_keys.extend(source.changed_page_keys(watermark.block_number, tip.block_number)?);
    }
    suspect_keys.extend(sidecar_page_keys);

    let mut by_account = BTreeMap::<Address, BTreeSet<PageIndex>>::new();
    for key in suspect_keys {
        by_account.entry(key.address).or_default().insert(key.index);
    }

    for (address, indices) in by_account {
        let mut dirty_pages = BTreeMap::new();
        for index in indices {
            dirty_pages.insert(index, source.page(address, index)?);
        }

        let account_updates = PageSmt::new(store, address).update(&dirty_pages)?;
        if sentinel_matches(source, address, account_updates.new_root)? {
            report.pages_rebuilt += account_updates.pages.len();
            updates.accounts.insert(address, account_updates);
        } else {
            rebuild_full_account(store, source, address, &mut updates, &mut report)?;
        }
    }

    Ok((updates, report))
}

fn rebuild_full_account<S, R>(
    store: &S,
    source: &R,
    address: Address,
    updates: &mut PageStateUpdates,
    report: &mut RecoveryReport,
) -> Result<(), PageStateError>
where
    S: PageStoreRead + PageStoreScan + ?Sized,
    R: PageStateRecoverySource + ?Sized,
{
    let source_pages = source.account_pages(address)?;
    let mut dirty_pages = source_pages
        .iter()
        .map(|(&index, page)| (index, Some(page.clone())))
        .collect::<BTreeMap<_, _>>();

    for existing_index in store.page_indices(address)? {
        dirty_pages.entry(existing_index).or_insert(None);
    }

    let account_updates = PageSmt::new(store, address).update(&dirty_pages)?;
    if !sentinel_matches(source, address, account_updates.new_root)? {
        let expected = source.sentinel_root(address)?;
        return Err(PageStateError::Recovery(format!(
            "rebuilt page root for {address} does not match sentinel {}: expected {:?}, got {}",
            sentinel::sentinel_slot(),
            expected,
            account_updates.new_root
        )));
    }

    report.pages_rebuilt += account_updates.pages.len();
    report.accounts_rebuilt_full += 1;
    updates.accounts.insert(address, account_updates);
    Ok(())
}

fn sentinel_matches<R>(source: &R, address: Address, root: B256) -> Result<bool, PageStateError>
where
    R: PageStateRecoverySource + ?Sized,
{
    Ok(source
        .sentinel_root(address)?
        .is_none_or(|expected| expected == root))
}

fn sorted_addresses(addresses: Vec<Address>) -> Vec<Address> {
    let mut addresses = addresses;
    addresses.sort_unstable();
    addresses.dedup();
    addresses
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{store::MemoryPageStore, updates::AccountPageUpdates};
    use alloy_primitives::{U256, address};

    struct TestRecoverySource {
        tip: Watermark,
        pages: BTreeMap<Address, BTreeMap<PageIndex, Page>>,
        changed: Vec<RecoveryPageKey>,
        sentinels: BTreeMap<Address, B256>,
    }

    impl Default for TestRecoverySource {
        fn default() -> Self {
            Self {
                tip: Watermark {
                    block_number: 0,
                    block_hash: B256::ZERO,
                },
                pages: BTreeMap::default(),
                changed: Vec::new(),
                sentinels: BTreeMap::default(),
            }
        }
    }

    impl PageStateRecoverySource for TestRecoverySource {
        fn best_block(&self) -> Result<Watermark, PageStateError> {
            Ok(self.tip)
        }

        fn changed_page_keys(
            &self,
            _from_exclusive: u64,
            _to_inclusive: u64,
        ) -> Result<Vec<RecoveryPageKey>, PageStateError> {
            Ok(self.changed.clone())
        }

        fn page_accounts(&self) -> Result<Vec<Address>, PageStateError> {
            Ok(self.pages.keys().copied().collect())
        }

        fn page(&self, address: Address, index: PageIndex) -> Result<Option<Page>, PageStateError> {
            Ok(self
                .pages
                .get(&address)
                .and_then(|pages| pages.get(&index))
                .cloned())
        }

        fn account_pages(
            &self,
            address: Address,
        ) -> Result<BTreeMap<PageIndex, Page>, PageStateError> {
            Ok(self.pages.get(&address).cloned().unwrap_or_default())
        }

        fn sentinel_root(&self, address: Address) -> Result<Option<B256>, PageStateError> {
            Ok(self.sentinels.get(&address).copied())
        }
    }

    #[test]
    fn full_recovery_builds_from_plain_pages() {
        let address = address!("0x20c0000000000000000000000000000000000001");
        let index = PageIndex::new(U256::ZERO);
        let page = Page::from_iter([(3, U256::from(42))]);
        let expected = root_from_pages(address, [(index, page.clone())]);
        let source = TestRecoverySource {
            tip: Watermark {
                block_number: 12,
                block_hash: B256::repeat_byte(12),
            },
            pages: [(address, [(index, page.clone())].into())].into(),
            sentinels: [(address, expected)].into(),
            ..Default::default()
        };
        let store = MemoryPageStore::default();

        let (updates, report) =
            recover_from_plain_state(&store, &source, source.best_block().unwrap(), None, [])
                .unwrap();

        let mut recovered = store;
        recovered.apply(&updates);
        assert_eq!(recovered.page(address, index).unwrap(), Some(page));
        assert_eq!(recovered.root(address).unwrap(), Some(expected));
        assert_eq!(
            report,
            RecoveryReport {
                pages_rebuilt: 1,
                accounts_rebuilt_full: 1,
            }
        );
    }

    #[test]
    fn partial_recovery_falls_back_to_full_rebuild_on_sentinel_mismatch() {
        let address = address!("0x20c0000000000000000000000000000000000001");
        let kept = PageIndex::new(U256::from(1));
        let stale = PageIndex::new(U256::from(2));
        let kept_page = Page::from_iter([(1, U256::from(10))]);
        let stale_page = Page::from_iter([(2, U256::from(99))]);
        let expected = root_from_pages(address, [(kept, kept_page.clone())]);

        let mut store = MemoryPageStore::default();
        let existing = account_updates_from_pages(
            &store,
            address,
            [(kept, kept_page.clone()), (stale, stale_page)],
        );
        store.apply(&PageStateUpdates {
            accounts: [(address, existing)].into(),
        });

        let source = TestRecoverySource {
            tip: Watermark {
                block_number: 12,
                block_hash: B256::repeat_byte(12),
            },
            pages: [(address, [(kept, kept_page.clone())].into())].into(),
            changed: vec![RecoveryPageKey::new(address, kept)],
            sentinels: [(address, expected)].into(),
        };

        let (updates, report) = recover_from_plain_state(
            &store,
            &source,
            source.best_block().unwrap(),
            Some(Watermark {
                block_number: 10,
                block_hash: B256::repeat_byte(10),
            }),
            [],
        )
        .unwrap();

        store.apply(&updates);
        assert_eq!(store.page(address, kept).unwrap(), Some(kept_page));
        assert_eq!(store.page(address, stale).unwrap(), None);
        assert_eq!(store.root(address).unwrap(), Some(expected));
        assert_eq!(report.accounts_rebuilt_full, 1);
    }

    fn root_from_pages(
        address: Address,
        pages: impl IntoIterator<Item = (PageIndex, Page)>,
    ) -> B256 {
        let store = MemoryPageStore::default();
        account_updates_from_pages(&store, address, pages).new_root
    }

    fn account_updates_from_pages(
        store: &MemoryPageStore,
        address: Address,
        pages: impl IntoIterator<Item = (PageIndex, Page)>,
    ) -> AccountPageUpdates {
        PageSmt::new(store, address)
            .update(
                &pages
                    .into_iter()
                    .map(|(index, page)| (index, Some(page)))
                    .collect(),
            )
            .unwrap()
    }
}
