use crate::{
    page::{Page, PageIndex},
    smt::{NodePath, PageTreeNode},
    updates::PageStateUpdates,
};
use alloy_primitives::{Address, B256};
use std::{collections::HashMap, sync::Arc};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum PageStoreError {
    #[error("page tree is missing node {path:?} for account {address}")]
    MissingNode { address: Address, path: NodePath },
    #[error("page-state database error: {0}")]
    Database(String),
    #[error("page-state codec error: {0}")]
    Codec(String),
    #[error("missing page-state delta for canonical block {hash} at height {number}")]
    MissingBlockDelta { number: u64, hash: B256 },
    #[error("sidecar database support is not implemented yet")]
    UnsupportedDb,
}

pub trait PageStoreRead: Send + Sync {
    fn node(
        &self,
        address: Address,
        path: &NodePath,
    ) -> Result<Option<PageTreeNode>, PageStoreError>;

    fn page(&self, address: Address, index: PageIndex) -> Result<Option<Page>, PageStoreError>;

    fn root(&self, address: Address) -> Result<Option<B256>, PageStoreError>;
}

pub trait PageStoreScan: PageStoreRead {
    fn page_indices(&self, address: Address) -> Result<Vec<PageIndex>, PageStoreError>;
}

#[derive(Clone, Debug, Default)]
pub struct MemoryPageStore {
    nodes: HashMap<(Address, NodePath), PageTreeNode>,
    pages: HashMap<(Address, PageIndex), Page>,
    roots: HashMap<Address, B256>,
}

impl PageStoreRead for MemoryPageStore {
    fn node(
        &self,
        address: Address,
        path: &NodePath,
    ) -> Result<Option<PageTreeNode>, PageStoreError> {
        Ok(self.nodes.get(&(address, path.clone())).cloned())
    }

    fn page(&self, address: Address, index: PageIndex) -> Result<Option<Page>, PageStoreError> {
        Ok(self.pages.get(&(address, index)).cloned())
    }

    fn root(&self, address: Address) -> Result<Option<B256>, PageStoreError> {
        Ok(self.roots.get(&address).copied())
    }
}

impl PageStoreScan for MemoryPageStore {
    fn page_indices(&self, address: Address) -> Result<Vec<PageIndex>, PageStoreError> {
        let mut indices = self
            .pages
            .keys()
            .filter_map(|(page_address, index)| (*page_address == address).then_some(*index))
            .collect::<Vec<_>>();
        indices.sort_unstable();
        indices.dedup();
        Ok(indices)
    }
}

impl MemoryPageStore {
    pub fn apply(&mut self, updates: &PageStateUpdates) {
        for (&address, account) in &updates.accounts {
            self.roots.insert(address, account.new_root);
            for (&index, page) in &account.pages {
                match page {
                    Some(page) => {
                        self.pages.insert((address, index), page.clone());
                    }
                    None => {
                        self.pages.remove(&(address, index));
                    }
                }
            }
            for (path, node) in &account.nodes {
                match node {
                    Some(node) => {
                        self.nodes.insert((address, path.clone()), node.clone());
                    }
                    None => {
                        self.nodes.remove(&(address, path.clone()));
                    }
                }
            }
        }
    }
}

pub struct OverlayPageStore<'a> {
    base: &'a dyn PageStoreRead,
    deltas: Vec<Arc<PageStateUpdates>>,
}

impl<'a> OverlayPageStore<'a> {
    pub fn new(base: &'a dyn PageStoreRead, deltas: Vec<Arc<PageStateUpdates>>) -> Self {
        Self { base, deltas }
    }
}

impl PageStoreRead for OverlayPageStore<'_> {
    fn node(
        &self,
        address: Address,
        path: &NodePath,
    ) -> Result<Option<PageTreeNode>, PageStoreError> {
        for delta in &self.deltas {
            if let Some(account) = delta.accounts.get(&address)
                && let Some(node) = account.nodes.get(path)
            {
                return Ok(node.clone());
            }
        }
        self.base.node(address, path)
    }

    fn page(&self, address: Address, index: PageIndex) -> Result<Option<Page>, PageStoreError> {
        for delta in &self.deltas {
            if let Some(account) = delta.accounts.get(&address)
                && let Some(page) = account.pages.get(&index)
            {
                return Ok(page.clone());
            }
        }
        self.base.page(address, index)
    }

    fn root(&self, address: Address) -> Result<Option<B256>, PageStoreError> {
        for delta in &self.deltas {
            if let Some(account) = delta.accounts.get(&address) {
                return Ok(Some(account.new_root));
            }
        }
        self.base.root(address)
    }
}
