use crate::{
    page::{Page, PageIndex},
    recovery::RecoveryPageKey,
    smt::{NodePath, PageTreeNode},
    store::{PageStoreError, PageStoreRead, PageStoreScan},
    updates::PageStateUpdates,
};
use alloy_primitives::{Address, B256};
use reth_db::{
    Database,
    mdbx::{DatabaseArguments, DatabaseEnv, init_db_for},
};
use reth_db_api::{
    DatabaseError,
    cursor::DbCursorRO,
    table::{Decode, Encode},
    transaction::{DbTx, DbTxMut},
};
use serde::{Deserialize, Serialize};
use std::{fs, path::Path, sync::Arc};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Watermark {
    pub block_number: u64,
    pub block_hash: B256,
}

#[derive(Clone, Debug)]
pub struct MdbxPageStore {
    db: Arc<DatabaseEnv>,
}

impl MdbxPageStore {
    pub fn open(path: &Path) -> Result<Self, PageStoreError> {
        fs::create_dir_all(path).map_err(to_store_error)?;
        let db = init_db_for::<_, tables::Tables>(path, DatabaseArguments::default())
            .map_err(to_store_error)?;
        Ok(Self { db: Arc::new(db) })
    }

    pub fn commit_block(
        &self,
        block: Watermark,
        updates: &PageStateUpdates,
    ) -> Result<(), PageStoreError> {
        let tx = self.db.tx_mut().map_err(to_store_error)?;
        for (&address, account) in &updates.accounts {
            tx.put::<tables::PageRoots>(address, account.new_root.as_slice().to_vec())
                .map_err(to_store_error)?;

            for (&index, page) in &account.pages {
                tx.put::<tables::PageChangeLog>(
                    ChangeLogDbKey::new(block.block_number, address, index),
                    Vec::new(),
                )
                .map_err(to_store_error)?;

                let key = PageDbKey::new(address, index);
                match page {
                    Some(page) => tx
                        .put::<tables::Pages>(key, page.encode())
                        .map_err(to_store_error)?,
                    None => {
                        tx.delete::<tables::Pages>(key, None)
                            .map_err(to_store_error)?;
                    }
                }
            }

            for (path, node) in &account.nodes {
                let key = NodeDbKey::new(address, path);
                match node {
                    Some(node) => tx
                        .put::<tables::Nodes>(key, node.encode())
                        .map_err(to_store_error)?,
                    None => {
                        tx.delete::<tables::Nodes>(key, None)
                            .map_err(to_store_error)?;
                    }
                }
            }
        }

        tx.put::<tables::Watermarks>(WATERMARK_KEY, encode_watermark(block))
            .map_err(to_store_error)?;
        tx.commit().map_err(to_store_error)?;
        Ok(())
    }

    pub fn watermark(&self) -> Result<Option<Watermark>, PageStoreError> {
        let tx = self.db.tx().map_err(to_store_error)?;
        let watermark = tx
            .get::<tables::Watermarks>(WATERMARK_KEY)
            .map_err(to_store_error)?
            .map(decode_watermark)
            .transpose()?;
        tx.commit().map_err(to_store_error)?;
        Ok(watermark)
    }

    pub fn prune_changelog_below(&self, block_number: u64) -> Result<(), PageStoreError> {
        let tx = self.db.tx_mut().map_err(to_store_error)?;
        {
            let mut cursor = tx
                .cursor_write::<tables::PageChangeLog>()
                .map_err(to_store_error)?;
            let mut walker = cursor.walk(None).map_err(to_store_error)?;
            while let Some((key, _)) = walker.next().transpose().map_err(to_store_error)? {
                if key.block_number() >= block_number {
                    break;
                }
                walker.delete_current().map_err(to_store_error)?;
            }
        }
        tx.commit().map_err(to_store_error)?;
        Ok(())
    }

    pub fn changelog_page_keys_after(
        &self,
        block_number: u64,
    ) -> Result<Vec<RecoveryPageKey>, PageStoreError> {
        let tx = self.db.tx().map_err(to_store_error)?;
        let mut keys = Vec::new();
        {
            let mut cursor = tx
                .cursor_read::<tables::PageChangeLog>()
                .map_err(to_store_error)?;
            let mut walker = cursor.walk(None).map_err(to_store_error)?;
            while let Some((key, _)) = walker.next().transpose().map_err(to_store_error)? {
                if key.block_number() > block_number {
                    keys.push(RecoveryPageKey::new(key.address(), key.page_index()));
                }
            }
        }
        tx.commit().map_err(to_store_error)?;
        keys.sort_unstable();
        keys.dedup();
        Ok(keys)
    }
}

impl PageStoreRead for MdbxPageStore {
    fn node(
        &self,
        address: Address,
        path: &NodePath,
    ) -> Result<Option<PageTreeNode>, PageStoreError> {
        let tx = self.db.tx().map_err(to_store_error)?;
        let node = tx
            .get::<tables::Nodes>(NodeDbKey::new(address, path))
            .map_err(to_store_error)?
            .map(|buf| PageTreeNode::decode(&buf).map_err(to_codec_error))
            .transpose()?;
        tx.commit().map_err(to_store_error)?;
        Ok(node)
    }

    fn page(&self, address: Address, index: PageIndex) -> Result<Option<Page>, PageStoreError> {
        let tx = self.db.tx().map_err(to_store_error)?;
        let page = tx
            .get::<tables::Pages>(PageDbKey::new(address, index))
            .map_err(to_store_error)?
            .map(|buf| Page::decode(&buf).map_err(to_codec_error))
            .transpose()?;
        tx.commit().map_err(to_store_error)?;
        Ok(page)
    }

    fn root(&self, address: Address) -> Result<Option<B256>, PageStoreError> {
        let tx = self.db.tx().map_err(to_store_error)?;
        let root = tx
            .get::<tables::PageRoots>(address)
            .map_err(to_store_error)?
            .map(decode_b256)
            .transpose()?;
        tx.commit().map_err(to_store_error)?;
        Ok(root)
    }
}

impl PageStoreScan for MdbxPageStore {
    fn page_indices(&self, address: Address) -> Result<Vec<PageIndex>, PageStoreError> {
        let tx = self.db.tx().map_err(to_store_error)?;
        let mut indices = Vec::new();
        {
            let mut cursor = tx.cursor_read::<tables::Pages>().map_err(to_store_error)?;
            let mut walker = cursor.walk(None).map_err(to_store_error)?;
            while let Some((key, _)) = walker.next().transpose().map_err(to_store_error)? {
                if key.address() == address {
                    indices.push(key.page_index());
                }
            }
        }
        tx.commit().map_err(to_store_error)?;
        indices.sort_unstable();
        indices.dedup();
        Ok(indices)
    }
}

const WATERMARK_KEY: u8 = 0;

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct PageDbKey(Vec<u8>);

impl PageDbKey {
    fn new(address: Address, index: PageIndex) -> Self {
        let mut out = vec![0u8; 52];
        out[..20].copy_from_slice(address.as_slice());
        out[20..].copy_from_slice(&index.to_be_bytes());
        Self(out)
    }

    fn address(&self) -> Address {
        Address::from_slice(&self.0[..20])
    }

    fn page_index(&self) -> PageIndex {
        let mut index = [0u8; 32];
        index.copy_from_slice(&self.0[20..52]);
        PageIndex::new(alloy_primitives::U256::from_be_bytes(index))
    }
}

impl Encode for PageDbKey {
    type Encoded = Vec<u8>;

    fn encode(self) -> Self::Encoded {
        self.0
    }
}

impl Decode for PageDbKey {
    fn decode(value: &[u8]) -> Result<Self, DatabaseError> {
        if value.len() != 52 {
            return Err(DatabaseError::Decode);
        }
        Ok(Self(value.to_vec()))
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct NodeDbKey(Vec<u8>);

impl NodeDbKey {
    fn new(address: Address, path: &NodePath) -> Self {
        let mut out = vec![0u8; 54];
        out[..20].copy_from_slice(address.as_slice());
        out[20..].copy_from_slice(&path.encode());
        Self(out)
    }
}

impl Encode for NodeDbKey {
    type Encoded = Vec<u8>;

    fn encode(self) -> Self::Encoded {
        self.0
    }
}

impl Decode for NodeDbKey {
    fn decode(value: &[u8]) -> Result<Self, DatabaseError> {
        if value.len() != 54 {
            return Err(DatabaseError::Decode);
        }
        Ok(Self(value.to_vec()))
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct ChangeLogDbKey(Vec<u8>);

impl ChangeLogDbKey {
    fn new(block_number: u64, address: Address, index: PageIndex) -> Self {
        let mut out = vec![0u8; 60];
        out[..8].copy_from_slice(&block_number.to_be_bytes());
        out[8..28].copy_from_slice(address.as_slice());
        out[28..].copy_from_slice(&index.to_be_bytes());
        Self(out)
    }

    fn block_number(&self) -> u64 {
        u64::from_be_bytes(
            self.0[..8]
                .try_into()
                .expect("changelog keys are fixed-width"),
        )
    }

    fn address(&self) -> Address {
        Address::from_slice(&self.0[8..28])
    }

    fn page_index(&self) -> PageIndex {
        let mut index = [0u8; 32];
        index.copy_from_slice(&self.0[28..60]);
        PageIndex::new(alloy_primitives::U256::from_be_bytes(index))
    }
}

impl Encode for ChangeLogDbKey {
    type Encoded = Vec<u8>;

    fn encode(self) -> Self::Encoded {
        self.0
    }
}

impl Decode for ChangeLogDbKey {
    fn decode(value: &[u8]) -> Result<Self, DatabaseError> {
        if value.len() != 60 {
            return Err(DatabaseError::Decode);
        }
        Ok(Self(value.to_vec()))
    }
}

fn decode_b256(value: Vec<u8>) -> Result<B256, PageStoreError> {
    if value.len() != 32 {
        return Err(PageStoreError::Codec(format!(
            "expected 32-byte B256, got {} bytes",
            value.len()
        )));
    }
    Ok(B256::from_slice(&value))
}

fn encode_watermark(block: Watermark) -> Vec<u8> {
    let mut out = Vec::with_capacity(40);
    out.extend_from_slice(&block.block_number.to_be_bytes());
    out.extend_from_slice(block.block_hash.as_slice());
    out
}

fn decode_watermark(value: Vec<u8>) -> Result<Watermark, PageStoreError> {
    if value.len() != 40 {
        return Err(PageStoreError::Codec(format!(
            "expected 40-byte watermark, got {} bytes",
            value.len()
        )));
    }
    let block_number =
        u64::from_be_bytes(value[..8].try_into().expect("slice length checked above"));
    let block_hash = B256::from_slice(&value[8..]);
    Ok(Watermark {
        block_number,
        block_hash,
    })
}

fn to_store_error(error: impl ToString) -> PageStoreError {
    PageStoreError::Database(error.to_string())
}

fn to_codec_error(error: impl ToString) -> PageStoreError {
    PageStoreError::Codec(error.to_string())
}

mod tables {
    use super::{ChangeLogDbKey, NodeDbKey, PageDbKey};
    use alloy_primitives::Address;
    use reth_db_api::{TableSet, TableType, TableViewer, table::TableInfo, tables};
    use std::fmt;

    tables! {
        table PageRoots {
            type Key = Address;
            type Value = Vec<u8>;
        }

        table Pages {
            type Key = PageDbKey;
            type Value = Vec<u8>;
        }

        table Nodes {
            type Key = NodeDbKey;
            type Value = Vec<u8>;
        }

        table PageChangeLog {
            type Key = ChangeLogDbKey;
            type Value = Vec<u8>;
        }

        table Watermarks {
            type Key = u8;
            type Value = Vec<u8>;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        page::Page,
        smt::{PageSmt, empty_page_root},
        updates::PageStateUpdates,
    };
    use alloy_primitives::{U256, address};
    use std::collections::BTreeMap;

    #[test]
    fn mdbx_store_persists_committed_pages() {
        let dir = tempfile::tempdir().unwrap();
        let store = MdbxPageStore::open(dir.path()).unwrap();
        let address = address!("0x20c0000000000000000000000000000000000001");
        let index = PageIndex::new(U256::from(3));
        let mut page = Page::default();
        page.set_word(7, U256::from(42));

        let account = PageSmt::new(&store, address)
            .update(&BTreeMap::from([(index, Some(page.clone()))]))
            .unwrap();
        store
            .commit_block(
                Watermark {
                    block_number: 1,
                    block_hash: B256::repeat_byte(1),
                },
                &PageStateUpdates {
                    accounts: [(address, account)].into(),
                },
            )
            .unwrap();

        assert_eq!(store.page(address, index).unwrap(), Some(page));
        assert_ne!(store.root(address).unwrap().unwrap(), empty_page_root());
        assert_eq!(
            store.watermark().unwrap(),
            Some(Watermark {
                block_number: 1,
                block_hash: B256::repeat_byte(1),
            })
        );

        let tx = store.db.tx().unwrap();
        assert_eq!(tx.entries::<tables::PageChangeLog>().unwrap(), 1);
        tx.commit().unwrap();
        assert_eq!(
            store.changelog_page_keys_after(0).unwrap(),
            vec![RecoveryPageKey::new(address, index)]
        );

        store.prune_changelog_below(2).unwrap();
        let tx = store.db.tx().unwrap();
        assert_eq!(tx.entries::<tables::PageChangeLog>().unwrap(), 0);
        tx.commit().unwrap();
    }
}
