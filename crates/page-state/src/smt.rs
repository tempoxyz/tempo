use crate::{
    page::{PAGE_INDEX_BITS, Page, PageCodecError, PageIndex},
    store::{PageStoreError, PageStoreRead},
    updates::AccountPageUpdates,
};
use alloy_primitives::{Address, B256, U256};
use std::{collections::BTreeMap, sync::LazyLock};

pub static EMPTY_PAGE_ROOT: LazyLock<B256> =
    LazyLock::new(|| B256::from_slice(blake3::hash(b"tempo/empty/v1").as_bytes()));

pub fn empty_page_root() -> B256 {
    *EMPTY_PAGE_ROOT
}

#[derive(Clone, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct NodePath {
    bits: U256,
    len: u16,
}

impl NodePath {
    pub const fn root() -> Self {
        Self {
            bits: U256::ZERO,
            len: 0,
        }
    }

    pub const fn len(&self) -> u16 {
        self.len
    }

    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    pub fn child(&self, bit: bool) -> Self {
        assert!(
            usize::from(self.len) < PAGE_INDEX_BITS,
            "node path is already full"
        );
        Self {
            bits: (self.bits << 1) | U256::from(bit as u8),
            len: self.len + 1,
        }
    }

    pub fn bit(&self, depth: usize) -> bool {
        assert!(
            depth < usize::from(self.len),
            "node path depth out of range"
        );
        let shift = usize::from(self.len) - depth - 1;
        ((self.bits >> shift) & U256::ONE) == U256::ONE
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(34);
        out.extend_from_slice(&self.len.to_be_bytes());
        out.extend_from_slice(&self.bits.to_be_bytes::<32>());
        out
    }

    pub fn decode(buf: &[u8]) -> Result<Self, PageCodecError> {
        if buf.len() != 34 {
            return Err(PageCodecError::TooShort);
        }
        let len = u16::from_be_bytes([buf[0], buf[1]]);
        if usize::from(len) > PAGE_INDEX_BITS {
            return Err(PageCodecError::InvalidPathLength(len));
        }
        let mut bits = [0u8; 32];
        bits.copy_from_slice(&buf[2..34]);
        Ok(Self {
            bits: U256::from_be_bytes(bits),
            len,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PageTreeNode {
    Branch { left: B256, right: B256 },
    Leaf { index: PageIndex, page_hash: B256 },
}

impl PageTreeNode {
    pub fn hash(&self) -> B256 {
        let mut hasher = blake3::Hasher::new();
        match self {
            Self::Branch { left, right } => {
                hasher.update(b"tempo/node/v1");
                hasher.update(left.as_slice());
                hasher.update(right.as_slice());
            }
            Self::Leaf { index, page_hash } => {
                hasher.update(b"tempo/leaf/v1");
                hasher.update(&index.to_be_bytes());
                hasher.update(page_hash.as_slice());
            }
        }
        B256::from_slice(hasher.finalize().as_bytes())
    }

    pub fn encode(&self) -> Vec<u8> {
        match self {
            Self::Branch { left, right } => {
                let mut out = Vec::with_capacity(65);
                out.push(0);
                out.extend_from_slice(left.as_slice());
                out.extend_from_slice(right.as_slice());
                out
            }
            Self::Leaf { index, page_hash } => {
                let mut out = Vec::with_capacity(65);
                out.push(1);
                out.extend_from_slice(&index.to_be_bytes());
                out.extend_from_slice(page_hash.as_slice());
                out
            }
        }
    }

    pub fn decode(buf: &[u8]) -> Result<Self, PageCodecError> {
        if buf.len() != 65 {
            return Err(PageCodecError::TooShort);
        }
        match buf[0] {
            0 => Ok(Self::Branch {
                left: B256::from_slice(&buf[1..33]),
                right: B256::from_slice(&buf[33..65]),
            }),
            1 => {
                let mut index = [0u8; 32];
                index.copy_from_slice(&buf[1..33]);
                Ok(Self::Leaf {
                    index: PageIndex::new(U256::from_be_bytes(index)),
                    page_hash: B256::from_slice(&buf[33..65]),
                })
            }
            tag => Err(PageCodecError::InvalidNodeTag(tag)),
        }
    }
}

/// Builds an account's page tree bottom-up from sorted, deduplicated `(index, page_hash)`
/// leaves, emitting every node through `sink`. Produces exactly the node layout the
/// incremental [`PageSmt::update`] editor would, but in O(leaves) time with O(depth)
/// memory — use this for bulk seeding instead of a giant `update` batch.
pub fn build_bulk(
    leaves: &[(PageIndex, B256)],
    mut sink: impl FnMut(NodePath, &PageTreeNode),
) -> B256 {
    fn build<F: FnMut(NodePath, &PageTreeNode)>(
        leaves: &[(PageIndex, B256)],
        path: NodePath,
        sink: &mut F,
    ) -> B256 {
        if let [(index, page_hash)] = leaves {
            // A subtree with a single page is represented by its leaf hoisted to the
            // divergence point.
            let node = PageTreeNode::Leaf {
                index: *index,
                page_hash: *page_hash,
            };
            let hash = node.hash();
            sink(path, &node);
            return hash;
        }

        let depth = usize::from(path.len());
        let split = leaves.partition_point(|(index, _)| !index.bit(depth));
        let left = match &leaves[..split] {
            [] => B256::ZERO,
            left => build(left, path.child(false), sink),
        };
        let right = match &leaves[split..] {
            [] => B256::ZERO,
            right => build(right, path.child(true), sink),
        };
        let node = PageTreeNode::Branch { left, right };
        let hash = node.hash();
        sink(path, &node);
        hash
    }

    debug_assert!(leaves.is_sorted_by(|a, b| a.0 < b.0), "leaves must be sorted and unique");
    if leaves.is_empty() {
        return empty_page_root();
    }
    build(leaves, NodePath::root(), &mut sink)
}

pub struct PageSmt<'a, S: PageStoreRead + ?Sized> {
    store: &'a S,
    address: Address,
}

impl<'a, S: PageStoreRead + ?Sized> PageSmt<'a, S> {
    pub const fn new(store: &'a S, address: Address) -> Self {
        Self { store, address }
    }

    pub fn root(&self) -> Result<B256, PageStoreError> {
        Ok(self
            .store
            .root(self.address)?
            .unwrap_or_else(empty_page_root))
    }

    pub fn update(
        &self,
        dirty: &BTreeMap<PageIndex, Option<Page>>,
    ) -> Result<AccountPageUpdates, PageStoreError> {
        let mut editor = SmtEditor {
            store: self.store,
            address: self.address,
            nodes: BTreeMap::new(),
        };

        let mut pages = BTreeMap::new();
        for (&index, page) in dirty {
            let page_hash = page.as_ref().map(|page| page.hash(self.address, index));
            editor.apply(NodePath::root(), index, page_hash)?;
            pages.insert(index, page.clone());
        }

        let root_node = editor.get_node(&NodePath::root())?;
        Ok(AccountPageUpdates {
            new_root: root_node
                .as_ref()
                .map(PageTreeNode::hash)
                .unwrap_or_else(empty_page_root),
            pages,
            nodes: editor.nodes,
        })
    }

    pub fn prove(&self, index: PageIndex) -> Result<PageProof, PageStoreError> {
        let mut path = NodePath::root();
        let mut path_nodes = Vec::new();
        let Some(mut node) = self.store.node(self.address, &path)? else {
            return Ok(PageProof {
                page: None,
                path_nodes,
            });
        };

        loop {
            path_nodes.push(node.clone());
            match node {
                PageTreeNode::Leaf {
                    index: leaf_index, ..
                } => {
                    let page = if leaf_index == index {
                        self.store.page(self.address, index)?
                    } else {
                        None
                    };
                    return Ok(PageProof { page, path_nodes });
                }
                PageTreeNode::Branch { left, right } => {
                    let bit = index.bit(usize::from(path.len()));
                    let child_hash = if bit { right } else { left };
                    if child_hash == B256::ZERO {
                        return Ok(PageProof {
                            page: None,
                            path_nodes,
                        });
                    }
                    path = path.child(bit);
                    node = self.store.node(self.address, &path)?.ok_or_else(|| {
                        PageStoreError::MissingNode {
                            address: self.address,
                            path: path.clone(),
                        }
                    })?;
                }
            }
        }
    }
}

struct SmtEditor<'a, S: PageStoreRead + ?Sized> {
    store: &'a S,
    address: Address,
    nodes: BTreeMap<NodePath, Option<PageTreeNode>>,
}

impl<S: PageStoreRead + ?Sized> SmtEditor<'_, S> {
    fn get_node(&self, path: &NodePath) -> Result<Option<PageTreeNode>, PageStoreError> {
        if let Some(node) = self.nodes.get(path) {
            return Ok(node.clone());
        }
        self.store.node(self.address, path)
    }

    fn put_node(
        &mut self,
        path: NodePath,
        node: Option<PageTreeNode>,
    ) -> Result<(), PageStoreError> {
        if self.get_node(&path)? != node {
            self.nodes.insert(path, node);
        }
        Ok(())
    }

    fn apply(
        &mut self,
        path: NodePath,
        index: PageIndex,
        page_hash: Option<B256>,
    ) -> Result<Option<PageTreeNode>, PageStoreError> {
        let current = self.get_node(&path)?;
        let next = match (current, page_hash) {
            (None, None) => None,
            (None, Some(page_hash)) => Some(PageTreeNode::Leaf { index, page_hash }),
            (
                Some(PageTreeNode::Leaf {
                    index: old_index,
                    page_hash: old_hash,
                }),
                None,
            ) => {
                if old_index == index {
                    None
                } else {
                    Some(PageTreeNode::Leaf {
                        index: old_index,
                        page_hash: old_hash,
                    })
                }
            }
            (
                Some(PageTreeNode::Leaf {
                    index: old_index,
                    page_hash: old_hash,
                }),
                Some(page_hash),
            ) => {
                if old_index == index {
                    Some(PageTreeNode::Leaf { index, page_hash })
                } else {
                    let old = PageTreeNode::Leaf {
                        index: old_index,
                        page_hash: old_hash,
                    };
                    let new = PageTreeNode::Leaf { index, page_hash };
                    Some(self.split_two(path.clone(), old, new)?)
                }
            }
            (Some(PageTreeNode::Branch { left, right }), page_hash) => {
                let bit = index.bit(usize::from(path.len()));
                let left_path = path.child(false);
                let right_path = path.child(true);
                let left_node = self.child_node(&left_path, left)?;
                let right_node = self.child_node(&right_path, right)?;

                let (left_node, right_node) = if bit {
                    let right_node = self.apply(right_path.clone(), index, page_hash)?;
                    (left_node, right_node)
                } else {
                    let left_node = self.apply(left_path.clone(), index, page_hash)?;
                    (left_node, right_node)
                };

                self.branch_from_children(left_path, left_node, right_path, right_node)?
            }
        };
        self.put_node(path, next.clone())?;
        Ok(next)
    }

    fn child_node(
        &self,
        path: &NodePath,
        child_hash: B256,
    ) -> Result<Option<PageTreeNode>, PageStoreError> {
        if child_hash == B256::ZERO {
            Ok(None)
        } else {
            self.get_node(path)?
                .map(Some)
                .ok_or_else(|| PageStoreError::MissingNode {
                    address: self.address,
                    path: path.clone(),
                })
        }
    }

    fn split_two(
        &mut self,
        path: NodePath,
        a: PageTreeNode,
        b: PageTreeNode,
    ) -> Result<PageTreeNode, PageStoreError> {
        let (PageTreeNode::Leaf { index: a_index, .. }, PageTreeNode::Leaf { index: b_index, .. }) =
            (&a, &b)
        else {
            unreachable!("split_two only accepts leaves");
        };
        let bit_a = a_index.bit(usize::from(path.len()));
        let bit_b = b_index.bit(usize::from(path.len()));
        let left_path = path.child(false);
        let right_path = path.child(true);

        if bit_a != bit_b {
            let (left, right) = if bit_a { (b, a) } else { (a, b) };
            self.put_node(left_path, Some(left.clone()))?;
            self.put_node(right_path, Some(right.clone()))?;
            return Ok(PageTreeNode::Branch {
                left: left.hash(),
                right: right.hash(),
            });
        }

        let child_path = path.child(bit_a);
        let child = self.split_two(child_path.clone(), a, b)?;
        self.put_node(child_path, Some(child.clone()))?;
        let child_hash = child.hash();
        Ok(if bit_a {
            PageTreeNode::Branch {
                left: B256::ZERO,
                right: child_hash,
            }
        } else {
            PageTreeNode::Branch {
                left: child_hash,
                right: B256::ZERO,
            }
        })
    }

    fn branch_from_children(
        &mut self,
        left_path: NodePath,
        left: Option<PageTreeNode>,
        right_path: NodePath,
        right: Option<PageTreeNode>,
    ) -> Result<Option<PageTreeNode>, PageStoreError> {
        match (left, right) {
            (None, None) => Ok(None),
            (Some(PageTreeNode::Leaf { index, page_hash }), None) => {
                self.put_node(left_path, None)?;
                Ok(Some(PageTreeNode::Leaf { index, page_hash }))
            }
            (None, Some(PageTreeNode::Leaf { index, page_hash })) => {
                self.put_node(right_path, None)?;
                Ok(Some(PageTreeNode::Leaf { index, page_hash }))
            }
            (left, right) => Ok(Some(PageTreeNode::Branch {
                left: left.as_ref().map(PageTreeNode::hash).unwrap_or_default(),
                right: right.as_ref().map(PageTreeNode::hash).unwrap_or_default(),
            })),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PageProof {
    pub page: Option<Page>,
    pub path_nodes: Vec<PageTreeNode>,
}

impl PageProof {
    pub fn verify(&self, root: B256, address: Address, index: PageIndex) -> bool {
        if self.path_nodes.is_empty() {
            return self.page.is_none() && root == empty_page_root();
        }

        let Some((last, parents)) = self.path_nodes.split_last() else {
            return false;
        };
        let mut current_hash = match last {
            PageTreeNode::Leaf {
                index: leaf_index,
                page_hash,
            } => {
                if *leaf_index == index {
                    let Some(page) = &self.page else {
                        return false;
                    };
                    if page.hash(address, index) != *page_hash {
                        return false;
                    }
                } else if self.page.is_some() {
                    return false;
                }
                last.hash()
            }
            PageTreeNode::Branch { left, right } => {
                if self.page.is_some() {
                    return false;
                }
                let depth = parents.len();
                let child = if index.bit(depth) { right } else { left };
                if *child != B256::ZERO {
                    return false;
                }
                last.hash()
            }
        };

        for (depth, parent) in parents.iter().enumerate().rev() {
            let PageTreeNode::Branch { left, right } = parent else {
                return false;
            };
            if index.bit(depth) {
                if *right != current_hash {
                    return false;
                }
            } else if *left != current_hash {
                return false;
            }
            current_hash = parent.hash();
        }

        current_hash == root
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{page::page_offset, store::MemoryPageStore, updates::PageStateUpdates};
    use alloy_primitives::Address;
    use proptest::prelude::*;
    use std::collections::BTreeMap;

    fn page_with_word(offset: u8, value: u64) -> Page {
        let mut page = Page::default();
        page.set_word(offset, U256::from(value));
        page
    }

    fn update_store(
        store: &mut MemoryPageStore,
        address: Address,
        dirty: BTreeMap<PageIndex, Option<Page>>,
    ) -> B256 {
        let updates = PageSmt::new(store, address).update(&dirty).unwrap();
        let root = updates.new_root;
        store.apply(&PageStateUpdates {
            accounts: BTreeMap::from([(address, updates)]),
        });
        root
    }

    #[test]
    fn insert_update_delete_roundtrip() {
        let address = Address::repeat_byte(0x11);
        let mut store = MemoryPageStore::default();
        let first = PageIndex::new(U256::from(10));
        let second = PageIndex::new(U256::from(11));

        let root = update_store(
            &mut store,
            address,
            BTreeMap::from([(first, Some(page_with_word(0, 1)))]),
        );
        let proof = PageSmt::new(&store, address).prove(first).unwrap();
        assert!(proof.verify(root, address, first));

        let root = update_store(
            &mut store,
            address,
            BTreeMap::from([(second, Some(page_with_word(3, 7)))]),
        );
        assert!(
            PageSmt::new(&store, address)
                .prove(first)
                .unwrap()
                .verify(root, address, first)
        );
        assert!(
            PageSmt::new(&store, address)
                .prove(second)
                .unwrap()
                .verify(root, address, second)
        );

        let root = update_store(&mut store, address, BTreeMap::from([(first, None)]));
        assert!(
            PageSmt::new(&store, address)
                .prove(first)
                .unwrap()
                .verify(root, address, first)
        );
        assert!(
            PageSmt::new(&store, address)
                .prove(second)
                .unwrap()
                .verify(root, address, second)
        );
    }

    proptest! {
        #[test]
        fn build_bulk_matches_incremental_editor(ops in prop::collection::vec((any::<u16>(), any::<u8>(), any::<u64>().prop_map(|v| v | 1)), 0..120)) {
            let address = Address::repeat_byte(0x33);
            let mut pages = BTreeMap::<PageIndex, Page>::new();
            for (raw_index, raw_offset, value) in ops {
                let slot = (U256::from(raw_index) << 7) + U256::from(raw_offset % 128);
                pages.entry(PageIndex::of_slot(slot)).or_default().set_word(page_offset(slot), U256::from(value));
            }

            // Incremental editor from an empty store.
            let store = MemoryPageStore::default();
            let dirty: BTreeMap<_, _> = pages.iter().map(|(&index, page)| (index, Some(page.clone()))).collect();
            let editor_updates = PageSmt::new(&store, address).update(&dirty).unwrap();
            let editor_nodes: BTreeMap<_, _> = editor_updates
                .nodes
                .iter()
                .filter_map(|(path, node)| node.clone().map(|node| (path.clone(), node)))
                .collect();

            // Bulk builder over the same leaves.
            let leaves: Vec<_> = pages.iter().map(|(&index, page)| (index, page.hash(address, index))).collect();
            let mut bulk_nodes = BTreeMap::new();
            let bulk_root = build_bulk(&leaves, |path, node| {
                bulk_nodes.insert(path, node.clone());
            });

            prop_assert_eq!(bulk_root, editor_updates.new_root);
            prop_assert_eq!(bulk_nodes, editor_nodes);
        }

        #[test]
        fn smt_proofs_verify_after_random_batches(ops in prop::collection::vec((any::<u16>(), any::<u8>(), any::<u64>()), 1..80)) {
            let address = Address::repeat_byte(0x22);
            let mut store = MemoryPageStore::default();
            let mut model = BTreeMap::<PageIndex, Option<Page>>::new();

            for (raw_index, raw_offset, value) in ops {
                let slot = (U256::from(raw_index) << 7) + U256::from(raw_offset % 128);
                let index = PageIndex::of_slot(slot);
                let offset = page_offset(slot);
                let mut page = store.page(address, index).unwrap().unwrap_or_default();
                page.set_word(offset, U256::from(value));
                model.insert(index, (!page.is_empty()).then_some(page));
            }

            let root = update_store(&mut store, address, model.clone());
            for index in model.keys().copied() {
                prop_assert!(PageSmt::new(&store, address).prove(index).unwrap().verify(root, address, index));
            }
        }
    }
}
