//! A partial Merkle-Patricia trie over content-addressed nodes.
//!
//! Nodes are stored by keccak256 of their RLP encoding, so any node reached from a trusted root
//! by hash is authentic: inserting proof nodes from an untrusted RPC into the store and walking
//! from the parent block's (verified) state root is the proof check. Updates resolve only the
//! nodes on the touched paths; a node a deletion needs but no proof revealed is reported as
//! [`Error::Missing`] with its path so the caller can fetch a covering proof and retry.

use std::collections::HashMap;

use alloy_primitives::{B256, keccak256};
use alloy_trie::{
    EMPTY_ROOT_HASH, Nibbles, TrieMask,
    nodes::{BranchNodeRef, ExtensionNodeRef, LeafNodeRef, RlpNode, TrieNode},
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Error {
    /// The node at this path (nibbles from the trie root) was needed but is not in the store.
    Missing(Vec<u8>),
    /// A stored node did not decode.
    Corrupt(String),
}

#[derive(Default)]
pub(crate) struct Store {
    nodes: HashMap<B256, Vec<u8>>,
    /// Hashes some extension node points at, so they are branches. Only used to skip resolving a
    /// branch that becomes an extension's child: a wrong entry can only make the recomputed root
    /// differ from the header's, never match it.
    branches: std::collections::HashSet<B256>,
}

impl Store {
    /// Adds RLP-encoded nodes (e.g. from eth_getProof), keyed by their own hash.
    pub(crate) fn add<'a>(&mut self, rlps: impl IntoIterator<Item = &'a [u8]>) {
        for rlp in rlps {
            self.nodes.insert(keccak256(rlp), rlp.to_vec());
        }
    }

    /// Adds every node a post-state proof node could have been before a deletion merged a
    /// prefix into it: each proper suffix of a leaf or extension. Keyed by hash, so only the
    /// genuine pre-state sibling is ever resolved.
    pub(crate) fn add_suffixes(&mut self, rlp: &[u8]) {
        let Ok(node) = <TrieNode as alloy_rlp::Decodable>::decode(&mut &rlp[..]) else {
            return;
        };
        let mut buf = Vec::new();
        match node {
            TrieNode::Leaf(l) => {
                let k = l.key.to_vec();
                for i in 1..=k.len() {
                    buf.clear();
                    let key = Nibbles::from_nibbles(&k[i..]);
                    let r = LeafNodeRef {
                        key: &key,
                        value: &l.value,
                    }
                    .rlp(&mut buf);
                    if r.as_hash().is_some() {
                        self.add([buf.as_slice()]);
                    }
                }
            }
            TrieNode::Extension(x) => {
                if let Some(h) = x.child.as_hash() {
                    self.branches.insert(h);
                }
                let k = x.key.to_vec();
                for i in 1..k.len() {
                    buf.clear();
                    let key = Nibbles::from_nibbles(&k[i..]);
                    let r = ExtensionNodeRef {
                        key: &key,
                        child: x.child.as_ref(),
                    }
                    .rlp(&mut buf);
                    if r.as_hash().is_some() {
                        self.add([buf.as_slice()]);
                    }
                }
            }
            _ => {}
        }
    }

    fn get(&self, hash: &B256) -> Option<&[u8]> {
        self.nodes.get(hash).map(Vec::as_slice)
    }
}

#[derive(Clone, Debug)]
enum Node {
    Empty,
    /// An unresolved child referenced by hash.
    Hash(B256),
    Leaf(Vec<u8>, Vec<u8>),
    Ext(Vec<u8>, Box<Node>),
    Branch(Box<[Node; 16]>),
}

fn empty_children() -> Box<[Node; 16]> {
    Box::new(std::array::from_fn(|_| Node::Empty))
}

fn from_rlp_node(r: &RlpNode) -> Result<Node, Error> {
    match r.as_hash() {
        Some(h) => Ok(Node::Hash(h)),
        None => decode(r.as_ref()),
    }
}

fn decode(mut rlp: &[u8]) -> Result<Node, Error> {
    let node = <TrieNode as alloy_rlp::Decodable>::decode(&mut rlp)
        .map_err(|e| Error::Corrupt(e.to_string()))?;
    Ok(match node {
        TrieNode::EmptyRoot => Node::Empty,
        TrieNode::Leaf(l) => Node::Leaf(l.key.to_vec(), l.value.clone()),
        TrieNode::Extension(x) => Node::Ext(x.key.to_vec(), Box::new(from_rlp_node(&x.child)?)),
        TrieNode::Branch(b) => {
            let mut children = empty_children();
            let mut stack = b.stack.iter();
            for i in 0..16u8 {
                if b.state_mask.is_bit_set(i) {
                    let child = stack
                        .next()
                        .ok_or_else(|| Error::Corrupt("short branch".into()))?;
                    children[i as usize] = from_rlp_node(child)?;
                }
            }
            Node::Branch(children)
        }
    })
}

/// A trie rooted at a known hash.
pub(crate) struct Trie {
    root: Node,
}

impl Trie {
    pub(crate) fn new(root: B256) -> Self {
        Self {
            root: if root == EMPTY_ROOT_HASH {
                Node::Empty
            } else {
                Node::Hash(root)
            },
        }
    }

    /// Looks up the value at keccak-hashed key `key`.
    pub(crate) fn get(&self, store: &Store, key: &B256) -> Result<Option<Vec<u8>>, Error> {
        let path = Nibbles::unpack(key).to_vec();
        let mut node = self.root.clone();
        let mut depth = 0;
        loop {
            node = match node {
                Node::Empty => return Ok(None),
                Node::Hash(h) => resolve(store, &h, &path[..depth])?,
                Node::Leaf(k, v) => return Ok((path[depth..] == k[..]).then_some(v)),
                Node::Ext(k, child) => {
                    if !path[depth..].starts_with(&k) {
                        return Ok(None);
                    }
                    depth += k.len();
                    *child
                }
                Node::Branch(children) => {
                    let i = path[depth] as usize;
                    depth += 1;
                    let mut children = children;
                    std::mem::replace(&mut children[i], Node::Empty)
                }
            }
        }
    }

    pub(crate) fn insert(
        &mut self,
        store: &Store,
        key: &B256,
        value: Vec<u8>,
    ) -> Result<(), Error> {
        let path = Nibbles::unpack(key).to_vec();
        let root = std::mem::replace(&mut self.root, Node::Empty);
        self.root = insert(store, root, &path, 0, value)?;
        Ok(())
    }

    pub(crate) fn remove(&mut self, store: &Store, key: &B256) -> Result<(), Error> {
        let path = Nibbles::unpack(key).to_vec();
        let root = std::mem::replace(&mut self.root, Node::Empty);
        self.root = remove(store, root, &path, 0)?;
        Ok(())
    }

    pub(crate) fn root(&self) -> B256 {
        match &self.root {
            Node::Empty => EMPTY_ROOT_HASH,
            Node::Hash(h) => *h,
            n => {
                let r = encode(n);
                r.as_hash().unwrap_or_else(|| keccak256(r.as_ref()))
            }
        }
    }
}

fn resolve(store: &Store, hash: &B256, path: &[u8]) -> Result<Node, Error> {
    let rlp = store
        .get(hash)
        .ok_or_else(|| Error::Missing(path.to_vec()))?;
    decode(rlp)
}

fn common(a: &[u8], b: &[u8]) -> usize {
    a.iter().zip(b).take_while(|(x, y)| x == y).count()
}

fn leaf(k: &[u8], v: Vec<u8>) -> Node {
    Node::Leaf(k.to_vec(), v)
}

fn insert(
    store: &Store,
    node: Node,
    path: &[u8],
    depth: usize,
    value: Vec<u8>,
) -> Result<Node, Error> {
    let rest = &path[depth..];
    Ok(match node {
        Node::Empty => leaf(rest, value),
        Node::Hash(h) => insert(
            store,
            resolve(store, &h, &path[..depth])?,
            path,
            depth,
            value,
        )?,
        Node::Leaf(k, v) => {
            if k[..] == rest[..] {
                leaf(rest, value)
            } else {
                let c = common(&k, rest);
                let mut children = empty_children();
                children[k[c] as usize] = leaf(&k[c + 1..], v);
                children[rest[c] as usize] = leaf(&rest[c + 1..], value);
                wrap(&rest[..c], Node::Branch(children))
            }
        }
        Node::Ext(k, child) => {
            let c = common(&k, rest);
            if c == k.len() {
                Node::Ext(k, Box::new(insert(store, *child, path, depth + c, value)?))
            } else {
                let mut children = empty_children();
                children[k[c] as usize] = if c + 1 == k.len() {
                    *child
                } else {
                    Node::Ext(k[c + 1..].to_vec(), child)
                };
                children[rest[c] as usize] = leaf(&rest[c + 1..], value);
                wrap(&rest[..c], Node::Branch(children))
            }
        }
        Node::Branch(mut children) => {
            let i = rest[0] as usize;
            let child = std::mem::replace(&mut children[i], Node::Empty);
            children[i] = insert(store, child, path, depth + 1, value)?;
            Node::Branch(children)
        }
    })
}

fn wrap(prefix: &[u8], node: Node) -> Node {
    if prefix.is_empty() {
        node
    } else {
        Node::Ext(prefix.to_vec(), Box::new(node))
    }
}

/// Prepends `prefix` to a node that lost its parent branch or extension.
fn join(store: &Store, prefix: Vec<u8>, node: Node, node_path: &[u8]) -> Result<Node, Error> {
    Ok(match node {
        Node::Empty => Node::Empty,
        Node::Hash(h) if store.get(&h).is_none() && store.branches.contains(&h) => {
            wrap(&prefix, Node::Hash(h))
        }
        Node::Hash(h) => join(store, prefix, resolve(store, &h, node_path)?, node_path)?,
        Node::Leaf(k, v) => Node::Leaf([prefix, k].concat(), v),
        Node::Ext(k, c) => Node::Ext([prefix, k].concat(), c),
        b @ Node::Branch(_) => wrap(&prefix, b),
    })
}

fn remove(store: &Store, node: Node, path: &[u8], depth: usize) -> Result<Node, Error> {
    let rest = &path[depth..];
    Ok(match node {
        Node::Empty => Node::Empty,
        Node::Hash(h) => remove(store, resolve(store, &h, &path[..depth])?, path, depth)?,
        Node::Leaf(k, v) => {
            if k[..] == rest[..] {
                Node::Empty
            } else {
                Node::Leaf(k, v)
            }
        }
        Node::Ext(k, child) => {
            if !rest.starts_with(&k) {
                return Ok(Node::Ext(k, child));
            }
            let child_path = &path[..depth + k.len()];
            let new_child = remove(store, *child, path, depth + k.len())?;
            join(store, k, new_child, child_path)?
        }
        Node::Branch(mut children) => {
            let i = rest[0] as usize;
            let child = std::mem::replace(&mut children[i], Node::Empty);
            children[i] = remove(store, child, path, depth + 1)?;
            let live: Vec<usize> = (0..16)
                .filter(|j| !matches!(children[*j], Node::Empty))
                .collect();
            match live.as_slice() {
                [] => Node::Empty,
                [j] => {
                    let j = *j;
                    let only = std::mem::replace(&mut children[j], Node::Empty);
                    let mut only_path = path[..depth].to_vec();
                    only_path.push(j as u8);
                    join(store, vec![j as u8], only, &only_path)?
                }
                _ => Node::Branch(children),
            }
        }
    })
}

fn encode(node: &Node) -> RlpNode {
    let mut buf = Vec::new();
    match node {
        Node::Empty => RlpNode::from_rlp(&[alloy_rlp::EMPTY_STRING_CODE]),
        Node::Hash(h) => RlpNode::word_rlp(h),
        Node::Leaf(k, v) => {
            let key = Nibbles::from_nibbles(k);
            LeafNodeRef {
                key: &key,
                value: v,
            }
            .rlp(&mut buf)
        }
        Node::Ext(k, c) => {
            let key = Nibbles::from_nibbles(k);
            let child = encode(c);
            ExtensionNodeRef {
                key: &key,
                child: child.as_ref(),
            }
            .rlp(&mut buf)
        }
        Node::Branch(children) => {
            let mut mask = TrieMask::default();
            let mut stack = Vec::new();
            for (i, c) in children.iter().enumerate() {
                if !matches!(c, Node::Empty) {
                    mask.set_bit(i as u8);
                    stack.push(encode(c));
                }
            }
            BranchNodeRef {
                stack: &stack,
                state_mask: mask,
            }
            .rlp(&mut buf)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_trie::HashBuilder;

    fn reference_root(items: &std::collections::BTreeMap<B256, Vec<u8>>) -> B256 {
        let mut hb = HashBuilder::default();
        for (k, v) in items {
            hb.add_leaf(Nibbles::unpack(k), v);
        }
        hb.root()
    }

    #[test]
    fn random_inserts_and_removes_match_hash_builder() {
        let mut items = std::collections::BTreeMap::new();
        let store = Store::default();
        let mut trie = Trie::new(EMPTY_ROOT_HASH);
        let mut x = 1u64;
        for step in 0..3000u64 {
            x = x
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            let key = keccak256((x % 400).to_be_bytes());
            if x % 3 == 0 {
                items.remove(&key);
                trie.remove(&store, &key).unwrap();
            } else {
                let v = alloy_rlp::encode(step);
                items.insert(key, v.clone());
                trie.insert(&store, &key, v).unwrap();
            }
            assert_eq!(trie.root(), reference_root(&items), "step {step}");
        }
    }
}
