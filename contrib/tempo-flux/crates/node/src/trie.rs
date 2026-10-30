//! In-memory Merkle Patricia trie that caches every node's RLP, so a root
//! after an update rehashes only the paths that changed. Keys are fixed
//! length (hashed), so branches never carry values.

use alloy_primitives::{B256, keccak256};
use alloy_trie::{
    EMPTY_ROOT_HASH, Nibbles, TrieMask,
    nodes::{BranchNodeRef, ExtensionNodeRef, LeafNodeRef, RlpNode},
};

#[derive(Default)]
enum Node {
    #[default]
    Empty,
    Leaf {
        key: Nibbles,
        value: Vec<u8>,
        rlp: Option<RlpNode>,
    },
    Ext {
        key: Nibbles,
        child: Box<Node>,
        rlp: Option<RlpNode>,
    },
    Branch {
        children: Box<[Node; 16]>,
        rlp: Option<RlpNode>,
    },
}

fn leaf(key: Nibbles, value: Vec<u8>) -> Node {
    Node::Leaf {
        key,
        value,
        rlp: None,
    }
}

fn ext_or_child(key: Nibbles, child: Node) -> Node {
    if key.is_empty() {
        child
    } else {
        Node::Ext {
            key,
            child: Box::new(child),
            rlp: None,
        }
    }
}

/// Puts `child` behind `prefix`, merging it into a leaf or extension.
fn prepend(prefix: Nibbles, child: Node) -> Node {
    match child {
        Node::Leaf { key, value, .. } => leaf(prefix.join(&key), value),
        Node::Ext { key, child, .. } => Node::Ext {
            key: prefix.join(&key),
            child,
            rlp: None,
        },
        other => ext_or_child(prefix, other),
    }
}

impl Node {
    fn insert(&mut self, path: Nibbles, value: Vec<u8>) {
        match std::mem::take(self) {
            Node::Empty => *self = leaf(path, value),
            Node::Leaf {
                key,
                value: old,
                rlp,
            } => {
                if key == path {
                    *self = leaf(path, value);
                    return;
                }
                let c = key.common_prefix_length(&path);
                let mut children: Box<[Node; 16]> = Box::default();
                children[key.get_unchecked(c) as usize] = leaf(key.slice(c + 1..), old);
                children[path.get_unchecked(c) as usize] = leaf(path.slice(c + 1..), value);
                let _ = rlp;
                *self = ext_or_child(
                    key.slice(..c),
                    Node::Branch {
                        children,
                        rlp: None,
                    },
                );
            }
            Node::Ext { key, mut child, .. } => {
                let c = key.common_prefix_length(&path);
                if c == key.len() {
                    child.insert(path.slice(c..), value);
                    *self = Node::Ext {
                        key,
                        child,
                        rlp: None,
                    };
                    return;
                }
                let mut children: Box<[Node; 16]> = Box::default();
                children[key.get_unchecked(c) as usize] = ext_or_child(key.slice(c + 1..), *child);
                children[path.get_unchecked(c) as usize] = leaf(path.slice(c + 1..), value);
                *self = ext_or_child(
                    key.slice(..c),
                    Node::Branch {
                        children,
                        rlp: None,
                    },
                );
            }
            Node::Branch { mut children, .. } => {
                children[path.get_unchecked(0) as usize].insert(path.slice(1..), value);
                *self = Node::Branch {
                    children,
                    rlp: None,
                };
            }
        }
    }

    /// Removes `path` if present, collapsing nodes left with one child.
    fn remove(&mut self, path: &Nibbles) -> bool {
        match self {
            Node::Empty => false,
            Node::Leaf { key, .. } => {
                if key == path {
                    *self = Node::Empty;
                    true
                } else {
                    false
                }
            }
            Node::Ext { key, child, rlp } => {
                if !path.starts_with(key) || !child.remove(&path.slice(key.len()..)) {
                    return false;
                }
                *rlp = None;
                let key = *key;
                let child = std::mem::take(child.as_mut());
                *self = match child {
                    Node::Empty => Node::Empty,
                    Node::Branch { children, .. } => Node::Ext {
                        key,
                        child: Box::new(Node::Branch {
                            children,
                            rlp: None,
                        }),
                        rlp: None,
                    },
                    other => prepend(key, other),
                };
                true
            }
            Node::Branch { children, rlp } => {
                let i = path.get_unchecked(0) as usize;
                if !children[i].remove(&path.slice(1..)) {
                    return false;
                }
                *rlp = None;
                let mut live = children
                    .iter()
                    .enumerate()
                    .filter(|(_, c)| !matches!(c, Node::Empty));
                let first = live.next().map(|(i, _)| i);
                if live.next().is_none() {
                    *self = match first {
                        None => Node::Empty,
                        Some(j) => {
                            let only = std::mem::take(&mut children[j]);
                            prepend(Nibbles::from_nibbles([j as u8]), only)
                        }
                    };
                }
                true
            }
        }
    }

    fn rlp(&mut self, buf: &mut Vec<u8>) -> RlpNode {
        match self {
            Node::Empty => RlpNode::from_rlp(&[alloy_rlp::EMPTY_STRING_CODE]),
            Node::Leaf { key, value, rlp } => rlp
                .get_or_insert_with(|| {
                    buf.clear();
                    LeafNodeRef::new(key, value).rlp(buf)
                })
                .clone(),
            Node::Ext { key, child, rlp } => {
                if rlp.is_none() {
                    let c = child.rlp(buf);
                    buf.clear();
                    *rlp = Some(ExtensionNodeRef::new(key, &c).rlp(buf));
                }
                rlp.clone().unwrap()
            }
            Node::Branch { children, rlp } => {
                if rlp.is_none() {
                    let mut mask = TrieMask::default();
                    let mut stack = Vec::with_capacity(16);
                    for (i, c) in children.iter_mut().enumerate() {
                        if !matches!(c, Node::Empty) {
                            mask.set_bit(i as u8);
                            stack.push(c.rlp(buf));
                        }
                    }
                    buf.clear();
                    *rlp = Some(BranchNodeRef::new(&stack, mask).rlp(buf));
                }
                rlp.clone().unwrap()
            }
        }
    }
}

#[derive(Default)]
pub struct Trie {
    root: Node,
    len: usize,
    buf: Vec<u8>,
}

impl Trie {
    pub fn insert(&mut self, key: B256, value: Vec<u8>) {
        if !self.contains(&key) {
            self.len += 1;
        }
        self.root.insert(Nibbles::unpack(key), value);
    }

    pub fn remove(&mut self, key: B256) {
        if self.root.remove(&Nibbles::unpack(key)) {
            self.len -= 1;
        }
    }

    fn contains(&self, key: &B256) -> bool {
        let path = Nibbles::unpack(key);
        let mut node = &self.root;
        let mut at = 0;
        loop {
            match node {
                Node::Empty => return false,
                Node::Leaf { key, .. } => return *key == path.slice(at..),
                Node::Ext { key, child, .. } => {
                    if !path.slice(at..).starts_with(key) {
                        return false;
                    }
                    at += key.len();
                    node = child;
                }
                Node::Branch { children, .. } => {
                    node = &children[path.get_unchecked(at) as usize];
                    at += 1;
                }
            }
        }
    }

    pub const fn len(&self) -> usize {
        self.len
    }

    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    pub fn root(&mut self) -> B256 {
        if matches!(self.root, Node::Empty) {
            return EMPTY_ROOT_HASH;
        }
        let rlp = self.root.rlp(&mut self.buf);
        rlp.as_hash().unwrap_or_else(|| keccak256(&rlp))
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use alloy_trie::HashBuilder;

    use super::*;

    fn reference(map: &BTreeMap<B256, Vec<u8>>) -> B256 {
        let mut hb = HashBuilder::default();
        for (k, v) in map {
            hb.add_leaf(Nibbles::unpack(k), v);
        }
        hb.root()
    }

    #[test]
    fn matches_hash_builder_under_random_updates() {
        let mut seed = 0x9e3779b97f4a7c15u64;
        let mut next = || {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            seed
        };
        let mut trie = Trie::default();
        let mut map = BTreeMap::new();
        assert_eq!(trie.root(), reference(&map));
        for round in 0..300 {
            for _ in 0..(1 + next() % 40) {
                // A small key space forces overwrites, deletes and shared prefixes.
                let key = keccak256((next() % 500).to_be_bytes());
                if next() % 4 == 0 {
                    trie.remove(key);
                    map.remove(&key);
                } else {
                    let value = vec![(next() % 251) as u8; 1 + (next() % 40) as usize];
                    trie.insert(key, value.clone());
                    map.insert(key, value);
                }
            }
            assert_eq!(trie.root(), reference(&map), "round {round}");
            assert_eq!(trie.len(), map.len());
        }
    }
}
