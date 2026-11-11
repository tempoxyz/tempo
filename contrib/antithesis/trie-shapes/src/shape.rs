//! Which shapes a block's tries reach, measured from their sorted keys and reported as Antithesis
//! coverage. Generators aim for shapes; this checks the tries really have them.

use crate::exploration::sometimes_each;
use alloy_primitives::{Address, B256};
use alloy_trie::{nodes::LeafNode, Nibbles};
use antithesis_sdk::assert_sometimes;
use serde_json::json;
use std::collections::{HashMap, HashSet};

/// A trie's leaves: hashed key and RLP-encoded value. Account trie values may be left empty, as
/// account leaves are never embedded.
pub type Leaves = Vec<(B256, Vec<u8>)>;

/// The nodes of one trie: branch paths, and extensions as their end path and length.
#[derive(Debug, Default)]
struct Nodes {
    branches: HashSet<Nibbles>,
    extensions: Vec<(Nibbles, usize)>,
    keys: usize,
}

/// Shapes reached in one block, across all its tries.
#[derive(Debug, Default)]
struct Reached {
    long_extension: bool,
    nested_extension: bool,
    full_branch_below_root: bool,
    full_branch_deep: bool,
    deep_narrow_branch: bool,
    deep_account_branch: bool,
    embedded_leaf: bool,
    large_storage: bool,
    emptied_storage: bool,
    collapsed_branch: bool,
    split_extension: bool,
}

/// Measures each block's tries and compares them with the previous block's.
#[derive(Debug, Default)]
pub struct ShapeTracker {
    previous: HashMap<Option<Address>, Nodes>,
}

impl ShapeTracker {
    /// Measures one block's tries: the account trie under None, each account's storage trie
    /// under its address, empty ones included.
    pub fn observe(&mut self, tries: Vec<(Option<Address>, Leaves)>) {
        let mut reached = Reached::default();
        let mut current = HashMap::with_capacity(tries.len());
        for (trie, mut leaves) in tries {
            leaves.sort_unstable_by_key(|(key, _)| *key);
            let keys = leaves.iter().map(|(key, _)| Nibbles::unpack(*key)).collect::<Vec<_>>();
            let root = match keys.len() {
                0 => "empty",
                1 => "leaf",
                _ if keys[0].common_prefix_length(&keys[keys.len() - 1]) == 0 => "branch",
                _ => "extension",
            };
            sometimes_each!(
                "Observed trie root shape",
                json!({"storage": trie.is_some(), "root": root})
            );
            let mut nodes = Nodes { keys: keys.len(), ..Default::default() };
            if !keys.is_empty() {
                walk(trie.is_some(), &keys, &leaves, 0, 0, &mut nodes, &mut reached);
            }
            if let Some(previous) = self.previous.get(&trie) {
                reached.emptied_storage |= trie.is_some() && previous.keys > 0 && keys.is_empty();
                // A branch that is gone while keys remain under it merged into a leaf or extension.
                reached.collapsed_branch |= previous.branches.iter().any(|branch| {
                    !nodes.branches.contains(branch) &&
                        keys.iter().any(|key| key.starts_with(branch))
                });
                // A branch now inside an earlier extension's path split that extension.
                reached.split_extension |= previous.extensions.iter().any(|(end, length)| {
                    (end.len() - length + 1..end.len())
                        .any(|at| nodes.branches.contains(&end.slice(..at)))
                });
            }
            reached.large_storage |= trie.is_some() && keys.len() >= 128;
            current.insert(trie, nodes);
        }
        self.previous = current;

        let details = json!({"tries": self.previous.len()});
        assert_sometimes!(
            reached.long_extension,
            "A trie has an extension of 8 or more nibbles",
            &details
        );
        assert_sometimes!(
            reached.nested_extension,
            "A trie has an extension below a branch below an extension",
            &details
        );
        assert_sometimes!(
            reached.full_branch_below_root,
            "A trie has a 16-child branch below the root",
            &details
        );
        assert_sometimes!(
            reached.full_branch_deep,
            "A trie has a 16-child branch at depth 2 or more",
            &details
        );
        assert_sometimes!(
            reached.deep_narrow_branch,
            "A trie has a 2-child branch at depth 8 or more",
            &details
        );
        assert_sometimes!(
            reached.deep_account_branch,
            "The account trie has a branch at depth 6 or more",
            &details
        );
        assert_sometimes!(reached.embedded_leaf, "A storage trie has an embedded leaf", &details);
        assert_sometimes!(
            reached.large_storage,
            "A storage trie holds 128 or more slots",
            &details
        );
        assert_sometimes!(reached.emptied_storage, "A storage trie is emptied", &details);
        assert_sometimes!(
            reached.collapsed_branch,
            "A branch collapses while keys remain below it",
            &details
        );
        assert_sometimes!(reached.split_extension, "An extension splits", &details);
    }
}

/// Walks the subtrie of the sorted keys below depth nibbles, recording its nodes and shapes.
/// extensions counts the extensions on the path from the root.
fn walk(
    storage: bool,
    keys: &[Nibbles],
    leaves: &[(B256, Vec<u8>)],
    depth: usize,
    extensions: usize,
    nodes: &mut Nodes,
    reached: &mut Reached,
) {
    if keys.len() == 1 {
        // Account values may be omitted by the caller, so their encoding size is unknown.
        let embedded = storage.then(|| {
            let leaf = LeafNode::new(keys[0].slice(depth..), leaves[0].1.clone());
            depth > 0 && alloy_rlp::encode(leaf).len() < 32
        });
        reached.embedded_leaf |= embedded == Some(true);
        sometimes_each!(
            "Observed trie leaf shape",
            json!({"storage": storage, "depth": depth, "root": depth == 0, "embedded": embedded})
        );
        return;
    }
    let branch = keys[0].common_prefix_length(&keys[keys.len() - 1]);
    let mut extensions = extensions;
    if branch > depth {
        let length = branch - depth;
        nodes.extensions.push((keys[0].slice(..branch), length));
        extensions += 1;
        reached.long_extension |= length >= 8;
        reached.nested_extension |= extensions >= 2;
        sometimes_each!(
            "Observed trie extension shape",
            json!({"storage": storage, "depth": depth, "root": depth == 0, "length": length})
        );
    }
    nodes.branches.insert(keys[0].slice(..branch));
    let mut state_mask = 0u16;
    let mut start = 0;
    while start < keys.len() {
        let nibble = keys[start].get_unchecked(branch);
        let end = start +
            keys[start..].iter().take_while(|key| key.get_unchecked(branch) == nibble).count();
        walk(
            storage,
            &keys[start..end],
            &leaves[start..end],
            branch + 1,
            extensions,
            nodes,
            reached,
        );
        state_mask |= 1u16 << nibble;
        start = end;
    }
    // Occupied children follow from the model's complete keys, not sparse-trie cache masks.
    sometimes_each!(
        "Observed trie branch shape",
        json!({"storage": storage, "depth": branch, "root": branch == 0, "state_mask": state_mask})
    );
    let children = state_mask.count_ones();
    reached.full_branch_below_root |= children == 16 && branch >= 1;
    reached.full_branch_deep |= children == 16 && branch >= 2;
    reached.deep_narrow_branch |= children == 2 && branch >= 8;
    reached.deep_account_branch |= !storage && branch >= 6;
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::{b256, keccak256};

    fn leaves(keys: &[B256]) -> Leaves {
        keys.iter().map(|key| (*key, alloy_rlp::encode(alloy_primitives::U256::from(1)))).collect()
    }

    fn measure(keys: &[B256]) -> (Nodes, Reached) {
        let mut leaves = leaves(keys);
        leaves.sort_unstable_by_key(|(key, _)| *key);
        let nibbles = leaves.iter().map(|(key, _)| Nibbles::unpack(*key)).collect::<Vec<_>>();
        let mut nodes = Nodes::default();
        let mut reached = Reached::default();
        walk(true, &nibbles, &leaves, 0, 0, &mut nodes, &mut reached);
        (nodes, reached)
    }

    #[test]
    fn measures_extensions_and_branches() {
        // Two keys sharing 10 nibbles: a root extension of 10 and a 2-child branch at depth 10,
        // with 1-byte values embedded below it.
        let a = b256!("0123456789a00000000000000000000000000000000000000000000000000000");
        let b = b256!("0123456789b00000000000000000000000000000000000000000000000000000");
        let (nodes, reached) = measure(&[a, b]);
        assert_eq!(nodes.extensions, vec![(Nibbles::unpack(a).slice(..10), 10)]);
        assert!(reached.long_extension && reached.deep_narrow_branch && reached.embedded_leaf);
        assert!(!reached.full_branch_below_root);

        // A key diverging at the root nests the pair's extension below a root branch.
        let c = b256!("f000000000000000000000000000000000000000000000000000000000000000");
        let (_, reached) = measure(&[a, b, c]);
        assert!(!reached.nested_extension);
        let d = b256!("0123000000000000000000000000000000000000000000000000000000000000");
        let (_, reached) = measure(&[a, b, c, d]);
        assert!(reached.nested_extension);
    }

    #[test]
    fn measures_full_branches_and_transitions() {
        let fan = (0..16u8)
            .map(|nibble| {
                let mut key = [0u8; 32];
                key[0] = 0x12;
                key[1] = nibble << 4;
                B256::from(key)
            })
            .collect::<Vec<_>>();
        let (_, reached) = measure(&fan);
        assert!(reached.full_branch_below_root && reached.full_branch_deep);

        let mut tracker = ShapeTracker::default();
        let keys = [keccak256([1u8]), keccak256([2u8]), keccak256([3u8])];
        tracker.observe(vec![(Some(Address::ZERO), leaves(&keys))]);
        tracker.observe(vec![(Some(Address::ZERO), leaves(&keys[..1]))]);
        tracker.observe(vec![(Some(Address::ZERO), Vec::new())]);
    }
}
