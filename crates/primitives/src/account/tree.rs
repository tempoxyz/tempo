//! Bounded, ordered active-policy tree committed in the account leaf.
use alloc::vec::Vec;
use alloy_primitives::{B256, U256, keccak256};
use alloy_rlp::{RlpDecodable, RlpEncodable};

pub const MAX_POLICIES: usize = 256;
pub const MAX_TOKENS: usize = 32;

#[derive(Clone, Debug, Default, PartialEq, Eq, Hash, RlpEncodable, RlpDecodable)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct AccountOpening {
    pub authority: B256,
    pub epoch: u64,
    pub next_id: u64,
    pub count: u16,
    pub policies: B256,
}

impl AccountOpening {
    pub fn empty(authority: B256) -> Self {
        Self {
            authority,
            policies: empty(),
            ..Self::default()
        }
    }

    pub fn commitment(&self) -> B256 {
        let mut bytes = Vec::from(b"tempo:account-tree:v2".as_slice());
        bytes.extend(alloy_rlp::encode(self));
        keccak256(bytes)
    }

    pub fn validate(&self) -> Result<(), &'static str> {
        if self.authority.is_zero()
            || self.count as usize > MAX_POLICIES
            || u64::from(self.count) > self.next_id
            || (self.count == 0 && self.policies != empty())
        {
            return Err("invalid account tree opening");
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Hash, RlpEncodable, RlpDecodable)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Usage {
    pub spent: U256,
    pub window: u64,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Hash, RlpEncodable, RlpDecodable)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct PolicyLeaf {
    pub id: u64,
    pub policy: B256,
    pub usage: Vec<Usage>,
}

impl PolicyLeaf {
    pub fn hash(&self) -> B256 {
        let mut bytes = Vec::from(b"tempo:account-tree:leaf:v2".as_slice());
        bytes.extend(alloy_rlp::encode(self));
        keccak256(bytes)
    }
}

/// Refreshable execution witness; its exact bytes remain in the transaction hash.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash, RlpEncodable, RlpDecodable)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct TreeWitness {
    pub opening: AccountOpening,
    pub index: u16,
    pub usage: Vec<Usage>,
    pub siblings: Vec<B256>,
}

/// Stable grant identity plus the mutable execution witness.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash, RlpEncodable, RlpDecodable)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct TreeAuthorization {
    pub epoch: u64,
    pub grant_id: u64,
    pub witness: TreeWitness,
}

pub fn empty() -> B256 {
    keccak256(b"tempo:account-tree:empty:v2")
}

pub fn branch(left: B256, right: B256) -> B256 {
    let mut bytes = Vec::from(b"tempo:account-tree:branch:v2".as_slice());
    bytes.extend_from_slice(left.as_slice());
    bytes.extend_from_slice(right.as_slice());
    keccak256(bytes)
}

pub fn depth(count: usize) -> usize {
    count.max(1).next_power_of_two().trailing_zeros() as usize
}

pub fn empty_subtree(height: usize) -> B256 {
    (0..height).fold(empty(), |node, _| branch(node, node))
}

pub fn root(leaves: &[B256]) -> Result<B256, &'static str> {
    if leaves.len() > MAX_POLICIES {
        return Err("too many policies");
    }
    let mut level = leaves.to_vec();
    level.resize(leaves.len().max(1).next_power_of_two(), empty());
    while level.len() > 1 {
        level = level
            .as_chunks::<2>()
            .0
            .iter()
            .map(|p| branch(p[0], p[1]))
            .collect();
    }
    Ok(level[0])
}

/// Includes an empty append position, expanding one level only when needed.
pub fn proof(leaves: &[B256], index: usize) -> Result<Vec<B256>, &'static str> {
    if index > leaves.len() || index >= MAX_POLICIES {
        return Err("invalid policy index");
    }
    let mut level = leaves.to_vec();
    level.resize((index + 1).max(leaves.len()).next_power_of_two(), empty());
    let mut result = Vec::new();
    let mut position = index;
    while level.len() > 1 {
        result.push(level[position ^ 1]);
        position /= 2;
        level = level
            .as_chunks::<2>()
            .0
            .iter()
            .map(|p| branch(p[0], p[1]))
            .collect();
    }
    Ok(result)
}

pub fn replace_root(
    mut leaf: B256,
    index: usize,
    count: usize,
    siblings: &[B256],
) -> Result<B256, &'static str> {
    if count == 0 || count > MAX_POLICIES || index >= count || siblings.len() != depth(count) {
        return Err("invalid policy proof shape");
    }
    for (height, sibling) in siblings.iter().enumerate() {
        // Right padding has one canonical value; the live count is authenticated.
        let sibling_start = ((index >> height) ^ 1) << height;
        if sibling_start >= count && *sibling != empty_subtree(height) {
            return Err("noncanonical policy padding");
        }
        leaf = if (index >> height) & 1 == 0 {
            branch(leaf, *sibling)
        } else {
            branch(*sibling, leaf)
        };
    }
    Ok(leaf)
}

impl TreeAuthorization {
    pub fn digest(&self, policy: B256) -> B256 {
        let mut bytes = Vec::from(b"tempo:account-tree:grant:v2".as_slice());
        bytes.extend_from_slice(policy.as_slice());
        bytes.extend_from_slice(&self.epoch.to_be_bytes());
        bytes.extend_from_slice(&self.grant_id.to_be_bytes());
        keccak256(bytes)
    }

    /// Authenticate membership or the next empty append position, then install the leaf.
    pub fn open(
        &self,
        policy: B256,
        tokens: usize,
    ) -> Result<(AccountOpening, PolicyLeaf), &'static str> {
        let w = &self.witness;
        w.opening.validate()?;
        if self.epoch != w.opening.epoch || tokens > MAX_TOKENS || w.usage.len() != tokens {
            return Err("invalid policy epoch or usage vector");
        }
        let mut opening = w.opening.clone();
        let leaf = PolicyLeaf {
            id: self.grant_id,
            policy,
            usage: w.usage.clone(),
        };
        if self.grant_id == opening.next_id {
            if usize::from(opening.count) == MAX_POLICIES
                || w.index != opening.count
                || w.usage.iter().any(|u| !u.spent.is_zero() || u.window != 0)
            {
                return Err("invalid policy installation");
            }
            let n = usize::from(opening.count);
            let old = replace_root(empty(), n, n + 1, &w.siblings)?;
            let expected = if n > 0 && n.is_power_of_two() {
                branch(opening.policies, empty_subtree(depth(n)))
            } else {
                opening.policies
            };
            if old != expected {
                return Err("invalid policy append proof");
            }
            opening.next_id = opening
                .next_id
                .checked_add(1)
                .ok_or("grant allocator exhausted")?;
            opening.count += 1;
        } else {
            if self.grant_id >= opening.next_id
                || replace_root(
                    leaf.hash(),
                    w.index.into(),
                    opening.count.into(),
                    &w.siblings,
                )? != opening.policies
            {
                return Err("invalid or stale policy proof");
            }
        }
        opening.policies = replace_root(
            leaf.hash(),
            w.index.into(),
            opening.count.into(),
            &w.siblings,
        )?;
        Ok((opening, leaf))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn account_tree_rejects_changed_usage_identity_epoch_and_overflow() {
        let policy = B256::repeat_byte(2);
        let leaf = PolicyLeaf {
            id: 4,
            policy,
            usage: vec![Usage {
                spent: U256::from(7),
                window: 1,
            }],
        };
        let opening = AccountOpening {
            authority: B256::repeat_byte(1),
            epoch: 3,
            next_id: 5,
            count: 1,
            policies: leaf.hash(),
        };
        let auth = TreeAuthorization {
            epoch: 3,
            grant_id: 4,
            witness: TreeWitness {
                opening,
                index: 0,
                usage: leaf.usage.clone(),
                siblings: vec![],
            },
        };
        assert!(auth.open(policy, 1).is_ok());
        for change in 0..6 {
            let mut bad = auth.clone();
            match change {
                0 => bad.witness.usage[0].spent = U256::ZERO,
                1 => bad.witness.usage[0].window = 0,
                2 => bad.grant_id = 3,
                3 => bad.epoch = 2,
                4 => bad.witness.index = 1,
                _ => bad.witness.siblings.push(empty()),
            }
            assert!(bad.open(policy, 1).is_err());
        }
        assert!(auth.open(B256::repeat_byte(3), 1).is_err());
        assert!(auth.open(policy, 0).is_err());
        let mut empty_opening = AccountOpening::empty(B256::repeat_byte(1));
        empty_opening.next_id = u64::MAX;
        let auth = TreeAuthorization {
            epoch: 0,
            grant_id: u64::MAX,
            witness: TreeWitness {
                opening: empty_opening,
                ..Default::default()
            },
        };
        assert!(auth.open(policy, 0).is_err());
    }
    #[test]
    fn account_tree_append_replace_and_padding() {
        let mut opening = AccountOpening::empty(B256::repeat_byte(1));
        let mut leaves = Vec::new();
        for id in 0..256 {
            let tree = TreeAuthorization {
                epoch: 0,
                grant_id: id,
                witness: TreeWitness {
                    opening: opening.clone(),
                    index: id as u16,
                    usage: vec![Usage::default()],
                    siblings: proof(&leaves, id as usize).unwrap(),
                },
            };
            let (next, mut leaf) = tree.open(B256::repeat_byte(2), 1).unwrap();
            leaves.push(leaf.hash());
            assert_eq!(next.policies, root(&leaves).unwrap());
            leaf.usage[0].spent = U256::from(123);
            let siblings = proof(&leaves, id as usize).unwrap();
            leaves[id as usize] = leaf.hash();
            opening = next;
            opening.policies =
                replace_root(leaf.hash(), id as usize, leaves.len(), &siblings).unwrap();
            assert_eq!(opening.policies, root(&leaves).unwrap());
        }
        assert_eq!(depth(1), 0);
        assert_eq!(depth(4), 2);
        assert!(proof(&leaves, 256).is_err());
    }
}
