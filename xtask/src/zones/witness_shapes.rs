//! Shapes the TIP-403 registry storage trie on Tempo L1 for absence proofs a Zone must verify.
//!
//! A Zone deposit reads the recipient's TIP-1028 receive-policy slot from the L1 registry. This
//! whitelists two accounts whose policy-set keys share [`SHARED`] leading nibbles, then picks two
//! recipients without a receive policy: the first diverges inside the extension above the
//! accounts' branch, the second at an empty child of that branch. It checks both proof shapes on
//! L1 and prints the recipients as JSON, for deposits that make the Zone read those slots.

use alloy::{
    primitives::{Address, B256, Bytes, U256, keccak256},
    providers::{Provider, ProviderBuilder},
};
use alloy_rlp::Decodable as _;
use alloy_trie::{Nibbles, nodes::TrieNode};
use eyre::{OptionExt as _, WrapErr as _, bail, ensure};
use std::collections::{HashMap, hash_map::Entry};
use tempo_alloy::TempoNetwork;
use tempo_contracts::precompiles::ITIP403Registry;
use tempo_precompiles::{
    TIP403_REGISTRY_ADDRESS, storage::StorageKey, tip403_registry::tip403_registry_slots,
};

use crate::zone_utils::{check, parse_private_key};

/// Leading nibbles the whitelisted accounts' keys share. The recipients' keys share one fewer
/// (diverging inside the extension) and exactly this many (an empty child of the branch).
const SHARED: usize = 4;

#[derive(Debug, clap::Parser)]
pub(crate) struct WitnessShapes {
    /// Tempo L1 RPC URL.
    #[arg(long, env = "L1_RPC_URL")]
    l1_rpc_url: String,

    /// Private key (hex) that creates and administers the whitelist policy.
    #[arg(long, env = "PRIVATE_KEY", hide_env_values = true)]
    private_key: String,
}

impl WitnessShapes {
    pub(crate) async fn run(self) -> eyre::Result<()> {
        let signer = parse_private_key(&self.private_key)?;
        let admin = signer.address();
        let provider = ProviderBuilder::new_with_network::<TempoNetwork>()
            .wallet(signer)
            .connect(&self.l1_rpc_url)
            .await?;
        let registry = ITIP403Registry::new(TIP403_REGISTRY_ADDRESS, &provider);

        // The policy ID is part of every member's slot, so grind for the next one.
        let policy_id = registry.policyIdCounter().call().await?;
        let (members, recipients) = grind(policy_id);
        let receipt = registry
            .createPolicyWithAccounts(
                admin,
                ITIP403Registry::PolicyType::WHITELIST,
                members.to_vec(),
            )
            .send_sync()
            .await
            .wrap_err("failed to create the whitelist policy")?;
        check(&receipt, "createPolicyWithAccounts")?;
        let created = receipt
            .decoded_log::<ITIP403Registry::PolicyCreated>()
            .ok_or_eyre("no PolicyCreated event")?
            .policyId;
        ensure!(
            created == policy_id,
            "created policy {created}, ground for {policy_id}"
        );

        let block = receipt.block_number.ok_or_eyre("receipt has no block")?;
        let slots = recipients.map(|recipient| B256::from(receive_policy_slot(recipient)));
        let proof = provider
            .get_proof(TIP403_REGISTRY_ADDRESS, slots.to_vec())
            .number(block)
            .await
            .wrap_err("failed to read registry proofs")?;
        for ((slot, storage), expected) in slots
            .iter()
            .zip(&proof.storage_proof)
            .zip([ProofEnd::Extension, ProofEnd::EmptyChild])
        {
            ensure!(storage.value.is_zero(), "receive policy {slot} is set");
            let end = proof_end(&storage.proof, keccak256(slot))?;
            ensure!(
                end == expected,
                "proof for {slot} ends at {end:?}, not {expected:?}"
            );
        }

        let shapes = serde_json::json!({
            "policy_id": policy_id,
            "members": members,
            "recipients": recipients,
            "block": block,
        });
        println!("{shapes}");
        Ok(())
    }
}

/// The node at which a proof for an absent key stops.
#[derive(Debug, PartialEq, Eq)]
enum ProofEnd {
    /// The key diverges inside an extension node.
    Extension,
    /// The key reaches a branch without a child at its next nibble.
    EmptyChild,
    /// The key reaches a leaf for another key.
    Leaf,
}

/// Picks two members whose policy-set keys share exactly [`SHARED`] nibbles, and two recipients
/// whose receive-policy keys share `SHARED - 1` and exactly `SHARED` nibbles with both members.
fn grind(policy_id: u64) -> ([Address; 2], [Address; 2]) {
    let set = policy_id.mapping_slot(tip403_registry_slots::POLICY_SET);
    let mut candidates = (0u64..).map(|i| Address::from_word(keccak256(i.to_be_bytes())));
    let mut seen = HashMap::new();
    let members = loop {
        let member = candidates.next().expect("unbounded candidates");
        let key = trie_key(member.mapping_slot(set));
        match seen.entry(key.slice(..SHARED)) {
            Entry::Vacant(entry) => {
                entry.insert((member, key));
            }
            Entry::Occupied(entry) if entry.get().1.common_prefix_length(&key) == SHARED => {
                break [*entry.get(), (member, key)];
            }
            Entry::Occupied(_) => {}
        }
    };

    let (mut extension, mut empty_child) = (None, None);
    loop {
        let recipient = candidates.next().expect("unbounded candidates");
        let key = trie_key(receive_policy_slot(recipient));
        match members
            .each_ref()
            .map(|(_, member)| member.common_prefix_length(&key))
        {
            [shared, _] if shared == SHARED - 1 => extension = extension.or(Some(recipient)),
            [SHARED, SHARED] => empty_child = empty_child.or(Some(recipient)),
            _ => {}
        }
        if let (Some(extension), Some(empty_child)) = (extension, empty_child) {
            return (members.map(|(member, _)| member), [extension, empty_child]);
        }
    }
}

/// Walks a storage proof from the root along `key` and reports where it stops.
fn proof_end(nodes: &[Bytes], key: B256) -> eyre::Result<ProofEnd> {
    let path = Nibbles::unpack(key);
    let mut depth = 0;
    for node in nodes {
        match TrieNode::decode(&mut node.as_ref()).wrap_err("invalid proof node")? {
            TrieNode::Branch(branch) => {
                if !branch.state_mask.is_bit_set(path.get_unchecked(depth)) {
                    return Ok(ProofEnd::EmptyChild);
                }
                depth += 1;
            }
            TrieNode::Extension(extension) => {
                if !path.slice(depth..).starts_with(&extension.key) {
                    return Ok(ProofEnd::Extension);
                }
                depth += extension.key.len();
            }
            TrieNode::Leaf(_) => return Ok(ProofEnd::Leaf),
            TrieNode::EmptyRoot => bail!("registry storage is empty"),
        }
    }
    bail!("proof stops at depth {depth} without reaching its end")
}

fn receive_policy_slot(account: Address) -> U256 {
    account.mapping_slot(tip403_registry_slots::RECEIVE_POLICIES)
}

fn trie_key(slot: U256) -> Nibbles {
    Nibbles::unpack(keccak256(B256::from(slot)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ground_keys_share_the_requested_prefixes() {
        let set = 2u64.mapping_slot(tip403_registry_slots::POLICY_SET);
        let (members, [extension, empty_child]) = grind(2);
        let [first, second] = members.map(|member| trie_key(member.mapping_slot(set)));
        assert_eq!(first.common_prefix_length(&second), SHARED);
        for member in [first, second] {
            let shared =
                |recipient| member.common_prefix_length(&trie_key(receive_policy_slot(recipient)));
            assert_eq!(shared(extension), SHARED - 1);
            assert_eq!(shared(empty_child), SHARED);
        }
    }
}
