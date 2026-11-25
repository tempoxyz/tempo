//! Shapes the TIP-403 registry storage trie on Tempo L1 for absence proofs a Zone must verify.
//!
//! A Zone deposit reads the recipient's TIP-1028 receive-policy slot from the L1 registry. This
//! whitelists two accounts whose policy-set keys share [`SHARED`] leading nibbles, then picks two
//! recipients without a receive policy: the first diverges inside the extension above the
//! accounts' branch, the second at an empty child of that branch. It checks both proof shapes on
//! L1 and prints the recipients as JSON, for deposits that make the Zone read those slots.

use alloy::{
    primitives::{Address, B256, U256, keccak256},
    providers::{Provider, ProviderBuilder},
};
use alloy_rlp::Decodable as _;
use alloy_trie::nodes::TrieNode;
use eyre::{OptionExt as _, WrapErr as _, ensure};
use tempo_alloy::TempoNetwork;
use tempo_contracts::precompiles::ITIP403Registry;
use tempo_precompiles::{
    TIP403_REGISTRY_ADDRESS, storage::StorageKey, tip403_registry::tip403_registry_slots,
};

use crate::zone_utils::{check, parse_private_key};

/// Leading nibbles the whitelisted accounts' keys share. The recipients' keys share one fewer
/// (diverging inside the extension) and exactly this many (an empty child of the branch).
///
/// The extension only exists while no other registry key shares `SHARED - 1` nibbles with the
/// accounts, which each of N keys does with odds 16^-(SHARED - 1). Grinding costs about
/// 16^SHARED hashes, a few seconds in release at 5.
const SHARED: usize = 5;

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
        let (members, recipients) = grind(policy_id, SHARED);
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
        for (i, (slot, storage)) in slots.iter().zip(&proof.storage_proof).enumerate() {
            ensure!(storage.value.is_zero(), "receive policy {slot} is set");
            // An absence proof ends at the node its key diverges from: the extension, then the
            // branch. Neither recipient's last node can be embedded at these depths.
            let end = storage.proof.last().ok_or_eyre("empty proof")?;
            let end = TrieNode::decode(&mut end.as_ref()).wrap_err("invalid proof node")?;
            ensure!(
                matches!(
                    (i, &end),
                    (0, TrieNode::Extension(_)) | (1, TrieNode::Branch(_))
                ),
                "proof for {slot} ends at {end:?}"
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

/// Picks two members whose policy-set keys share exactly `shared` nibbles, and two recipients
/// whose receive-policy keys share `shared - 1` and exactly `shared` nibbles with both members.
fn grind(policy_id: u64, shared: usize) -> ([Address; 2], [Address; 2]) {
    let set = policy_id.mapping_slot(tip403_registry_slots::POLICY_SET);
    let member_key = |account: Address| trie_key(account.mapping_slot(set));
    let receive_key = |account: Address| trie_key(receive_policy_slot(account));
    let mut candidates = (0u64..).map(|i| Address::from_word(keccak256(i.to_be_bytes())));
    let mut find = |key: &dyn Fn(Address) -> B256, matches: &dyn Fn(B256) -> bool| {
        candidates
            .find(|&account| matches(key(account)))
            .expect("unbounded candidates")
    };

    let first = find(&member_key, &|_| true);
    let first_key = member_key(first);
    let second = find(&member_key, &|key| shared_nibbles(key, first_key) == shared);
    let second_key = member_key(second);
    let extension = find(&receive_key, &|key| {
        shared_nibbles(key, first_key) == shared - 1
    });
    let empty_child = find(&receive_key, &|key| {
        shared_nibbles(key, first_key) == shared && shared_nibbles(key, second_key) == shared
    });
    ([first, second], [extension, empty_child])
}

fn receive_policy_slot(account: Address) -> U256 {
    account.mapping_slot(tip403_registry_slots::RECEIVE_POLICIES)
}

fn trie_key(slot: U256) -> B256 {
    keccak256(B256::from(slot))
}

fn shared_nibbles(a: B256, b: B256) -> usize {
    U256::from_be_bytes((a ^ b).0).leading_zeros() / 4
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ground_keys_share_the_requested_prefixes() {
        // Four nibbles keep the search fast in debug builds.
        let shared = 4;
        let set = 2u64.mapping_slot(tip403_registry_slots::POLICY_SET);
        let (members, [extension, empty_child]) = grind(2, shared);
        let [first, second] = members.map(|member| trie_key(member.mapping_slot(set)));
        assert_eq!(shared_nibbles(first, second), shared);
        for member in [first, second] {
            let shares =
                |recipient| shared_nibbles(member, trie_key(receive_policy_slot(recipient)));
            assert_eq!(shares(extension), shared - 1);
            assert_eq!(shares(empty_child), shared);
        }
    }
}
