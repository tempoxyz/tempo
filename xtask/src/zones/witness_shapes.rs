//! Shapes the TIP-403 registry's L1 storage trie so two absent receive-policy slots prove through
//! an extension node and through a branch's empty child, and prints their recipients as JSON, for
//! deposits that make a Zone verify both proof shapes. It whitelists two ground accounts on a new
//! policy, whose `policy_set` keys share a trie path prefix and so hang below an extension.

use alloy::{
    primitives::{Address, B256, U256, keccak256},
    providers::{Provider, ProviderBuilder},
};
use alloy_rlp::Decodable as _;
use alloy_trie::nodes::TrieNode;
use eyre::{OptionExt as _, WrapErr as _, ensure};
use tempo_alloy::TempoNetwork;
use tempo_contracts::precompiles::ITIP403Registry as TIP403Registry;
use tempo_precompiles::{
    TIP403_REGISTRY_ADDRESS, storage::StorageKey, tip403_registry::tip403_registry_slots,
};

use crate::zone_utils::{check, normalize_http_rpc, parse_private_key};

/// Nibbles the two whitelisted keys share: an extension spans the last ones.
const PREFIX: usize = 3;

#[derive(Debug, clap::Parser)]
pub(crate) struct WitnessShapes {
    /// L1 RPC URL that receives the policy transactions and serves the registry proofs.
    #[arg(long, env = "L1_RPC_URL")]
    l1_rpc_url: String,

    /// Private key (hex) that creates the policy and whitelists the ground accounts.
    #[arg(long, env = "PRIVATE_KEY", hide_env_values = true)]
    private_key: String,
}

fn nibble(path: &B256, index: usize) -> u8 {
    (path[index / 2] >> if index.is_multiple_of(2) { 4 } else { 0 }) & 0xf
}

/// The storage trie path of a slot.
fn path(slot: U256) -> B256 {
    keccak256(B256::from(slot))
}

/// The first ground address, from seed, whose slot path satisfies accept.
fn grind(seed: u64, slot: impl Fn(Address) -> U256, accept: impl Fn(&B256) -> bool) -> Address {
    (0u64..)
        .map(|i| Address::from_word(keccak256([seed.to_be_bytes(), i.to_be_bytes()].concat())))
        .find(|address| accept(&path(slot(*address))))
        .expect("an unbounded search finds a match")
}

impl WitnessShapes {
    pub(crate) async fn run(self) -> eyre::Result<()> {
        let signer = parse_private_key(&self.private_key)?;
        let admin = signer.address();
        let provider = ProviderBuilder::new_with_network::<TempoNetwork>()
            .wallet(signer)
            .connect(&normalize_http_rpc(&self.l1_rpc_url))
            .await?;
        let registry = TIP403Registry::new(TIP403_REGISTRY_ADDRESS, &provider);
        let receipt = registry
            .createPolicy(admin, TIP403Registry::PolicyType::WHITELIST)
            .send_sync()
            .await?;
        check(&receipt, "createPolicy(whitelist)")?;
        let policy_id = receipt
            .decoded_log::<TIP403Registry::PolicyCreated>()
            .map(|event| event.policyId)
            .ok_or_eyre("no PolicyCreated event")?;
        let policy_slot = policy_id.mapping_slot(tip403_registry_slots::POLICY_SET);
        let whitelisted = |account: Address| account.mapping_slot(policy_slot);
        let receive =
            |account: Address| account.mapping_slot(tip403_registry_slots::RECEIVE_POLICIES);

        // Both keys share the prefix and part at its next nibble, so the trie keeps a branch
        // there below an extension, unless an existing key shares it: the proofs catch that.
        let first = grind(0, whitelisted, |_| true);
        let prefix = path(whitelisted(first));
        let shares = |p: &B256, len: usize| (0..len).all(|i| nibble(p, i) == nibble(&prefix, i));
        let second = grind(1, whitelisted, |p| {
            shares(p, PREFIX) && nibble(p, PREFIX) != nibble(&prefix, PREFIX)
        });
        let children = [
            nibble(&prefix, PREFIX),
            nibble(&path(whitelisted(second)), PREFIX),
        ];
        // Diverging inside the extension ends at it; below it, an unused nibble is empty.
        let extension = grind(2, receive, |p| {
            shares(p, PREFIX - 1) && nibble(p, PREFIX - 1) != nibble(&prefix, PREFIX - 1)
        });
        let empty_child = grind(3, receive, |p| {
            shares(p, PREFIX) && !children.contains(&nibble(p, PREFIX))
        });
        for account in [first, second] {
            let receipt = registry
                .modifyPolicyWhitelist(policy_id, account, true)
                .send_sync()
                .await?;
            check(&receipt, "modifyPolicyWhitelist")?;
        }
        let slots = [extension, empty_child]
            .map(|r| B256::from(receive(r)))
            .to_vec();
        let proof = tokio::time::timeout(
            std::time::Duration::from_secs(30),
            provider.get_proof(TIP403_REGISTRY_ADDRESS, slots),
        )
        .await
        .wrap_err("timed out reading registry proofs")?
        .wrap_err("failed to read registry proofs")?;
        let ends = proof
            .storage_proof
            .iter()
            .map(|storage| {
                // Leaves at this depth encode to at least 32 bytes, so none is inlined into its
                // branch: a proof ending at a branch means the selected child is empty.
                let end = storage.proof.last().ok_or_eyre("empty proof")?;
                TrieNode::decode(&mut end.as_ref()).wrap_err("invalid proof node")
            })
            .collect::<eyre::Result<Vec<_>>>()?;
        ensure!(
            matches!(
                ends.as_slice(),
                [TrieNode::Extension(_), TrieNode::Branch(_)]
            ),
            "an existing registry key shares the ground prefix"
        );
        println!(
            "{}",
            serde_json::json!({ "recipients": [extension, empty_child] })
        );
        Ok(())
    }
}
