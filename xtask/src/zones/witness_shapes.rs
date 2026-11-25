//! Finds absence proofs of the shapes a Zone must verify in the TIP-403 registry's L1 storage trie.
//!
//! A Zone deposit reads the recipient's TIP-1028 receive-policy slot from the L1 registry. This
//! proves the receive-policy slots of candidate recipients until one absence proof ends inside an
//! extension node and another at an empty child of a branch, then prints both recipients as JSON,
//! for deposits that make the Zone read those slots. It only reads, so it needs a registry with
//! enough keys to hold an extension, such as Moderato's or mainnet's.

use alloy::{
    primitives::{Address, B256, keccak256},
    providers::{Provider, ProviderBuilder},
};
use alloy_rlp::Decodable as _;
use alloy_trie::nodes::TrieNode;
use eyre::{OptionExt as _, WrapErr as _, bail};
use tempo_alloy::TempoNetwork;
use tempo_precompiles::{
    TIP403_REGISTRY_ADDRESS, storage::StorageKey, tip403_registry::tip403_registry_slots,
};

/// Slots proven per request. About 1.5% of Moderato's and mainnet's absence proofs end inside an
/// extension, so one batch usually finds both shapes.
const BATCH: usize = 256;
/// Batches to try before giving up.
const MAX_BATCHES: usize = 16;

#[derive(Debug, clap::Parser)]
pub(crate) struct WitnessShapes {
    /// Tempo L1 RPC URL.
    #[arg(long, env = "L1_RPC_URL")]
    l1_rpc_url: String,
}

impl WitnessShapes {
    pub(crate) async fn run(self) -> eyre::Result<()> {
        let provider = ProviderBuilder::new_with_network::<TempoNetwork>()
            .connect(&self.l1_rpc_url)
            .await?;
        let block = provider.get_block_number().await?;
        let mut candidates = (0u64..).map(|i| Address::from_word(keccak256(i.to_be_bytes())));
        let (mut extension, mut empty_child) = (None, None);
        for _ in 0..MAX_BATCHES {
            let recipients: Vec<_> = candidates.by_ref().take(BATCH).collect();
            let slots = recipients
                .iter()
                .map(|recipient| {
                    B256::from(recipient.mapping_slot(tip403_registry_slots::RECEIVE_POLICIES))
                })
                .collect();
            let proof = provider
                .get_proof(TIP403_REGISTRY_ADDRESS, slots)
                .number(block)
                .await
                .wrap_err("failed to read registry proofs")?;
            for (recipient, storage) in recipients.into_iter().zip(proof.storage_proof) {
                if !storage.value.is_zero() {
                    continue;
                }
                // An absence proof ends at the node its key diverges from. Storage leaves at these
                // depths are never embedded, so a final branch means an empty child.
                let end = storage.proof.last().ok_or_eyre("empty proof")?;
                match TrieNode::decode(&mut end.as_ref()).wrap_err("invalid proof node")? {
                    TrieNode::Extension(_) => extension = extension.or(Some(recipient)),
                    TrieNode::Branch(_) => empty_child = empty_child.or(Some(recipient)),
                    _ => {}
                }
            }
            if let (Some(extension), Some(empty_child)) = (extension, empty_child) {
                let shapes = serde_json::json!({
                    "recipients": [extension, empty_child],
                    "block": block,
                });
                println!("{shapes}");
                return Ok(());
            }
        }
        bail!(
            "no extension and empty-child absence proofs among {} registry slots",
            BATCH * MAX_BATCHES
        )
    }
}
