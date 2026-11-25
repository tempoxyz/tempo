//! Finds receive-policy slots in the TIP-403 registry's L1 storage trie whose absence proofs end
//! inside an extension and at a branch's empty child, and prints their recipients as JSON, for
//! deposits that make a Zone verify both proof shapes.

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

const BATCH: usize = 256;
const MAX_BATCHES: usize = 32;

#[derive(Debug, clap::Parser)]
pub(crate) struct WitnessShapes {
    #[arg(long, env = "L1_RPC_URL")]
    l1_rpc_url: String,
}

impl WitnessShapes {
    pub(crate) async fn run(self) -> eyre::Result<()> {
        let provider = ProviderBuilder::new_with_network::<TempoNetwork>()
            .connect(&self.l1_rpc_url)
            .await?;
        let mut candidates = (0u64..).map(|i| Address::from_word(keccak256(i.to_be_bytes())));
        let (mut extension, mut empty_child) = (None, None);
        for _ in 0..MAX_BATCHES {
            let recipients: Vec<_> = candidates.by_ref().take(BATCH).collect();
            let slots = recipients
                .iter()
                .map(|r| B256::from(r.mapping_slot(tip403_registry_slots::RECEIVE_POLICIES)))
                .collect();
            let proof = tokio::time::timeout(
                std::time::Duration::from_secs(30),
                provider.get_proof(TIP403_REGISTRY_ADDRESS, slots),
            )
            .await
            .wrap_err("timed out reading registry proofs")?
            .wrap_err("failed to read registry proofs")?;
            for (recipient, storage) in recipients.into_iter().zip(proof.storage_proof) {
                // A proof ends where its key diverges. Leaves this deep are never embedded, so a
                // set slot ends at its leaf and an absent one at an extension or a branch.
                let end = storage.proof.last().ok_or_eyre("empty proof")?;
                match TrieNode::decode(&mut end.as_ref()).wrap_err("invalid proof node")? {
                    TrieNode::Extension(_) => extension = extension.or(Some(recipient)),
                    TrieNode::Branch(_) => empty_child = empty_child.or(Some(recipient)),
                    _ => {}
                }
            }
            if let (Some(extension), Some(empty_child)) = (extension, empty_child) {
                println!(
                    "{}",
                    serde_json::json!({ "recipients": [extension, empty_child] })
                );
                return Ok(());
            }
        }
        bail!(
            "no extension and empty-child proofs among {} slots",
            BATCH * MAX_BATCHES
        )
    }
}
