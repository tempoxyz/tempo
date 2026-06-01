use std::{sync::Arc, time::Instant};

use alloy_primitives::Bytes;
use eyre::WrapErr as _;
use reth_primitives_traits::{AlloyBlockHeader as _, SealedBlock};
use reth_tracing::tracing::info;
use reth_trie_parallel::state_root_task::StateRootHandle;
use tempo_payload_types::TempoExecutionData;
use tempo_primitives::Block as TempoBlock;

use crate::TempoFullNode;

/// Requests a private Reth sparse-trie state-root pipeline for a BAL speculative child build.
///
/// Reth owns the live sparse-trie and state-trie-overlay state, so the snapshot must be prepared by
/// the engine tree before consensus submits the parent block for validation. The returned handle is
/// backed by private cloned state and can be passed to the payload builder without mutating
/// validation caches.
pub async fn speculative_bal_state_root_handle(
    node: &TempoFullNode,
    speculative_parent_block: &SealedBlock<TempoBlock>,
    block_access_list: &Bytes,
) -> eyre::Result<StateRootHandle> {
    let prepare_start = Instant::now();
    let payload = TempoExecutionData {
        block: Arc::new(speculative_parent_block.clone()),
        block_access_list: Some(block_access_list.clone()),
        validator_set: None,
    };

    let handle = node
        .add_ons_handle
        .beacon_engine_handle
        .payload_builder_sparse_trie_handle::<StateRootHandle>(payload)
        .await
        .wrap_err("failed preparing speculative BAL sparse trie through Reth engine")?;

    info!(
        parent_hash = %speculative_parent_block.hash(),
        parent_number = speculative_parent_block.number(),
        parent_state_root = %speculative_parent_block.state_root(),
        prepare_elapsed = ?prepare_start.elapsed(),
        "prepared speculative BAL sparse-trie handle from Reth snapshot",
    );

    Ok(handle)
}
