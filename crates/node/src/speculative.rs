use std::{sync::Arc, time::Duration, time::Instant};

use alloy_primitives::Bytes;
use eyre::{WrapErr as _, eyre};
use reth_chain_state::{ComputedTrieData, ExecutedBlock, StateTrieOverlayManager};
use reth_engine_tree::tree::{PayloadProcessor, precompile_cache::PrecompileCacheMap};
use reth_execution_types::BlockExecutionOutput;
use reth_primitives_traits::{
    AlloyBlockHeader as _, RecoveredBlock, SealedBlock, SignedTransaction,
};
use reth_provider::{
    StateProviderFactory as _,
    providers::{OverlayBuilder, OverlayStateProviderFactory},
};
use reth_storage_api::StateRootProvider as _;
use reth_tracing::tracing::{info, warn};
use reth_trie_db::ChangesetCache;
use reth_trie_parallel::state_root_task::StateRootHandle;
use tempo_payload_builder::bal_overlay::block_access_list_hashed_post_state;
use tempo_primitives::{Block as TempoBlock, TempoPrimitives, TempoReceipt};

use crate::TempoFullNode;

const SPARSE_TRIE_PREPARE_SLOW_THRESHOLD: Duration = Duration::from_millis(50);

/// Creates a private sparse-trie state-root pipeline for a BAL speculative child build.
///
/// The handle is intentionally not wired to Reth's global preserved sparse trie. It is backed by a
/// fresh `PayloadProcessor` and a private Reth `StateTrieOverlayManager` seeded with B's
/// BAL-derived post-state and trie updates. This gives proof workers the same trie-node overlay
/// Reth uses for in-memory parents without mutating the shared execution or sparse-trie caches.
pub fn speculative_bal_state_root_handle(
    node: &TempoFullNode,
    speculative_parent_block: &SealedBlock<TempoBlock>,
    block_access_list: &Bytes,
) -> eyre::Result<StateRootHandle> {
    let prepare_start = Instant::now();
    let base_parent_hash = speculative_parent_block.parent_hash();
    let speculative_parent_hash = speculative_parent_block.hash();
    let speculative_parent_state_root = speculative_parent_block.state_root();

    let base_provider = node
        .provider
        .state_by_block_hash(base_parent_hash)
        .wrap_err_with(|| {
            eyre!(
                "failed loading base parent state `{base_parent_hash}` for speculative BAL sparse trie",
            )
        })?;

    let decode_start = Instant::now();
    let bal_post_state =
        block_access_list_hashed_post_state(base_provider.as_ref(), block_access_list)
            .wrap_err("failed decoding BAL post-state for speculative sparse trie")?;
    let decode_elapsed = decode_start.elapsed();

    let bal_accounts = bal_post_state.accounts.len();
    let bal_storage_accounts = bal_post_state.storages.len();
    let bal_storage_slots: usize = bal_post_state
        .storages
        .values()
        .map(|storage| storage.storage.len())
        .sum();

    let parent_state_root_start = Instant::now();
    let (computed_parent_state_root, parent_trie_updates) = base_provider
        .state_root_with_updates(bal_post_state.clone())
        .wrap_err("failed computing BAL parent trie updates for speculative sparse trie")?;
    let parent_state_root_elapsed = parent_state_root_start.elapsed();
    if computed_parent_state_root != speculative_parent_state_root {
        return Err(eyre!(
            "BAL post-state root mismatch for speculative parent `{speculative_parent_hash}`: computed `{computed_parent_state_root}`, header `{speculative_parent_state_root}`",
        ));
    }

    let parent_trie_updates_total = parent_trie_updates.account_nodes_ref().len()
        + parent_trie_updates.removed_nodes_ref().len()
        + parent_trie_updates
            .storage_tries_ref()
            .values()
            .map(|storage| storage.len())
            .sum::<usize>();

    let overlay_seed_start = Instant::now();
    let trie_data = ComputedTrieData::new(
        Arc::new(bal_post_state.into_sorted()),
        Arc::new(parent_trie_updates.into_sorted()),
    );
    let state_trie_overlays = StateTrieOverlayManager::<TempoPrimitives>::default();
    state_trie_overlays.insert_block(ExecutedBlock::new(
        Arc::new(recovered_parent_block(speculative_parent_block)?),
        Arc::new(BlockExecutionOutput::<TempoReceipt>::default()),
        trie_data,
    ));
    let overlay_seed_elapsed = overlay_seed_start.elapsed();

    let tree_config = node.config.engine.tree_config();
    let overlay_builder =
        OverlayBuilder::<TempoPrimitives>::new(speculative_parent_hash, ChangesetCache::new())
            .with_state_trie_overlay_manager(state_trie_overlays);
    let overlay_factory = OverlayStateProviderFactory::new(node.provider.clone(), overlay_builder);
    let payload_processor = PayloadProcessor::new(
        node.task_executor.clone(),
        node.evm_config.clone(),
        &tree_config,
        PrecompileCacheMap::default(),
    );
    let handle = payload_processor.spawn_state_root(
        overlay_factory,
        speculative_parent_state_root,
        false,
        &tree_config,
    );

    let prepare_elapsed = prepare_start.elapsed();
    info!(
        base_parent_hash = %base_parent_hash,
        speculative_parent_hash = %speculative_parent_hash,
        speculative_parent_state_root = %speculative_parent_state_root,
        bal_accounts,
        bal_storage_accounts,
        bal_storage_slots,
        parent_trie_updates_total,
        decode_elapsed = ?decode_elapsed,
        parent_state_root_elapsed = ?parent_state_root_elapsed,
        overlay_seed_elapsed = ?overlay_seed_elapsed,
        prepare_elapsed = ?prepare_elapsed,
        "created private BAL speculative sparse-trie handle",
    );

    if prepare_elapsed > SPARSE_TRIE_PREPARE_SLOW_THRESHOLD {
        warn!(
            base_parent_hash = %base_parent_hash,
            speculative_parent_hash = %speculative_parent_hash,
            speculative_parent_state_root = %speculative_parent_state_root,
            bal_accounts,
            bal_storage_accounts,
            bal_storage_slots,
            parent_trie_updates_total,
            decode_elapsed = ?decode_elapsed,
            parent_state_root_elapsed = ?parent_state_root_elapsed,
            overlay_seed_elapsed = ?overlay_seed_elapsed,
            prepare_elapsed = ?prepare_elapsed,
            threshold = ?SPARSE_TRIE_PREPARE_SLOW_THRESHOLD,
            "private BAL speculative sparse-trie preparation exceeded threshold",
        );
    }

    Ok(handle)
}

fn recovered_parent_block(
    block: &SealedBlock<TempoBlock>,
) -> eyre::Result<RecoveredBlock<TempoBlock>> {
    let senders = block
        .body()
        .transactions
        .iter()
        .map(SignedTransaction::try_recover)
        .collect::<Result<Vec<_>, _>>()
        .wrap_err("failed recovering senders for speculative BAL parent block")?;

    Ok(RecoveredBlock::new_unhashed(
        block.clone().unseal(),
        senders,
    ))
}
