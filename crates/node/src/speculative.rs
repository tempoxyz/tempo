use std::{sync::Arc, time::Duration, time::Instant};

use alloy_primitives::{B256, Bytes};
use eyre::{WrapErr as _, eyre};
use reth_engine_tree::tree::{PayloadProcessor, precompile_cache::PrecompileCacheMap};
use reth_provider::{
    StateProviderFactory as _,
    providers::{OverlayBuilder, OverlayStateProviderFactory},
};
use reth_tracing::tracing::{info, warn};
use reth_trie_db::ChangesetCache;
use reth_trie_parallel::state_root_task::StateRootHandle;
use tempo_payload_builder::bal_overlay::block_access_list_hashed_post_state;
use tempo_primitives::TempoPrimitives;

use crate::TempoFullNode;

const SPARSE_TRIE_PREPARE_SLOW_THRESHOLD: Duration = Duration::from_millis(5);

/// Creates a private sparse-trie state-root pipeline for a BAL speculative child build.
///
/// The handle is intentionally not wired to Reth's global preserved sparse trie. It is backed by a
/// fresh `PayloadProcessor` and an overlay proof provider that sees
/// `state(parent_of_B) + BAL_post_state(B)` as the speculative child's parent state.
pub fn speculative_bal_state_root_handle(
    node: &TempoFullNode,
    base_parent_hash: B256,
    speculative_parent_hash: B256,
    speculative_parent_state_root: B256,
    block_access_list: &Bytes,
) -> eyre::Result<StateRootHandle> {
    let prepare_start = Instant::now();

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
    let bal_post_state = Arc::new(bal_post_state.into_sorted());

    let tree_config = node.config.engine.tree_config();
    let overlay_builder =
        OverlayBuilder::<TempoPrimitives>::new(base_parent_hash, ChangesetCache::new())
            .with_hashed_state_overlay(Some(bal_post_state));
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
        decode_elapsed = ?decode_elapsed,
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
            decode_elapsed = ?decode_elapsed,
            prepare_elapsed = ?prepare_elapsed,
            threshold = ?SPARSE_TRIE_PREPARE_SLOW_THRESHOLD,
            "private BAL speculative sparse-trie preparation exceeded threshold",
        );
    }

    Ok(handle)
}
