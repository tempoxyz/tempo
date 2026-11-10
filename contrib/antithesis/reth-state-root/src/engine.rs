//! Block production as the engine tree does it, shared with reth-proofs: the sparse-trie state
//! root task computes each block's root, blocks go into the OverlayManager, and one background
//! writer persists them with state masking. Blocks are produced only when the server is asked.

use crate::{input::Operation, persistence::Persistence, Node};
use alloy_consensus::Header;
use alloy_primitives::{keccak256, B256};
use eyre::{ensure, Result};
use reth_chain_state::ExecutedBlock;
use reth_chainspec::ChainSpec;
use reth_db::init_db;
use reth_engine_primitives::MIN_PERSISTENCE_BACKPRESSURE_THRESHOLD;
use reth_engine_tree::tree::{
    state_root_strategy::{
        publish_sparse_trie, DefaultStateRootStrategy, StateAccessHint, StateRootTaskOptions,
    },
    TreeConfig, CHANGESET_CACHE_RETENTION_BLOCKS,
};
use reth_ethereum_primitives::{Block, EthPrimitives};
use reth_evm_ethereum::EthEvmConfig;
use reth_execution_types::{BlockExecutionOutput, BlockExecutionResult};
use reth_node_builder::common::{LaunchContext, WithConfigs};
use reth_node_core::{
    dirs::{ChainPath, DataDirPath},
    node_config::NodeConfig,
};
use reth_primitives_traits::{AlloyBlockHeader, RecoveredBlock, SealedHeader};
use reth_provider::{
    DatabaseProviderROFactory, HeaderProvider, ProviderFactory, SaveBlocksInput,
    StageCheckpointReader, StateRootProvider,
};
use reth_stages_types::StageId;
use reth_storage_overlay::{OverlayManager, OverlayStateProviderFactory};
use reth_tasks::{RayonConfig, Runtime, RuntimeBuilder, RuntimeConfig, TokioConfig};
use reth_trie::{bundle_state::BundleState, HashedPostState, SortedTrieData};
use serde_json::json;
use std::{collections::BTreeSet, fs, path::Path, sync::Arc, time::Duration};

/// Engine and persistence settings both workloads take from their configuration.
pub(crate) struct Settings {
    pub proof_workers: usize,
    pub timeout_secs: u64,
    pub persistence_threshold: u64,
    pub num_state_masking_blocks: u64,
    pub memory_block_buffer_target: Option<u64>,
}

/// One database and the blocks produced on it since it was opened.
pub(crate) struct Engine {
    runtime: Runtime,
    factory: ProviderFactory<Node>,
    tree_config: TreeConfig,
    strategy: DefaultStateRootStrategy,
    timeout: Duration,
    persistence_threshold: u64,
    buffer: u64,
    masking: u64,
    backpressure: u64,
    /// The block the database held when opened; blocks holds those produced since.
    base: u64,
    base_hash: B256,
    parent: SealedHeader,
    blocks: Vec<ExecutedBlock<EthPrimitives>>,
    persistence: Persistence,
    /// db_tip includes saved blocks; state_tip is the potentially older unmasked trie frontier.
    db_tip: u64,
    state_tip: u64,
    prune_requested: bool,
    /// Acknowledged saves.
    pub commits: u64,
    /// Acknowledged saves that left state masked.
    pub partial_commits: u64,
    /// Update batches streamed to the state root task.
    pub update_batches: u64,
    /// Prewarm hint batches streamed to the state root task.
    pub hint_batches: u64,
}

impl Engine {
    /// Opens or creates the database in datadir through the node's startup path, including
    /// consistency checks, the durable unwind marker and Merkle's recovery mode.
    pub(crate) fn open(settings: &Settings, datadir: &Path) -> Result<Self> {
        ensure!((1..=16).contains(&settings.proof_workers), "proof_workers must be 1..=16");
        ensure!((1..=3600).contains(&settings.timeout_secs), "timeout_secs must be 1..=3600");
        let threshold = settings.persistence_threshold;
        let buffer = settings
            .memory_block_buffer_target
            .unwrap_or_else(|| TreeConfig::default().memory_block_buffer_target().min(threshold));
        let masking = if threshold == 0 { 0 } else { settings.num_state_masking_blocks };
        let backpressure = threshold.saturating_mul(2).max(MIN_PERSISTENCE_BACKPRESSURE_THRESHOLD);
        ensure!(backpressure > threshold, "persistence threshold is too large");
        ensure!(buffer <= threshold, "buffer must not exceed persistence threshold");
        ensure!(
            masking == 0 ||
                matches!(masking.checked_add(buffer), Some(window) if window < threshold),
            "masking blocks + buffer must be less than persistence threshold"
        );
        // Clear the default window before applying smaller thresholds: TreeConfig checks each
        // setter.
        let tree_config = TreeConfig::default()
            .with_num_state_masking_blocks(0)
            .with_memory_block_buffer_target(0)
            .with_persistence_backpressure_threshold(u64::MAX)
            .with_persistence_threshold(threshold)
            .with_num_state_masking_blocks(masking)
            .with_memory_block_buffer_target(buffer)
            .with_persistence_backpressure_threshold(backpressure);
        let runtime = RuntimeBuilder::new(RuntimeConfig {
            tokio: TokioConfig::with_worker_threads(2),
            rayon: RayonConfig {
                cpu_threads: Some(2),
                rpc_threads: Some(1),
                storage_threads: Some(2),
                proof_storage_worker_threads: Some(settings.proof_workers),
                proof_account_worker_threads: Some(settings.proof_workers),
                prewarming_threads: Some(1),
                bal_streaming_threads: Some(1),
                state_trie_overlay_worker_threads: Some(1),
                ..Default::default()
            },
        })
        .build()?;
        fs::create_dir_all(datadir)?;
        let chain = Arc::new(ChainSpec::default());
        let data_dir = ChainPath::<DataDirPath>::new(
            datadir.to_string_lossy().parse()?,
            chain.chain,
            Default::default(),
        );
        let db = Arc::new(init_db(data_dir.db(), Default::default())?);
        let context = LaunchContext::new(runtime.clone(), data_dir)
            .with(WithConfigs { config: NodeConfig::new(chain), toml_config: Default::default() })
            .attach(db);
        println!("{}", json!({"recovery": "start"}));
        let factory = runtime.handle().block_on(
            context.create_provider_factory_with_recovery::<Node, EthEvmConfig>(
                OverlayManager::new(runtime.state_trie_overlay_worker_pool()),
                None,
                &[],
                |factory| {
                    let checkpoint = factory
                        .provider()?
                        .get_stage_checkpoint(StageId::Finish)?
                        .unwrap_or_default();
                    let partial = checkpoint
                        .finish_stage_checkpoint()
                        .and_then(|finish| finish.partial_state_trie());
                    println!(
                        "{}",
                        json!({"recovery": "frontiers", "finish": checkpoint.block_number,
                        "partial_state_trie": partial})
                    );
                    Ok(())
                },
            ),
        )?;
        reth_db_common::init::init_genesis(&factory)?;
        let base = factory
            .provider()?
            .get_stage_checkpoint(StageId::Finish)?
            .unwrap_or_default()
            .block_number;
        let parent = factory
            .provider()?
            .sealed_header(base)?
            .ok_or_else(|| eyre::eyre!("missing header {base}"))?;
        Ok(Self {
            persistence: Persistence::new(factory.clone()),
            runtime,
            factory,
            tree_config,
            strategy: DefaultStateRootStrategy::default(),
            timeout: Duration::from_secs(settings.timeout_secs),
            persistence_threshold: threshold,
            buffer,
            masking,
            backpressure,
            base,
            base_hash: parent.hash(),
            parent,
            blocks: Vec::new(),
            db_tip: base,
            state_tip: base,
            prune_requested: false,
            commits: 0,
            partial_commits: 0,
            update_batches: 0,
            hint_batches: 0,
        })
    }

    pub(crate) const fn factory(&self) -> &ProviderFactory<Node> {
        &self.factory
    }

    /// The newest block's header.
    pub(crate) const fn parent(&self) -> &SealedHeader {
        &self.parent
    }

    /// The newest block's number.
    pub(crate) fn head(&self) -> u64 {
        self.base + self.blocks.len() as u64
    }

    /// The persisted block data and state frontiers.
    pub(crate) const fn tips(&self) -> (u64, u64) {
        (self.db_tip, self.state_tip)
    }

    /// Advances persistence as the engine tree does between blocks: acknowledges a finished save,
    /// waiting for it under backpressure, then starts the next threshold save. With flush, saves
    /// both frontiers up to the head and waits for them. persisted runs after each acknowledged
    /// save with the factory, the previous db tip and the new db and state tips.
    pub(crate) fn persist(
        &mut self,
        flush: bool,
        mut persisted: impl FnMut(&ProviderFactory<Node>, u64, u64, u64) -> Result<()>,
    ) -> Result<()> {
        loop {
            let head = self.head();
            // Only an acknowledgement advances the durable frontiers; submission is asynchronous.
            let must_wait = flush ||
                head.saturating_sub(self.state_tip).saturating_sub(self.buffer) >=
                    self.backpressure;
            if let Some((db_tip, state_tip)) =
                self.persistence.acknowledge(must_wait, self.timeout)?
            {
                let previous = std::mem::replace(&mut self.db_tip, db_tip);
                self.state_tip = state_tip;
                self.commits += 1;
                self.partial_commits += u64::from(db_tip != state_tip);
                let manager = self.factory.overlay_manager();
                manager.evict_cached_changesets(
                    db_tip.saturating_sub(CHANGESET_CACHE_RETENTION_BLOCKS),
                );
                persisted(&self.factory, previous, db_tip, state_tip)?;
                manager.remove_blocks(
                    self.blocks
                        .iter()
                        .filter(|block| block.recovered_block().number() <= state_tip)
                        .map(|block| block.recovered_block().hash()),
                );
                let anchor = if state_tip == self.base {
                    self.base_hash
                } else {
                    self.blocks[(state_tip - self.base) as usize - 1].recovered_block().hash()
                };
                manager.precompute_execution_overlay(self.parent.hash(), anchor);
                self.prune_requested = true;
                println!(
                    "{}",
                    json!({"persistence": "complete", "head": head,
                        "db_tip": db_tip, "state_tip": state_tip})
                );
                continue;
            }
            if self.persistence.is_idle() {
                // Match EngineApiTreeHandler::get_save_blocks_input's Threshold and Head targets.
                let next_db = if flush { head } else { head.saturating_sub(self.buffer) };
                if flush ||
                    (head.saturating_sub(self.state_tip) > self.persistence_threshold &&
                        next_db > self.db_tip)
                {
                    let next_state = if flush {
                        head
                    } else {
                        next_db.saturating_sub(self.masking).max(self.state_tip)
                    };
                    if next_db != self.db_tip || next_state != self.state_tip {
                        println!(
                            "{}",
                            json!({"persistence": "start", "head": head,
                            "db_tip": self.db_tip, "state_tip": self.state_tip,
                            "next_db_tip": next_db, "next_state_tip": next_state,
                            "flush": flush})
                        );
                        let start = (self.state_tip - self.base) as usize;
                        let end = (next_db - self.base) as usize;
                        self.persistence.save(
                            SaveBlocksInput::new(
                                self.blocks[start..end].to_vec(),
                                self.db_tip,
                                self.state_tip,
                                next_db,
                                next_state,
                            ),
                            next_db,
                            next_state,
                        )?;
                        continue;
                    }
                }
            }
            return Ok(());
        }
    }

    /// Produces the next block from one block's operations and the model's execution output for
    /// them, and checks the state root task's root against expected_root. Returns the block hash.
    pub(crate) fn produce(
        &mut self,
        operations: &[Operation],
        bundle: BundleState,
        updates: Vec<HashedPostState>,
        expected_root: B256,
    ) -> Result<B256> {
        let number = self.head() + 1;
        let manager = self.factory.overlay_manager();
        let factory_view = OverlayStateProviderFactory::new(
            self.factory.clone(),
            manager.overlay_builder(self.parent.hash()),
        );
        let state_tip = self.state_tip;
        let retained = std::mem::take(&mut self.prune_requested).then(|| {
            self.blocks
                .iter()
                .filter(|block| block.recovered_block().number() > state_tip)
                .rev()
                .cloned()
                .collect()
        });
        let (mut handle, pending) = self.strategy.spawn_state_root(
            &self.runtime,
            factory_view,
            StateRootTaskOptions {
                parent_header: self.parent.clone(),
                preserved_sparse_trie: manager.take_sparse_trie(),
                transaction_count: None,
                gas_used: None,
                config: &self.tree_config,
                pending_sparse_trie_prune_blocks: retained,
            },
        );
        let stream = handle.take_hashed_update_stream();
        let hints = handle.take_hint_stream();
        let written = updates
            .iter()
            .flat_map(|update| {
                update
                    .accounts
                    .keys()
                    .chain(update.storages.keys())
                    .map(|address| (*address, None))
                    .chain(update.storages.iter().flat_map(|(address, storage)| {
                        storage.storage.keys().map(move |slot| (*address, Some(*slot)))
                    }))
            })
            .collect::<BTreeSet<_>>();
        let mut hinted = BTreeSet::new();
        let mut updates = updates.into_iter();
        // Preserve input ordering: hints interleave with the corresponding updates.
        for operation in operations {
            match operation {
                Operation::PrewarmBatch { accounts, storages } => {
                    let mut hint = StateAccessHint::default();
                    for address in accounts {
                        let address = keccak256(address);
                        hint.accounts.push(address);
                        hinted.insert((address, None));
                    }
                    for storage in storages {
                        let address = keccak256(storage.address);
                        let slot = keccak256(B256::from(storage.slot));
                        hint.storages.entry(address).or_default().push(slot);
                        hinted.insert((address, Some(slot)));
                    }
                    hints.on_access_hint(hint);
                    self.hint_batches += 1;
                }
                Operation::UpdateBatch { updates: batch_updates } => {
                    let mut batch = HashedPostState::default();
                    for update in updates.by_ref().take(batch_updates.len()) {
                        batch.extend(update);
                    }
                    stream.on_hashed_state_update(batch);
                    self.update_batches += 1;
                }
                // Commit marks the end of this block, not a database transaction.
                // Finalize its streams and await the root below before scheduling persistence.
                Operation::Commit => break,
            }
        }
        println!(
            "{}",
            json!({"block_number": number, "hint_coverage": {
            "written": written.len(), "overlap": written.intersection(&hinted).count(),
            "unhinted": written.difference(&hinted).count(),
            "read_only": hinted.difference(&written).count()}})
        );
        drop(hints);
        stream.finish();
        let outcome = handle.take_state_root_rx().recv_timeout(self.timeout)??;
        drop(handle);
        invariant!(
            outcome.state_root == expected_root,
            "block {number}: expected {}, actual {}",
            expected_root,
            outcome.state_root
        );
        let block = RecoveredBlock::new_unhashed(
            Block {
                header: Header {
                    parent_hash: self.parent.hash(),
                    number,
                    state_root: outcome.state_root,
                    timestamp: number,
                    ..Default::default()
                },
                ..Default::default()
            },
            Vec::new(),
        );
        self.parent = SealedHeader::new_unhashed(block.header().clone());
        let executed = ExecutedBlock::new(
            Arc::new(block),
            Arc::new(BlockExecutionOutput {
                state: bundle,
                result: BlockExecutionResult {
                    receipts: Vec::new(),
                    requests: Default::default(),
                    gas_used: 0,
                    blob_gas_used: 0,
                },
            }),
            SortedTrieData {
                hashed_state: Arc::new(match Arc::try_unwrap(outcome.hashed_state) {
                    Ok(state) => state.into_sorted(),
                    Err(state) => state.clone_into_sorted(),
                }),
                trie_updates: Arc::new(match Arc::try_unwrap(outcome.trie_updates) {
                    Ok(updates) => updates.into_sorted(),
                    Err(updates) => updates.clone_into_sorted(),
                }),
            },
        );
        manager.insert_block(executed.clone());
        publish_sparse_trie(&pending, manager, self.parent.hash(), outcome.state_root);
        self.blocks.push(executed);
        Ok(self.parent.hash())
    }

    /// The state root the overlay serves at the head, computed from the database and in-memory
    /// blocks rather than by the state root task.
    pub(crate) fn tip_root(&self) -> Result<B256> {
        let provider = OverlayStateProviderFactory::new(
            self.factory.clone(),
            self.factory.overlay_manager().overlay_builder(self.parent.hash()),
        )
        .database_provider_ro()?;
        Ok(provider.state_root(HashedPostState::default())?)
    }

    /// Stops the writer once every save is acknowledged, and drains the worker pools.
    pub(crate) fn close(self) -> Result<()> {
        self.persistence.finish()?;
        // Synchronize final trie completion before the caller takes a metrics snapshot.
        if let Some(trie) = self.factory.overlay_manager().take_sparse_trie() {
            invariant!(
                trie.into_trie_for(self.parent.hash())?.is_some(),
                "missing final reusable trie"
            );
        }
        // Root delivery precedes worker teardown. Drain their queues so the last database handle
        // closes before process exit destroys RocksDB's global scheduler.
        for name in ["sparse-trie", "trie-hashing", "storage-workers", "account-workers", "drop"] {
            self.runtime.spawn_blocking_named(name, || {}).get();
        }
        Ok(())
    }
}
