//! Antithesis workload for the sparse-trie, proof, overlay and persistence pipeline.

mod input;
mod journal;
mod lifecycle;
mod model;
mod persistence;

use alloy_consensus::Header;
use alloy_primitives::{keccak256, B256, U256};
use antithesis_instrumentation as _;
use antithesis_sdk::{
    assert_always, assert_always_or_unreachable, assert_sometimes, assert_unreachable,
    lifecycle::setup_complete,
};
use eyre::{ensure, Context, Result};
use input::{Input, Operation};
use journal::RoundJournal;
use lifecycle::{persist_json, Campaign};
use metrics_util::debugging::{DebugValue, DebuggingRecorder, Snapshotter};
use model::{apply, root, Model};
use persistence::{Persistence, Phase};
use reth_chain_state::ExecutedBlock;
use reth_chainspec::ChainSpec;
use reth_db::{init_db, DatabaseEnv};
use reth_db_api::{cursor::DbCursorRO, tables, transaction::DbTx};
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
    providers::LatestStateProviderRef, test_utils::MockNodeTypesWithDB, AccountReader,
    DatabaseProviderROFactory, HeaderProvider, ProviderFactory, SaveBlocksInput,
    StageCheckpointReader, StateProvider, StateRootProvider,
};
use reth_stages_types::StageId;
use reth_storage_overlay::{OverlayManager, OverlayStateProviderFactory};
use reth_tasks::{RayonConfig, Runtime, RuntimeBuilder, RuntimeConfig, TokioConfig};
use reth_trie::{HashedPostState, SortedTrieData};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::PathBuf,
    sync::{Arc, Once},
    time::Duration,
};

macro_rules! invariant {
    ($condition:expr, $message:literal $(, $argument:expr)* $(,)?) => {{
        let holds = $condition;
        assert_always!(holds, $message, &json!({"context": format!($message $(, $argument)*)}));
        ensure!(holds, $message $(, $argument)*);
    }};
}

type Node = MockNodeTypesWithDB<Arc<DatabaseEnv>>;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct Config {
    #[serde(skip)]
    round: u64,
    /// A finite local smoke run; absent means run indefinitely.
    rounds: Option<u64>,
    input: Option<Input>,
    datadir: Option<PathBuf>,
    blocks: u64,
    updates: usize,
    proof_workers: usize,
    timeout_secs: u64,
    persistence_threshold: u64,
    num_state_masking_blocks: u64,
    memory_block_buffer_target: Option<u64>,
}

impl Default for Config {
    fn default() -> Self {
        let tree = TreeConfig::default();
        Self {
            round: 0,
            rounds: None,
            input: None,
            datadir: Some(PathBuf::from("/data/reth-trie")),
            blocks: 64,
            updates: 64,
            proof_workers: 2,
            timeout_secs: 60,
            persistence_threshold: tree.persistence_threshold(),
            num_state_masking_blocks: tree.num_state_masking_blocks(),
            memory_block_buffer_target: None,
        }
    }
}

#[allow(clippy::clone_on_copy, reason = "Account is not Copy with account-ext enabled.")]
fn verify(factory: &ProviderFactory<Node>, state: &Model, tip: u64, state_tip: u64) -> Result<()> {
    let provider = factory.provider()?;
    let checkpoint = provider
        .get_stage_checkpoint(StageId::Finish)?
        .ok_or_else(|| eyre::eyre!("missing Finish checkpoint"))?;
    invariant!(checkpoint.block_number == tip, "Finish != {tip}");
    let actual_state_tip = checkpoint
        .finish_stage_checkpoint()
        .and_then(|finish| finish.partial_state_trie())
        .unwrap_or(checkpoint.block_number);
    invariant!(actual_state_tip == state_tip, "state/trie frontier != {state_tip}");
    let hash =
        provider.sealed_header(tip)?.ok_or_else(|| eyre::eyre!("missing header {tip}"))?.hash();
    drop(provider);
    let view = OverlayStateProviderFactory::new(
        factory.clone(),
        factory.overlay_manager().overlay_builder(hash),
    )
    .database_provider_ro()?;
    for (address, entry) in state {
        invariant!(
            view.basic_account(address)?.as_ref() == Some(&entry.account),
            "plain account {address} at {tip}"
        );
        // Include deleted slots and both range endpoints, not only surviving leaves.
        for slot in entry
            .touched_slots
            .iter()
            .copied()
            .chain([U256::ZERO, U256::from(u32::MAX)])
            .map(B256::from)
            .collect::<BTreeSet<_>>()
        {
            invariant!(
                view.storage(*address, slot)?.unwrap_or_default() ==
                    entry.storage.get(&U256::from_be_bytes(slot.0)).copied().unwrap_or_default(),
                "plain storage {address}/{slot} at {tip}"
            );
        }
    }
    drop(view);
    if tip == state_tip {
        let expected_root = root(state);
        let provider = factory.provider()?;
        let accounts = provider
            .tx_ref()
            .cursor_read::<tables::HashedAccounts>()?
            .walk(None)?
            .collect::<Result<BTreeMap<_, _>, _>>()?;
        let expected = state
            .iter()
            .map(|(address, entry)| (keccak256(address), entry.account.clone()))
            .collect::<BTreeMap<_, _>>();
        invariant!(accounts == expected, "persisted hashed accounts at {tip}");
        let storage = provider
            .tx_ref()
            .cursor_read::<tables::HashedStorages>()?
            .walk(None)?
            .map(|row| row.map(|(address, entry)| ((address, entry.key), entry.value)))
            .collect::<Result<BTreeMap<_, _>, _>>()?;
        let expected = state
            .iter()
            .flat_map(|(address, entry)| {
                entry.storage.iter().map(move |(slot, value)| {
                    ((keccak256(address), keccak256(B256::from(*slot))), *value)
                })
            })
            .collect::<BTreeMap<_, _>>();
        invariant!(storage == expected, "persisted hashed storage at {tip}");
        let latest = LatestStateProviderRef::new(&provider);
        invariant!(
            latest.state_root(HashedPostState::default())? == expected_root,
            "persisted root at {tip}"
        );
    }
    Ok(())
}

fn metric_counts(snapshotter: &Snapshotter) -> BTreeMap<String, u64> {
    snapshotter
        .snapshot()
        .into_vec()
        .into_iter()
        .filter_map(|(key, _, _, value)| {
            let name = key.key().name().to_string();
            if !(name.contains("tree.root") ||
                name.contains("state_trie_overlay") ||
                name.contains("storage.overlay"))
            {
                return None;
            }
            let count = match value {
                DebugValue::Counter(count) => count,
                DebugValue::Histogram(values) => values.len() as u64,
                _ => return None,
            };
            Some((name, count))
        })
        .collect()
}

fn run(
    config: &mut Config,
    snapshotter: &Snapshotter,
    runtime: &Runtime,
    db: Arc<DatabaseEnv>,
) -> Result<()> {
    ensure!((1..=1024).contains(&config.blocks), "blocks must be 1..=1024");
    ensure!((1..=4096).contains(&config.updates), "updates must be 1..=4096");
    ensure!((1..=16).contains(&config.proof_workers), "proof_workers must be 1..=16");
    ensure!((1..=3600).contains(&config.timeout_secs), "timeout_secs must be 1..=3600");
    let buffer = config.memory_block_buffer_target.unwrap_or_else(|| {
        TreeConfig::default().memory_block_buffer_target().min(config.persistence_threshold)
    });
    let masking =
        if config.persistence_threshold == 0 { 0 } else { config.num_state_masking_blocks };
    let backpressure =
        config.persistence_threshold.saturating_mul(2).max(MIN_PERSISTENCE_BACKPRESSURE_THRESHOLD);
    ensure!(backpressure > config.persistence_threshold, "persistence threshold is too large");
    ensure!(buffer <= config.persistence_threshold, "buffer must not exceed persistence threshold");
    ensure!(
        masking == 0 ||
            matches!(masking.checked_add(buffer), Some(window) if window < config.persistence_threshold),
        "masking blocks + buffer must be less than persistence threshold"
    );
    // Clear the default window before applying smaller thresholds: TreeConfig checks each setter.
    let tree_config = TreeConfig::default()
        .with_num_state_masking_blocks(0)
        .with_memory_block_buffer_target(0)
        .with_persistence_backpressure_threshold(u64::MAX)
        .with_persistence_threshold(config.persistence_threshold)
        .with_num_state_masking_blocks(masking)
        .with_memory_block_buffer_target(buffer)
        .with_persistence_backpressure_threshold(backpressure);
    let datadir = config.datadir.as_ref().expect("campaign supplies the round directory");
    fs::create_dir_all(datadir)?;
    let chain = Arc::new(ChainSpec::default());
    let data_dir = ChainPath::<DataDirPath>::new(
        datadir.to_string_lossy().parse()?,
        chain.chain,
        Default::default(),
    );
    let context = LaunchContext::new(runtime.clone(), data_dir)
        .with(WithConfigs { config: NodeConfig::new(chain), toml_config: Default::default() })
        .attach(db);
    println!("{}", json!({"recovery": "start"}));
    // This is the node's startup path, including consistency checks, the durable unwind
    // marker and Merkle's walk_all_changed_branch_children recovery mode.
    let factory = runtime.handle().block_on(
        context.create_provider_factory_with_recovery::<Node, EthEvmConfig>(
            OverlayManager::new(runtime.state_trie_overlay_worker_pool()),
            None,
            &[],
            |factory| {
                let checkpoint =
                    factory.provider()?.get_stage_checkpoint(StageId::Finish)?.unwrap_or_default();
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
    // Snapshot before drawing a new input, so branches can explore distinct operations.
    static SETUP: Once = Once::new();
    SETUP.call_once(|| {
        setup_complete(&json!({"workload": "reth-trie", "database_initialized": true}))
    });
    let input_path = datadir.join("input.json");
    let input = if input_path.exists() {
        serde_json::from_slice(&fs::read(&input_path)?)?
    } else {
        let input =
            config.input.take().unwrap_or_else(|| Input::generate(config.blocks, config.updates));
        persist_json(&input_path, &input)?;
        input
    };
    input.validate()?;
    let input_blocks =
        input.operations.split_inclusive(|op| matches!(op, Operation::Commit)).collect::<Vec<_>>();
    let total_blocks = input_blocks.len() as u64;
    let mut journal = RoundJournal::open(&datadir, total_blocks)?;

    let manager = factory.overlay_manager();
    let base =
        factory.provider()?.get_stage_checkpoint(StageId::Finish)?.unwrap_or_default().block_number;
    let mut parent = factory
        .provider()?
        .sealed_header(base)?
        .ok_or_else(|| eyre::eyre!("missing header {base}"))?;
    let base_hash = parent.hash();
    let strategy = DefaultStateRootStrategy::default();
    let mut state = Model::default();
    journal.replay(1..=base, &mut state)?;
    if base > 0 {
        verify(&factory, &state, base, base)?;
    }
    let recovered_root = root(&state);
    invariant!(recovered_root == parent.state_root(), "recovered root at {base}");
    println!("{}", json!({"recovery": "complete", "head": base, "root": recovered_root}));
    assert_sometimes!(base > 0, "Restart recovers persisted blocks");
    let mut blocks = Vec::<ExecutedBlock<EthPrimitives>>::new();
    // Replay journal updates instead of retaining a full model for every block.
    let mut persisted_state = state.clone();
    let timeout = Duration::from_secs(config.timeout_secs);
    let mut persistence = Persistence::new(factory.clone());
    // db_tip includes saved blocks; state_tip is the potentially older unmasked trie frontier.
    let mut db_tip = base;
    let mut state_tip = base;
    let mut commits = 0;
    let mut partial_commits = 0;
    let mut update_batches = 0;
    let mut hint_batches = 0;
    let mut prune_requested = false;
    let mut phase = Phase::Running;
    loop {
        let head = base + blocks.len() as u64;
        // Only an acknowledgement advances the durable frontiers; submission is asynchronous.
        let must_wait = phase == Phase::Flushing ||
            head.saturating_sub(state_tip).saturating_sub(buffer) >= backpressure;
        if let Some((next_db, next_state)) = persistence.acknowledge(must_wait, timeout)? {
            journal.replay((db_tip + 1)..=next_db, &mut persisted_state)?;
            db_tip = next_db;
            state_tip = next_state;
            commits += 1;
            partial_commits += u64::from(db_tip != state_tip);
            manager
                .evict_cached_changesets(db_tip.saturating_sub(CHANGESET_CACHE_RETENTION_BLOCKS));
            verify(&factory, &persisted_state, db_tip, state_tip)?;
            manager.remove_blocks(
                blocks
                    .iter()
                    .filter(|block| block.recovered_block().number() <= state_tip)
                    .map(|block| block.recovered_block().hash()),
            );
            let anchor = if state_tip == base {
                base_hash
            } else {
                blocks[(state_tip - base) as usize - 1].recovered_block().hash()
            };
            manager.precompute_execution_overlay(parent.hash(), anchor);
            prune_requested = true;
            println!(
                "{}",
                json!({"persistence": "complete", "head": head,
                    "db_tip": db_tip, "state_tip": state_tip})
            );
            continue;
        }
        if persistence.is_idle() {
            // Match EngineApiTreeHandler::get_save_blocks_input's Threshold and Head targets.
            let next_db = if phase == Phase::Flushing { head } else { head.saturating_sub(buffer) };
            if phase == Phase::Flushing ||
                (head.saturating_sub(state_tip) > config.persistence_threshold &&
                    next_db > db_tip)
            {
                let next_state = if phase == Phase::Flushing {
                    head
                } else {
                    next_db.saturating_sub(masking).max(state_tip)
                };
                if next_db != db_tip || next_state != state_tip {
                    println!(
                        "{}",
                        json!({"persistence": "start", "head": head,
                        "db_tip": db_tip, "state_tip": state_tip,
                        "next_db_tip": next_db, "next_state_tip": next_state,
                        "shutdown": phase == Phase::Flushing})
                    );
                    persistence.save(
                        SaveBlocksInput::new(
                            blocks[(state_tip - base) as usize..(next_db - base) as usize].to_vec(),
                            db_tip,
                            state_tip,
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
        if head == total_blocks {
            if phase == Phase::Flushing {
                break;
            }
            // Let the last block trigger normal threshold persistence before shutdown.
            // Flush both frontiers to head, even when the final threshold save was masked.
            phase = Phase::Flushing;
            continue;
        }
        let number = head + 1;
        // Sync the replay record before mutating the model or starting production tasks.
        let operations = journal.operations(number, input_blocks[number as usize - 1])?;
        let updates_input = operations
            .iter()
            .flat_map(|op| match op {
                Operation::UpdateBatch { updates } => updates.as_slice(),
                _ => &[],
            })
            .cloned()
            .collect::<Vec<_>>();
        let mut accounts = state.keys().copied().collect::<BTreeSet<_>>();
        for op in &updates_input {
            match op {
                model::Update::Account { address, .. } => {
                    accounts.insert(*address);
                }
                model::Update::Storage { address, .. } => ensure!(
                    accounts.contains(address),
                    "storage before account creation: {address}"
                ),
            }
        }
        let (bundle, updates) = apply(&mut state, number, &updates_input);
        // The full operations are in the journal before production tasks run.
        println!(
            "{}",
            json!({"block": number, "round": config.round, "db_tip": db_tip,
            "state_tip": state_tip, "operations": operations.len()})
        );
        let factory_view = OverlayStateProviderFactory::new(
            factory.clone(),
            manager.overlay_builder(parent.hash()),
        );
        let retained = std::mem::take(&mut prune_requested).then(|| {
            blocks
                .iter()
                .filter(|block| block.recovered_block().number() > state_tip)
                .rev()
                .cloned()
                .collect()
        });
        let (mut handle, pending) = strategy.spawn_state_root(
            runtime,
            factory_view,
            StateRootTaskOptions {
                parent_header: parent.clone(),
                preserved_sparse_trie: manager.take_sparse_trie(),
                transaction_count: None,
                gas_used: None,
                config: &tree_config,
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
        for operation in &operations {
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
                    hint_batches += 1;
                }
                Operation::UpdateBatch { updates: batch_updates } => {
                    let mut batch = HashedPostState::default();
                    for update in updates.by_ref().take(batch_updates.len()) {
                        batch.extend(update);
                    }
                    stream.on_hashed_state_update(batch);
                    update_batches += 1;
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
        let outcome = handle.take_state_root_rx().recv_timeout(timeout)??;
        drop(handle);
        // Rebuild from the plain model, independently of production hashed state and trie updates.
        let expected_root = root(&state);
        invariant!(
            outcome.state_root == expected_root,
            "round {} block {number}: expected {}, actual {}",
            config.round,
            expected_root,
            outcome.state_root
        );
        let block = RecoveredBlock::new_unhashed(
            Block {
                header: Header {
                    parent_hash: parent.hash(),
                    number,
                    state_root: outcome.state_root,
                    timestamp: number,
                    ..Default::default()
                },
                ..Default::default()
            },
            Vec::new(),
        );
        parent = SealedHeader::new_unhashed(block.header().clone());
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
        publish_sparse_trie(&pending, manager, parent.hash(), outcome.state_root);
        blocks.push(executed);
    }
    persistence.finish()?;
    // Synchronize final trie completion before taking the metrics snapshot.
    if let Some(trie) = manager.take_sparse_trie() {
        invariant!(trie.into_trie_for(parent.hash())?.is_some(), "missing final reusable trie");
    }
    drop(factory);
    // Root delivery precedes worker teardown. Drain their queues so round-local handles
    // are released before the next round resets its tables and files.
    for name in ["sparse-trie", "trie-hashing", "storage-workers", "account-workers", "drop"] {
        runtime.spawn_blocking_named(name, || {}).get();
    }
    assert_sometimes!(partial_commits > 0, "Persistence commits with masked state");
    assert_sometimes!(hint_batches > 0, "Prewarm hints reach trie workers");
    let metrics = metric_counts(snapshotter);
    println!(
        "{}",
        json!({"completed": true, "round": config.round, "blocks": total_blocks,
        "commits": commits, "partial_commits": partial_commits,
        "update_batches": update_batches, "hint_batches": hint_batches,
        "metrics": metrics})
    );
    Ok(())
}

fn workload() -> Result<()> {
    let text = std::env::args().nth(1).unwrap_or_else(|| "{}".into());
    let mut config: Config =
        serde_json::from_str(&text).wrap_err("invalid workload configuration")?;
    ensure!(config.rounds != Some(0), "rounds must be positive");
    let recorder = DebuggingRecorder::new();
    let snapshotter = recorder.snapshotter();
    recorder.install()?;
    let input = config.input.clone();
    let campaign = Campaign::new(&config)?;
    let runtime = RuntimeBuilder::new(RuntimeConfig {
        tokio: TokioConfig::with_worker_threads(2),
        rayon: RayonConfig {
            cpu_threads: Some(2),
            rpc_threads: Some(1),
            storage_threads: Some(2),
            proof_storage_worker_threads: Some(config.proof_workers),
            proof_account_worker_threads: Some(config.proof_workers),
            prewarming_threads: Some(1),
            bal_streaming_threads: Some(1),
            state_trie_overlay_worker_threads: Some(1),
            ..Default::default()
        },
    })
    .build()?;
    let db = Arc::new(init_db(campaign.database_path()?, Default::default())?);
    loop {
        config.datadir = Some(campaign.start(&db)?);
        config.input = input.clone();
        run(&mut config, &snapshotter, &runtime, db.clone())
            .wrap_err_with(|| format!("reth-trie-antithesis round={}", config.round))?;
        invariant!(Arc::strong_count(&db) == 1, "round releases all database handles");
        assert_sometimes!(true, "Trie workload completes a round");
        // Only a verified, fully flushed round can authorize resetting its database and journal.
        campaign.retire()?;
        config.round += 1;
        if config.rounds.is_some_and(|rounds| config.round >= rounds) {
            return Ok(());
        }
    }
}

fn main() -> Result<()> {
    antithesis_sdk::antithesis_init();
    let previous_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |information| {
        assert_unreachable!(
            "Trie workload or worker thread panicked",
            &json!({"panic": information.to_string()})
        );
        previous_hook(information);
    }));
    let result = workload();
    assert_always_or_unreachable!(
        result.is_ok(),
        "Trie workload completes without errors",
        &json!({
            "error": result.as_ref().err().map(|error| format!("{error:#}"))
        })
    );
    result
}
