//! Antithesis workload for `eth_getMultiProof` over in-memory, masked and persisted trie state.
//!
//! Blocks are produced like in the reth-state-root workload: the sparse-trie state root task
//! computes each root, blocks are inserted into the `OverlayManager`, and a background writer
//! persists them with state masking. Meanwhile proof threads serve `eth_getMultiProof` requests at
//! random produced blocks through the provider the RPC uses, and verify every proof against the
//! block's state root.

#[expect(dead_code, reason = "Shared with reth-state-root, whose input generator is unused here.")]
#[path = "../../reth-state-root/src/model.rs"]
mod model;
#[path = "../../reth-state-root/src/persistence.rs"]
mod persistence;

mod generate;
mod proof;

use alloy_consensus::Header;
use alloy_primitives::B256;
use antithesis_instrumentation as _;
use antithesis_sdk::{
    assert_always, assert_always_or_unreachable, assert_sometimes, assert_unreachable,
    lifecycle::setup_complete, random::AntithesisRng,
};
use antithesis_trie_shapes::{Collider, ShapeTracker};
use eyre::{ensure, eyre, Context, Result};
use model::{apply, root, Model};
use persistence::{Persistence, Phase};
use rand_09::Rng;
use reth_chain_state::ExecutedBlock;
use reth_chainspec::ChainSpec;
use reth_db::{init_db, DatabaseEnv};
use reth_engine_primitives::MIN_PERSISTENCE_BACKPRESSURE_THRESHOLD;
use reth_engine_tree::tree::{
    state_root_strategy::{publish_sparse_trie, DefaultStateRootStrategy, StateRootTaskOptions},
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
    test_utils::MockNodeTypesWithDB, DatabaseProviderROFactory, HeaderProvider, ProviderFactory,
    SaveBlocksInput,
};
use reth_storage_overlay::{OverlayManager, OverlayStateProviderFactory};
use reth_tasks::{RayonConfig, RuntimeBuilder, RuntimeConfig, TokioConfig};
use reth_trie::{HashedPostState, SortedTrieData};
use serde::Deserialize;
use serde_json::json;
use std::{
    sync::{
        atomic::{AtomicU64, Ordering},
        mpsc, Arc, Mutex, Once, RwLock,
    },
    thread,
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

#[derive(Clone, Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct Config {
    /// A finite local smoke run; absent means run indefinitely.
    rounds: Option<u64>,
    blocks: u64,
    updates: usize,
    /// Most accounts the generated state holds.
    accounts: usize,
    /// `eth_getMultiProof` requests queued after each block and after the final flush.
    requests: usize,
    request_threads: usize,
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
            rounds: None,
            blocks: 64,
            updates: 32,
            accounts: 256,
            requests: 8,
            request_threads: 2,
            proof_workers: 2,
            timeout_secs: 60,
            persistence_threshold: tree.persistence_threshold(),
            num_state_masking_blocks: tree.num_state_masking_blocks(),
            memory_block_buffer_target: None,
        }
    }
}

/// A produced block's post-state, retained so proofs at any block of the round can be checked.
struct Snapshot {
    number: u64,
    hash: B256,
    root: B256,
    state: Model,
}

/// State shared between block production and the proof request threads.
struct Shared {
    blocks: RwLock<Vec<Arc<Snapshot>>>,
    /// Highest block whose block data is persisted.
    db_tip: AtomicU64,
    /// Highest block whose state and trie are persisted; masked blocks lie between the tips.
    state_tip: AtomicU64,
}

/// Serves one `eth_getMultiProof` request at a random produced block and checks the response.
fn request_proof(factory: &ProviderFactory<Node>, shared: &Shared) -> Result<()> {
    let mut rng = AntithesisRng;
    // Persistence may advance during the request; the tips only classify coverage.
    let db_tip = shared.db_tip.load(Ordering::Acquire);
    let state_tip = shared.state_tip.load(Ordering::Acquire);
    let snapshot = {
        let blocks = shared.blocks.read().map_err(|_| eyre!("block snapshots poisoned"))?;
        Arc::clone(&blocks[rng.random_range(0..blocks.len())])
    };
    let number = snapshot.number;
    assert_sometimes!(number > db_tip, "Proof served from in-memory blocks");
    assert_sometimes!(number > state_tip && number <= db_tip, "Proof served from masked blocks");
    assert_sometimes!(number == state_tip && number > 0, "Proof served at the persisted state tip");
    assert_sometimes!(number < state_tip, "Proof served from reverted historical state");
    let targets = generate::targets(&mut rng, &snapshot.state);
    // The provider BlockchainProvider resolves for a block hash, in memory or persisted.
    let result = OverlayStateProviderFactory::new(
        factory.clone(),
        factory.overlay_manager().overlay_builder(snapshot.hash),
    )
    .database_provider_ro()
    .map_err(eyre::Report::from)
    .and_then(|provider| proof::get_multi_proof(&provider, &targets))
    .and_then(|proofs| proof::check(snapshot.root, &targets, &proofs));
    let error = result.err().map(|error| format!("{error:#}"));
    invariant!(
        error.is_none(),
        "eth_getMultiProof at block {number} (db tip {db_tip}, state tip {state_tip}) for \
         {targets:?}: {}",
        error.as_deref().unwrap_or_default()
    );
    Ok(())
}

fn run(config: &Config, round: u64) -> Result<()> {
    ensure!((1..=1024).contains(&config.blocks), "blocks must be 1..=1024");
    ensure!((1..=4096).contains(&config.updates), "updates must be 1..=4096");
    ensure!((1..=4096).contains(&config.accounts), "accounts must be 1..=4096");
    ensure!(config.requests <= 1024, "requests must be at most 1024");
    ensure!((1..=16).contains(&config.request_threads), "request_threads must be 1..=16");
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
    // Each round starts from an empty database; restart recovery is reth-state-root's subject.
    let datadir = tempfile::tempdir()?;
    let chain = Arc::new(ChainSpec::default());
    let data_dir = ChainPath::<DataDirPath>::new(
        datadir.path().to_string_lossy().parse()?,
        chain.chain,
        Default::default(),
    );
    let db = Arc::new(init_db(data_dir.db(), Default::default())?);
    let context = LaunchContext::new(runtime.clone(), data_dir)
        .with(WithConfigs { config: NodeConfig::new(chain), toml_config: Default::default() })
        .attach(db);
    let factory = runtime.handle().block_on(
        context.create_provider_factory_with_recovery::<Node, EthEvmConfig>(
            OverlayManager::new(runtime.state_trie_overlay_worker_pool()),
            None,
            &[],
            |_| Ok(()),
        ),
    )?;
    reth_db_common::init::init_genesis(&factory)?;
    static SETUP: Once = Once::new();
    SETUP.call_once(|| {
        setup_complete(&json!({"workload": "reth-proofs", "database_initialized": true}))
    });

    let manager = factory.overlay_manager();
    let mut parent =
        factory.provider()?.sealed_header(0)?.ok_or_else(|| eyre!("missing genesis header"))?;
    let base_hash = parent.hash();
    let mut state = Model::default();
    let mut collider = Collider::default();
    let mut shapes = ShapeTracker::default();
    invariant!(root(&state) == parent.state_root(), "genesis root");
    let shared = Arc::new(Shared {
        blocks: RwLock::new(vec![Arc::new(Snapshot {
            number: 0,
            hash: base_hash,
            root: parent.state_root(),
            state: state.clone(),
        })]),
        db_tip: AtomicU64::new(0),
        state_tip: AtomicU64::new(0),
    });
    let (requests, request_rx) = mpsc::channel::<()>();
    let request_rx = Arc::new(Mutex::new(request_rx));
    let request_threads = (0..config.request_threads)
        .map(|_| {
            let (factory, shared, request_rx) =
                (factory.clone(), Arc::clone(&shared), Arc::clone(&request_rx));
            thread::spawn(move || -> Result<u64> {
                let mut served = 0;
                // The channel closes after the round's last request is queued.
                while request_rx.lock().map_err(|_| eyre!("request queue poisoned"))?.recv().is_ok()
                {
                    request_proof(&factory, &shared)?;
                    served += 1;
                }
                Ok(served)
            })
        })
        .collect::<Vec<_>>();

    let strategy = DefaultStateRootStrategy::default();
    let mut rng = AntithesisRng;
    let mut blocks = Vec::<ExecutedBlock<EthPrimitives>>::new();
    let timeout = Duration::from_secs(config.timeout_secs);
    let mut persistence = Persistence::new(factory.clone());
    // db_tip includes saved blocks; state_tip is the potentially older unmasked trie frontier.
    let mut db_tip = 0;
    let mut state_tip = 0;
    let mut partial_commits = 0;
    let mut prune_requested = false;
    let mut phase = Phase::Running;
    loop {
        let head = blocks.len() as u64;
        // Only an acknowledgement advances the durable frontiers; submission is asynchronous.
        let must_wait = phase == Phase::Flushing ||
            head.saturating_sub(state_tip).saturating_sub(buffer) >= backpressure;
        if let Some((next_db, next_state)) = persistence.acknowledge(must_wait, timeout)? {
            db_tip = next_db;
            state_tip = next_state;
            partial_commits += u64::from(db_tip != state_tip);
            shared.db_tip.store(db_tip, Ordering::Release);
            shared.state_tip.store(state_tip, Ordering::Release);
            manager
                .evict_cached_changesets(db_tip.saturating_sub(CHANGESET_CACHE_RETENTION_BLOCKS));
            manager.remove_blocks(
                blocks
                    .iter()
                    .filter(|block| block.recovered_block().number() <= state_tip)
                    .map(|block| block.recovered_block().hash()),
            );
            let anchor = if state_tip == 0 {
                base_hash
            } else {
                blocks[state_tip as usize - 1].recovered_block().hash()
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
                    persistence.save(
                        SaveBlocksInput::new(
                            blocks[state_tip as usize..next_db as usize].to_vec(),
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
        if head == config.blocks {
            if phase == Phase::Flushing {
                break;
            }
            phase = Phase::Flushing;
            continue;
        }
        let number = head + 1;
        let writes =
            generate::writes(&mut rng, &state, &mut collider, config.accounts, config.updates);
        let (bundle, updates) = apply(&mut state, number, &writes);
        shapes.observe(model::tries(&state));
        let retained = std::mem::take(&mut prune_requested).then(|| {
            blocks
                .iter()
                .filter(|block| block.recovered_block().number() > state_tip)
                .rev()
                .cloned()
                .collect()
        });
        let (mut handle, pending) = strategy.spawn_state_root(
            &runtime,
            OverlayStateProviderFactory::new(
                factory.clone(),
                manager.overlay_builder(parent.hash()),
            ),
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
        drop(handle.take_hint_stream());
        let mut updates = updates.into_iter().peekable();
        while updates.peek().is_some() {
            let mut batch = HashedPostState::default();
            for update in updates.by_ref().take(rng.random_range(1..=16)) {
                batch.extend(update);
            }
            stream.on_hashed_state_update(batch);
        }
        stream.finish();
        let outcome = handle.take_state_root_rx().recv_timeout(timeout)??;
        drop(handle);
        let expected_root = root(&state);
        invariant!(
            outcome.state_root == expected_root,
            "round {round} block {number}: expected {expected_root}, actual {}",
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
        // Publish the block only once the overlay manager can serve it.
        shared.blocks.write().map_err(|_| eyre!("block snapshots poisoned"))?.push(Arc::new(
            Snapshot { number, hash: parent.hash(), root: expected_root, state: state.clone() },
        ));
        for _ in 0..config.requests {
            requests.send(())?;
        }
    }
    persistence.finish()?;
    // Requests after the flush see every block persisted, most of them reverted from the tip.
    for _ in 0..config.requests {
        requests.send(())?;
    }
    drop(requests);
    let mut served = 0;
    for thread in request_threads {
        served += thread.join().map_err(|_| eyre!("proof request thread panicked"))??;
    }
    // Drain the worker pools so the last database handle closes before the runtime drops.
    for name in ["sparse-trie", "trie-hashing", "storage-workers", "account-workers", "drop"] {
        runtime.spawn_blocking_named(name, || {}).get();
    }
    assert_sometimes!(partial_commits > 0, "Persistence commits with masked state");
    println!(
        "{}",
        json!({"completed": true, "round": round, "blocks": config.blocks,
        "partial_commits": partial_commits, "proofs_served": served})
    );
    Ok(())
}

fn workload() -> Result<()> {
    let text = std::env::args().nth(1).unwrap_or_else(|| "{}".into());
    let config: Config = serde_json::from_str(&text).wrap_err("invalid workload configuration")?;
    ensure!(config.rounds != Some(0), "rounds must be positive");
    let mut round = 0;
    loop {
        run(&config, round).wrap_err_with(|| format!("reth-proofs-antithesis round={round}"))?;
        assert_sometimes!(true, "Proof workload completes a round");
        round += 1;
        if config.rounds.is_some_and(|rounds| round >= rounds) {
            return Ok(());
        }
    }
}

fn main() -> Result<()> {
    antithesis_sdk::antithesis_init();
    let previous_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |information| {
        assert_unreachable!(
            "Proof workload or worker thread panicked",
            &json!({"panic": information.to_string()})
        );
        previous_hook(information);
    }));
    let result = workload();
    assert_always_or_unreachable!(
        result.is_ok(),
        "Proof workload completes without errors",
        &json!({
            "error": result.as_ref().err().map(|error| format!("{error:#}"))
        })
    );
    result
}
