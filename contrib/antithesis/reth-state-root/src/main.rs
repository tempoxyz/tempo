//! Antithesis workload for the sparse-trie, proof, overlay and persistence pipeline.
//!
//! `serve` runs the server: it owns the database, the engine, the model and the journal that
//! replays blocks after a restart, and builds blocks only when a test command asks. Each block's
//! root comes from the sparse-trie state root task and is checked against the model's; test
//! commands also check the root the overlay serves at the tip, and ask for `eth_getMultiProof`
//! at any block of the round, served through the provider the RPC uses concurrently with block
//! production, to verify against the model's root at that block. Every other subcommand is a test
//! template command; see the antithesis-trie-shapes harness.

macro_rules! invariant {
    ($condition:expr, $message:literal $(, $argument:expr)* $(,)?) => {{
        let holds = $condition;
        antithesis_sdk::assert_always!(
            holds,
            $message,
            &serde_json::json!({"context": format!($message $(, $argument)*)})
        );
        eyre::ensure!(holds, $message $(, $argument)*);
    }};
}

mod engine;
mod generate;
mod input;
mod journal;
mod lifecycle;
mod model;
mod persistence;
mod proof;
mod sparse_guidance;

use alloy_primitives::{keccak256, B256, U256};
use antithesis_instrumentation as _;
use antithesis_sdk::{
    assert_always_or_unreachable, assert_sometimes, assert_unreachable, random::AntithesisRng,
};
use antithesis_trie_shapes::{
    harness::{self, BlockRoot, ProofTarget, Request, Response, Summary},
    proofs::Proved,
    Collider, ShapeTracker, Write,
};
use engine::{Engine, Settings};
use eyre::{ensure, eyre, Context, Result};
use journal::RoundJournal;
use lifecycle::{clear_tables, persist_json, Campaign};
use metrics_util::debugging::{DebugValue, DebuggingRecorder, Snapshotter};
use model::{apply, root, write_updates, Model};
use rand_09::Rng;
use reth_db::{init_db, DatabaseEnv};
use reth_db_api::{cursor::DbCursorRO, tables, transaction::DbTx};
use reth_primitives_traits::AlloyBlockHeader;
use reth_provider::{
    providers::LatestStateProviderRef, test_utils::MockNodeTypesWithDB, AccountReader,
    DatabaseProviderROFactory, HeaderProvider, ProviderFactory, StageCheckpointReader,
    StateProvider, StateRootProvider, StorageSettingsCache,
};
use reth_stages_types::StageId;
use reth_storage_overlay::OverlayStateProviderFactory;
use reth_tasks::Runtime;
use reth_trie::{
    verify::{Output, DEFAULT_STORAGE_LOOKAHEAD},
    HashedPostState,
};
use reth_trie_db::{with_adapter, DatabaseVerifier};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::PathBuf,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc, Mutex, RwLock,
    },
};

/// Most driver writes queued at once; submissions past it are rejected.
const MAX_PENDING: usize = 4096;

type Node = MockNodeTypesWithDB<Arc<DatabaseEnv>>;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct Config {
    /// A finite local smoke run; absent means run indefinitely.
    rounds: Option<u64>,
    datadir: Option<PathBuf>,
    /// Blocks in a round. The block after the last starts a new round on a fresh database.
    blocks: u64,
    /// Updates in a block: queued driver writes first, padded with random ones.
    updates: usize,
    /// Most accounts the random padding creates.
    accounts: usize,
    proof_workers: usize,
    timeout_secs: u64,
    persistence_threshold: u64,
    num_state_masking_blocks: u64,
    memory_block_buffer_target: Option<u64>,
}

impl Config {
    const fn settings(&self) -> Settings {
        Settings {
            proof_workers: self.proof_workers,
            timeout_secs: self.timeout_secs,
            persistence_threshold: self.persistence_threshold,
            num_state_masking_blocks: self.num_state_masking_blocks,
            memory_block_buffer_target: self.memory_block_buffer_target,
        }
    }
}

impl Default for Config {
    fn default() -> Self {
        Self {
            rounds: None,
            datadir: Some(PathBuf::from("/data/reth-state-root")),
            blocks: 64,
            updates: 64,
            accounts: 256,
            proof_workers: 2,
            timeout_secs: 60,
            // Small windows mask and prune state every few blocks.
            persistence_threshold: 5,
            num_state_masking_blocks: 2,
            memory_block_buffer_target: Some(0),
        }
    }
}

/// The server: one active round at a time, which every request but a summary changes.
struct Server {
    config: Config,
    campaign: Campaign,
    /// Shared by every round's engine.
    runtime: Runtime,
    /// The campaign database every round resets and reuses.
    db: Arc<DatabaseEnv>,
    snapshotter: Snapshotter,
    /// None only while one round is retired and the next opens.
    round: Mutex<Option<Round>>,
    /// The active round's view, which proof requests read without waiting for block production.
    /// Retiring a round takes it out, which waits for the proof requests reading it.
    view: RwLock<Option<Arc<View>>>,
}

impl Server {
    fn handle(&self, request: Request) -> Result<Response> {
        if let Request::GetProof { round, block, targets } = request {
            let view = self.view.read().map_err(|_| eyre!("view lock poisoned"))?;
            let Some(view) = view.as_deref() else {
                return Ok(Response::Rejected { reason: format!("round {round} is over") });
            };
            return prove(view, round, block, &targets);
        }
        let mut guard = self.round.lock().map_err(|_| eyre!("round lock poisoned"))?;
        let round = guard.as_mut().ok_or_else(|| eyre!("no active round"))?;
        match request {
            Request::StateSummary => round.summary(),
            Request::SubmitWrites { round: id, writes, collider } => {
                if id != round.id {
                    return Ok(Response::Rejected { reason: format!("round {id} is over") });
                }
                if round.pending.len() + writes.len() > MAX_PENDING {
                    return Ok(Response::Rejected { reason: "too many queued writes".into() });
                }
                round.collider.merge(collider);
                round.pending.extend(writes);
                Ok(Response::Queued { pending: round.pending.len() })
            }
            Request::BuildBlock => {
                if round.engine.head() == self.config.blocks {
                    let finished = guard.take().expect("active round");
                    let number = finished.number + 1;
                    // Wait for proof requests at this round to release its database handles.
                    *self.view.write().map_err(|_| eyre!("view lock poisoned"))? = None;
                    finished.finish(&self.snapshotter)?;
                    invariant!(
                        Arc::strong_count(&self.db) == 1,
                        "round releases all database handles"
                    );
                    assert_sometimes!(true, "Trie workload completes a round");
                    // Only a verified, fully flushed round can authorize resetting its database
                    // and journal.
                    self.campaign.retire()?;
                    if self.config.rounds.is_some_and(|rounds| number >= rounds) {
                        std::process::exit(0);
                    }
                    let next = Round::open(self, number)?;
                    *self.view.write().map_err(|_| eyre!("view lock poisoned"))? =
                        Some(Arc::clone(&next.view));
                    *guard = Some(next);
                }
                guard.as_mut().expect("active round").build_block(&self.config)
            }
            Request::GetProof { .. } => unreachable!("served above"),
            Request::CheckRoot => round.check_root(),
            Request::Flush => {
                round.persist(true)?;
                Ok(Response::Flushed { round: round.id, head: round.engine.head() })
            }
        }
    }
}

/// One database, from its first block to the verified flush that retires it, across restarts.
struct Round {
    /// Random, so commands can tell rounds apart across restarts.
    id: u64,
    /// Rounds this process completed before this one.
    number: u64,
    engine: Engine,
    journal: RoundJournal,
    state: Model,
    /// The model at the db tip, replayed from the journal as saves are acknowledged.
    persisted_state: Model,
    collider: Collider,
    /// Where the collider is saved after each generated block, so a restart can revisit its
    /// groups.
    collider_path: PathBuf,
    shapes: ShapeTracker,
    pending: Vec<Write>,
    view: Arc<View>,
}

impl Round {
    /// Resumes the active round, verifying what the database recovered, or starts a new one.
    fn open(server: &Server, number: u64) -> Result<Self> {
        let config = &server.config;
        let datadir = server.campaign.start(&server.db)?;
        // reth writes genesis static files before committing the database, and refuses to open
        // static files without one. A round killed before genesis was durable has no blocks yet,
        // so start its tables and files over.
        let initialized = datadir.join("initialized");
        if !initialized.exists() {
            clear_tables(&server.db)?;
            for entry in fs::read_dir(&datadir)? {
                let path = entry?.path();
                if path.file_name().is_some_and(|name| name != "config.json") {
                    if path.is_dir() {
                        fs::remove_dir_all(&path)?
                    } else {
                        fs::remove_file(&path)?
                    }
                }
            }
        }
        let engine =
            Engine::open(&config.settings(), server.runtime.clone(), server.db.clone(), &datadir)?;
        if !initialized.exists() {
            persist_json(&initialized, &true)?;
        }
        let journal = RoundJournal::open(&datadir, config.blocks)?;
        let base = engine.head();
        let mut state = Model::default();
        // Recovered blocks stay provable, at the model's root after each.
        let mut blocks = Vec::with_capacity(base as usize + 1);
        let mut recovered_root = root(&state);
        for number in 0..=base {
            if number > 0 {
                journal.replay(number..=number, &mut state)?;
                recovered_root = root(&state);
            }
            let header = engine
                .factory()
                .sealed_header(number)?
                .ok_or_else(|| eyre!("missing header {number}"))?;
            invariant!(recovered_root == header.state_root(), "recovered root at {number}");
            blocks.push((header.hash(), recovered_root));
        }
        if base > 0 {
            verify(engine.factory(), &state, base, base)?;
        }
        println!("{}", json!({"recovery": "complete", "head": base, "root": recovered_root}));
        assert_sometimes!(base > 0, "Restart recovers persisted blocks");
        let collider_path = datadir.join("collider.json");
        let collider = if collider_path.exists() {
            serde_json::from_slice(&fs::read(&collider_path)?)?
        } else {
            Collider::default()
        };
        // The replayed tries are the baseline the next block's transitions are measured from.
        let mut shapes = ShapeTracker::default();
        shapes.observe(model::tries(&state));
        let id = AntithesisRng.random();
        let view = Arc::new(View {
            round: id,
            factory: engine.factory().clone(),
            blocks: RwLock::new(blocks),
            db_tip: AtomicU64::new(base),
            state_tip: AtomicU64::new(base),
        });
        Ok(Self {
            id,
            number,
            engine,
            journal,
            persisted_state: state.clone(),
            state,
            collider,
            collider_path,
            shapes,
            pending: Vec::new(),
            view,
        })
    }

    fn summary(&self) -> Result<Response> {
        let (db_tip, state_tip) = self.engine.tips();
        let roots = self
            .view
            .blocks
            .read()
            .map_err(|_| eyre!("block list poisoned"))?
            .iter()
            .enumerate()
            .map(|(number, (_, root))| BlockRoot { number: number as u64, root: *root })
            .collect();
        Ok(Response::Summary(Summary {
            round: self.id,
            head: self.engine.head(),
            db_tip,
            state_tip,
            roots,
            accounts: model::sample(&mut AntithesisRng, &self.state),
            collider: self.collider.clone(),
        }))
    }

    /// Advances persistence, verifying the persisted state after every acknowledged save.
    fn persist(&mut self, flush: bool) -> Result<()> {
        let Self { engine, journal, persisted_state, view, .. } = self;
        engine.persist(flush, |factory, previous, db_tip, state_tip| {
            journal.replay((previous + 1)..=db_tip, persisted_state)?;
            verify(factory, persisted_state, db_tip, state_tip)?;
            view.db_tip.store(db_tip, Ordering::Release);
            view.state_tip.store(state_tip, Ordering::Release);
            Ok(())
        })
    }

    fn build_block(&mut self, config: &Config) -> Result<Response> {
        self.persist(false)?;
        let number = self.engine.head() + 1;
        // A block journaled before a restart is produced again exactly; queued writes wait.
        let operations = match self.journal.recorded(number) {
            Some(operations) => operations,
            None => {
                let mut rng = AntithesisRng;
                let queued = self.pending.len().min(config.updates);
                let mut scratch = self.state.clone();
                let mut updates = self
                    .pending
                    .drain(..queued)
                    .flat_map(|write| write_updates(&mut scratch, write))
                    .collect::<Vec<_>>();
                assert_sometimes!(!updates.is_empty(), "A block includes driver writes");
                let padding = config.updates.saturating_sub(updates.len());
                updates.extend(generate::writes(
                    &mut rng,
                    &scratch,
                    &mut self.collider,
                    config.accounts,
                    padding,
                ));
                let operations = input::operations(&mut rng, updates);
                // Sync the replay record before mutating the model or starting production tasks.
                // Save the collider first: a kill before the journal record regenerates the block,
                // and groups for keys never written are harmless to revisit.
                persist_json(&self.collider_path, &self.collider)?;
                self.journal.record(number, &operations)?;
                operations
            }
        };
        let updates_input = operations
            .iter()
            .flat_map(|op| match op {
                input::Operation::UpdateBatch { updates } => updates.as_slice(),
                _ => &[],
            })
            .cloned()
            .collect::<Vec<_>>();
        let mut accounts = self.state.keys().copied().collect::<BTreeSet<_>>();
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
        let (bundle, updates) = apply(&mut self.state, number, &updates_input);
        self.shapes.observe(model::tries(&self.state));
        let (db_tip, state_tip) = self.engine.tips();
        // The full operations are in the journal before production tasks run.
        println!(
            "{}",
            json!({"block": number, "round": self.id, "db_tip": db_tip,
            "state_tip": state_tip, "operations": operations.len()})
        );
        // Rebuild from the plain model, independently of production hashed state and trie updates.
        let expected_root = root(&self.state);
        let hash = self.engine.produce(&operations, bundle, updates, expected_root)?;
        // Publish the block only once the overlay manager can serve it.
        self.view
            .blocks
            .write()
            .map_err(|_| eyre!("block list poisoned"))?
            .push((hash, expected_root));
        Ok(Response::Block { round: self.id, number, root: expected_root })
    }

    fn check_root(&self) -> Result<Response> {
        let number = self.engine.head();
        let expected = root(&self.state);
        let actual = self.engine.tip_root()?;
        invariant!(
            actual == expected,
            "overlay root at {number}: expected {expected}, actual {actual}"
        );
        let (_, state_tip) = self.engine.tips();
        assert_sometimes!(number > state_tip, "Root checked over in-memory blocks");
        Ok(Response::Root { number, root: actual })
    }

    /// Flushes and verifies both frontiers at the head, then closes the database.
    fn finish(mut self, snapshotter: &Snapshotter) -> Result<()> {
        self.persist(true)?;
        let Self { engine, id, .. } = self;
        let (blocks, commits, partial_commits, update_batches, hint_batches) = (
            engine.head(),
            engine.commits,
            engine.partial_commits,
            engine.update_batches,
            engine.hint_batches,
        );
        engine.close()?;
        assert_sometimes!(partial_commits > 0, "Persistence commits with masked state");
        assert_sometimes!(hint_batches > 0, "Prewarm hints reach trie workers");
        println!(
            "{}",
            json!({"completed": true, "round": id, "blocks": blocks,
            "commits": commits, "partial_commits": partial_commits,
            "update_batches": update_batches, "hint_batches": hint_batches,
            "metrics": metric_counts(snapshotter)})
        );
        Ok(())
    }
}

/// What proof requests read, without waiting for block production.
struct View {
    /// The round's ID.
    round: u64,
    factory: ProviderFactory<Node>,
    /// Hash and model state root of every block of the round, by number.
    blocks: RwLock<Vec<(B256, B256)>>,
    /// Highest block whose block data is persisted.
    db_tip: AtomicU64,
    /// Highest block whose state and trie are persisted; masked blocks lie between the tips.
    state_tip: AtomicU64,
}

/// Serves one `eth_getMultiProof` request, with the witness of the same reads, at a block of
/// the view's round.
fn prove(view: &View, round: u64, number: u64, targets: &[ProofTarget]) -> Result<Response> {
    if round != view.round {
        return Ok(Response::Rejected { reason: format!("round {round} is over") });
    }
    // Persistence may advance during the request; the tips only classify coverage.
    let db_tip = view.db_tip.load(Ordering::Acquire);
    let state_tip = view.state_tip.load(Ordering::Acquire);
    let Some((hash, _)) =
        view.blocks.read().map_err(|_| eyre!("block list poisoned"))?.get(number as usize).copied()
    else {
        return Ok(Response::Rejected { reason: format!("no block {number}") });
    };
    assert_sometimes!(number > db_tip, "Proof served from in-memory blocks");
    assert_sometimes!(number > state_tip && number <= db_tip, "Proof served from masked blocks");
    assert_sometimes!(number == state_tip && number > 0, "Proof served at the persisted state tip");
    assert_sometimes!(number < state_tip, "Proof served from reverted historical state");
    // The provider BlockchainProvider resolves for a block hash, in memory or persisted.
    let result = OverlayStateProviderFactory::new(
        view.factory.clone(),
        view.factory.overlay_manager().overlay_builder(hash),
    )
    .database_provider_ro()
    .map_err(eyre::Report::from)
    .and_then(|provider| {
        let proofs = proof::get_multi_proof(&provider, targets)?;
        let witness = proof::witness(&provider, &proofs)?;
        Ok(Proved { proofs, witness })
    });
    let error = result.as_ref().err().map(|error| format!("{error:#}"));
    invariant!(
        error.is_none(),
        "eth_getMultiProof and witness at block {number} (db tip {db_tip}, state tip \
         {state_tip}) for {targets:?}: {}",
        error.as_deref().unwrap_or_default()
    );
    Ok(Response::Proofs { proofs: serde_json::to_value(result?)? })
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
        // repair-trie --dry-run: every stored trie node must be the one a rebuild from hashed
        // state produces, including nodes a matching root would not reveal. The persistence
        // writer is idle here, so the verifier's transactions read one snapshot.
        let inconsistencies = with_adapter!(factory, |A| {
            DatabaseVerifier::<_, A>::new(factory.db_ref(), 2, DEFAULT_STORAGE_LOOKAHEAD)?
                .filter(|output| !matches!(output, Ok(Output::Progress(_))))
                .take(16)
                .collect::<Result<Vec<_>, _>>()?
        });
        invariant!(
            inconsistencies.is_empty(),
            "persisted trie nodes at {tip}: {inconsistencies:?}"
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

fn serve(config: Option<String>) -> Result<()> {
    let config: Config = serde_json::from_str(config.as_deref().unwrap_or("{}"))
        .wrap_err("invalid workload configuration")?;
    ensure!(config.rounds != Some(0), "rounds must be positive");
    ensure!((1..=1024).contains(&config.blocks), "blocks must be 1..=1024");
    ensure!((1..=4096).contains(&config.updates), "updates must be 1..=4096");
    ensure!((1..=4096).contains(&config.accounts), "accounts must be 1..=4096");
    let recorder = DebuggingRecorder::new();
    let snapshotter = recorder.snapshotter();
    recorder.install()?;
    let campaign = Campaign::new(&config)?;
    let runtime = engine::runtime(&config.settings())?;
    let db = Arc::new(init_db(campaign.database_path()?, Default::default())?);
    let mut server = Server {
        config,
        campaign,
        runtime,
        db,
        snapshotter,
        round: Mutex::new(None),
        view: RwLock::new(None),
    };
    let round = Round::open(&server, 0)?;
    server.view = RwLock::new(Some(Arc::clone(&round.view)));
    server.round = Mutex::new(Some(round));
    harness::serve(
        &json!({"workload": "reth-state-root", "database_initialized": true}),
        move |request| server.handle(request),
    )
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
    let mut arguments = std::env::args().skip(1);
    let command = arguments.next().unwrap_or_default();
    let result = match command.as_str() {
        "serve" => serve(arguments.next()),
        other => Err(eyre!("unknown command {other:?}")),
    };
    assert_always_or_unreachable!(
        result.is_ok(),
        "Trie workload completes without errors",
        &json!({
            "command": command,
            "error": result.as_ref().err().map(|error| format!("{error:#}"))
        })
    );
    result
}
