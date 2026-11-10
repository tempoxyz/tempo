//! Antithesis workload for the sparse-trie, proof, overlay and persistence pipeline.
//!
//! `serve` runs the server: it owns the database, the engine, the model and the journal that
//! replays blocks after a restart, and builds blocks only when a test command asks. Every other
//! subcommand is a test template command; see the antithesis-trie-shapes harness.

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
mod input;
mod journal;
mod lifecycle;
mod model;
mod persistence;

use alloy_primitives::{keccak256, B256, U256};
use antithesis_instrumentation as _;
use antithesis_sdk::{
    assert_always_or_unreachable, assert_sometimes, assert_unreachable, random::AntithesisRng,
};
use antithesis_trie_shapes::{
    harness::{self, BlockRoot, Client, Request, Response, Summary},
    Collider, ShapeTracker, Write,
};
use engine::{Engine, Settings};
use eyre::{bail, ensure, eyre, Context, Result};
use journal::RoundJournal;
use lifecycle::{persist_json, Campaign};
use metrics_util::debugging::{DebugValue, DebuggingRecorder, Snapshotter};
use model::{apply, generate, root, write_updates, Model};
use rand_09::Rng;
use reth_db::DatabaseEnv;
use reth_db_api::{cursor::DbCursorRO, tables, transaction::DbTx};
use reth_engine_tree::tree::TreeConfig;
use reth_primitives_traits::AlloyBlockHeader;
use reth_provider::{
    providers::LatestStateProviderRef, test_utils::MockNodeTypesWithDB, AccountReader,
    DatabaseProviderROFactory, HeaderProvider, ProviderFactory, StageCheckpointReader,
    StateProvider, StateRootProvider, StorageSettingsCache,
};
use reth_stages_types::StageId;
use reth_storage_overlay::OverlayStateProviderFactory;
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
    sync::{Arc, Mutex},
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
        let tree = TreeConfig::default();
        Self {
            rounds: None,
            datadir: Some(PathBuf::from("/data/reth-state-root")),
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

/// The server: one active round at a time, which every request but a summary changes.
struct Server {
    config: Config,
    campaign: Campaign,
    snapshotter: Snapshotter,
    /// None only while one round is retired and the next opens.
    round: Mutex<Option<Round>>,
}

impl Server {
    fn handle(&self, request: Request) -> Result<Response> {
        let mut guard = self.round.lock().map_err(|_| eyre!("round lock poisoned"))?;
        let round = guard.as_mut().ok_or_else(|| eyre!("no active round"))?;
        match request {
            Request::StateSummary => Ok(Response::Summary(round.summary())),
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
                    finished.finish(&self.snapshotter)?;
                    assert_sometimes!(true, "Trie workload completes a round");
                    // Only a verified, fully flushed round can retire its database and journal.
                    self.campaign.retire()?;
                    if self.config.rounds.is_some_and(|rounds| number >= rounds) {
                        std::process::exit(0);
                    }
                    *guard = Some(Round::open(&self.config, &self.campaign, number)?);
                }
                guard.as_mut().expect("active round").build_block(&self.config)
            }
            Request::GetProof { .. } => {
                Ok(Response::Rejected { reason: "reth-state-root serves no proofs".into() })
            }
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
}

impl Round {
    /// Resumes the active round, verifying what the database recovered, or starts a new one.
    fn open(config: &Config, campaign: &Campaign, number: u64) -> Result<Self> {
        let datadir = campaign.start()?;
        let engine = Engine::open(&config.settings(), &datadir)?;
        let journal = RoundJournal::open(&datadir, config.blocks)?;
        let base = engine.head();
        let mut state = Model::default();
        journal.replay(1..=base, &mut state)?;
        if base > 0 {
            verify(engine.factory(), &state, base, base)?;
        }
        let recovered_root = root(&state);
        invariant!(recovered_root == engine.parent().state_root(), "recovered root at {base}");
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
        Ok(Self {
            id: AntithesisRng.random(),
            number,
            engine,
            journal,
            persisted_state: state.clone(),
            state,
            collider,
            collider_path,
            shapes,
            pending: Vec::new(),
        })
    }

    fn summary(&self) -> Summary {
        let (db_tip, state_tip) = self.engine.tips();
        let head = self.engine.head();
        Summary {
            round: self.id,
            head,
            db_tip,
            state_tip,
            roots: vec![BlockRoot { number: head, root: self.engine.parent().state_root() }],
            accounts: model::sample(&mut AntithesisRng, &self.state),
            collider: self.collider.clone(),
        }
    }

    /// Advances persistence, verifying the persisted state after every acknowledged save.
    fn persist(&mut self, flush: bool) -> Result<()> {
        let Self { engine, journal, persisted_state, .. } = self;
        engine.persist(flush, |factory, previous, db_tip, state_tip| {
            journal.replay((previous + 1)..=db_tip, persisted_state)?;
            verify(factory, persisted_state, db_tip, state_tip)
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
                updates.extend(generate(&mut rng, &scratch, &mut self.collider, padding));
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
        self.engine.produce(&operations, bundle, updates, expected_root)?;
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
    let recorder = DebuggingRecorder::new();
    let snapshotter = recorder.snapshotter();
    recorder.install()?;
    let campaign = Campaign::new(&config)?;
    let round = Round::open(&config, &campaign, 0)?;
    let server = Server { config, campaign, snapshotter, round: Mutex::new(Some(round)) };
    harness::serve(
        &json!({"workload": "reth-state-root", "database_initialized": true}),
        move |request| server.handle(request),
    )
}

/// anytime_root: checks the root the overlay serves at the tip against the model's.
fn anytime_root() -> Result<()> {
    let Some(mut client) = Client::connect()? else { return harness::unavailable() };
    match client.call(&Request::CheckRoot)? {
        None => harness::unavailable(),
        Some(Response::Root { number, root }) => {
            println!("{}", json!({"root": {"number": number, "root": root}}));
            Ok(())
        }
        Some(other) => bail!("unexpected answer to check_root: {other:?}"),
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
    let mut arguments = std::env::args().skip(1);
    let command = arguments.next().unwrap_or_default();
    let result = match command.as_str() {
        "serve" => serve(arguments.next()),
        "first_genesis" => harness::first_genesis(),
        "parallel_driver_writes" => harness::parallel_driver_writes(),
        "parallel_driver_blocks" => harness::parallel_driver_blocks(),
        "anytime_root" => anytime_root(),
        "eventually_persisted" => harness::persisted().map(drop),
        "finally_recovered" => harness::finally(|| Ok(harness::persisted()?.is_some())),
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
