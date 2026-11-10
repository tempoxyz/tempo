//! Antithesis workload for `eth_getMultiProof` over in-memory, masked and persisted trie state.
//!
//! `serve` runs the server. It produces blocks like the reth-state-root workload when a test
//! command asks: the sparse-trie state root task computes each root, blocks are inserted into the
//! `OverlayManager`, and a background writer persists them with state masking. Proof commands ask
//! for `eth_getMultiProof` at any block of the round, served through the provider the RPC uses
//! concurrently with block production, and verify every proof against the model's state root.
//! Every round starts on a fresh database; restart recovery is reth-state-root's subject.

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

#[expect(dead_code, reason = "Shared with reth-state-root, which checks the overlay root.")]
#[path = "../../reth-state-root/src/engine.rs"]
mod engine;
#[path = "../../reth-state-root/src/input.rs"]
mod input;
#[expect(dead_code, reason = "Shared with reth-state-root, whose input generator is unused here.")]
#[path = "../../reth-state-root/src/model.rs"]
mod model;
#[path = "../../reth-state-root/src/persistence.rs"]
mod persistence;

mod generate;
mod proof;

use alloy_primitives::B256;
use antithesis_instrumentation as _;
use antithesis_sdk::{
    assert_always_or_unreachable, assert_sometimes, assert_unreachable, random::AntithesisRng,
};
use antithesis_trie_shapes::{
    harness::{self, BlockRoot, ProofTarget, Request, Response, Summary},
    Collider, ShapeTracker, Write,
};
use engine::{Engine, Settings};
use eyre::{ensure, eyre, Context, Result};
use model::{apply, root, write_updates, Model};
use rand_09::Rng;
use reth_db::{init_db, DatabaseEnv};
use reth_engine_tree::tree::TreeConfig;
use reth_primitives_traits::AlloyBlockHeader;
use reth_provider::{test_utils::MockNodeTypesWithDB, DatabaseProviderROFactory, ProviderFactory};
use reth_storage_overlay::OverlayStateProviderFactory;
use serde::Deserialize;
use serde_json::json;
use std::sync::{
    atomic::{AtomicU64, Ordering},
    Arc, Mutex, RwLock,
};
use tempfile::TempDir;

/// Most driver writes queued at once; submissions past it are rejected.
const MAX_PENDING: usize = 4096;

type Node = MockNodeTypesWithDB<Arc<DatabaseEnv>>;

#[derive(Clone, Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct Config {
    /// A finite local smoke run; absent means run indefinitely.
    rounds: Option<u64>,
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

impl Default for Config {
    fn default() -> Self {
        let tree = TreeConfig::default();
        Self {
            rounds: None,
            blocks: 64,
            updates: 32,
            accounts: 256,
            proof_workers: 2,
            timeout_secs: 60,
            persistence_threshold: tree.persistence_threshold(),
            num_state_masking_blocks: tree.num_state_masking_blocks(),
            memory_block_buffer_target: None,
        }
    }
}

/// What proof requests read, without waiting for block production.
struct View {
    round: u64,
    factory: ProviderFactory<Node>,
    /// Hash and model state root of every block of the round, by number.
    blocks: RwLock<Vec<(B256, B256)>>,
    /// Highest block whose block data is persisted.
    db_tip: AtomicU64,
    /// Highest block whose state and trie are persisted; masked blocks lie between the tips.
    state_tip: AtomicU64,
    /// Deleted once the last proof request of the round lets go of the view.
    _datadir: TempDir,
}

struct Server {
    config: Config,
    /// None only while one round closes and the next opens.
    round: Mutex<Option<Round>>,
    view: RwLock<Arc<View>>,
}

impl Server {
    fn handle(&self, request: Request) -> Result<Response> {
        if let Request::GetProof { round, block, targets } = request {
            let view = Arc::clone(&*self.view.read().map_err(|_| eyre!("view lock poisoned"))?);
            return prove(&view, round, block, &targets);
        }
        let mut guard = self.round.lock().map_err(|_| eyre!("round lock poisoned"))?;
        let round = guard.as_mut().ok_or_else(|| eyre!("no active round"))?;
        match request {
            Request::StateSummary => round.summary(),
            Request::SubmitWrites { round: id, writes, collider } => {
                if id != round.view.round {
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
                    finished.finish()?;
                    assert_sometimes!(true, "Proof workload completes a round");
                    if self.config.rounds.is_some_and(|rounds| number >= rounds) {
                        std::process::exit(0);
                    }
                    let next = Round::open(&self.config, number)?;
                    *self.view.write().map_err(|_| eyre!("view lock poisoned"))? =
                        Arc::clone(&next.view);
                    *guard = Some(next);
                }
                guard.as_mut().expect("active round").build_block(&self.config)
            }
            Request::Flush => {
                round.persist(true)?;
                Ok(Response::Flushed { round: round.view.round, head: round.engine.head() })
            }
            Request::CheckRoot => {
                Ok(Response::Rejected { reason: "reth-proofs checks proofs, not roots".into() })
            }
            Request::GetProof { .. } => unreachable!("served above"),
        }
    }
}

/// One fresh database, from genesis to the flush that closes it.
struct Round {
    /// Rounds this process completed before this one.
    number: u64,
    engine: Engine,
    state: Model,
    collider: Collider,
    shapes: ShapeTracker,
    pending: Vec<Write>,
    view: Arc<View>,
}

impl Round {
    fn open(config: &Config, number: u64) -> Result<Self> {
        let datadir = tempfile::tempdir()?;
        let settings = Settings {
            proof_workers: config.proof_workers,
            timeout_secs: config.timeout_secs,
            persistence_threshold: config.persistence_threshold,
            num_state_masking_blocks: config.num_state_masking_blocks,
            memory_block_buffer_target: config.memory_block_buffer_target,
        };
        let db = Arc::new(init_db(datadir.path().join("db"), Default::default())?);
        let engine = Engine::open(&settings, engine::runtime(&settings)?, db, datadir.path())?;
        let state = Model::default();
        let genesis = engine.parent();
        invariant!(root(&state) == genesis.state_root(), "genesis root");
        let view = Arc::new(View {
            round: AntithesisRng.random(),
            factory: engine.factory().clone(),
            blocks: RwLock::new(vec![(genesis.hash(), genesis.state_root())]),
            db_tip: AtomicU64::new(0),
            state_tip: AtomicU64::new(0),
            _datadir: datadir,
        });
        Ok(Self {
            number,
            engine,
            state,
            collider: Collider::default(),
            shapes: ShapeTracker::default(),
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
            round: self.view.round,
            head: self.engine.head(),
            db_tip,
            state_tip,
            roots,
            accounts: model::sample(&mut AntithesisRng, &self.state),
            collider: self.collider.clone(),
        }))
    }

    fn persist(&mut self, flush: bool) -> Result<()> {
        let view = &self.view;
        self.engine.persist(flush, |_, _, db_tip, state_tip| {
            view.db_tip.store(db_tip, Ordering::Release);
            view.state_tip.store(state_tip, Ordering::Release);
            Ok(())
        })
    }

    fn build_block(&mut self, config: &Config) -> Result<Response> {
        self.persist(false)?;
        let number = self.engine.head() + 1;
        let mut rng = AntithesisRng;
        let queued = self.pending.len().min(config.updates);
        let mut scratch = self.state.clone();
        let mut writes = self
            .pending
            .drain(..queued)
            .flat_map(|write| write_updates(&mut scratch, write))
            .collect::<Vec<_>>();
        assert_sometimes!(!writes.is_empty(), "A block includes driver writes");
        let padding = config.updates.saturating_sub(writes.len());
        writes.extend(generate::writes(
            &mut rng,
            &scratch,
            &mut self.collider,
            config.accounts,
            padding,
        ));
        let (bundle, updates) = apply(&mut self.state, number, &writes);
        self.shapes.observe(model::tries(&self.state));
        let operations = input::operations(&mut rng, writes);
        let expected_root = root(&self.state);
        let hash = self.engine.produce(&operations, bundle, updates, expected_root)?;
        // Publish the block only once the overlay manager can serve it.
        self.view
            .blocks
            .write()
            .map_err(|_| eyre!("block list poisoned"))?
            .push((hash, expected_root));
        Ok(Response::Block { round: self.view.round, number, root: expected_root })
    }

    fn finish(mut self) -> Result<()> {
        self.persist(true)?;
        let (round, blocks, partial_commits) =
            (self.view.round, self.engine.head(), self.engine.partial_commits);
        self.engine.close()?;
        assert_sometimes!(partial_commits > 0, "Persistence commits with masked state");
        println!(
            "{}",
            json!({"completed": true, "round": round, "blocks": blocks,
            "partial_commits": partial_commits})
        );
        Ok(())
    }
}

/// Serves one `eth_getMultiProof` request at a block of the view's round.
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
    .and_then(|provider| proof::get_multi_proof(&provider, targets));
    let error = result.as_ref().err().map(|error| format!("{error:#}"));
    invariant!(
        error.is_none(),
        "eth_getMultiProof at block {number} (db tip {db_tip}, state tip {state_tip}) for \
         {targets:?}: {}",
        error.as_deref().unwrap_or_default()
    );
    Ok(Response::Proofs { proofs: serde_json::to_value(result?)? })
}

fn serve(config: Option<String>) -> Result<()> {
    let config: Config = serde_json::from_str(config.as_deref().unwrap_or("{}"))
        .wrap_err("invalid workload configuration")?;
    ensure!(config.rounds != Some(0), "rounds must be positive");
    ensure!((1..=1024).contains(&config.blocks), "blocks must be 1..=1024");
    ensure!((1..=4096).contains(&config.updates), "updates must be 1..=4096");
    ensure!((1..=4096).contains(&config.accounts), "accounts must be 1..=4096");
    let round = Round::open(&config, 0)?;
    let view = RwLock::new(Arc::clone(&round.view));
    let server = Server { config, round: Mutex::new(Some(round)), view };
    harness::serve(
        &json!({"workload": "reth-proofs", "database_initialized": true}),
        move |request| server.handle(request),
    )
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
    let mut arguments = std::env::args().skip(1);
    let command = arguments.next().unwrap_or_default();
    let result = match command.as_str() {
        "serve" => serve(arguments.next()),
        other => Err(eyre!("unknown command {other:?}")),
    };
    assert_always_or_unreachable!(
        result.is_ok(),
        "Proof workload completes without errors",
        &json!({
            "command": command,
            "error": result.as_ref().err().map(|error| format!("{error:#}"))
        })
    );
    result
}
