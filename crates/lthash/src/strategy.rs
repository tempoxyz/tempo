//! The engine-facing state-root strategy backed by the lthash task.

use crate::{
    accumulator::LthashAccumulator,
    error::LthashError,
    store::LthashStore,
    task::{LthashInput, LthashMessage, LthashOutcome, LthashTask, send_evm_state_to_lthash},
};
use alloy_consensus::BlockHeader as _;
use alloy_eip7928::bal::DecodedBal;
use crossbeam_channel::Sender as CrossbeamSender;
use reth_engine_tree::tree::{
    StateProviderBuilder,
    payload_processor::multiproof::{
        PayloadStateRootHandle, StateRootComputeOutcome, StateRootSink, StateRootStreams,
        StateRootTaskError,
    },
    payload_validator::LazyHashedPostState,
    state_root_strategy::{
        PayloadStateRootJobContext, PreparedStateRootJob, StateRootJob, StateRootJobContext,
        StateRootJobOutcome, StateRootStrategy,
    },
};
use reth_errors::{ProviderError, ProviderResult};
use reth_evm::ConfigureEvm;
use reth_execution_types::BlockExecutionOutput;
use reth_primitives_traits::{NodePrimitives, RecoveredBlock};
use reth_revm::{context::Block as _, state::EvmState};
use reth_storage_api::{BlockReader, DatabaseProviderFactory, StateProviderFactory, StateReader};
use reth_trie::updates::TrieUpdates;
use std::sync::{Arc, mpsc};
use tracing::debug;

/// Tempo state-root strategy backed by the TIP-1078 lthash accumulator prototype.
#[derive(Debug)]
pub struct TempoLthashStateRootStrategy {
    /// Accumulator store shared with the persistence hook.
    store: Arc<LthashStore>,
}

impl TempoLthashStateRootStrategy {
    /// Creates a strategy sharing the given accumulator store.
    pub const fn new(store: Arc<LthashStore>) -> Self {
        Self { store }
    }
}

impl<N, P, Evm> StateRootStrategy<N, P, Evm> for TempoLthashStateRootStrategy
where
    N: NodePrimitives,
    P: BlockReader
        + StateProviderFactory
        + StateReader
        + DatabaseProviderFactory
        + Clone
        + Send
        + Sync
        + 'static,
    Evm: ConfigureEvm<Primitives = N> + 'static,
{
    fn prepare(
        &self,
        ctx: StateRootJobContext<'_, N, P, Evm>,
    ) -> ProviderResult<PreparedStateRootJob<N>> {
        // On the parallel BAL path the complete access list is known before execution starts,
        // so the job consumes it directly and needs no execution stream. Otherwise per-tx
        // updates arrive through the execution hook.
        let decoded_bal = ctx
            .parallel_bal_execution()
            .then(|| ctx.env().decoded_bal.clone())
            .flatten();
        let block_number: u64 = ctx.env().evm_env.block_env.number().saturating_to();
        let provider_builder = ctx.provider_builder();
        let parent_accumulator = self.store.resolve_parent(
            provider_builder.provider_factory(),
            ctx.env().parent_state_root,
            block_number.saturating_sub(1),
        )?;
        let (handle, streams) = spawn_lthash_task(
            ctx.executor(),
            ctx.provider_builder(),
            decoded_bal,
            parent_accumulator,
            block_number,
            self.store.clone(),
        );

        Ok(PreparedStateRootJob::new(
            Box::new(TempoLthashStateRootJob {
                handle: Some(handle),
            }),
            streams,
            None,
        ))
    }

    fn prepare_payload_builder(
        &self,
        ctx: PayloadStateRootJobContext<'_, N, P, Evm>,
    ) -> ProviderResult<Option<PayloadStateRootHandle>> {
        let provider_builder = ctx.provider_builder();
        let parent_number = ctx.parent_header().number();
        let parent_accumulator = self.store.resolve_parent(
            provider_builder.provider_factory(),
            ctx.parent_state_root(),
            parent_number,
        )?;
        let (handle, streams) = spawn_lthash_task(
            ctx.executor(),
            ctx.provider_builder(),
            None,
            parent_accumulator,
            parent_number + 1,
            self.store.clone(),
        );
        let (state_root_tx, state_root_rx) = mpsc::channel();

        ctx.executor()
            .spawn_blocking_named("lthash-payload-result", move || {
                let result = handle
                    .outcome()
                    .map(into_state_root_compute_outcome)
                    .map_err(|err| StateRootTaskError::Other(err.to_string()));
                let _ = state_root_tx.send(result);
            });

        Ok(Some(PayloadStateRootHandle::new(
            "lthash",
            streams,
            state_root_rx,
            None,
        )))
    }
}

struct TempoLthashStateRootJob {
    handle: Option<LthashHandle>,
}

impl<N> StateRootJob<N> for TempoLthashStateRootJob
where
    N: NodePrimitives,
{
    fn name(&self) -> &'static str {
        "lthash"
    }

    fn finish(
        &mut self,
        _block: &RecoveredBlock<N::Block>,
        _output: Arc<BlockExecutionOutput<N::Receipt>>,
        _hashed_state: &LazyHashedPostState,
    ) -> ProviderResult<StateRootJobOutcome> {
        let outcome = self
            .handle
            .take()
            .expect("lthash state-root job already finished")
            .outcome()
            .map_err(ProviderError::other)?;

        debug!(
            target: "tempo::lthash",
            state_root = ?outcome.root,
            account_updates = outcome.account_updates,
            storage_updates = outcome.storage_updates,
            "lthash state root task finished"
        );

        Ok(StateRootJobOutcome::new(
            outcome.root,
            Arc::new(TrieUpdates::default()),
        ))
    }
}

#[derive(Debug)]
struct LthashHandle {
    outcome_rx: mpsc::Receiver<Result<LthashOutcome, LthashError>>,
}

impl LthashHandle {
    fn outcome(self) -> Result<LthashOutcome, LthashError> {
        self.outcome_rx
            .recv()
            .map_err(|_| LthashError::OutcomeClosed)?
    }
}

#[derive(Clone, Debug)]
struct LthashSink {
    updates_tx: CrossbeamSender<LthashMessage>,
}

impl StateRootSink for LthashSink {
    fn on_state_update(&self, state: EvmState) {
        send_evm_state_to_lthash(&state, &self.updates_tx);
    }

    fn on_hashed_state_update(&self, _state: reth_trie::HashedPostState) {}

    fn on_updates_finished(&self) {
        let _ = self.updates_tx.send(LthashMessage::FinishedUpdates);
    }
}

fn spawn_lthash_task<N, P>(
    executor: &reth_tasks::Runtime,
    provider_builder: StateProviderBuilder<N, P>,
    decoded_bal: Option<Arc<DecodedBal>>,
    parent_accumulator: LthashAccumulator,
    block_number: u64,
    store: Arc<LthashStore>,
) -> (LthashHandle, StateRootStreams)
where
    N: NodePrimitives,
    P: BlockReader + StateProviderFactory + StateReader + Clone + Send + Sync + 'static,
{
    let (outcome_tx, outcome_rx) = mpsc::channel();

    // With a complete BAL the task needs no execution stream: it starts its parent-state reads
    // right away, in parallel with block execution. Otherwise updates arrive per transaction
    // through the execution hook.
    let (input, streams) = match decoded_bal {
        Some(bal) => (LthashInput::Bal(bal), StateRootStreams::empty()),
        None => {
            let (updates_tx, updates_rx) = crossbeam_channel::unbounded();
            (
                LthashInput::Stream(updates_rx),
                StateRootStreams::from_sink(Arc::new(LthashSink { updates_tx }), true),
            )
        }
    };

    executor.spawn_blocking_named("lthash", move || {
        let result = provider_builder
            .build()
            .map_err(LthashError::ProviderBuild)
            .and_then(|provider| LthashTask::new(provider, parent_accumulator).run(input));
        // Record the accumulator under the root it hashes to. This runs on the build and
        // the validation path alike, so a proposer building on its own block finds the
        // parent accumulator even though built payloads skip engine validation.
        if let Ok(outcome) = &result {
            store.record(outcome.root, block_number, outcome.accumulator.clone());
        }
        let _ = outcome_tx.send(result);
    });

    (LthashHandle { outcome_rx }, streams)
}

fn into_state_root_compute_outcome(outcome: LthashOutcome) -> StateRootComputeOutcome {
    StateRootComputeOutcome {
        state_root: outcome.root,
        trie_updates: Arc::new(TrieUpdates::default()),
        changed_paths: None,
        #[cfg(feature = "trie-debug")]
        debug_recorders: Vec::new(),
    }
}
