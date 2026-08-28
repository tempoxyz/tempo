//! Execution-layer driver for follower nodes.
//!
//! This actor sends verified certificate targets to Reth as forkchoice heads. It advances the safe
//! and finalized targets as marshal delivers persisted finalized blocks. It also refreshes
//! forkchoice with a heartbeat and advances marshal's floor behind Reth's finalized state.
//!
//! Unlike the executor used by validator nodes, it does not build payloads, canonicalize proposal
//! heads, or track blocks proposed by this node. Followers receive complete blocks from their
//! upstream, submit them to Reth as finalized payloads, and rely on Reth's sync machinery plus
//! marshal gap repair to fill history.

use std::{collections::VecDeque, time::Duration};

use commonware_consensus::{
    Heightable as _,
    marshal::Update,
    types::{Epocher as _, FixedEpocher, Height},
};
use commonware_runtime::{Clock, ContextCell, FutureExt as _, Handle, Pacer, Spawner, spawn_cell};
use commonware_utils::{Acknowledgement as _, acknowledgement::Exact};
use eyre::{Report, WrapErr as _, ensure, eyre};
use futures::{FutureExt as _, StreamExt as _, channel::mpsc, future::BoxFuture};
use tempo_node::TempoExecutionData;
use tracing::{Level, debug, error, instrument};

use super::{
    Config, ExecutionEngine, FinalizedBlockProvider, Marshal,
    fcu::{ForkchoiceTargets, ForkchoiceTracker, Target},
    ingress::Message,
};
use crate::{consensus::block::Block, utils::OptionFuture};

const FINALIZED_FCU_RETRY_INTERVAL: Duration = Duration::from_secs(1);

pub(crate) struct Actor<TContext, P, E, M = crate::alias::marshal::Mailbox> {
    context: ContextCell<TContext>,
    mailbox: mpsc::UnboundedReceiver<Message>,

    execution_provider: P,
    execution_engine: E,
    marshal: M,

    epoch_strategy: FixedEpocher,
    floor: Height,

    forkchoice: ForkchoiceTracker,

    block_queue: VecDeque<(Block, Exact)>,
    floor_candidate: Option<Height>,

    execution_task: OptionFuture<BoxFuture<'static, ExecutionTaskResult>>,

    fcu_heartbeat_interval: Duration,
    fcu_heartbeat_timer: OptionFuture<BoxFuture<'static, ()>>,
}

impl<TContext, P, E, M> Actor<TContext, P, E, M>
where
    TContext: Clock + Pacer + Spawner,
    P: FinalizedBlockProvider + 'static,
    E: Clone + ExecutionEngine + 'static,
    M: Marshal + 'static,
{
    pub(super) fn new(
        context: TContext,
        config: Config<P, E, M>,
        mailbox: mpsc::UnboundedReceiver<Message>,
    ) -> Self {
        let Config {
            execution_provider,
            execution_engine,
            marshal,
            epoch_strategy,
            floor,
            fcu_heartbeat_interval,
        } = config;

        let finalized_header = execution_provider
            .finalized_header()
            .expect("failed reading finalized execution header");
        let forkchoice = ForkchoiceTracker::new(Target::from_header(&finalized_header));

        Self {
            context: ContextCell::new(context),

            mailbox,
            marshal,
            epoch_strategy,
            floor,
            execution_provider,
            execution_engine,

            forkchoice,
            block_queue: VecDeque::new(),
            floor_candidate: None,
            execution_task: OptionFuture::none(),

            fcu_heartbeat_interval,
            fcu_heartbeat_timer: OptionFuture::none(),
        }
    }

    pub(crate) fn start(mut self) -> Handle<()> {
        spawn_cell!(self.context, self.run())
    }

    async fn run(mut self) {
        let mut heartbeat = false;
        loop {
            self.start_execution_task(heartbeat);
            heartbeat = false;

            self.update_fcu_heartbeat_timer();

            tokio::select! {
                biased;

                result = &mut self.execution_task => {
                    self.execution_task = OptionFuture::none();
                    match result {
                        ExecutionTaskResult::Completed(submitted_fcu) => {
                            if let Some(submitted_fcu) = submitted_fcu {
                                self.forkchoice.note_submitted(submitted_fcu);
                            }

                            // Emits an event on error.
                            let _: Result<_, _> = self.try_advance_floor().await;
                        }
                        ExecutionTaskResult::Fatal(error) => {
                            error!(%error, "execution task failed");
                            break;
                        }
                    }
                }

                Some(message) = self.mailbox.next() => {
                    match message {
                        Message::Update(Update::Block(block, ack)) => {
                            // Marshal delivers persisted finalized blocks in height order. The
                            // executor submits each payload before using it as Reth's finalized
                            // forkchoice target.
                            self.block_queue.push_back(((*block).clone(), ack));
                        }

                        Message::Update(Update::Tip(round, height, digest)) => {
                            // Marshal reports known finalized tips before it completes gap-free
                            // block delivery. The certificate can guide the head while finalized
                            // follows delivered blocks.
                            if self.floor_candidate.is_none() {
                                self.floor_candidate = Some(height);
                            }
                            self.forkchoice
                                .advance_head(Target::from_finalization(round, digest));
                        }
                        Message::Finalization { round, digest } => {
                            let candidate = Target::from_finalization(round, digest);
                            self.forkchoice.advance_head(candidate);
                        }
                    }
                }

                _ = (&mut self.fcu_heartbeat_timer).fuse() => {
                    heartbeat = true;
                }
            }
        }
    }

    fn update_fcu_heartbeat_timer(&mut self) {
        if self.execution_task.is_none() && self.block_queue.is_empty() {
            if self.fcu_heartbeat_timer.is_none() {
                self.fcu_heartbeat_timer
                    .replace(self.context.sleep(self.fcu_heartbeat_interval).boxed());
            }
        } else {
            self.fcu_heartbeat_timer = OptionFuture::none();
        }
    }

    fn start_execution_task(&mut self, heartbeat: bool) {
        if !self.execution_task.is_none() {
            return;
        }

        let request = if let Some((block, ack)) = self.block_queue.pop_front() {
            let finalized_advanced = self
                .forkchoice
                .advance_finalized(Target::from_block(&block));
            let forkchoice = (self.forkchoice.requires_update() || heartbeat)
                .then_some(self.forkchoice.latest());
            ExecutionRequest::Block {
                block,
                forkchoice,
                finalized_advanced,
                ack,
            }
        } else if self.forkchoice.requires_update() || heartbeat {
            ExecutionRequest::Forkchoice(self.forkchoice.latest())
        } else {
            return;
        };

        let context = self.context.child("execute_request");
        let execution_engine = self.execution_engine.clone();
        self.execution_task
            .replace(execute_request(context, execution_engine, request).boxed());
    }

    #[instrument(skip_all, err(level = Level::WARN))]
    async fn try_advance_floor(&mut self) -> eyre::Result<()> {
        let finalized_height = Height::new(
            self.execution_provider
                .finalized_header()?
                .num_hash()
                .number,
        );
        let epoch_length = self
            .epoch_strategy
            .containing(finalized_height)
            .expect("strategy is valid for all heights and epochs")
            .length();

        let Some(floor_height) = self.floor_candidate else {
            return Ok(());
        };

        let floor_ceiling = finalized_height.saturating_sub(epoch_length);
        if floor_height > floor_ceiling {
            return Ok(());
        }

        let Some(floor_digest) = self
            .execution_provider
            .durable_block_hash(floor_height.get())
            .wrap_err("failed reading floor block hash")?
        else {
            debug!(%finalized_height, %floor_height, "floor not durable in execution");
            return Ok(());
        };

        debug!(%finalized_height, %floor_height, %floor_digest, "advancing marshal floor");

        let finalization = self
            .marshal
            .get_finalization(floor_height)
            .await
            .ok_or_else(|| eyre!("floor candidate `{floor_height}` missing finalization"))?;

        self.marshal.set_floor(finalization);

        self.floor = floor_height;
        self.floor_candidate = None;

        Ok(())
    }
}

enum ExecutionRequest {
    Forkchoice(ForkchoiceTargets),
    Block {
        block: Block,
        forkchoice: Option<ForkchoiceTargets>,
        ack: Exact,
        /// Whether the block advances finality and must wait for a `VALID` FCU before
        /// acknowledgement.
        finalized_advanced: bool,
    },
}

enum ExecutionTaskResult {
    Completed(Option<ForkchoiceTargets>),
    Fatal(Report),
}

enum ForkchoiceOutcome {
    Valid,
    Syncing,
}

async fn execute_request<TContext: Pacer, E: ExecutionEngine + 'static>(
    context: TContext,
    execution_engine: E,
    request: ExecutionRequest,
) -> ExecutionTaskResult {
    match request {
        ExecutionRequest::Forkchoice(forkchoice) => {
            let result = submit_forkchoice_update(&context, &execution_engine, &forkchoice).await;
            match result {
                Ok(ForkchoiceOutcome::Valid | ForkchoiceOutcome::Syncing) => {
                    ExecutionTaskResult::Completed(Some(forkchoice))
                }
                Err(error) => ExecutionTaskResult::Fatal(error),
            }
        }
        ExecutionRequest::Block {
            block,
            forkchoice,
            finalized_advanced,
            ack,
        } => {
            if let Err(error) = submit_new_payload(&context, &execution_engine, block).await {
                return ExecutionTaskResult::Fatal(error);
            }

            if let Some(forkchoice) = forkchoice {
                loop {
                    let result =
                        submit_forkchoice_update(&context, &execution_engine, &forkchoice).await;
                    match result {
                        Ok(ForkchoiceOutcome::Valid) => break,
                        Ok(ForkchoiceOutcome::Syncing) if finalized_advanced => {
                            debug!(
                                "execution layer is syncing before applying finalized FCU; retrying"
                            );
                            context.sleep(FINALIZED_FCU_RETRY_INTERVAL).await;
                        }
                        Ok(ForkchoiceOutcome::Syncing) => break,
                        Err(error) => return ExecutionTaskResult::Fatal(error),
                    }
                }
            }

            ack.acknowledge();
            ExecutionTaskResult::Completed(forkchoice)
        }
    }
}

#[instrument(
    skip_all,
    fields(block.height = %block.height(), block.digest = %block.digest()),
    err,
)]
async fn submit_new_payload<TContext: Pacer, E: ExecutionEngine + ?Sized>(
    context: &TContext,
    execution_engine: &E,
    block: Block,
) -> eyre::Result<()> {
    let (block, block_access_list) = block.into_parts();
    let payload_status = execution_engine
        .new_payload(TempoExecutionData {
            block,
            block_access_list,
            // can be omitted for finalized blocks
            validator_set: None,
        })
        .pace(context, Duration::from_millis(20))
        .await
        .wrap_err("failed sending finalized payload")?;

    ensure!(
        payload_status.is_valid() || payload_status.is_syncing(),
        "payload status of finalized block was neither valid nor syncing: \
         `{payload_status}`"
    );

    Ok(())
}

#[instrument(
    skip_all,
    fields(
        head.round = ?forkchoice.head.round,
        head.digest = %forkchoice.head.digest,
        finalized.round = ?forkchoice.finalized.round,
        finalized.digest = %forkchoice.finalized.digest,
    )
)]
async fn submit_forkchoice_update<TContext: Pacer, E: ExecutionEngine + ?Sized>(
    context: &TContext,
    execution_engine: &E,
    forkchoice: &ForkchoiceTargets,
) -> eyre::Result<ForkchoiceOutcome> {
    let forkchoice = forkchoice.rpc_state();

    let response = execution_engine
        .fork_choice_updated(forkchoice, None)
        .pace(context, Duration::from_millis(20))
        .await
        .wrap_err("failed to update forkchoice state")?;

    debug!(payload_status = %response.payload_status, "execution layer reported FCU status");

    if response.payload_status.is_valid() {
        return Ok(ForkchoiceOutcome::Valid);
    }

    if response.payload_status.is_syncing() {
        return Ok(ForkchoiceOutcome::Syncing);
    }

    Err(Report::msg(response.payload_status).wrap_err("execution layer rejected fcu"))
}
