//! Execution-layer driver for follower nodes.
//!
//! This actor sends verified finalized tips to Reth as head and marshal-delivered blocks as safe
//! and finalized forkchoice updates, periodically refreshes that forkchoice with a heartbeat, and
//! advances marshal's floor to one epoch behind Reth's finalized state.
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
    Config, ExecutionEngine, FinalizedBlockProvider, Marshal, fcu::Forkchoice, ingress::Message,
};
use crate::{consensus::block::Block, utils::OptionFuture};

pub(crate) struct Actor<TContext, P, E, M = crate::alias::marshal::Mailbox> {
    context: ContextCell<TContext>,
    mailbox: mpsc::UnboundedReceiver<Message>,

    execution_provider: P,
    execution_engine: E,
    marshal: M,

    epoch_strategy: FixedEpocher,
    floor: Height,

    // The last completed FCU
    last_fcu: Forkchoice,
    // Next FCU to be delivered when it superseded the last
    pending_fcu: Forkchoice,

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
        let forkchoice = Forkchoice::new(&finalized_header);

        Self {
            context: ContextCell::new(context),

            mailbox,
            marshal,
            epoch_strategy,
            floor,
            execution_provider,
            execution_engine,

            last_fcu: forkchoice,
            pending_fcu: forkchoice,
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
                        ExecutionTaskResult::Completed(last_fcu) => {
                            self.last_fcu = last_fcu;

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
                            self.block_queue.push_back(((*block).clone(), ack));
                        }

                        // A Tip update has a persisted finalization, so it can
                        // start a new floor cycle.
                        Message::Update(Update::Tip(round, height, digest)) => {
                            if self.floor_candidate.is_none() {
                                self.floor_candidate = Some(height);
                            }
                            self.pending_fcu.update_head(round, digest);
                        }
                        Message::Finalization { round, digest } => {
                            self.pending_fcu.update_head(round, digest);
                        }
                    }
                }

                _ = (&mut self.fcu_heartbeat_timer).fuse() => {
                    heartbeat = true;
                }
            }
        }
    }

    fn should_send_forkchoice(&self) -> bool {
        self.pending_fcu.head_digest() != self.last_fcu.head_digest()
            || self.pending_fcu.finalized_digest() != self.last_fcu.finalized_digest()
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
            let forkchoice = self
                .pending_fcu
                .update_finalized(&block)
                .then_some(self.pending_fcu);
            ExecutionRequest::Block(block, forkchoice, ack)
        } else if self.should_send_forkchoice() || heartbeat {
            ExecutionRequest::Forkchoice(self.pending_fcu)
        } else {
            return;
        };

        let last_fcu = self.last_fcu;
        let context = self.context.child("execute_request");
        let execution_engine = self.execution_engine.clone();
        self.execution_task
            .replace(execute_request(context, execution_engine, last_fcu, request).boxed());
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
    Forkchoice(Forkchoice),
    Block(Block, Option<Forkchoice>, Exact),
}

enum ExecutionTaskResult {
    Completed(Forkchoice),
    Fatal(Report),
}

async fn execute_request<TContext: Pacer, E: ExecutionEngine + 'static>(
    context: TContext,
    execution_engine: E,
    last_fcu: Forkchoice,
    request: ExecutionRequest,
) -> ExecutionTaskResult {
    match request {
        ExecutionRequest::Forkchoice(forkchoice) => {
            match submit_forkchoice_update(&context, &execution_engine, &forkchoice).await {
                Ok(()) => ExecutionTaskResult::Completed(forkchoice),
                Err(error) => ExecutionTaskResult::Fatal(error),
            }
        }
        ExecutionRequest::Block(block, forkchoice, ack) => {
            if let Err(error) = submit_new_payload(&context, &execution_engine, block).await {
                return ExecutionTaskResult::Fatal(error);
            }

            let last_fcu = if let Some(forkchoice) = forkchoice {
                if let Err(error) =
                    submit_forkchoice_update(&context, &execution_engine, &forkchoice).await
                {
                    return ExecutionTaskResult::Fatal(error);
                }
                forkchoice
            } else {
                last_fcu
            };

            ack.acknowledge();
            ExecutionTaskResult::Completed(last_fcu)
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
        head.digest = %forkchoice.head_digest(),
        finalized.digest = %forkchoice.finalized_digest(),
    )
)]
async fn submit_forkchoice_update<TContext: Pacer, E: ExecutionEngine + ?Sized>(
    context: &TContext,
    execution_engine: &E,
    forkchoice: &Forkchoice,
) -> eyre::Result<()> {
    let forkchoice = (*forkchoice).into();

    let response = execution_engine
        .fork_choice_updated(forkchoice, None)
        .pace(context, Duration::from_millis(20))
        .await
        .wrap_err("failed to update forkchoice state")?;

    debug!(payload_status = %response.payload_status, "execution layer reported FCU status");

    ensure!(
        !response.is_invalid(),
        Report::msg(response.payload_status).wrap_err("execution layer rejected fcu")
    );

    Ok(())
}
