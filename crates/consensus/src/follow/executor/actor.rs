//! Execution-layer driver for follower nodes.
//!
//! This actor sends verified finalized tips to Reth as head, safe, and finalized forkchoice
//! updates, periodically refreshes that forkchoice with a heartbeat, and advances marshal's floor
//! to one epoch behind Reth's finalized state.
//!
//! Unlike the executor used by validator nodes, it does not build payloads, canonicalize proposal
//! heads, or track blocks proposed by this node. Followers receive complete blocks from their
//! upstream, submit them to Reth as finalized payloads, and rely on Reth's sync machinery plus
//! marshal gap repair to fill history.

use std::{collections::VecDeque, time::Duration};

use alloy_rpc_types_engine::ForkchoiceState;
use commonware_consensus::{
    Heightable as _,
    marshal::Update,
    types::{Epocher as _, FixedEpocher, Height},
};
use commonware_runtime::{Clock, ContextCell, FutureExt as _, Handle, Pacer, Spawner, spawn_cell};
use commonware_utils::{Acknowledgement as _, acknowledgement::Exact};
use eyre::{Report, WrapErr as _, ensure};
use futures::{FutureExt as _, StreamExt as _, channel::mpsc, future::BoxFuture};
use tempo_node::TempoExecutionData;
use tracing::{Level, debug, error, instrument};

use super::{Config, ExecutionEngine, FinalizedBlockProvider, Marshal};
use crate::{
    consensus::{Digest, block::Block},
    utils::OptionFuture,
};

#[derive(Clone, Copy, Debug)]
struct FinalizedTip {
    height: Height,
    digest: Digest,
}

pub(crate) struct Actor<TContext, P, E, M = crate::alias::marshal::Mailbox> {
    context: ContextCell<TContext>,
    mailbox: mpsc::UnboundedReceiver<Update<Block>>,

    execution_provider: P,
    execution_engine: E,
    marshal: M,

    epoch_strategy: FixedEpocher,
    floor: Height,

    last_fcu: FinalizedTip,
    latest_tip: FinalizedTip,

    block_queue: VecDeque<(Block, Exact)>,
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
        mailbox: mpsc::UnboundedReceiver<Update<Block>>,
    ) -> Self {
        let Config {
            execution_provider,
            execution_engine,
            marshal,
            epoch_strategy,
            floor,
            fcu_heartbeat_interval,
        } = config;

        let tip = execution_provider
            .finalized_block_num_hash()
            .expect("failed reading finalized execution tip");
        let tip = FinalizedTip {
            height: Height::new(tip.number),
            digest: Digest(tip.hash),
        };

        Self {
            context: ContextCell::new(context),

            mailbox,
            marshal,
            epoch_strategy,
            floor,
            execution_provider,
            execution_engine,

            last_fcu: tip,
            latest_tip: tip,
            block_queue: VecDeque::new(),
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

                Some(update) = self.mailbox.next() => {
                    match update {
                        Update::Block(block, ack) => {
                            self.block_queue.push_back((block, ack));
                        }
                        Update::Tip(_, height, digest) => {
                            if height > self.latest_tip.height {
                                self.latest_tip = FinalizedTip { height, digest };
                            }
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
            ExecutionRequest::Block(block, ack)
        } else if self.latest_tip.height > self.last_fcu.height || heartbeat {
            ExecutionRequest::Forkchoice(self.latest_tip)
        } else {
            return;
        };

        let last_fcu = self.last_fcu;
        let context = self.context.clone();
        let execution_engine = self.execution_engine.clone();
        self.execution_task
            .replace(execute_request(context, execution_engine, last_fcu, request).boxed());
    }

    #[instrument(skip_all, err(level = Level::WARN))]
    async fn try_advance_floor(&mut self) -> eyre::Result<()> {
        let finalized = self.execution_provider.finalized_block_num_hash()?;

        let finalized_height = Height::new(finalized.number);
        let epoch_length = self
            .epoch_strategy
            .containing(finalized_height)
            .expect("strategy is valid for all heights and epochs")
            .length();

        let floor_height = finalized_height.saturating_sub(epoch_length);
        if floor_height <= self.floor {
            return Ok(());
        }

        let floor_digest = self
            .execution_provider
            .durable_block_hash(floor_height.get())
            .wrap_err("failed reading floor block hash")?;

        let Some(floor_digest) = floor_digest else {
            debug!(%finalized_height, %floor_height, "floor not durable in execution");
            return Ok(());
        };

        debug!(%finalized_height, %floor_height, %floor_digest, "advancing marshal floor");
        self.marshal.set_floor(floor_height).await;
        self.floor = floor_height;

        Ok(())
    }
}

enum ExecutionRequest {
    Forkchoice(FinalizedTip),
    Block(Block, Exact),
}

enum ExecutionTaskResult {
    Completed(FinalizedTip),
    Fatal(Report),
}

async fn execute_request<TContext: Pacer, E: ExecutionEngine + 'static>(
    context: ContextCell<TContext>,
    execution_engine: E,
    last_fcu: FinalizedTip,
    request: ExecutionRequest,
) -> ExecutionTaskResult {
    match request {
        ExecutionRequest::Forkchoice(tip) => {
            match submit_forkchoice_update(&context, &execution_engine, &tip).await {
                Ok(()) => ExecutionTaskResult::Completed(tip),
                Err(error) => ExecutionTaskResult::Fatal(error),
            }
        }
        ExecutionRequest::Block(block, ack) => {
            let tip = FinalizedTip {
                height: block.height(),
                digest: block.digest(),
            };

            if let Err(error) = submit_new_payload(&context, &execution_engine, block).await {
                return ExecutionTaskResult::Fatal(error);
            }

            let last_fcu = if tip.height > last_fcu.height {
                if let Err(error) =
                    submit_forkchoice_update(&context, &execution_engine, &tip).await
                {
                    return ExecutionTaskResult::Fatal(error);
                }
                tip
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

#[instrument(skip_all, fields(height = %tip.height, digest = %tip.digest))]
async fn submit_forkchoice_update<TContext: Pacer, E: ExecutionEngine + ?Sized>(
    context: &TContext,
    execution_engine: &E,
    tip: &FinalizedTip,
) -> eyre::Result<()> {
    let hash = tip.digest.0;
    let forkchoice = ForkchoiceState {
        head_block_hash: hash,
        safe_block_hash: hash,
        finalized_block_hash: hash,
    };

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
