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
    types::{Epocher as _, FixedEpocher, Height, Round},
};
use commonware_runtime::{Clock, ContextCell, FutureExt as _, Handle, Pacer, Spawner, spawn_cell};
use commonware_utils::{Acknowledgement as _, acknowledgement::Exact};
use eyre::{Report, WrapErr as _, ensure, eyre};
use futures::{FutureExt as _, StreamExt as _, channel::mpsc, future::BoxFuture};
use tempo_node::TempoExecutionData;
use tracing::{Level, debug, error, instrument};

use super::{
    BlockLocation, Config, ExecutionEngine, FinalizedBlockProvider, Marshal, ingress::Message,
    target::Target,
};
use crate::{
    consensus::{Digest, block::Block},
    utils::OptionFuture,
};

pub(crate) struct Actor<TContext, P, E, M = crate::alias::marshal::Mailbox> {
    context: ContextCell<TContext>,
    mailbox: mpsc::UnboundedReceiver<Message>,

    execution_provider: P,
    execution_engine: E,
    marshal: M,

    epoch_strategy: FixedEpocher,
    floor: Height,

    last_fcu: Target,
    latest_tip: Target,

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
            startup_tip,
            fcu_heartbeat_interval,
        } = config;

        let tip = execution_provider
            .finalized_block_num_hash()
            .expect("failed reading finalized execution tip");
        let tip = Target::from_execution(Height::new(tip.number), Digest(tip.hash));

        let mut actor = Self {
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
            floor_candidate: None,
            execution_task: OptionFuture::none(),

            fcu_heartbeat_interval,
            fcu_heartbeat_timer: OptionFuture::none(),
        };

        // Store the startup round before marshal sends the same tip. This lets
        // the actor order certificates received during that gap. Genesis has
        // no round, so this call changes nothing there.
        actor.observe(startup_tip.into());
        actor
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

                        // Finalization certificates for Tip updates must be available
                        // making them a good candidates for setting marshal's floor.
                        Message::Update(Update::Tip(round, height, digest)) => {
                            if self.floor_candidate.is_none() {
                                self.floor_candidate = Some(height);
                            }
                            self.observe(Target::finalized(round, height, digest));
                        }
                        Message::CertifiedTip { round, digest } => {
                            if let Err(error) = self.observe_certified(round, digest) {
                                error!(%error, %round, %digest, "failed ordering certified tip");
                                break;
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

    fn observe(&mut self, candidate: Target) {
        if candidate.supersedes(&self.latest_tip) {
            self.latest_tip = candidate;
        } else if candidate.digest == self.latest_tip.digest {
            self.latest_tip.height = self.latest_tip.height.or(candidate.height);
            self.latest_tip.round = self.latest_tip.round.or(candidate.round);
        }

        if candidate.digest == self.last_fcu.digest {
            self.last_fcu.height = self.last_fcu.height.or(candidate.height);
            self.last_fcu.round = self.last_fcu.round.or(candidate.round);
        }
    }

    fn observe_certified(&mut self, round: Round, digest: Digest) -> eyre::Result<()> {
        let candidate = Target::certified(round, digest);
        let current = self.latest_tip;

        // After a restart, execution may be ahead of the local certificate
        // archive. Its tip then has a height but no round. A new certificate
        // has a round but no height until execution knows its block. The normal
        // `Target` order cannot compare these values, so use the epoch and block
        // location to decide:
        //
        // Certificate                          Result
        // -----------                          ------
        // Earlier epoch                        Ignore it.
        // Later epoch                          Use it as the new target.
        // Same epoch, unknown block            Use it as the new target.
        // Same epoch, block above the tip      Use the known height.
        // Same epoch, canonical block below    Ignore it.
        // Same epoch, any block at the tip     Report a finality conflict.
        // Same epoch, side block below the tip Report a finality conflict.
        //
        // A verified block that is unknown can be treated as newer because an
        // older block should already be present under consensus safety. A known
        // block must also be in the epoch named by its certificate.

        if candidate.digest == current.digest {
            self.observe(candidate);
            return Ok(());
        }

        if current.round.is_some() {
            self.observe(candidate);
            return Ok(());
        }

        let current_height = current
            .height
            .expect("a roundless forkchoice target must have a height");

        let current_epoch = self
            .epoch_strategy
            .containing(current_height)
            .expect("strategy is valid for all heights and epochs")
            .epoch();

        if round.epoch() < current_epoch {
            return Ok(());
        }

        if round.epoch() > current_epoch {
            self.latest_tip = candidate;
            return Ok(());
        }

        let (height, canonical) = match self
            .execution_provider
            .locate_block(candidate.digest.0)
            .wrap_err("failed locating certified block in execution")?
        {
            BlockLocation::Canonical(height) => (Height::new(height), true),
            BlockLocation::NonCanonical(height) => (Height::new(height), false),
            BlockLocation::Unknown => {
                self.latest_tip = candidate;
                return Ok(());
            }
        };

        let block_epoch = self
            .epoch_strategy
            .containing(height)
            .expect("strategy is valid for all heights and epochs")
            .epoch();
        ensure!(
            block_epoch == round.epoch(),
            "certified block `{digest}` is at height `{height}` in epoch `{block_epoch}`, but its \
             certificate is from epoch `{}`",
            round.epoch(),
        );

        if height > current_height {
            self.latest_tip = Target::finalized(round, height, digest);
            return Ok(());
        }

        ensure!(
            canonical && height < current_height,
            "certified block `{digest}` at height `{height}` conflicts with finalized execution \
             tip `{}` at height `{current_height}`",
            current.digest,
        );
        Ok(())
    }

    fn should_send_forkchoice(&self) -> bool {
        self.latest_tip.digest != self.last_fcu.digest
            && !self.last_fcu.supersedes(&self.latest_tip)
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
        } else if self.should_send_forkchoice() || heartbeat {
            ExecutionRequest::Forkchoice(self.latest_tip)
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
        let finalized = self.execution_provider.finalized_block_num_hash()?;

        let finalized_height = Height::new(finalized.number);
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
    Forkchoice(Target),
    Block(Block, Exact),
}

enum ExecutionTaskResult {
    Completed(Target),
    Fatal(Report),
}

async fn execute_request<TContext: Pacer, E: ExecutionEngine + 'static>(
    context: TContext,
    execution_engine: E,
    last_fcu: Target,
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
            let tip = Target::from_execution(block.height(), block.digest());

            if let Err(error) = submit_new_payload(&context, &execution_engine, block).await {
                return ExecutionTaskResult::Fatal(error);
            }

            let last_fcu = if tip.supersedes(&last_fcu) {
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

#[instrument(skip_all, fields(height = ?tip.height, digest = %tip.digest))]
async fn submit_forkchoice_update<TContext: Pacer, E: ExecutionEngine + ?Sized>(
    context: &TContext,
    execution_engine: &E,
    tip: &Target,
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
