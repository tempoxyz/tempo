//! Execution-layer driver for follower nodes.
//!
//! This actor sends marshal's finalized tips to Reth as head, safe, and finalized forkchoice
//! updates, periodically refreshes that forkchoice with a heartbeat, and advances marshal's floor
//! to one epoch behind Reth's finalized state.
//!
//! Like the validator executor, finalized blocks are acknowledged to marshal only once Reth has
//! durably persisted them, so marshal's processed height never runs ahead of the execution
//! layer's durable state and a restart never skips a block marshal considers processed.
//!
//! One hash serves as head, safe and finalized, so a forkchoice target must never name a block
//! marshal has not stored. Marshal tips are the only source of one: the driver does not address
//! this actor, so a bare verified certificate cannot move Reth's finalized watermark ahead of
//! marshal's own archives.
//!
//! Unlike the executor used by validator nodes, it does not build payloads, canonicalize proposal
//! heads, or track blocks proposed by this node. Followers receive complete blocks from their
//! upstream, submit them to Reth as finalized payloads, and rely on Reth's sync machinery plus
//! marshal gap repair to fill history.

use commonware_cryptography::{Digested, Digestible as _};
use std::{
    collections::{BTreeMap, VecDeque},
    time::Duration,
};

use alloy_rpc_types_engine::{ForkchoiceState, ForkchoiceUpdateError};
use commonware_consensus::{
    Heightable as _,
    marshal::Update,
    types::{Epocher as _, FixedEpocher, Height},
};
use commonware_runtime::{Clock, ContextCell, FutureExt as _, Handle, Pacer, Spawner, spawn_cell};
use commonware_utils::{Acknowledgement as _, acknowledgement::Exact};
use eyre::{Report, WrapErr as _, ensure, eyre};
use futures::{FutureExt as _, StreamExt as _, channel::mpsc, future::BoxFuture};
use reth_engine_primitives::BeaconForkChoiceUpdateError;
use reth_ethereum::rpc::eth::primitives::BlockNumHash;
use tempo_node::TempoExecutionData;
use tokio::sync::watch;
use tracing::{Level, debug, error, instrument};

use super::{
    Config, ExecutionEngine, FinalizedBlockProvider, Marshal, ingress::Message, target::Target,
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

    // Highest target attempted or covered, even on SYNCING, to throttle tip retries.
    // Catch-up is gated by the provider's live finality, not this watermark.
    last_fcu: Target,
    latest_tip: Target,

    block_queue: VecDeque<(Digested<Block>, Exact)>,
    floor_candidate: Option<Height>,

    // Finalized blocks handed to the execution layer, waiting for it to
    // durably persist them before they are acknowledged to marshal.
    pending_acknowledgements: BTreeMap<Height, (Digest, Exact)>,
    persisted_blocks: watch::Receiver<Option<BlockNumHash>>,

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
        let tip = Target::from_header(&finalized_header);
        let persisted_blocks = execution_provider.subscribe_persisted_block();

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
            floor_candidate: None,
            pending_acknowledgements: BTreeMap::new(),
            persisted_blocks,
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
                        ExecutionTaskResult::Completed(last_fcu, delivered) => {
                            if let Some((height, digest, ack)) = delivered {
                                self.pending_acknowledgements.insert(height, (digest, ack));
                            }
                            if let Err(error) = self.acknowledge_persisted() {
                                error!(%error, "failed acknowledging persisted blocks");
                                break;
                            }
                            self.last_fcu = last_fcu;
                            if last_fcu.supersedes(&self.latest_tip) {
                                self.latest_tip = last_fcu;
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
                            self.block_queue.push_back((block, ack));
                        }

                        // A Tip update has a persisted finalization, so it can
                        // start a new floor cycle.
                        Message::Update(Update::Tip(round, height, digest)) => {
                            if self.floor_candidate.is_none() {
                                self.floor_candidate = Some(height);
                            }
                            let candidate = Target::from_finalization(round, digest);
                            if candidate.supersedes(&self.latest_tip) {
                                self.latest_tip = candidate;
                            }
                        }
                    }
                }

                changed = self.persisted_blocks.changed() => {
                    if let Err(error) = changed
                        .wrap_err("execution layer closed its persisted-block notifications")
                        .and_then(|()| self.acknowledge_persisted())
                    {
                        error!(%error, "failed acknowledging persisted blocks");
                        break;
                    }

                    // Emits an event on error.
                    let _: Result<_, _> = self.try_advance_floor().await;
                }

                _ = (&mut self.fcu_heartbeat_timer).fuse() => {
                    heartbeat = true;
                }
            }
        }
    }

    fn should_send_forkchoice(&self) -> bool {
        self.latest_tip.digest != self.last_fcu.digest && self.latest_tip.supersedes(&self.last_fcu)
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

        let result = execute_request(
            self.context.child("execute_request"),
            self.execution_engine.clone(),
            self.execution_provider.clone(),
            self.last_fcu,
            request,
        );
        self.execution_task.replace(result.boxed());
    }

    /// Acknowledges every pending block at or below the execution layer's
    /// durable frontier. Pending blocks are finalized and contiguous, so a
    /// durable block matching the pending block at its height proves every
    /// lower pending block durable too. A mismatch waits for the execution
    /// layer to unwind the conflicting block.
    #[instrument(skip_all, err)]
    fn acknowledge_persisted(&mut self) -> eyre::Result<()> {
        let Some((highest, _)) = self.pending_acknowledgements.last_key_value() else {
            return Ok(());
        };
        let durable = self
            .execution_provider
            .durable_block_at_or_below(highest.get())
            .wrap_err("failed reading the execution layer's durable block")?;
        let height = Height::new(durable.number);
        let Some((digest, _)) = self.pending_acknowledgements.get(&height) else {
            return Ok(());
        };
        if digest.0 != durable.hash {
            debug!(
                durable.height = durable.number,
                durable.hash = %durable.hash,
                finalized.digest = %digest,
                "durable block conflicts with the finalized block at its height; \
                waiting for the execution layer to unwind it",
            );
            return Ok(());
        }
        let pending = self.pending_acknowledgements.split_off(&height.next());
        for (_, (_, ack)) in std::mem::replace(&mut self.pending_acknowledgements, pending) {
            ack.acknowledge();
        }
        Ok(())
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

        // A floor marks every block below it processed without an acknowledgement,
        // so it must not pass the execution layer's crash-safe frontier.
        let durable = self
            .execution_provider
            .durable_block_at_or_below(floor_height.get())
            .wrap_err("failed reading the execution layer's durable block")?;
        if durable.number < floor_height.get() {
            debug!(%finalized_height, %floor_height, durable.height = durable.number, "floor not durable in execution");
            return Ok(());
        }

        debug!(%finalized_height, %floor_height, "advancing marshal floor");

        let finalization = self
            .marshal
            .get_finalization(floor_height)
            .await
            .ok_or_else(|| eyre!("floor candidate `{floor_height}` missing finalization"))?;

        self.marshal.set_floor(finalization);

        // Marshal drops its in-flight acks below a newly installed floor and
        // redelivers from the floor, so their pending acknowledgements are stale.
        self.pending_acknowledgements = self.pending_acknowledgements.split_off(&floor_height);

        self.floor = floor_height;
        self.floor_candidate = None;

        Ok(())
    }
}

enum ExecutionRequest {
    Forkchoice(Target),
    Block(Digested<Block>, Exact),
}

enum ExecutionTaskResult {
    /// The new forkchoice watermark, and the delivered finalized block that
    /// is acknowledged once it is durable.
    Completed(Target, Option<(Height, Digest, Exact)>),
    Fatal(Report),
}

async fn execute_request<TContext: Pacer, E: ExecutionEngine, P: FinalizedBlockProvider>(
    context: TContext,
    execution_engine: E,
    execution_provider: P,
    last_fcu: Target,
    request: ExecutionRequest,
) -> ExecutionTaskResult {
    let (tip, ack) = match request {
        ExecutionRequest::Forkchoice(tip) => (tip, None),
        ExecutionRequest::Block(block, ack) => {
            let tip = Target::from_block(block.inner());
            let delivered = (block.height(), block.digest());
            if let Err(error) = submit_new_payload(&context, &execution_engine, block).await {
                return ExecutionTaskResult::Fatal(error);
            }
            (tip, Some((delivered, ack)))
        }
    };

    // Use live finality, not the requested tip, since pipeline sync can complete independently.
    let finalized = match execution_provider.finalized_header() {
        Ok(header) => Target::from_header(&header),
        Err(error) => return ExecutionTaskResult::Fatal(error),
    };
    // Skip catch-up blocks at or below live finality, but let heartbeats reaffirm an equal tip.
    let handled = if finalized.supersedes(&tip) || (ack.is_some() && !tip.supersedes(&finalized)) {
        finalized
    } else {
        match submit_forkchoice_update(&context, &execution_engine, &execution_provider, &tip).await
        {
            Ok(target) => target,
            Err(error) => return ExecutionTaskResult::Fatal(error),
        }
    };

    // Keep the watermark monotonic so older catch-up blocks cannot immediately retry a newer tip.
    // The block is acknowledged once the execution layer persists it, which on SYNCING is after
    // its pipeline sync passes the block.
    ExecutionTaskResult::Completed(
        if handled.supersedes(&last_fcu) {
            handled
        } else {
            last_fcu
        },
        ack.map(|((height, digest), ack)| (height, digest, ack)),
    )
}

#[instrument(
    skip_all,
    fields(block.height = %block.height(), block.digest = %block.digest()),
    err,
)]
async fn submit_new_payload<TContext: Pacer, E: ExecutionEngine + ?Sized>(
    context: &TContext,
    execution_engine: &E,
    block: Digested<Block>,
) -> eyre::Result<()> {
    #[cfg(feature = "fuzz")]
    let details =
        serde_json::json!({ "height": block.height().get(), "digest": block.digest().to_string() });
    let block = block.inner().execution_block();
    let payload_status = execution_engine
        .new_payload(TempoExecutionData { block })
        .pace(context, Duration::from_millis(20))
        .await
        .wrap_err("failed sending finalized payload")?;

    #[cfg(feature = "fuzz")]
    antithesis_sdk::assert_always!(
        !payload_status.is_invalid(),
        "Follow mode execution never rejects a finalized block as invalid",
        &details
    );
    ensure!(
        payload_status.is_valid() || payload_status.is_syncing(),
        "payload status of finalized block was neither valid nor syncing: \
         `{payload_status}`"
    );

    Ok(())
}

#[instrument(skip_all, fields(round = ?tip.round, digest = %tip.digest))]
async fn submit_forkchoice_update<
    TContext: Pacer,
    E: ExecutionEngine + ?Sized,
    P: FinalizedBlockProvider,
>(
    context: &TContext,
    execution_engine: &E,
    execution_provider: &P,
    tip: &Target,
) -> eyre::Result<Target> {
    let hash = tip.digest.0;
    let forkchoice = ForkchoiceState {
        head_block_hash: hash,
        safe_block_hash: hash,
        finalized_block_hash: hash,
    };

    let response = execution_engine
        .fork_choice_updated(forkchoice, None)
        .pace(context, Duration::from_millis(20))
        .await;

    let response = match response {
        Ok(response) => response,
        Err(error) => {
            // Re-read finality on TooDeepReorg. Ignore only if finality advanced past the target.
            if matches!(
                &error,
                BeaconForkChoiceUpdateError::ForkchoiceUpdateError(
                    ForkchoiceUpdateError::TooDeepReorg
                )
            ) {
                let finalized = Target::from_header(&execution_provider.finalized_header()?);
                if finalized.supersedes(tip) {
                    return Ok(finalized);
                }
            }
            return Err(error).wrap_err("failed to update forkchoice state");
        }
    };

    debug!(payload_status = %response.payload_status, "execution layer reported FCU status");

    #[cfg(feature = "fuzz")]
    antithesis_sdk::assert_always!(
        !response.is_invalid(),
        "Follow mode forkchoice never rejects a finalized tip as invalid",
        &serde_json::json!({ "digest": tip.digest.to_string(), "status": response.payload_status.to_string() })
    );

    ensure!(
        !response.is_invalid(),
        Report::msg(response.payload_status).wrap_err("execution layer rejected fcu")
    );

    Ok(*tip)
}
