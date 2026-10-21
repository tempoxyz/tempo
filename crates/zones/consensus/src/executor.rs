//! The executor drives reth for the Zone consensus engine.
//!
//! One actor owns every engine-API call so that at most one is in flight. It executes blocks for
//! verification and proposal ancestry, builds proposals, and applies finalized blocks in height
//! order: execute, persist the witness, move reth's finalized marker, then consume the block's
//! Tempo import from the deposit queue and acknowledge marshal.
//!
//! Finalized blocks take priority over verification and building. The executor never fetches
//! blocks from peers: the application hands it the unexecuted ancestry marshal already resolved.

use std::{sync::Arc, time::Duration};

use alloy_consensus::BlockHeader as _;
use alloy_eips::NumHash;
use alloy_rpc_types_engine::{ForkchoiceState, PayloadStatusEnum};
use commonware_actor::Feedback;
use commonware_consensus::{Reporter, marshal::Update, types::Height};
use commonware_runtime::{Clock, Handle, Metrics, Spawner};
use commonware_utils::{Acknowledgement as _, acknowledgement::Exact};
use eyre::{OptionExt as _, WrapErr as _};
use futures::{
    StreamExt as _,
    channel::{mpsc, oneshot},
};
use reth_node_api::ConsensusEngineHandle;
use reth_payload_builder::PayloadBuilderHandle;
use reth_payload_primitives::PayloadKind;
use tempo_consensus::consensus::{Block, Digest};
use tempo_payload_types::TempoExecutionData;
use tracing::{debug, error, info, instrument, warn};
use zone_l1::{DepositQueue, L1BlockTracker};
use zone_payload::{ZonePayloadAttributes, ZonePayloadTypes};
use zone_sequencer::ProofCollectorHandle;

use crate::{
    MarshalMailbox,
    import::{DecodedTempoImport, decode_advance_tempo},
    provider::ConsensusProvider,
};

/// Attempts to persist a finalized block's witness before the node stops.
const WITNESS_ATTEMPTS: u32 = 3;
/// Delay between execution-layer readiness probes at startup.
const READINESS_RETRY: Duration = Duration::from_millis(100);

/// Executor settings.
pub(crate) struct Config<TProvider> {
    pub(crate) provider: TProvider,
    pub(crate) engine: ConsensusEngineHandle<ZonePayloadTypes>,
    pub(crate) payload_builder: PayloadBuilderHandle<ZonePayloadTypes>,
    pub(crate) deposit_queue: DepositQueue,
    pub(crate) l1_block_tracker: L1BlockTracker,
    pub(crate) proof_collector: Option<ProofCollectorHandle>,
    pub(crate) marshal: MarshalMailbox,
    /// Highest height marshal will not redeliver; the executor replays up to it from marshal's
    /// archive at startup.
    pub(crate) finalized_floor: Height,
    pub(crate) fcu_heartbeat_interval: Duration,
}

/// Handle to the executor actor. Also the marshal reporter that receives finalized blocks.
#[derive(Clone, Debug)]
pub(crate) struct Mailbox {
    requests: mpsc::UnboundedSender<Request>,
    finalized: mpsc::UnboundedSender<(Arc<Block>, Exact)>,
}

impl Mailbox {
    /// Execute `blocks`, oldest first, each on top of the previous one.
    ///
    /// Returns `Ok(false)` when reth rejects one as invalid, and an error when reth cannot reach a
    /// verdict, for example because the first block's parent is unknown.
    pub(crate) async fn execute(&self, blocks: Vec<Arc<Block>>) -> eyre::Result<bool> {
        let (response, receiver) = oneshot::channel();
        self.requests
            .unbounded_send(Request::Execute { blocks, response })
            .map_err(|_| eyre::eyre!("executor stopped"))?;
        receiver
            .await
            .map_err(|_| eyre::eyre!("executor dropped the request"))?
    }

    /// Build a block on the executed `parent` and execute it.
    pub(crate) async fn build(
        &self,
        parent: Digest,
        attributes: ZonePayloadAttributes,
    ) -> eyre::Result<Block> {
        let (response, receiver) = oneshot::channel();
        self.requests
            .unbounded_send(Request::Build {
                parent,
                attributes: Box::new(attributes),
                response,
            })
            .map_err(|_| eyre::eyre!("executor stopped"))?;
        receiver
            .await
            .map_err(|_| eyre::eyre!("executor dropped the request"))?
    }
}

impl Reporter for Mailbox {
    type Activity = Update<Block>;

    fn report(&mut self, activity: Self::Activity) -> Feedback {
        match activity {
            Update::Tip(..) => Feedback::Ok,
            Update::Block(block, ack) => match self.finalized.unbounded_send((block, ack)) {
                Ok(()) => Feedback::Ok,
                Err(_) => Feedback::Closed,
            },
        }
    }
}

enum Request {
    Execute {
        blocks: Vec<Arc<Block>>,
        response: oneshot::Sender<eyre::Result<bool>>,
    },
    Build {
        parent: Digest,
        attributes: Box<ZonePayloadAttributes>,
        response: oneshot::Sender<eyre::Result<Block>>,
    },
}

/// The executor actor; see the module documentation.
pub(crate) struct Actor<TProvider> {
    config: Config<TProvider>,
    requests: mpsc::UnboundedReceiver<Request>,
    finalized_blocks: mpsc::UnboundedReceiver<(Arc<Block>, Exact)>,
    /// Last finalized block applied to reth and the deposit queue.
    finalized: NumHash,
}

/// Create the executor actor and its mailbox.
pub(crate) fn init<TProvider: ConsensusProvider>(
    config: Config<TProvider>,
) -> eyre::Result<(Actor<TProvider>, Mailbox)> {
    let finalized = config.provider.finalized_block_num_hash()?.map_or_else(
        || {
            config
                .provider
                .block_hash(0)?
                .map(|hash| NumHash::new(0, hash))
                .ok_or_eyre("execution layer has no genesis block")
        },
        Ok,
    )?;
    let (requests_tx, requests) = mpsc::unbounded();
    let (finalized_tx, finalized_blocks) = mpsc::unbounded();
    Ok((
        Actor {
            config,
            requests,
            finalized_blocks,
            finalized,
        },
        Mailbox {
            requests: requests_tx,
            finalized: finalized_tx,
        },
    ))
}

impl<TProvider: ConsensusProvider> Actor<TProvider> {
    /// Spawn the actor. The handle resolves only when the actor stops on a fatal error.
    pub(crate) fn start<TContext>(self, context: TContext) -> Handle<()>
    where
        TContext: Spawner + Clock + Metrics,
    {
        context.spawn(move |context| async move {
            if let Err(error) = self.run(context).await {
                error!(target: "zone::consensus", error = ?error, "Zone executor stopped");
            }
        })
    }

    async fn run(mut self, context: impl Clock) -> eyre::Result<()> {
        self.wait_until_ready(&context).await?;
        self.backfill_to_floor().await?;
        info!(
            target: "zone::consensus",
            finalized = ?self.finalized,
            "Zone executor caught up with the marshal floor"
        );

        let mut heartbeat = tokio::time::interval(self.config.fcu_heartbeat_interval);
        heartbeat.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tokio::select! {
                biased;
                finalized = self.finalized_blocks.next() => {
                    let (block, ack) = finalized.ok_or_eyre("marshal dropped the executor")?;
                    self.apply_finalized(&block).await?;
                    ack.acknowledge();
                    heartbeat.reset();
                }
                request = self.requests.next() => {
                    let request = request.ok_or_eyre("every executor mailbox was dropped")?;
                    self.handle(request).await;
                }
                _ = heartbeat.tick() => {
                    if let Err(error) = self.forkchoice_updated(self.current_forkchoice()?).await {
                        warn!(target: "zone::consensus", %error, "Forkchoice heartbeat failed");
                    }
                }
            }
        }
    }

    /// Wait until reth accepts its own forkchoice state; it reports `SYNCING` while starting.
    async fn wait_until_ready(&self, context: &impl Clock) -> eyre::Result<()> {
        loop {
            let state = self.current_forkchoice()?;
            let response = self
                .config
                .engine
                .fork_choice_updated(state, None)
                .await
                .wrap_err("execution-layer readiness forkchoice update failed")?;
            if response.is_valid() {
                return Ok(());
            }
            eyre::ensure!(
                response.payload_status.is_syncing(),
                "execution layer rejected its own forkchoice state: {response:?}"
            );
            context.sleep(READINESS_RETRY).await;
        }
    }

    /// Replay finalized blocks marshal will not redeliver because it already processed them.
    ///
    /// Reth persists lazily, so after an unclean stop its finalized marker can trail marshal.
    async fn backfill_to_floor(&mut self) -> eyre::Result<()> {
        let floor = self.config.finalized_floor.get();
        for height in self.finalized.number + 1..=floor {
            let block = self
                .config
                .marshal
                .get_block(Height::new(height))
                .await
                .ok_or_else(|| eyre::eyre!("marshal archive has no finalized block {height}"))?;
            self.apply_finalized(&block).await?;
        }
        Ok(())
    }

    async fn handle(&mut self, request: Request) {
        match request {
            Request::Execute { blocks, response } => {
                let result = self.execute(&blocks).await;
                let _ = response.send(result);
            }
            Request::Build {
                parent,
                attributes,
                response,
            } => {
                let result = self.build(parent, *attributes).await;
                if let Err(error) = &result {
                    warn!(target: "zone::consensus", %error, %parent, "Failed building a Zone proposal");
                }
                let _ = response.send(result);
            }
        }
    }

    async fn execute(&self, blocks: &[Arc<Block>]) -> eyre::Result<bool> {
        for block in blocks {
            if !self.new_payload(block).await? {
                return Ok(false);
            }
        }
        Ok(true)
    }

    /// Submit one block. `Ok(false)` means reth found it invalid.
    async fn new_payload(&self, block: &Block) -> eyre::Result<bool> {
        let status = self
            .config
            .engine
            .new_payload(TempoExecutionData {
                block: block.clone().into_execution_block(),
            })
            .await
            .wrap_err_with(|| format!("new_payload failed for block {block}"))?;
        match status.status {
            PayloadStatusEnum::Valid => Ok(true),
            PayloadStatusEnum::Invalid { validation_error } => {
                warn!(target: "zone::consensus", %block, validation_error, "Execution layer rejected block");
                Ok(false)
            }
            other => Err(eyre::eyre!(
                "execution layer could not validate block {block}: {other:?}"
            )),
        }
    }

    #[instrument(skip_all, fields(%parent), err)]
    async fn build(
        &self,
        parent: Digest,
        attributes: ZonePayloadAttributes,
    ) -> eyre::Result<Block> {
        let state = ForkchoiceState {
            head_block_hash: parent.0,
            safe_block_hash: self.finalized.hash,
            finalized_block_hash: self.finalized.hash,
        };
        let response = self
            .config
            .engine
            .fork_choice_updated(state, Some(attributes))
            .await?;
        eyre::ensure!(
            response.is_valid(),
            "execution layer rejected the build forkchoice: {response:?}"
        );
        let payload_id = response
            .payload_id
            .ok_or_eyre("execution layer started no payload build")?;
        let payload = self
            .config
            .payload_builder
            .resolve_kind(payload_id, PayloadKind::WaitForPending)
            .await
            .ok_or_eyre("payload build job disappeared")??;
        let (block, encoded) = payload.clone().into_consensus_execution_payload();
        let block = Block::from_execution_block_unchecked_with_encoded_cache(block, encoded);
        eyre::ensure!(
            block.parent_digest() == parent,
            "payload builder built on {} instead of {parent}",
            block.parent_digest()
        );
        let status = self
            .config
            .engine
            .new_payload(payload.into())
            .await
            .wrap_err("new_payload failed for the built block")?;
        eyre::ensure!(
            status.is_valid(),
            "execution layer rejected its own built block {block}: {status:?}"
        );
        debug!(target: "zone::consensus", %block, gas_used = block.header().gas_used(), "Built Zone proposal");
        Ok(block)
    }

    /// Apply one finalized block. Every error is fatal: marshal will redeliver after restart.
    #[instrument(skip_all, fields(block = %block), err)]
    async fn apply_finalized(&mut self, block: &Block) -> eyre::Result<()> {
        let number = block.number();
        let hash = block.hash();
        if number <= self.finalized.number {
            let canonical = self.config.provider.block_hash(number)?;
            eyre::ensure!(
                canonical == Some(hash),
                "finalized block {number} ({hash}) conflicts with the canonical {canonical:?}"
            );
            return Ok(());
        }
        eyre::ensure!(
            number == self.finalized.number + 1 && block.parent_hash() == self.finalized.hash,
            "finalized block {number} ({hash}) does not extend the applied finalized block {:?}",
            self.finalized
        );

        eyre::ensure!(
            self.new_payload(block).await?,
            "execution layer rejected finalized block {number} ({hash})"
        );
        let import = decode_advance_tempo(block.block())
            .wrap_err("finalized block has no valid Tempo import")?;
        let anchor = import
            .anchor()
            .ok_or_eyre("finalized block imports no Tempo header")?;
        // Consuming the import requires the deposit queue to hold its whole range. The
        // subscriber enqueues each L1 block before recording it in the tracker.
        self.config
            .l1_block_tracker
            .wait_for(anchor)
            .await
            .wrap_err("cannot observe the finalized block's Tempo anchor")?;

        if let Some(collector) = &self.config.proof_collector {
            let mut attempt = 1;
            loop {
                match collector.collect_and_persist(number, hash).await {
                    Ok(_) => break,
                    Err(error) if attempt < WITNESS_ATTEMPTS => {
                        warn!(target: "zone::consensus", %error, attempt, "Retrying witness collection");
                        attempt += 1;
                    }
                    Err(error) => {
                        return Err(error.wrap_err(format!(
                            "collect witness before finalizing Zone block {number}"
                        )));
                    }
                }
            }
        }

        // A finalized block that is already canonical keeps any executed descendant as head.
        let head = if self.config.provider.block_hash(number)? == Some(hash) {
            self.config.provider.chain_info()?.best_hash
        } else {
            hash
        };
        self.forkchoice_updated(ForkchoiceState {
            head_block_hash: head,
            safe_block_hash: hash,
            finalized_block_hash: hash,
        })
        .await
        .wrap_err_with(|| format!("cannot finalize Zone block {number}"))?;

        match import {
            DecodedTempoImport::CheckpointOnly { .. } => {
                self.config.deposit_queue.defer_through(anchor)?
            }
            DecodedTempoImport::Full { .. } => self
                .config
                .deposit_queue
                .confirm_operational_through(anchor)?,
        }
        self.config.l1_block_tracker.prune_through(anchor.number);
        self.finalized = NumHash::new(number, hash);
        info!(
            target: "zone::consensus",
            number,
            %hash,
            tempo_anchor = anchor.number,
            beneficiary = %block.header().beneficiary(),
            "Finalized Zone block"
        );
        Ok(())
    }

    /// Reth's canonical head with this executor's finalized block as safe and finalized.
    fn current_forkchoice(&self) -> eyre::Result<ForkchoiceState> {
        Ok(ForkchoiceState {
            head_block_hash: self.config.provider.chain_info()?.best_hash,
            safe_block_hash: self.finalized.hash,
            finalized_block_hash: self.finalized.hash,
        })
    }

    async fn forkchoice_updated(&self, state: ForkchoiceState) -> eyre::Result<()> {
        let response = self.config.engine.fork_choice_updated(state, None).await?;
        eyre::ensure!(
            response.is_valid(),
            "execution layer rejected forkchoice {state:?}: {response:?}"
        );
        Ok(())
    }
}
