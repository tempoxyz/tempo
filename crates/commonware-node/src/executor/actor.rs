//! Drives the execution layer.
//!
//! This agent maps consensus layer finalizations and certifications to
//! execution layer forkchoice states. It is solely responsible for sending
//! blocks to the execution layer and updating its state.
//!
//! # Types of state updates.
//!
//! There are two processes pushing blocks and updating FCU state running
//! concurrently:
//!
//! 1. bottom to top driven by the finalization pipeline of the marshal
//!    actor. The marshal actor sends blocks ascending by height and waits
//!    for the executor to acknowledge their successful execution.
//! 2. top to bottom driven by notarizations/certifications. If a notarization
//!    certificate is received, a stream walking the ancestors of the proposal
//!    is kickstarted to backfill all blocks to the execution layer.
use std::{
    collections::{BTreeMap, HashMap, VecDeque},
    pin::Pin,
    sync::Arc,
    task::{Poll, ready},
    time::Duration,
};

use alloy_rpc_types_engine::{
    ForkchoiceState, ForkchoiceUpdated, PayloadId, PayloadStatus, PayloadStatusEnum,
};
use commonware_consensus::{
    Heightable as _,
    types::{Height, Round},
};

use commonware_runtime::{Clock, ContextCell, Handle, Metrics, Pacer, Spawner, spawn_cell};
use commonware_utils::{Acknowledgement, acknowledgement::Exact};
use eyre::{OptionExt as _, Report, WrapErr as _, eyre};
use futures::{
    FutureExt as _, StreamExt as _,
    channel::{
        mpsc::{self, UnboundedReceiver},
        oneshot,
    },
    future::BoxFuture,
};
use pin_project::pin_project;
use reth_ethereum::{chainspec::EthChainSpec, rpc::eth::primitives::BlockNumHash};
use reth_node_builder::{BeaconForkChoiceUpdateError, BeaconOnNewPayloadError};
use reth_provider::BlockIdReader as _;
use tempo_node::{TempoExecutionData, TempoFullNode};
use tempo_payload_types::TempoPayloadAttributes;
use tokio::select;
use tracing::{debug, error, info, instrument, warn};

use super::{Config, ingress::MessageWithSpan};
use crate::{
    consensus::{Digest, block::Block},
    executor::ingress::{CanonicalizeAndBuild, FinalizedBlock, FinalizedTip},
    utils::OptionFuture,
};

pub(crate) struct Actor<TContext> {
    context: ContextCell<TContext>,

    /// A handle to the execution node layer. Used to forward finalized blocks
    /// and to update the canonical chain by sending forkchoice updates.
    execution_node: Arc<TempoFullNode>,

    /// The last finalized height as reported by the marshal actor. Important
    /// when reconciling Consensus Layer and Execution Layer state at startup.
    last_marshal_finalized_height: Height,

    /// The channel over which the agent will receive new commands from the
    /// application actor.
    mailbox: mpsc::UnboundedReceiver<MessageWithSpan>,

    /// The mailbox of the marshal actor. Used to backfill blocks.
    marshal: crate::alias::marshal::Mailbox,

    latest_state: LatestState,

    /// The interval at which to send a forkchoice update heartbeat to the
    /// execution layer.
    fcu_heartbeat_interval: Duration,

    /// The timer for the next FCU heartbeat. Reset whenever an FCU is sent.
    fcu_heartbeat_timer: OptionFuture<BoxFuture<'static, ()>>,

    /// The highest finalized tip known to the node.
    ///
    /// Used when performing ancestry walks from a notarization back to
    finalized_tip: Option<FinalizedTip>,

    /// Blocks received from the marshal actor that are waiting to be forwarded
    /// to the execution layer and acknowledged.
    ///
    /// This relies on (and doesn't check) that the marshal actor indeed
    /// forwards block sequentially and without gaps.
    pending_finalizations: VecDeque<FinalizedBlock>,

    /// A state submission that is currently in flight to the execution layer.
    pending_state_submission: OptionFuture<BoxFuture<'static, StateSubmissionResponse>>,

    // A cache of blocks that are certified
    cache_of_certified_blocks: CertifiedBlockCache,

    /// In-flight proposal build.
    build: Option<PendingBuild>,

    /// Highest known sync target — either a locally-certified block (safe
    /// to HEAD-advance to) or a notarization target (HEAD-advances only
    /// to its parent, which the protocol guarantees is locally
    /// certified).
    head_sync: Option<HeadSync>,

    /// In-flight sync-pipeline fetch .
    pending_sync_fetch: OptionFuture<SyncFetch>,
}

impl<TContext> Actor<TContext>
where
    TContext: Clock + Metrics + Pacer + Spawner,
{
    #[instrument(skip_all, err)]
    pub(super) fn init(
        context: TContext,
        config: super::Config,
        mailbox: UnboundedReceiver<super::ingress::MessageWithSpan>,
    ) -> eyre::Result<Self> {
        let Config {
            execution_node,
            last_finalized_height,
            marshal,
            fcu_heartbeat_interval,
        } = config;
        let BlockNumHash {
            number: finalized_number,
            hash: finalized_hash,
        } = execution_node
            .provider
            .finalized_block_num_hash()
            .wrap_err("failed to read finalized block number and hash from execution layer")?
            .unwrap_or_else(|| {
                info!("execution layer reported no finalized block number/hash; using genesis");
                BlockNumHash {
                    number: 0,
                    hash: execution_node.chain_spec().genesis_hash(),
                }
            });

        let fcu_heartbeat_timer = OptionFuture::some(context.sleep(fcu_heartbeat_interval).boxed());
        Ok(Self {
            context: ContextCell::new(context),
            execution_node,
            last_marshal_finalized_height: last_finalized_height,
            mailbox,
            marshal,
            fcu_heartbeat_interval,
            fcu_heartbeat_timer,

            latest_state: LatestState::from_finalized_state(
                Height::new(finalized_number),
                Digest::new(finalized_hash),
            ),
            finalized_tip: None,

            pending_finalizations: VecDeque::new(),

            pending_state_submission: OptionFuture::none(),
            cache_of_certified_blocks: CertifiedBlockCache::default(),

            build: None,
            head_sync: None,
            pending_sync_fetch: OptionFuture::none(),
        })
    }

    pub(crate) fn start(mut self) -> Handle<()> {
        spawn_cell!(self.context, self.run().await)
    }

    async fn run(mut self) {
        let reason: eyre::Result<()> = loop {
            select! {
                biased;

                response = &mut self.pending_state_submission => {
                    if let Err(error) = self.process_state_submission_response(response) {
                        break Err(error);
                    }
                }

                rsp = &mut self.pending_sync_fetch => {
                    if let Err(error) = self.handle_sync_fetch_response(rsp) {
                        warn!(%error, "failed handle fetching block in the sync pipeline");
                    }
                }

                msg = self.mailbox.next() => {
                    let Some(msg) = msg else {
                        break Err(eyre::Report::msg("actor mailbox closed unexpectedly"));
                    };
                    if let Err(error) = self.handle_message(msg).await {
                        break Err(error).wrap_err(
                            "executor encountered fatal error; \
                            shutting down to prevent consensus-execution divergence"
                        );
                    }
                },

                () = &mut self.fcu_heartbeat_timer => {},
            }

            if let Err(err) = self
                .drive_sync()
                .await
                .wrap_err("dispatcher failed to drive sync")
            {
                break Err(err);
            }
        };

        match reason {
            Ok(()) => info!("shutting down"),
            Err(reason) => error!(%reason, "shutting down"),
        }
    }

    async fn handle_message(&mut self, message: MessageWithSpan) -> eyre::Result<()> {
        let _cause = message.cause;
        match message.inner {
            super::ingress::Message::CanonicalizeAndBuild(CanonicalizeAndBuild {
                height,
                digest,
                payload_attributes,
                response,
            }) => {
                if let Some(prev) = self.build.take() {
                    let _ = prev.response.send(Err(eyre!("build request superseded")));
                }

                self.build.replace(PendingBuild {
                    target_digest: digest,
                    target_height: height,
                    payload_attributes,
                    response,
                });
            }

            super::ingress::Message::Certification(certification) => {
                let incoming_round = certification.round();
                let should_replace = self
                    .head_sync
                    .as_ref()
                    .is_none_or(|cur| incoming_round > cur.target_round);

                if should_replace {
                    self.head_sync.replace(HeadSync {
                        target_digest: certification.proposal.payload,
                        target_round: incoming_round,
                        target_notarized: false,
                    });
                }
            }

            super::ingress::Message::Notarization(notarization) => {
                let incoming_round = notarization.round();
                let should_replace = self
                    .head_sync
                    .as_ref()
                    .is_none_or(|cur| incoming_round > cur.target_round);

                if should_replace {
                    self.head_sync.replace(HeadSync {
                        target_digest: notarization.proposal.payload,
                        target_round: incoming_round,
                        target_notarized: true,
                    });
                }
            }

            super::ingress::Message::FinalizedBlock(finalized_block) => {
                self.pending_finalizations.push_back(*finalized_block);
            }

            super::ingress::Message::FinalizedTip(new_tip) => {
                if self
                    .finalized_tip
                    .as_ref()
                    .is_none_or(|old_tip| new_tip.round > old_tip.round)
                {
                    self.finalized_tip.replace(new_tip);
                    self.prune()
                }
            }
        }
        Ok(())
    }

    // Drops syncing state up to the finalzed tip
    fn prune(&mut self) {
        if let Some(finalized_tip) = self.finalized_tip.as_ref() {
            if self
                .head_sync
                .as_ref()
                .is_some_and(|s| s.target_round <= finalized_tip.round)
            {
                self.head_sync = None;
            }

            if let Some(build) = self.build.as_ref()
                && build.target_height <= finalized_tip.height
            {
                debug!(%finalized_tip.height, "pruning build whose target height is now finalized");
                let prev = self.build.take().expect("just checked");
                let _ = prev.response.send(Err(eyre!("build target is finalized")));
            }

            self.cache_of_certified_blocks
                .retain(|height, _| *height > finalized_tip.height);
        }
    }

    /// Handles a completed sync-pipeline fetch.
    fn handle_sync_fetch_response(&mut self, response: SyncFetchResponse) -> eyre::Result<()> {
        let block = response.block_response.wrap_err(format!(
            "fetch subsciption failed. digest={}",
            response.target_digest
        ))?;

        // If this response for the notarized sync target, adjust the to the parent (certified)
        if response.target_notarized
            && let Some(head_sync) = self.head_sync.as_mut()
            && head_sync.target_digest == response.target_digest
            && head_sync.target_notarized
        {
            head_sync.target_digest = block.parent_digest();
            head_sync.target_notarized = false;
            return Ok(());
        }

        // Cache the certified block
        self.cache_of_certified_blocks.insert(block);
        Ok(())
    }

    /// Fetches the next unavailable block in the certified chain.
    ///
    /// Walks back from `head_sync.target_digest` until it finds the first
    /// block not present in the cache.
    ///
    /// Returns `None` when the chain is fully connected from `target` back to
    /// `latest_state.certified`. This marker is ensured to be correct as the driver
    /// will roll back to finalized tip on a mismatch, thus continuing the walk
    async fn next_pending_sync_fetch(&mut self) -> Option<SyncFetch> {
        let latest_certified_digest = self.latest_state.certified_digest;
        let sync = self
            .head_sync
            .as_ref()
            .filter(|s| latest_certified_digest != s.target_digest)?;

        let mut current_digest = sync.target_digest;
        loop {
            match self
                .cache_of_certified_blocks
                .get_by_digest(&current_digest)
            {
                None => {
                    // First missing link in the chain — fetch this.
                    let subscription = self.marshal.subscribe_by_digest(None, current_digest).await;
                    return Some(SyncFetch {
                        target_digest: current_digest,
                        target_notarized: sync.target_notarized
                            && current_digest == sync.target_digest,
                        subscription,
                    });
                }
                Some(b) if b.parent_digest() == self.latest_state.certified_digest => {
                    // Chain is fully connected from target back to certified.
                    return None;
                }
                Some(b) => {
                    // Continue walking back through cached parents.
                    current_digest = b.parent_digest();
                }
            }
        }
    }

    /// Drives one syncing step.
    ///
    /// Order of operations:
    ///
    ///   1. If a state submission is in flight, do nothing.
    ///   2. Startup backfill. Catch up the ELs finalized pointer to the CL.
    ///   3. If `build` is satisfied (EL is at the build's parent), fire its FCU+payloadAttrs.
    ///   4. Check if HEAD has reorged. Otherwise submit the next contiguous certified block.
    ///   5. Kick off fetching needed blocks.
    ///   6. Drain pending finalizations.
    ///   7. FCU heartbeat.
    #[allow(dead_code)]
    async fn drive_sync(&mut self) -> eyre::Result<()> {
        // Flush any stale sync targets
        if let Some(sync) = self.head_sync.as_ref()
            && self.latest_state.certified_digest == sync.target_digest
        {
            self.head_sync = None;
        }

        // 1. FCU in progress
        if self.pending_state_submission.is_some() {
            return Ok(());
        }

        // 2. Backfill: catch the EL's finalized pointer up to marshal's
        if self.last_marshal_finalized_height > self.latest_state.finalized_height {
            debug!(
                consensus_layer.finalized_height = %self.last_marshal_finalized_height,
                execution_layer.finalized_height = %self.latest_state.finalized_height,
                "backfilling finalized blocks",
            );
            let next_block_to_backfill = self.latest_state.finalized_height.next();
            let block = self
                .marshal
                .get_block(next_block_to_backfill)
                .await
                .ok_or_else(|| {
                    eyre!(
                        "v2 reconciliation failed; consensus layer is at height `{}` while \
                        execution layer is at height `{}`, but consensus layer does not have \
                        block `{next_block_to_backfill}`",
                        self.last_marshal_finalized_height,
                        self.latest_state.finalized_height,
                    )
                })?;
            let (acknowledgement, _) = Exact::handle();
            self.pending_state_submission.replace(
                StateSubmission {
                    execution_node: self.execution_node.clone(),
                    submission_type: SubmissionType::Finalized { acknowledgement },
                    digest: block.digest(),
                    height: block.height(),
                    block: Some(block),
                    base_state: self.latest_state,
                    payload_attributes: None,
                }
                .send()
                .boxed(),
            );
            return Ok(());
        }

        // 3. Payload Build
        if self
            .build
            .as_ref()
            .is_some_and(|b| self.latest_state.certified_digest == b.target_digest)
        {
            let PendingBuild {
                target_digest,
                target_height,
                payload_attributes,
                response,
            } = self.build.take().expect("just checked");

            debug!(%target_height, %target_digest, "firing build FCU + payload attributes");
            self.pending_state_submission.replace(
                StateSubmission {
                    execution_node: self.execution_node.clone(),
                    digest: target_digest,
                    height: target_height,
                    block: None,
                    submission_type: SubmissionType::Build { response },
                    base_state: self.latest_state,
                    payload_attributes: Some(*payload_attributes),
                }
                .send()
                .boxed(),
            );
            return Ok(());
        }

        // 4. Detect Reorg or Submit forward
        let next_height = self.latest_state.certified_height.next();
        if let Some(next) = self.cache_of_certified_blocks.get_by_height(&next_height) {
            if next.parent_digest() != self.latest_state.certified_digest {
                warn!(
                    height = %self.latest_state.certified_height,
                    old.head.digest = %self.latest_state.certified_digest,
                    reported.head.digest = %next.parent_digest(),
                    "sibling fork detected at certified head; rolling EL back to finalized",
                );

                let rolled_back = self.latest_state.with_rolled_back_to_finalized();
                self.pending_state_submission.replace(
                    StateSubmission {
                        execution_node: self.execution_node.clone(),
                        digest: rolled_back.finalized_digest,
                        height: rolled_back.finalized_height,
                        block: None,
                        submission_type: SubmissionType::Head,
                        base_state: rolled_back,
                        payload_attributes: None,
                    }
                    .send()
                    .boxed(),
                );
            } else {
                let block = self
                    .cache_of_certified_blocks
                    .remove_by_height(&next_height)
                    .expect("just observed");

                debug!(block.height = %block.height(), block.digest = %block.digest(), "setting head hash");
                self.pending_state_submission.replace(
                    StateSubmission {
                        execution_node: self.execution_node.clone(),
                        digest: block.digest(),
                        height: block.height(),
                        block: Some(block),
                        submission_type: SubmissionType::Head,
                        base_state: self.latest_state,
                        payload_attributes: None,
                    }
                    .send()
                    .boxed(),
                );
            }

            return Ok(());
        }

        // 5. Fetch missing blocks
        if self.pending_sync_fetch.is_none()
            && let Some(next) = self.next_pending_sync_fetch().await
        {
            debug!(digest=%next.target_digest, "fetching ancestor");
            self.pending_sync_fetch.replace(next);
            return Ok(());
        }

        // 6. Drain the the marshal finalization pipeline.
        if let Some(FinalizedBlock {
            block,
            acknowledgement,
        }) = self.pending_finalizations.pop_front()
        {
            debug!(block.height = %block.height(), block.digest = %block.digest(), "finalizing block");
            self.pending_state_submission.replace(
                StateSubmission {
                    execution_node: self.execution_node.clone(),
                    digest: block.digest(),
                    height: block.height(),
                    block: Some(block),
                    submission_type: SubmissionType::Finalized { acknowledgement },
                    base_state: self.latest_state,
                    payload_attributes: None,
                }
                .send()
                .boxed(),
            );
            return Ok(());
        }

        // 7. Heartbeat
        if self.fcu_heartbeat_timer.is_none() {
            debug!("heartbeat timer fired, resending latest FCU");
            self.pending_state_submission.replace(
                StateSubmission {
                    execution_node: self.execution_node.clone(),
                    digest: self.latest_state.certified_digest,
                    height: self.latest_state.certified_height,
                    block: None,
                    submission_type: SubmissionType::Head,
                    base_state: self.latest_state,
                    payload_attributes: None,
                }
                .send()
                .boxed(),
            );
            return Ok(());
        }

        Ok(())
    }

    fn process_state_submission_response(
        &mut self,
        StateSubmissionResponse {
            fcu_response,
            submission_type,
            new_payload_response,
            submitted_state,
        }: StateSubmissionResponse,
    ) -> eyre::Result<()> {
        let fcu_status = fcu_response.wrap_err(
            "communication with execution layer failed for sending forkchoice state state",
        )?;
        if let Some(new_payload_response) = new_payload_response {
            let new_payload_status = new_payload_response
                .wrap_err("communication with execution layer failed for sending new payload")?;

            // We require that all blocks sent to the execution layer in
            // order and such that a) there are no gaps, and b) that no EL
            // pipeline sync is triggered. Hence, the only valid status for
            // a notarized and/or finalized block is VALID.
            match new_payload_status.status {
                PayloadStatusEnum::Valid => {}
                other => {
                    Err(Report::msg(other)).wrap_err("new-payload encountered invalid status")?
                }
            }
        }
        // We require that the CL supplies all blocks to the EL in
        // order. If any value other than VALID is returned this means
        // that either a) the parent was not supplied (which is a
        // violation of the previous invariant), or b) that something
        // is wrong with the block or status itself.
        //
        // TODO: should this be relaxed for SubmissionType::Head and
        // SubmissionType::Build and only be enforced on SubmissionType::Finalized?
        match fcu_status.payload_status.status {
            PayloadStatusEnum::Valid => {}
            other => {
                Err(Report::msg(other)).wrap_err("forkchoice-updated encountered invalid status")?
            }
        }

        match submission_type {
            SubmissionType::Build { response } => {
                let _ = response.send(
                    fcu_status
                        .payload_id
                        .ok_or_eyre("execution layer response was missing payload ID"),
                );
            }
            SubmissionType::Finalized { acknowledgement } => acknowledgement.acknowledge(),
            SubmissionType::Head => {}
        }

        self.latest_state = submitted_state;
        self.fcu_heartbeat_timer
            .replace(self.context.sleep(self.fcu_heartbeat_interval).boxed());

        Ok(())
    }
}

enum SubmissionType {
    Build {
        response: oneshot::Sender<eyre::Result<PayloadId>>,
    },
    Finalized {
        acknowledgement: Exact,
    },
    Head,
}

struct SyncFetch {
    target_digest: Digest,
    target_notarized: bool,
    subscription: tokio::sync::oneshot::Receiver<Block>,
}

#[derive(Debug)]
struct SyncFetchResponse {
    target_digest: Digest,
    target_notarized: bool,
    block_response: Result<Block, tokio::sync::oneshot::error::RecvError>,
}

impl Future for SyncFetch {
    type Output = SyncFetchResponse;

    fn poll(mut self: Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> Poll<Self::Output> {
        let block_response = ready!(self.subscription.poll_unpin(cx));
        Poll::Ready(SyncFetchResponse {
            target_digest: self.target_digest,
            target_notarized: self.target_notarized,
            block_response,
        })
    }
}

/// A desired EL canonical head
struct HeadSync {
    target_digest: Digest,
    target_round: Round,

    /// If this target came from a notarization (vs a certification). The
    /// notarization itself is not safe to set as HEAD; only its parent is.
    target_notarized: bool,
}

/// A pending payload-build request. Fires once the EL's certified head reaches
/// `target_digest`. Backfill is driven by `head_sync` — the build target is,
/// by construction, locally certified and on `head_sync`'s walk path, so this
/// slot is purely a passive trigger.
struct PendingBuild {
    target_digest: Digest,
    target_height: Height,
    payload_attributes: Box<TempoPayloadAttributes>,
    response: oneshot::Sender<eyre::Result<PayloadId>>,
}

/// A state submission that is currently in flight to the execution layer.
///
/// A state submission consists of 3 parts:
///
/// 1. a block fetch from the marshal actor, where necessary.
/// 2. a submission of the block to the execution layer.
/// 3. a submission of a forkchoice-update to the execution layer.
#[pin_project]
struct StateSubmission {
    execution_node: Arc<TempoFullNode>,
    /// The block to be submitted to the execution layer.
    block: Option<Block>,
    /// The type of submission.
    submission_type: SubmissionType,
    /// The digest of the block. The invariant must hold that, if a block is
    /// set, block.digest() == digest.
    digest: Digest,
    /// The height of the block. The invariant must hold that, if a block is
    /// set, block.height() == height.
    height: Height,
    /// The forkchoice state on top of which this state submission is executed.
    base_state: LatestState,
    /// Payload attributes forwarded to the execution layer when building a
    /// block. Only set when asked to build a payload.
    payload_attributes: Option<TempoPayloadAttributes>,
}

impl StateSubmission {
    async fn send(self) -> StateSubmissionResponse {
        let Self {
            execution_node,
            mut block,
            submission_type,
            digest,
            height,
            base_state,
            mut payload_attributes,
        } = self;

        let mut new_payload_response = None;
        if let Some(block) = block.take() {
            new_payload_response.replace(
                execution_node
                    .add_ons_handle
                    .beacon_engine_handle
                    .new_payload(TempoExecutionData {
                        block: Arc::new(block.into_inner()),
                        // The blocks submitted here are always notarized or finalized,
                        // so no extra validator checking is necessary.
                        validator_set: None,
                    })
                    .await,
            );
        };

        let submitted_state = match &submission_type {
            SubmissionType::Head | SubmissionType::Build { .. } => {
                base_state.with_updated_certification(height, digest)
            }
            SubmissionType::Finalized { .. } => base_state.with_updated_finalized(height, digest),
        };

        let fcu_response = execution_node
            .add_ons_handle
            .beacon_engine_handle
            .fork_choice_updated(submitted_state.to_fcu_state(), payload_attributes.take())
            .await;

        StateSubmissionResponse {
            submission_type,
            fcu_response,
            new_payload_response,
            submitted_state,
        }
    }
}

struct StateSubmissionResponse {
    submission_type: SubmissionType,
    fcu_response: Result<ForkchoiceUpdated, BeaconForkChoiceUpdateError>,
    new_payload_response: Option<Result<PayloadStatus, BeaconOnNewPayloadError>>,
    submitted_state: LatestState,
}

/// A cache of `Block`s indexed by both height and digest.
#[derive(Default)]
struct CertifiedBlockCache {
    by_height: BTreeMap<Height, Block>,
    by_digest: HashMap<Digest, Height>,
}

impl CertifiedBlockCache {
    /// Inserts `block`, replacing any prior block at the same height.
    ///
    /// If a different block previously occupied this height, its digest
    /// entry is removed from the index before the new digest is inserted.
    fn insert(&mut self, block: Block) {
        let height = block.height();
        let digest = block.digest();
        if let Some(prev) = self.by_height.insert(height, block)
            && prev.digest() != digest
        {
            self.by_digest.remove(&prev.digest());
        }

        self.by_digest.insert(digest, height);
    }

    fn get_by_height(&self, height: &Height) -> Option<&Block> {
        self.by_height.get(height)
    }

    fn get_by_digest(&self, digest: &Digest) -> Option<&Block> {
        let height = self.by_digest.get(digest)?;
        self.by_height.get(height)
    }

    fn remove_by_height(&mut self, height: &Height) -> Option<Block> {
        let block = self.by_height.remove(height)?;
        self.by_digest.remove(&block.digest());
        Some(block)
    }

    /// Mirrors `BTreeMap::retain`, keeping the digest index consistent.
    fn retain<F>(&mut self, mut f: F)
    where
        F: FnMut(&Height, &Block) -> bool,
    {
        self.by_height.retain(|height, block| {
            let keep = f(height, block);
            if !keep {
                self.by_digest.remove(&block.digest());
            }
            keep
        });
    }
}

#[derive(Clone, Copy, Debug)]
struct LatestState {
    finalized_digest: Digest,
    finalized_height: Height,

    certified_digest: Digest,
    certified_height: Height,
}

impl LatestState {
    fn from_finalized_state(height: Height, digest: Digest) -> Self {
        Self {
            finalized_digest: digest,
            finalized_height: height,
            certified_digest: digest,
            certified_height: height,
        }
    }

    fn to_fcu_state(&self) -> ForkchoiceState {
        ForkchoiceState {
            head_block_hash: self.certified_digest.0,
            safe_block_hash: self.finalized_digest.0,
            finalized_block_hash: self.finalized_digest.0,
        }
    }

    fn with_updated_finalized(&self, height: Height, digest: Digest) -> Self {
        let mut this = *self;
        if height > this.finalized_height {
            this.finalized_height = height;
            this.finalized_digest = digest;
        }
        if this.finalized_height >= self.certified_height {
            this.certified_height = this.finalized_height;
            this.certified_digest = this.finalized_digest;
        }
        this
    }

    fn with_updated_certification(&self, height: Height, digest: Digest) -> Self {
        let mut this = *self;
        if height >= this.certified_height {
            this.certified_height = height;
            this.certified_digest = digest;
        }
        this
    }

    /// Rolls the optimistic certified pointer back to match the finalized
    /// pointer. Used to express a reorg at the certified head; bypasses
    /// the monotonicity of `with_updated_certification`.
    fn with_rolled_back_to_finalized(&self) -> Self {
        let mut this = *self;
        this.certified_height = this.finalized_height;
        this.certified_digest = this.finalized_digest;
        this
    }
}
