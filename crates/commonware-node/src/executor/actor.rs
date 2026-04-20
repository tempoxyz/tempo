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
    collections::{BTreeMap, VecDeque},
    pin::Pin,
    sync::Arc,
    task::{Poll, ready},
    time::Duration,
};

use alloy_rpc_types_engine::{
    ForkchoiceState, ForkchoiceUpdated, PayloadId, PayloadStatus, PayloadStatusEnum,
};
use commonware_consensus::{
    CertifiableBlock as _, Epochable, Heightable as _,
    types::{Epocher as _, FixedEpocher, Height, Round, View},
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
use tempo_chainspec::hardfork::TempoHardforks as _;
use tempo_node::{TempoExecutionData, TempoFullNode};
use tempo_payload_types::TempoPayloadAttributes;
use tokio::select;
use tracing::{debug, error, info, instrument, warn};

use super::{Config, ingress::MessageWithSpan};
use crate::{
    alias::simplex::Notarization,
    consensus::{Digest, block::Block},
    executor::ingress::{CanonicalizeAndBuild, FinalizedBlock, FinalizedTip},
    utils::OptionFuture,
};

pub(crate) struct Actor<TContext> {
    context: ContextCell<TContext>,

    /// A handle to the execution node layer. Used to forward finalized blocks
    /// and to update the canonical chain by sending forkchoice updates.
    execution_node: Arc<TempoFullNode>,

    /// The epoch strategy used throughout the node.
    epoch_strategy: FixedEpocher,

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

    /// Pending certifications are notarizations that have been been locally
    /// executed and verified.
    pending_certifications: VecDeque<Notarization>,

    /// A map of notarizations and the round they were received in.
    observed_notarizations: BTreeMap<Round, Notarization>,

    /// A state submission that is currently in flight to the execution layer.
    pending_state_submission: OptionFuture<BoxFuture<'static, StateSubmissionResponse>>,

    /// An in-flight fetch of a notarized block from the marshal actor.
    // TODO: Can this be parallelized in any fashion? If we have multiple
    // notarization certificates, we should be able to just schedule several
    // concurrent walks.
    pending_certified_block_fetch: OptionFuture<FetchCertifiedBlock>,

    /// A pending request to canonicalize a (notarized/head) block and build
    /// a block for a proposal.
    pending_build_request: Option<CanonicalizeAndBuild>,

    // A cache of blocks that is continuously populated from notarizations
    // coming in. Note that this contains stricly certified blocks only. These
    // are blocks that have been notarized and certified. As notarizations come
    // in, their parents are assumed notarized and certified.
    cache_of_certified_blocks: BTreeMap<Height, Block>,
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
            epoch_strategy,
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
            epoch_strategy,
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
            pending_certifications: VecDeque::new(),
            observed_notarizations: BTreeMap::new(),

            pending_build_request: None,
            pending_state_submission: OptionFuture::none(),
            pending_certified_block_fetch: OptionFuture::none(),
            cache_of_certified_blocks: BTreeMap::new(),
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

                rsp = &mut self.pending_certified_block_fetch => {
                    self.continue_notarization_ancestry_walk(rsp).await;
                }

                msg = self.mailbox.next() => {
                    let Some(msg) = msg else { break Err(eyre::Report::msg(
                        "actor mailbox closed unexpectedly"
                    )); };
                    if let Err(error) = self.handle_message(msg).await {
                        break Err(error).wrap_err(
                            "executor encountered fatal fork choice update error; \
                            shutting down to prevent consensus-execution divergence"
                        );
                    }
                },

                () = &mut self.fcu_heartbeat_timer => {},
            }

            self.prune_certifications();
            if let Err(err) = self
                .submit_next_state()
                .await
                .wrap_err("failed to submit next state")
            {
                break Err(err);
            }
            self.kick_off_notarization_ancestry_walk().await;
        };

        match reason {
            Ok(()) => info!("shutting down"),
            Err(reason) => error!(%reason, "shutting down"),
        }
    }

    async fn handle_message(&mut self, message: MessageWithSpan) -> eyre::Result<()> {
        let _cause = message.cause;
        match message.inner {
            super::ingress::Message::CanonicalizeAndBuild(canonicalize_and_build) => {
                self.pending_build_request.replace(canonicalize_and_build);
            }
            super::ingress::Message::Certification(certification) => {
                self.pending_certifications.push_back(certification);
            }
            super::ingress::Message::Notarization(notarization) => {
                if Some(notarization.round())
                    > self
                        .observed_notarizations
                        .last_key_value()
                        .map(|(round, _)| *round)
                {
                    self.observed_notarizations
                        .insert(notarization.round(), notarization);
                }
            }
            super::ingress::Message::FinalizedBlock(finalized_block) => {
                self.pending_finalizations.push_back(finalized_block)
            }

            super::ingress::Message::FinalizedTip(new_tip) => {
                if self
                    .finalized_tip
                    .as_ref()
                    .is_none_or(|old_tip| new_tip.round > old_tip.round)
                {
                    self.finalized_tip.replace(new_tip);
                }
            }
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

        Ok(())
    }

    /// Kicks off an ancestry walk from the oldest certificate received.
    async fn kick_off_notarization_ancestry_walk(&mut self) {
        // Keep
        if self.pending_certified_block_fetch.is_some() {
            return;
        }

        if let Some((_, notarization)) = self.observed_notarizations.pop_first() {
            // If on the first notarization of an epoch, don't start the fetch
            // process: the goal is to forward all ancestors to the execution
            // layer. But an epoch's first block's parent is the last block
            // of the previous epoch. And for that boundary block it is expected
            // that a) there exists finalization certificate, that b) this block
            // always enters the system through the finalization pipeline, and
            // finally c) that simplex engines for a specific epoch are only
            // started after the genesis block for that epoch was processed and
            // finalized (such that the executor actor would never observe a
            // notarization for the new epoch).
            if notarization.proposal.parent != View::zero() {
                // TODO: investigate how this can be de-asynced. Manual future
                // impl? This initial communication with the marshal actor to
                // get a subscription should resolve immediately and would only
                // stall if the marshal actor is extering backpressure.
                let fetch_digest = notarization.proposal.payload;
                let subscription = self
                    .marshal
                    .subscribe_by_digest(Some(notarization.round()), fetch_digest)
                    .await;

                self.pending_certified_block_fetch
                    .replace(FetchCertifiedBlock {
                        source_notarization: notarization,
                        fetch_digest,
                        fetch_height: None,
                        marshal: self.marshal.clone(),
                        subscription,
                    });
            }
        }
    }

    #[instrument(
        skip_all,
        fields(
            %fetch_digest,
            fetch_height = fetch_height.map(tracing::field::display),
            source_notarization.digest = %source_notarization.proposal.payload,
            source_notarization.round = %source_notarization.round(),
        ),
    )]
    async fn continue_notarization_ancestry_walk(
        &mut self,
        FetchCertifiedBlockResponse {
            source_notarization,
            marshal,
            block_response,
            fetch_digest,
            fetch_height,
        }: FetchCertifiedBlockResponse,
    ) {
        // TODO: move to a separate handler
        match block_response {
            Err(error) => {
                warn!(
                    %error,
                    "an error occured while walking and fetching the \
                    notarization ancestors; aborting");
                return;
            }

            Ok(block) => {
                // Don't cache the block matching the certifcate: it is not
                // guaranteed to be certified, only its parent blocks are.
                // Certified blocks arrive as `Certified` activity from the
                // simplex engine.
                if source_notarization.proposal.payload != block.digest() {
                    self.cache_of_certified_blocks
                        .insert(block.height(), block.clone());
                }

                let parent_digest = block.parent_digest();

                let epoch_info = self
                    .epoch_strategy
                    .containing(block.height())
                    .expect("epoch strategy is valid for all heights and epochs");

                // Only schedule the parent if:
                // 1. it is still within the same epoch,
                // 2. isn't already cached,
                // 3. is ahead of the latest canonicalized head,
                if let Some(parent_height) = block.height().previous()
                    && parent_height >= epoch_info.first()
                    && self
                        .cache_of_certified_blocks
                        .get(&parent_height)
                        .is_none_or(|cached| cached.digest() != parent_digest)
                    && (parent_height > self.latest_state.certified_height
                        || (parent_height == self.latest_state.certified_height
                            && parent_digest != self.latest_state.certified_digest))
                {
                    let parent_round = self
                        .execution_node
                        .chain_spec()
                        .is_t4_active_at_timestamp(block.timestamp())
                        .then(|| {
                            let context = block.context();
                            let (parent_view, _) = &context.parent;
                            Round::new(context.epoch(), *parent_view)
                        });

                    let subscription = marshal
                        .subscribe_by_digest(parent_round, parent_digest)
                        .await;
                    self.pending_certified_block_fetch
                        .replace(FetchCertifiedBlock {
                            source_notarization,
                            fetch_digest: parent_digest,
                            fetch_height: Some(parent_height),
                            marshal,
                            subscription,
                        });
                }
            }
        }
    }

    /// Prunes those certifications and blocks older than what was finalized
    /// locally.
    ///
    /// Also cancels those requests that are currently under way so that they
    /// never complete.
    ///
    /// Older notarizations will not have their ancestors fetched pro-actively,
    /// and older blocks will never be forwarded as head blocks.
    fn prune_certifications(&mut self) {
        if let Some(finalized_tip) = &self.finalized_tip {
            self.observed_notarizations
                .retain(|round, _| round > &finalized_tip.round);
            self.cache_of_certified_blocks
                .retain(|height, _| height > &finalized_tip.height);

            if self
                .pending_certified_block_fetch
                .as_ref()
                .is_some_and(|fetch| fetch.source_notarization.round() <= finalized_tip.round)
            {
                self.pending_certified_block_fetch.take();
            }
        }
    }

    /// Submits the next block + FCU to the execution layer.
    ///
    /// The order of blocks and state updates submitted is like this:
    ///
    /// 1. backfilling has highest priority: if the marshal actor's finalization
    ///    view is ahead of the execution layer, the node likely suffered a
    ///    persistence loss after shutdown/restart.
    /// 2. `canonicalize-and-build` have highest priority so that proposers can
    ///    return as proposal as soon as follow.
    /// 3. certified blocks follow to ensure the node stays at the tip of the
    ///    (notarized/certified) tip.
    /// 4. notarized (but not yet finalized) blocks to get a lagging node to the
    ///    tip of the chain as fast as possible.
    /// 5. finalized blocks last.
    #[instrument(skip_all, err)]
    async fn submit_next_state(&mut self) -> eyre::Result<()> {
        if self.pending_state_submission.is_some() {
            return Ok(());
        }

        if self.last_marshal_finalized_height > self.latest_state.finalized_height {
            debug!(
                consensus_layer.finalized_height = %self.last_marshal_finalized_height,
                execution_layer.finalized_height = %self.latest_state.finalized_height,
                "gap detected on startup; reconciling consensus and exection layers",
            );
            let next_block_to_backfill = self.latest_state.finalized_height.next();
            let block = self
                .marshal
                .get_block(next_block_to_backfill)
                .await
                .ok_or_else(|| {
                    eyre!(
                        "reconciliation on restart failed; consensus layer is \
                        at height `{}` while execution layer is at height `{}`, \
                        but consensus layer does not have block `{next_block_to_backfill}`",
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
                    base_state: self.latest_state.clone(),
                    payload_attributes: None,
                }
                .send()
                .boxed(),
            );
        } else if let Some(CanonicalizeAndBuild {
            height,
            digest,
            payload_attributes,
            response,
        }) = self.pending_build_request.take()
        {
            debug!(
                %height,
                %digest,
                "setting head hash and kicking off payload build",
            );
            // TODO: add a sanity check here: proposals should only work if on
            // top of the canonicalized chain. That is,
            // if `height = latest.certified_height`.
            self.pending_state_submission.replace(
                StateSubmission {
                    execution_node: self.execution_node.clone(),
                    digest,
                    height,
                    block: None,
                    submission_type: SubmissionType::Build { response },
                    base_state: self.latest_state,
                    payload_attributes: Some(*payload_attributes),
                }
                .send()
                .boxed(),
            );
        } else if let Some(certification) = self.pending_certifications.pop_front() {
            debug!(
                certification.round = %certification.round(),
                digest = %certification.proposal.payload,
                "setting head hash from certified block",
            );
            let digest = certification.proposal.payload;
            let block = self.marshal.get_block(&digest).await.ok_or_else(|| {
                eyre!("we observed a certificatoin for block `{digest}`, we must have it")
            })?;
            self.pending_state_submission.replace(
                StateSubmission {
                    execution_node: self.execution_node.clone(),
                    digest,
                    height: block.height(),
                    block: Some(block),
                    submission_type: SubmissionType::Head,
                    base_state: self.latest_state,
                    payload_attributes: None,
                }
                .send()
                .boxed(),
            );
        } else if let Some(FinalizedBlock {
            block,
            acknowledgement,
        }) = self.pending_finalizations.pop_front()
        {
            debug!(
                block.height = %block.height(),
                block.digest = %block.digest(),
                "finalizing block",
            );
            // TODO: need to assert contiguity - the finalized block here must be
            // on top of the last finalized block as per the execution layer. Need
            // to ensure this at startup so that it holds for the lifetime of the
            // actor.
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
        } else if let Some(block) = self
            .cache_of_certified_blocks
            .remove(&self.latest_state.certified_height.next())
        {
            debug!(
                block.height = %block.height(),
                block.digest = %block.digest(),
                "setting head hash from certified block",
            );
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
        } else if self.fcu_heartbeat_timer.is_none() {
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
        }
        if self.pending_state_submission.is_some() {
            self.fcu_heartbeat_timer
                .replace(self.context.sleep(self.fcu_heartbeat_interval).boxed());
        }
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

struct FetchCertifiedBlockResponse {
    /// The notarization that kicked off the request.
    /// Note: this notarization is not expected to be certified at the moment
    /// of receipt!
    source_notarization: Notarization,

    /// The digest of the block fetched.
    fetch_digest: Digest,

    /// The height of the block fetched (if known at the moment the block was
    /// scheduled).
    fetch_height: Option<Height>,

    /// The mailbox of the marshal actor to which the request will be made.
    marshal: crate::alias::marshal::Mailbox,

    block_response: Result<Block, tokio::sync::oneshot::error::RecvError>,
}

/// A request to the marshal actor to return a given block.
struct FetchCertifiedBlock {
    /// The notarization that kicked off the request.
    /// Note: this notarization is not expected to be certified at the moment
    /// of receipt!
    source_notarization: Notarization,

    /// The digest of the block to be fetched.
    fetch_digest: Digest,

    /// The height of the block to be fetched, if known.
    fetch_height: Option<Height>,

    /// The mailbox of the marshal actor to which the request will be made.
    marshal: crate::alias::marshal::Mailbox,

    /// An ongoing subscription to the
    subscription: tokio::sync::oneshot::Receiver<Block>,
}

impl Future for FetchCertifiedBlock {
    type Output = FetchCertifiedBlockResponse;

    fn poll(mut self: Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> Poll<Self::Output> {
        let block_response = ready!(self.subscription.poll_unpin(cx));
        Poll::Ready(FetchCertifiedBlockResponse {
            source_notarization: self.source_notarization.clone(),
            marshal: self.marshal.clone(),
            block_response,
            fetch_digest: self.fetch_digest,
            fetch_height: self.fetch_height,
        })
    }
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
            finalized_block_hash: self.certified_digest.0,
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
}
