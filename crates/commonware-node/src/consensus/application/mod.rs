//! [`TempoApplication`] implements the commonware-consensus `Application`,
//! `VerifyingApplication`, and `Reporter` traits.
//!
//! # On the usage of the commonware-pacer
//!
//! All interactions with the execution layer are wrapped in `Pacer::pace`
//! calls. This is a no-op in production (the commonware tokio runtime ignores
//! them), but critical in e2e tests using the deterministic runtime: since the
//! EL still runs on tokio, these calls signal the deterministic runtime to
//! spend real time waiting for the EL calls to complete.

use std::{
    sync::{Arc, OnceLock},
    time::{Duration, Instant},
};

use alloy_consensus::BlockHeader;
use alloy_primitives::{B256, Bytes};
use alloy_rpc_types_engine::PayloadId;
use commonware_codec::{Encode as _, ReadExt as _};
use commonware_consensus::{
    Heightable as _, Reporter,
    marshal::{
        Update,
        ancestry::{AncestorStream, BlockProvider},
    },
    simplex::{scheme::bls12381_threshold::vrf::Scheme, types::Context},
    types::{Epoch, EpochInfo, Epocher as _, FixedEpocher, HeightDelta, Round, View},
};
use commonware_cryptography::{
    bls12381::primitives::variant::MinSig, certificate::Provider as _, ed25519::PublicKey,
};
use commonware_runtime::{Clock, FutureExt as _, Metrics, Pacer, Spawner};
use commonware_utils::{Acknowledgement as _, SystemTimeExt};
use eyre::{OptionExt as _, WrapErr as _};
use futures::{StreamExt as _, channel::oneshot};
use prometheus_client::metrics::counter::Counter;
use rand_08::{CryptoRng, Rng};
use reth_node_builder::{Block as _, BuiltPayload, PayloadKind};
use reth_provider::BlockReader as _;
use tempo_chainspec::hardfork::TempoHardforks as _;
use tempo_dkg_onchain_artifacts::OnchainDkgOutcome;
use tempo_node::{TempoExecutionData, TempoFullNode};
use tempo_payload_types::TempoPayloadAttributes;
use tempo_primitives::TempoConsensusContext;
use tempo_telemetry_util::display_duration;
use tracing::{debug, info, instrument, warn};

use crate::{
    consensus::{Digest, block::Block},
    epoch::SchemeProvider,
    subblocks,
};

#[derive(Clone)]
pub(crate) struct Config {
    pub(crate) public_key: PublicKey,
    pub(crate) fee_recipient: Option<alloy_primitives::Address>,
    pub(crate) execution_node: TempoFullNode,
    pub(crate) executor: crate::executor::Mailbox,
    pub(crate) subblocks: Option<subblocks::Mailbox>,
    pub(crate) scheme_provider: SchemeProvider,
    pub(crate) epoch_strategy: FixedEpocher,
    pub(crate) payload_resolve_time: Duration,
    pub(crate) payload_return_time: Duration,
}

#[derive(Clone)]
pub(crate) struct TempoApplication {
    config: Config,
    /// Initialized after construction because of a dependency cycle. The dkg manager
    /// requires the epoch manager which consumes this application.
    dkg_manager: Arc<OnceLock<crate::dkg::manager::Mailbox>>,
    parent_ahead_of_local_time: Counter,
}

impl TempoApplication {
    pub(crate) fn new<TContext: Metrics>(context: TContext, config: Config) -> Self {
        let parent_ahead_of_local_time = Counter::default();
        context.register(
            "parent_ahead_of_local_time",
            "number of times the parent block timestamp was ahead of local time",
            parent_ahead_of_local_time.clone(),
        );

        Self {
            config,
            dkg_manager: Arc::new(OnceLock::new()),
            parent_ahead_of_local_time,
        }
    }

    /// Sets the DKG manager mailbox. Must be called prior to any `propose` or `verify` invocations.
    pub(crate) fn set_dkg_manager(&self, mailbox: crate::dkg::manager::Mailbox) {
        self.dkg_manager
            .set(mailbox)
            .expect("dkg_manager mailbox must only be set once");
    }

    fn dkg_manager(&self) -> &crate::dkg::manager::Mailbox {
        self.dkg_manager
            .get()
            .expect("dkg_manager mailbox must be set before first use")
    }

    async fn build_extra_data(
        &self,
        round: Round,
        parent: &Block,
        parent_digest: Digest,
        parent_epoch_info: &EpochInfo,
    ) -> eyre::Result<Bytes> {
        if parent_epoch_info.last() == parent.height().next()
            && parent_epoch_info.epoch() == round.epoch()
        {
            // At epoch boundary: include public ceremony outcome.
            let outcome = self
                .dkg_manager()
                .get_dkg_outcome(parent_digest, parent.height())
                .await
                .wrap_err("failed getting public dkg ceremony outcome")?;
            eyre::ensure!(
                round.epoch().next() == outcome.epoch,
                "outcome is for epoch `{}`, but we are trying to include the \
                outcome for epoch `{}`",
                outcome.epoch,
                round.epoch().next(),
            );
            info!(
                %outcome.epoch,
                outcome.network_identity = %outcome.network_identity(),
                outcome.dealers = ?outcome.dealers(),
                outcome.players = ?outcome.players(),
                outcome.next_players = ?outcome.next_players(),
                "received DKG outcome; will include in payload builder attributes",
            );
            Ok(outcome.encode().into())
        } else {
            // Regular block: try to include DKG dealer log.
            match self.dkg_manager().get_dealer_log(round.epoch()).await {
                Err(error) => {
                    warn!(
                        %error,
                        "failed getting signed dealer log for current epoch \
                        because actor dropped response channel",
                    );
                    Ok(Bytes::default())
                }
                Ok(None) => Ok(Bytes::default()),
                Ok(Some(log)) => {
                    info!(
                        "received signed dealer log; will include in payload \
                        builder attributes",
                    );
                    Ok(log.encode().into())
                }
            }
        }
    }
}

impl<E> commonware_consensus::Application<E> for TempoApplication
where
    E: Rng
        + CryptoRng
        + Spawner
        + commonware_runtime::Metrics
        + Clock
        + Pacer
        + governor::clock::Clock,
{
    type SigningScheme = Scheme<PublicKey, MinSig>;
    type Context = Context<Digest, PublicKey>;
    type Block = Block;

    async fn genesis(&mut self) -> Self::Block {
        let genesis_block = self
            .config
            .execution_node
            .provider
            .block_by_number(0)
            .expect("block provider should work")
            .expect("genesis block must exist");

        Block::from_execution_block(genesis_block.seal())
    }

    #[instrument(
        skip_all,
        fields(
            epoch = %context.1.round.epoch(),
            view = %context.1.round.view(),
            parent.view = %context.1.parent.0,
            parent.digest = %context.1.parent.1,
        ),
    )]
    async fn propose<A: BlockProvider<Block = Self::Block>>(
        &mut self,
        context: (E, Self::Context),
        mut ancestry: AncestorStream<A, Self::Block>,
    ) -> Option<Self::Block> {
        let (runtime, ctx) = context;
        let propose_start = Instant::now();

        let parent = match ancestry.next().await {
            Some(p) => p,
            None => {
                warn!("missing parent, cannot propose");
                return None;
            }
        };

        debug!(height = %parent.height(), "retrieved parent block");

        let parent_epoch_info = self
            .config
            .epoch_strategy
            .containing(parent.height())
            .expect("epoch strategy is for all heights");

        let is_genesis_parent = parent.height().is_zero()
            || parent_epoch_info.last() == parent.height()
                && parent_epoch_info.epoch().next() == ctx.round.epoch();

        if !is_genesis_parent {
            match verify_block(
                runtime.clone(),
                parent_epoch_info.epoch(),
                &self.config.epoch_strategy,
                self.config
                    .execution_node
                    .add_ons_handle
                    .beacon_engine_handle
                    .clone(),
                &parent,
                parent.parent_digest(),
                &self.config.scheme_provider,
            )
            .await
            {
                Ok(true) => {}
                Ok(false) => {
                    warn!("the proposal parent block is not valid");
                    return None;
                }
                Err(error) => {
                    warn!(%error, parent=%parent.digest(), "failed verifying parent block");
                    return None;
                }
            }
        }

        let extra_data = self
            .build_extra_data(ctx.round, &parent, parent.digest(), &parent_epoch_info)
            .await
            .ok()?;

        let mut epoch_millis = runtime.current().epoch_millis();
        if epoch_millis <= parent.timestamp_millis() {
            self.parent_ahead_of_local_time.inc();
            epoch_millis = parent.timestamp_millis() + 1;
        }

        let (timestamp, timestamp_millis_part) = (epoch_millis / 1000, epoch_millis % 1000);

        let consensus_context = if self
            .config
            .execution_node
            .chain_spec()
            .is_t4_active_at_timestamp(timestamp)
        {
            Some(TempoConsensusContext {
                epoch: ctx.round.epoch().get(),
                view: ctx.round.view().get(),
                parent_view: ctx.parent.0.get(),
                proposer: crate::utils::public_key_to_tempo_primitive(&ctx.leader),
            })
        } else {
            None
        };

        let parent_hash = parent.block_hash();
        let proposer_public_key = crate::utils::public_key_to_b256(&self.config.public_key);
        let subblocks = self.config.subblocks.clone();
        let attrs = TempoPayloadAttributes::new(
            self.config.fee_recipient.unwrap_or_default(),
            Some(proposer_public_key),
            timestamp,
            timestamp_millis_part,
            extra_data,
            consensus_context,
            move || {
                subblocks
                    .as_ref()
                    .and_then(|s| s.get_subblocks(parent_hash).ok())
                    .unwrap_or_default()
            },
        );

        let interrupt_handle = attrs.interrupt_handle().clone();

        let payload_id_rx = match self.config.executor.canonicalize_and_build(
            parent.height(),
            parent.digest(),
            attrs,
        ) {
            Ok(rx) => rx,
            Err(error) => {
                warn!(%error, "failed dispatching new payload build to executor");
                return None;
            }
        };

        // The guard ensures that any in-flight triggers cancellation if dropped prior to resolving the payload
        let mut payload_id_guard = CancellablePayloadReceiver::new(
            runtime.clone(),
            self.config.execution_node.clone(),
            payload_id_rx,
        );

        let payload_id = match payload_id_guard.payload_id().await {
            Ok(id) => id,
            Err(error) => {
                warn!(%error, "failed obtaining payload id from executor");
                return None;
            }
        };

        let elapsed = propose_start.elapsed();
        let remaining_resolve = self.config.payload_resolve_time.saturating_sub(elapsed);
        let remaining_return = self.config.payload_return_time.saturating_sub(elapsed);
        debug!(
            elapsed = %display_duration(elapsed),
            resolve_time = %display_duration(remaining_resolve),
            return_time = %display_duration(remaining_return),
            "sleeping before payload builder resolving",
        );

        let payload_return_time = runtime.current() + remaining_return;
        runtime.sleep(remaining_resolve).await;
        interrupt_handle.interrupt();

        let payload = match self
            .config
            .execution_node
            .payload_builder_handle
            .resolve_kind(payload_id, PayloadKind::WaitForPending)
            .pace(&runtime, Duration::from_millis(20))
            .await
        {
            Some(Ok(p)) => p,
            Some(Err(error)) => {
                warn!(%error, ?payload_id, "failed getting payload");
                return None;
            }
            None => {
                warn!(?payload_id, "no payload found");
                return None;
            }
        };

        let proposal = Block::from_execution_block(payload.block().clone());

        runtime.sleep_until(payload_return_time).await;
        info!(proposal.digest = %proposal.digest(), "constructed proposal");

        payload_id_guard.disarm();
        Some(proposal)
    }
}

impl<E> commonware_consensus::VerifyingApplication<E> for TempoApplication
where
    E: Rng
        + CryptoRng
        + Spawner
        + commonware_runtime::Metrics
        + Clock
        + Pacer
        + governor::clock::Clock,
{
    #[instrument(
        skip_all,
        fields(
            epoch = %context.1.round.epoch(),
            view = %context.1.round.view(),
            parent.view = %context.1.parent.0,
            parent.digest = %context.1.parent.1,
        ),
    )]
    async fn verify<A: BlockProvider<Block = Self::Block>>(
        &mut self,
        context: (E, Self::Context),
        mut ancestry: AncestorStream<A, Self::Block>,
    ) -> bool {
        let (runtime, ctx) = context;

        let block = match ancestry.next().await {
            Some(b) => b,
            None => {
                warn!("ancestry stream yielded no block to verify");
                return false;
            }
        };

        let parent = match ancestry.next().await {
            Some(p) => p,
            None => {
                warn!("ancestry stream yielded no parent for verification");
                return false;
            }
        };

        if let Err(reason) = verify_header(
            &block,
            ctx.parent,
            ctx.round,
            self.config.execution_node.chain_spec().as_ref(),
            self.dkg_manager(),
            &self.config.epoch_strategy,
            &ctx.leader,
        )
        .await
        {
            warn!(%reason, "header could not be verified; failing block");
            return false;
        }

        if let Err(error) = self
            .config
            .executor
            .canonicalize_head(parent.height(), parent.digest())
            .await
        {
            warn!(
                %error,
                parent.height = %parent.height(),
                parent.digest = %parent.digest(),
                "failed updating canonical head to parent; trying to go on",
            );
        }

        let is_good = match verify_block(
            runtime,
            ctx.round.epoch(),
            &self.config.epoch_strategy,
            self.config
                .execution_node
                .add_ons_handle
                .beacon_engine_handle
                .clone(),
            &block,
            ctx.parent.1,
            &self.config.scheme_provider,
        )
        .await
        {
            Ok(valid) => valid,
            Err(error) => {
                warn!(%error, "failed verifying block against execution layer");
                return false;
            }
        };

        if is_good
            && let Err(error) = self
                .config
                .executor
                .canonicalize_head(block.height(), block.digest())
                .await
        {
            warn!(
                %error,
                "failed making the verified proposal the head of the canonical chain",
            );
            return false;
        }

        is_good
    }
}

impl Reporter for TempoApplication {
    type Activity = Update<Block>;

    async fn report(&mut self, update: Self::Activity) {
        if let Update::Block(_, ack) = update {
            ack.acknowledge();
        }
    }
}

/// Verifies `block` given its `parent` against the execution layer.
///
/// Returns whether the block is valid or not. Returns an error if validation
/// was not possible, for example if communication with the execution layer
/// failed.
#[instrument(
    skip_all,
    fields(
        %epoch,
        epoch_length,
        block.parent_digest = %block.parent_digest(),
        block.digest = %block.digest(),
        block.height = %block.height(),
        block.timestamp = block.timestamp(),
        parent.digest = %parent_digest,
    )
)]
async fn verify_block<TContext: Pacer>(
    context: TContext,
    epoch: Epoch,
    epoch_strategy: &FixedEpocher,
    engine: reth_node_builder::ConsensusEngineHandle<tempo_node::TempoPayloadTypes>,
    block: &Block,
    parent_digest: Digest,
    scheme_provider: &SchemeProvider,
) -> eyre::Result<bool> {
    use alloy_rpc_types_engine::PayloadStatusEnum;

    let epoch_info = epoch_strategy
        .containing(block.height())
        .expect("epoch strategy is for all heights");

    if epoch_info.epoch() != epoch {
        info!("block does not belong to this epoch");
        return Ok(false);
    }
    if block.parent_hash() != *parent_digest {
        info!(
            "parent digest stored in block must match the digest of the parent \
            argument but doesn't"
        );
        return Ok(false);
    }

    let scheme = scheme_provider
        .scoped(epoch)
        .ok_or_eyre("cannot determine participants in the current epoch")?;

    let validator_set = Some(
        scheme
            .participants()
            .into_iter()
            .map(|p| B256::from_slice(p))
            .collect(),
    );

    let block = block.clone().into_inner();
    let execution_data = TempoExecutionData {
        block: Arc::new(block),
        validator_set,
    };

    let payload_status = engine
        .new_payload(execution_data)
        .pace(&context, Duration::from_millis(50))
        .await
        .wrap_err("failed sending `new payload` message to execution layer to validate block")?;

    match payload_status.status {
        PayloadStatusEnum::Valid => Ok(true),
        PayloadStatusEnum::Invalid { validation_error } => {
            info!(
                validation_error,
                "execution layer returned that the block was invalid"
            );
            Ok(false)
        }
        PayloadStatusEnum::Accepted => {
            eyre::bail!(
                "failed validating block because payload was accepted, meaning \
                that this was not actually executed by the execution layer for some reason"
            )
        }
        PayloadStatusEnum::Syncing => {
            eyre::bail!(
                "failed validating block because payload is still syncing, \
                this means the parent block was available to the consensus \
                layer but not the execution layer"
            )
        }
    }
}

#[instrument(skip_all, err(Display))]
async fn verify_header(
    block: &Block,
    parent: (View, Digest),
    round: Round,
    chainspec: &tempo_chainspec::TempoChainSpec,
    dkg_manager: &crate::dkg::manager::Mailbox,
    epoch_strategy: &FixedEpocher,
    proposer: &PublicKey,
) -> eyre::Result<()> {
    let epoch_info = epoch_strategy
        .containing(block.height())
        .expect("epoch strategy is for all heights");

    if chainspec.is_t4_active_at_timestamp(block.timestamp()) {
        let ctx = block
            .header()
            .consensus_context
            .ok_or_eyre("missing consensus context after t4 activation")?;

        let expected_ctx = TempoConsensusContext {
            epoch: round.epoch().get(),
            view: round.view().get(),
            parent_view: parent.0.get(),
            proposer: crate::utils::public_key_to_tempo_primitive(proposer),
        };

        if ctx != expected_ctx {
            eyre::bail!("mismatching block consensus context");
        }
    } else if block.header().consensus_context.is_some() {
        eyre::bail!("block consensus context set prior to activation");
    }

    if epoch_info.last() == block.height() {
        info!(
            "on last block of epoch; verifying that the boundary block \
            contains the correct DKG outcome",
        );
        let our_outcome = dkg_manager
            .get_dkg_outcome(parent.1, block.height().saturating_sub(HeightDelta::new(1)))
            .await
            .wrap_err(
                "failed getting public dkg ceremony outcome; cannot verify end \
                of epoch block",
            )?;
        let block_outcome = OnchainDkgOutcome::read(&mut block.header().extra_data().as_ref())
            .wrap_err(
                "failed decoding extra data header as DKG ceremony \
                outcome; cannot verify end of epoch block",
            )?;
        if our_outcome != block_outcome {
            warn!(
                our.epoch = %our_outcome.epoch,
                our.players = ?our_outcome.players(),
                our.next_players = ?our_outcome.next_players(),
                our.sharing = ?our_outcome.sharing(),
                our.is_next_full_dkg = ?our_outcome.is_next_full_dkg,
                block.epoch = %block_outcome.epoch,
                block.players = ?block_outcome.players(),
                block.next_players = ?block_outcome.next_players(),
                block.sharing = ?block_outcome.sharing(),
                block.is_next_full_dkg = ?block_outcome.is_next_full_dkg,
                "our public dkg outcome does not match what's stored \
                in the block",
            );
            return Err(eyre::eyre!(
                "our public dkg outcome does not match what's \
                stored in the block header extra_data field; they must \
                match so that the end-of-block is valid",
            ));
        }
    } else if !block.header().extra_data().is_empty() {
        let bytes = block.header().extra_data().to_vec();
        let dealer = dkg_manager
            .verify_dealer_log(round.epoch(), bytes)
            .await
            .wrap_err("failed request to verify DKG dealing")?;
        eyre::ensure!(
            &dealer == proposer,
            "proposer `{proposer}` is not the dealer `{dealer}` of the dealing \
            in the block",
        );
    }

    Ok(())
}

struct CancellablePayloadReceiver<E: Spawner> {
    ctx: E,
    execution_node: TempoFullNode,
    state: PayloadState,
    armed: bool,
}

enum PayloadState {
    Pending(oneshot::Receiver<eyre::Result<PayloadId>>),
    Known(PayloadId),
    Empty,
}

impl<E: Spawner> CancellablePayloadReceiver<E> {
    fn new(
        ctx: E,
        execution_node: TempoFullNode,
        payload_id_rx: oneshot::Receiver<eyre::Result<PayloadId>>,
    ) -> Self {
        Self {
            ctx,
            execution_node,
            state: PayloadState::Pending(payload_id_rx),
            armed: true,
        }
    }

    async fn payload_id(&mut self) -> eyre::Result<PayloadId> {
        let PayloadState::Pending(rx) = std::mem::replace(&mut self.state, PayloadState::Empty)
        else {
            eyre::bail!("payload id already retrieved");
        };

        let id = rx
            .await
            .wrap_err("executor dropped payload build response")?
            .wrap_err("failed requesting a new payload build")?;

        self.state = PayloadState::Known(id);
        Ok(id)
    }

    fn disarm(mut self) {
        self.armed = false;
    }
}

impl<E: Spawner> Drop for CancellablePayloadReceiver<E> {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }

        let state = std::mem::replace(&mut self.state, PayloadState::Empty);
        let execution_node = self.execution_node.clone();
        self.ctx.clone().spawn(|_| async move {
            let id = match state {
                PayloadState::Empty => return,
                PayloadState::Known(id) => id,
                PayloadState::Pending(rx) => match rx.await {
                    Ok(Ok(id)) => id,
                    Ok(Err(error)) => {
                        debug!(%error, "executor reported error after propose cancellation");
                        return;
                    }
                    Err(_) => {
                        debug!("executor dropped response after propose cancellation");
                        return;
                    }
                },
            };

            // We drop the future for this payload id since if still armed, the constructed proposal for this
            // this payload id was not returned to the application and we want to cancel any in-flight jobs.
            match execution_node
                .payload_builder_handle
                .resolve_kind_fut(id, PayloadKind::WaitForPending)
                .await
            {
                Ok(fut) => drop(fut),
                Err(error) => debug!(%error, ?id, "failed cancelling in-flight payload"),
            }
        });
    }
}
