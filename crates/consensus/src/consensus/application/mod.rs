//! [`TempoApplication`] implements the commonware-consensus `Application` trait.
//!
//! # On the usage of the commonware-pacer
//!
//! All interactions with the execution layer are wrapped in `Pacer::pace`
//! calls. This is a no-op in production because the commonware tokio runtime
//! ignores these. However, these are critical in e2e tests using the commonware
//! deterministic runtime: since the execution layer is still running on the
//! tokio runtime, these calls signal the deterministic runtime to spend real
//! time waiting for the execution layer calls to complete.

use std::{
    sync::{Arc, Mutex, OnceLock},
    time::{Duration, Instant},
};

use alloy_consensus::BlockHeader;
use alloy_primitives::{B256, Bytes};
use commonware_actor::Feedback;
use commonware_codec::{Encode as _, EncodeSize as _, ReadExt as _};
use commonware_consensus::{
    Application, Heightable as _, Reporter,
    marshal::{Update, ancestry::Ancestry},
    simplex::{scheme::bls12381_threshold::vrf::Scheme, types::Context},
    types::{Epoch, EpochInfo, Epocher as _, FixedEpocher, HeightDelta, Round, View},
};
use commonware_cryptography::{
    bls12381::primitives::variant::MinSig, certificate::Provider as _, ed25519::PublicKey,
};
use commonware_runtime::{
    Clock, FutureExt as _, Pacer, Spawner,
    telemetry::metrics::{Counter, MetricsExt as _},
};
use commonware_utils::{Acknowledgement as _, SystemTimeExt};
use eyre::{OptionExt as _, WrapErr as _, bail, ensure, eyre};
use futures::StreamExt as _;
use rand_08::{CryptoRng, Rng};
use reth_node_builder::ConsensusEngineHandle;
use reth_primitives_traits::BlockBody as _;
use tempo_dkg_onchain_artifacts::OnchainDkgOutcome;
use tempo_node::{TempoExecutionData, TempoFullNode, TempoPayloadTypes};
use tempo_payload_types::{
    TempoPayloadAttributes, ValidationLatencyEstimator, ValidationLatencyWorkload,
    marshal_persist_estimate,
};
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
    /// This node's ed25519 public key, used to look up the fee recipient from
    /// the validator config v2 contract.
    pub(crate) public_key: PublicKey,

    pub(crate) executor: crate::executor::Mailbox,

    /// A handle to the execution node to verify and create new payloads.
    pub(crate) execution_node: Arc<TempoFullNode>,

    /// A handle to the subblocks service to get subblocks for proposals.
    pub(crate) subblocks: Option<subblocks::Mailbox>,

    /// Local proposal return budget, excluding the network propagation allowance.
    ///
    /// Starts at `target_block_time - network_budget`; `propose` subtracts time
    /// already spent in the view before handing the remaining budget to the
    /// payload builder.
    pub(crate) proposal_return_budget: Duration,

    /// The epoch strategy used by tempo, to map block heights to epochs.
    pub(crate) epoch_strategy: FixedEpocher,

    /// The scheme provider to use for the application.
    pub(crate) scheme_provider: SchemeProvider,
}

#[derive(Clone)]
pub(crate) struct TempoApplication {
    public_key: PublicKey,
    epoch_strategy: FixedEpocher,
    proposal_return_budget: Duration,
    execution_node: Arc<TempoFullNode>,
    executor: crate::executor::Mailbox,
    subblocks: Option<subblocks::Mailbox>,
    scheme_provider: SchemeProvider,
    validation_latency_estimator: Arc<Mutex<ValidationLatencyEstimator>>,
    /// Initialized after construction because of a dependency cycle. The DKG
    /// manager requires the epoch manager, and the epoch manager consumes this
    /// application through the marshal inline wrapper.
    dkg_manager: Arc<OnceLock<crate::dkg::manager::Mailbox>>,
    metrics: Metrics,
}

impl TempoApplication {
    pub(crate) fn new<TContext>(context: TContext, config: Config) -> Self
    where
        TContext: commonware_runtime::Metrics,
    {
        Self {
            public_key: config.public_key,
            epoch_strategy: config.epoch_strategy,
            proposal_return_budget: config.proposal_return_budget,
            execution_node: config.execution_node,
            executor: config.executor,
            subblocks: config.subblocks,
            scheme_provider: config.scheme_provider,
            validation_latency_estimator: Default::default(),
            dkg_manager: Arc::new(OnceLock::new()),
            metrics: Metrics::init(&context),
        }
    }

    /// Sets the DKG manager mailbox. Must be called before any `propose` or
    /// `verify` invocation reaches the application.
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
            let outcome = self
                .dkg_manager()
                .get_dkg_outcome(parent_digest, parent.height())
                .await
                .wrap_err("failed getting public dkg ceremony outcome")?;
            ensure!(
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

    async fn build_proposal<TContext>(
        &self,
        context: &TContext,
        consensus_context: &Context<Digest, PublicKey>,
        parent: Block,
        propose_start: Instant,
    ) -> eyre::Result<Block>
    where
        TContext: Clock + Pacer,
    {
        debug!(height = %parent.height(), "retrieved parent block");

        let parent_epoch_info = self
            .epoch_strategy
            .containing(parent.height())
            .expect("epoch strategy is for all heights");

        let is_genesis_parent = parent.height().is_zero()
            || parent_epoch_info.last() == parent.height()
                && parent_epoch_info.epoch().next() == consensus_context.round.epoch();

        if !is_genesis_parent
            && verify_block(
                context,
                parent_epoch_info.epoch(),
                &self.epoch_strategy,
                self.execution_node
                    .add_ons_handle
                    .beacon_engine_handle
                    .clone(),
                &parent,
                parent.parent_digest(),
                &self.scheme_provider,
            )
            .await
            .wrap_err("failed verifying block against execution layer")?
            .is_none()
        {
            bail!("the proposal parent block is not valid");
        }

        let extra_data = self
            .build_extra_data(
                consensus_context.round,
                &parent,
                parent.digest(),
                &parent_epoch_info,
            )
            .await?;

        let mut epoch_millis = context.current().epoch_millis();
        if epoch_millis <= parent.timestamp_millis() {
            self.metrics.parent_ahead_of_local_time.metric().inc();
            epoch_millis = parent.timestamp_millis() + 1;
        };

        let (timestamp, timestamp_millis_part) = (epoch_millis / 1000, epoch_millis % 1000);

        let consensus_context_attr = Some(TempoConsensusContext {
            epoch: consensus_context.round.epoch().get(),
            view: consensus_context.round.view().get(),
            parent_view: consensus_context.parent.0.get(),
            proposer: crate::utils::public_key_to_tempo_primitive(&consensus_context.leader),
        });

        let parent_hash = parent.block_hash();
        let proposer_public_key = crate::utils::public_key_to_b256(&self.public_key);
        let marshal_persist = marshal_persist_estimate();
        let build_budget = self
            .proposal_return_budget
            .saturating_sub(propose_start.elapsed());
        let validation_latency_estimate = self
            .validation_latency_estimator
            .lock()
            .ok()
            .and_then(|estimator| estimator.estimate());
        let subblocks = self.subblocks.clone();
        let attrs = TempoPayloadAttributes::new(
            Some(proposer_public_key),
            timestamp,
            timestamp_millis_part,
            extra_data,
            consensus_context_attr,
            move || {
                subblocks
                    .as_ref()
                    .and_then(|s| s.get_subblocks(parent_hash).ok())
                    .unwrap_or_default()
            },
        )
        .with_payload_build_budget(build_budget)
        .with_validation_latency_estimate(validation_latency_estimate);

        let payload_build_start = Instant::now();
        let payload = self
            .executor
            .canonicalize_and_build(parent.height(), parent.digest(), attrs)?
            .await
            .wrap_err("executor dropped response")?;

        let payload_build_elapsed = payload_build_start.elapsed();
        let payload_validation_work_elapsed = payload.validation_work_duration();
        let validation_latency_elapsed = payload.validation_latency_duration();
        let execution_block_rlp_size_estimate_bytes = payload.execution_block_size_estimate();
        let (block, block_access_list, execution_block_encoded) =
            payload.into_consensus_execution_payload();
        let block_access_list_size_bytes = block_access_list
            .as_ref()
            .map_or(0, |block_access_list| block_access_list.encode_size());
        let proposal = Block::from_execution_block_with_encoded_cache(
            block,
            block_access_list,
            execution_block_encoded,
        )
        .wrap_err("payload builder produced an invalid block access list")?;
        let block_size_estimate_bytes =
            execution_block_rlp_size_estimate_bytes + block_access_list_size_bytes;
        let validator_marshal_persist = marshal_persist.estimate(block_size_estimate_bytes);
        let proposal_elapsed = propose_start.elapsed();
        let return_delay = self
            .proposal_return_budget
            .saturating_sub(proposal_elapsed)
            .saturating_sub(validation_latency_elapsed)
            .saturating_sub(validator_marshal_persist);
        debug!(
            proposal_elapsed = %display_duration(proposal_elapsed),
            build_time = %display_duration(payload_build_elapsed),
            payload_validation_work = %display_duration(payload_validation_work_elapsed),
            validation_latency_time = %display_duration(validation_latency_elapsed),
            validator_marshal_persist = %display_duration(validator_marshal_persist),
            return_time = %display_duration(return_delay),
            execution_block_rlp_size_estimate_bytes,
            block_size_estimate_bytes,
            "sleeping before returning proposal"
        );
        context.sleep_until(context.current() + return_delay).await;

        Ok(proposal)
    }
}

impl<E> Application<E> for TempoApplication
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

    #[instrument(
        skip_all,
        fields(
            epoch = %context.1.round.epoch(),
            view = %context.1.round.view(),
            parent.view = %context.1.parent.0,
            parent.digest = %context.1.parent.1,
        ),
    )]
    async fn propose(
        &mut self,
        context: (E, Self::Context),
        mut ancestry: impl Ancestry<Self::Block>,
    ) -> Option<Self::Block> {
        let (runtime, consensus_context) = context;
        let propose_start = Instant::now();
        let parent = match ancestry.next().await {
            Some(parent) => parent,
            None => {
                warn!("missing parent, cannot propose");
                return None;
            }
        };

        match self
            .build_proposal(&runtime, &consensus_context, parent, propose_start)
            .await
        {
            Ok(proposal) => {
                info!(proposal.digest = %proposal.digest(), "constructed proposal");
                Some(proposal)
            }
            Err(error) => {
                warn!(%error, "failed creating a proposal");
                None
            }
        }
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
    async fn verify(
        &mut self,
        context: (E, Self::Context),
        mut ancestry: impl Ancestry<Self::Block>,
    ) -> bool {
        let (runtime, consensus_context) = context;

        let block = match ancestry.next().await {
            Some(block) => block,
            None => {
                warn!("ancestry stream yielded no block to verify");
                return false;
            }
        };

        let parent = match ancestry.next().await {
            Some(parent) => parent,
            None => {
                warn!("ancestry stream yielded no parent for verification");
                return false;
            }
        };

        if let Err(reason) = verify_header(
            &block,
            consensus_context.parent,
            consensus_context.round,
            self.dkg_manager(),
            &self.epoch_strategy,
            &consensus_context.leader,
        )
        .await
        {
            warn!(%reason, "header could not be verified; failing block");
            return false;
        }

        if let Err(error) = self
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

        let validation_duration = match verify_block(
            &runtime,
            consensus_context.round.epoch(),
            &self.epoch_strategy,
            self.execution_node
                .add_ons_handle
                .beacon_engine_handle
                .clone(),
            &block,
            consensus_context.parent.1,
            &self.scheme_provider,
        )
        .await
        {
            Ok(duration) => duration,
            Err(error) => {
                warn!(%error, "failed verifying block against execution layer");
                return false;
            }
        };

        if let Some(duration) = validation_duration
            && let Ok(mut estimator) = self.validation_latency_estimator.lock()
        {
            estimator.observe(
                block.height().get(),
                ValidationLatencyWorkload::new(
                    block.block().gas_used(),
                    block.block().body().transaction_count(),
                ),
                duration,
            );
        }

        let is_good = validation_duration.is_some();
        if is_good
            && let Err(error) = self
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

    fn report(&mut self, update: Self::Activity) -> Feedback {
        if let Update::Block(_, ack) = update {
            ack.acknowledge();
        }
        Feedback::Ok
    }
}

/// Verifies `block` given its `parent` against the execution layer.
///
/// Returns EL validation duration when validation reached the execution layer
/// and succeeded, or `None` if the block is invalid. Returns an error if
/// validation was not possible, for example if communication with the execution
/// layer failed.
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
    context: &TContext,
    epoch: Epoch,
    epoch_strategy: &FixedEpocher,
    engine: ConsensusEngineHandle<TempoPayloadTypes>,
    block: &Block,
    parent_digest: Digest,
    scheme_provider: &SchemeProvider,
) -> eyre::Result<Option<Duration>> {
    use alloy_rpc_types_engine::PayloadStatusEnum;

    let epoch_info = epoch_strategy
        .containing(block.height())
        .expect("epoch strategy is for all heights");
    if epoch_info.epoch() != epoch {
        info!("block does not belong to this epoch");
        return Ok(None);
    }
    if block.parent_hash() != *parent_digest {
        info!(
            "parent digest stored in block must match the digest of the parent \
            argument but doesn't"
        );
        return Ok(None);
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
    let (block, block_access_list) = block.clone().into_parts();
    let execution_data = TempoExecutionData {
        block,
        block_access_list,
        validator_set,
    };
    let validation_start = Instant::now();
    let payload_status = engine
        .new_payload(execution_data)
        .pace(context, Duration::from_millis(50))
        .await
        .wrap_err("failed sending `new payload` message to execution layer to validate block")?;
    match payload_status.status {
        PayloadStatusEnum::Valid => Ok(Some(validation_start.elapsed())),
        PayloadStatusEnum::Invalid { validation_error } => {
            info!(
                validation_error,
                "execution layer returned that the block was invalid"
            );
            Ok(None)
        }
        PayloadStatusEnum::Accepted => {
            bail!(
                "failed validating block because payload was accepted, meaning \
                that this was not actually executed by the execution layer for some reason"
            )
        }
        PayloadStatusEnum::Syncing => {
            bail!(
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
    dkg_manager: &crate::dkg::manager::Mailbox,
    epoch_strategy: &FixedEpocher,
    proposer: &PublicKey,
) -> eyre::Result<()> {
    let epoch_info = epoch_strategy
        .containing(block.height())
        .expect("epoch strategy is for all heights");

    let ctx = block
        .header()
        .consensus_context
        .clone()
        .ok_or_eyre("missing consensus context")?;

    let expected_ctx = TempoConsensusContext {
        epoch: round.epoch().get(),
        view: round.view().get(),
        parent_view: parent.0.get(),
        proposer: crate::utils::public_key_to_tempo_primitive(proposer),
    };

    ensure!(
        ctx == expected_ctx,
        "mismatch in consensus context for block `{}`. expected `{expected_ctx:?}`. got `{ctx:?}`",
        block.digest()
    );

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
            return Err(eyre!(
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
        ensure!(
            &dealer == proposer,
            "proposer `{proposer}` is not the dealer `{dealer}` of the dealing \
            in the block",
        );
    }

    Ok(())
}

#[derive(Clone)]
struct Metrics {
    parent_ahead_of_local_time: Counter,
}

impl Metrics {
    fn init<TContext>(context: &TContext) -> Self
    where
        TContext: commonware_runtime::Metrics,
    {
        let parent_ahead_of_local_time = context.counter(
            "parent_ahead_of_local_time",
            "number of times the parent block timestamp was ahead of local time",
        );

        Self {
            parent_ahead_of_local_time,
        }
    }
}
