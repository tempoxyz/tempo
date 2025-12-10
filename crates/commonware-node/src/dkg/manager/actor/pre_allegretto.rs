use std::net::SocketAddr;

use commonware_codec::{EncodeSize, RangeCfg, Read, ReadExt as _, Write, varint::UInt};
use commonware_consensus::{Block as _, Reporter as _, types::Epoch, utils};
use commonware_cryptography::{
    bls12381::primitives::{group::Share, poly::Public, variant::MinSig},
    ed25519::PublicKey,
};
use commonware_p2p::{Receiver, Sender, utils::mux::MuxHandle};
use commonware_runtime::{Clock, ContextCell, Metrics, Spawner, Storage};
use commonware_storage::metadata::Metadata;
use commonware_utils::{
    quorum,
    sequence::U64,
    set::{Ordered, OrderedAssociated},
};
use eyre::{OptionExt as _, WrapErr as _};
use rand_core::CryptoRngCore;
use tempo_chainspec::hardfork::TempoHardforks;
use tempo_dkg_onchain_artifacts::PublicOutcome;
use tracing::{Span, info, instrument, warn};

use crate::{
    consensus::block::Block,
    dkg::{
        HardforkRegime,
        ceremony::{self, Ceremony},
        manager::validators::ValidatorState,
    },
    epoch,
};

const CURRENT_EPOCH_KEY: U64 = U64::new(0);
const PREVIOUS_EPOCH_KEY: U64 = U64::new(1);

impl<TContext, TPeerManager> super::Actor<TContext, TPeerManager>
where
    TContext: Clock + CryptoRngCore + commonware_runtime::Metrics + Spawner + Storage,
    TPeerManager: commonware_p2p::Manager<
            PublicKey = PublicKey,
            Peers = OrderedAssociated<PublicKey, SocketAddr>,
        >,
{
    /// Runs the pre-allegretto initialization routines.
    ///
    /// This is a no-op if post-allegretto artifacts exists on disk and there no
    /// pre-allegretto artifacts remaining. The assumption is that the last pre-
    /// allegretto ceremony deletes its state from disk.
    ///
    /// If neither pre- nor post-allegretto artifacts are found, this method
    /// assumes that the node is starting from genesis.
    #[instrument(skip_all, err)]
    pub(super) async fn pre_allegretto_init(&mut self) -> eyre::Result<()> {
        if !self.post_allegretto_metadatas.exists() {
            let spec = self.config.execution_node.chain_spec();
            let public_polynomial = spec
                .info
                .public_polynomial()
                .clone()
                .ok_or_eyre("chainspec did not contain publicPolynomial; cannot go on without it")?
                .into_inner();

            let validators = spec
                .info
                .validators()
                .clone()
                .ok_or_eyre("chainspec did not contain validators; cannot go on without them")?
                .into_inner();

            if self
                .pre_allegretto_metadatas
                .epoch_metadata
                .get(&CURRENT_EPOCH_KEY)
                .is_none()
            {
                self.pre_allegretto_metadatas
                    .epoch_metadata
                    .put_sync(
                        CURRENT_EPOCH_KEY,
                        EpochState {
                            epoch: 0,
                            participants: validators.keys().clone(),
                            public: public_polynomial,
                            share: self.config.initial_share.clone(),
                        },
                    )
                    .await
                    .expect("must always be able to persists state");
            }

            // Safeguard when updating from older binaries that might not yet have written
            // the validators metadata.
            //
            // Note that pre-allegretto the validator set never changes.
            let current_epoch = self
                .pre_allegretto_metadatas
                .epoch_metadata
                .get(&CURRENT_EPOCH_KEY)
                .expect("we ensured above that the epoch state is initialized")
                .epoch();
            self.validators_metadata
                .put_sync(
                    // Write the validators for the *previous* epoch. This assumes
                    // that after this state is written, self.register_current_epoch_state
                    // is called that will set the validators for the *current*
                    // epoch.
                    current_epoch.saturating_sub(1).into(),
                    ValidatorState::with_unknown_contract_state(validators.clone()),
                )
                .await
                .expect("must always be able to write state");
        }
        Ok(())
    }

    /// Handles a finalized block.
    ///
    /// Depending on which height of an epoch the block is, this method exhibits
    /// different behavior:
    ///
    /// + first height of an epoch: notify the epoch manager that the previous
    /// epoch can be shut down.
    /// + first half of an epoch: distribute the shares generated during the
    /// DKG ceremony and collect shares from other dealers, and acks from other
    /// players.
    /// + exact middle of an epoch: generate the intermediate outcome of the
    /// ceremony.
    /// + second half of an epoch: read intermediate outcomes from blocks.
    /// + pre-to-last height of an epoch: generate the overall ceremony outcome,
    /// update CURRENT_EPOCH_KEY.
    /// + last height of an epoch: notify the epoch manager that a new epoch can
    /// be started, using the outcome of the last epoch. Start a new ceremony
    /// for the next epoch.
    #[instrument(
        parent = &cause,
        skip_all,
        fields(
            block.derived_epoch = utils::epoch(self.config.epoch_length, block.height()),
            block.height = block.height(),
            block.timestamp = block.timestamp(),
            latest_epoch = self.current_epoch_state().epoch(),
        ),
    )]
    pub(super) async fn handle_finalized_pre_allegretto<TReceiver, TSender>(
        &mut self,
        cause: Span,
        block: Block,
        maybe_ceremony: &mut Option<Ceremony<ContextCell<TContext>, TReceiver, TSender>>,
        ceremony_mux: &mut MuxHandle<TSender, TReceiver>,
    ) where
        TReceiver: Receiver<PublicKey = PublicKey>,
        TSender: Sender<PublicKey = PublicKey>,
    {
        // Special case the last height.
        //
        // On the last height, the new ("current") ceremony can be entered
        // because that is what provides the "genesis" of the new epoch.
        if let Some(block_epoch) =
            utils::is_last_block_in_epoch(self.config.epoch_length, block.height())
        {
            let epoch_state = self.current_epoch_state();
            if block_epoch + 1 == epoch_state.epoch() {
                if self
                    .config
                    .execution_node
                    .chain_spec()
                    .is_allegretto_active_at_timestamp(block.timestamp())
                {
                    info!(
                        "block timestamp is after allegretto hardfork; attempting \
                        to transition to dynamic validator sets by reading validators \
                        from smart contract",
                    );
                    match self
                        .transition_to_dynamic_validator_sets(ceremony_mux)
                        .await
                    {
                        Ok(ceremony) => {
                            maybe_ceremony.replace(ceremony);
                            info!(
                                "transitioning to dynamic validator sets was successful; \
                                deleting current pre-allegretto epoch state and leaving \
                                DKG logic to the post-hardfork routines",
                            );
                            self.pre_allegretto_metadatas
                                .delete_current_epoch_state()
                                .await;
                            return;
                        }
                        Err(error) => {
                            self.metrics.failed_allegretto_transitions.inc();
                            warn!(
                                %error,
                                "transitioning to dynamic validator sets was not \
                                successful; will attempt again next epoch"
                            );
                        }
                    }
                }

                // NOTE: This acts as restart protection: on pre-allegretto,
                // CURRENT_EPOCH_KEY is updated on the block *last height - 1*.
                // If a node restarts, it immediately starts a ceremony for
                // CURRENT_EPOCH_KEY, and then starts processing *last height*.
                //
                // This attempt to create a ceremony with the same mux subchannel
                // and fail.
                if maybe_ceremony.is_none()
                    || maybe_ceremony
                        .as_ref()
                        .is_some_and(|ceremony| ceremony.epoch() != epoch_state.epoch())
                {
                    maybe_ceremony.replace(self.start_pre_allegretto_ceremony(ceremony_mux).await);
                }
                self.register_current_epoch_state().await;
            } else {
                warn!(
                    "block was a boundary block, but not the last block of the \
                    previous epoch; ignoring it"
                );
            }
            return;
        }

        // Notify the epoch manager that the first height of the new epoch
        // was entered and the previous epoch can be exited.
        //
        // Recall, for an epoch length E the first heights are 0E, 1E, 2E, ...
        if block.height().is_multiple_of(self.config.epoch_length)
            && let Some(old_epoch_state) = self
                .pre_allegretto_metadatas
                .epoch_metadata
                .remove(&PREVIOUS_EPOCH_KEY)
        {
            self.config
                .epoch_manager
                .report(
                    epoch::Exit {
                        epoch: old_epoch_state.epoch,
                    }
                    .into(),
                )
                .await;
            self.pre_allegretto_metadatas
                .epoch_metadata
                .sync()
                .await
                .expect("must always be able to persist state");
        }

        let mut ceremony = maybe_ceremony
            .take()
            .expect("a ceremony must always exist except for the last block");

        match epoch::relative_position(block.height(), self.config.epoch_length) {
            epoch::RelativePosition::FirstHalf => {
                let _ = ceremony.distribute_shares().await;
                let _ = ceremony.process_messages().await;
            }
            epoch::RelativePosition::Middle => {
                let _ = ceremony.process_messages().await;
                let _ = ceremony
                    .construct_intermediate_outcome(HardforkRegime::PreAllegretto)
                    .await;
            }
            epoch::RelativePosition::SecondHalf => {
                let _ = ceremony
                    .process_dealings_in_block(&block, HardforkRegime::PreAllegretto)
                    .await;
            }
        }

        let is_one_before_boundary =
            utils::is_last_block_in_epoch(self.config.epoch_length, block.height() + 1).is_some();

        if !is_one_before_boundary {
            assert!(
                maybe_ceremony.replace(ceremony).is_none(),
                "ceremony was taken out of the option and is being put back"
            );
            return;
        }

        // XXX: Need to finalize on the pre-to-last height of the epoch so that
        // the information becomes available on the last height and can be
        // stored on chain.
        info!("on pre-to-last height of epoch; finalizing ceremony");

        let next_epoch = ceremony.epoch() + 1;

        let ceremony_outcome = match ceremony.finalize() {
            Ok(outcome) => {
                self.metrics.ceremony.one_more_success();
                info!(
                    "ceremony was successful; using the new participants, polynomial and secret key"
                );
                outcome
            }
            Err(outcome) => {
                self.metrics.ceremony.one_more_failure();
                warn!(
                    "ceremony was a failure; using the old participants, polynomial and secret key"
                );
                outcome
            }
        };
        let (public, share) = ceremony_outcome.role.into_key_pair();

        let old_epoch_state = self
            .pre_allegretto_metadatas
            .epoch_metadata
            .remove(&CURRENT_EPOCH_KEY)
            .expect("there must always be a current epoch state");

        self.pre_allegretto_metadatas
            .epoch_metadata
            .put(PREVIOUS_EPOCH_KEY, old_epoch_state);

        let new_epoch_state = EpochState {
            epoch: next_epoch,
            participants: ceremony_outcome.participants,
            public,
            share,
        };
        self.pre_allegretto_metadatas
            .epoch_metadata
            .put(CURRENT_EPOCH_KEY, new_epoch_state.clone());

        self.pre_allegretto_metadatas
            .epoch_metadata
            .sync()
            .await
            .expect("must always be able to write epoch state to disk");

        // Prune older ceremony.
        if let Some(epoch) = new_epoch_state.epoch.checked_sub(2) {
            let mut ceremony_metadata = self.ceremony_metadata.lock().await;
            ceremony_metadata.remove(&epoch.into());
            ceremony_metadata.sync().await.expect("metadata must sync");
        }
    }

    #[instrument(skip_all, fields(epoch = self.pre_allegretto_metadatas.current_epoch_state().unwrap().epoch()))]
    pub(super) async fn start_pre_allegretto_ceremony<TReceiver, TSender>(
        &mut self,
        mux: &mut MuxHandle<TSender, TReceiver>,
    ) -> Ceremony<ContextCell<TContext>, TReceiver, TSender>
    where
        TReceiver: Receiver<PublicKey = PublicKey>,
        TSender: Sender<PublicKey = PublicKey>,
    {
        let epoch_state = self
            .pre_allegretto_metadatas
            .epoch_metadata
            .get(&CURRENT_EPOCH_KEY)
            .expect("the epoch state must always during the lifetime of the actor");
        let config = ceremony::Config {
            namespace: self.config.namespace.clone(),
            me: self.config.me.clone(),
            public: epoch_state.public.clone(),
            share: epoch_state.share.clone(),
            epoch: epoch_state.epoch,
            dealers: epoch_state.participants.clone(),
            players: epoch_state.participants.clone(),
        };

        let ceremony = ceremony::Ceremony::init(
            &mut self.context,
            mux,
            self.ceremony_metadata.clone(),
            config,
            self.metrics.ceremony.clone(),
        )
        .await
        .expect("must always be able to initialize ceremony");

        info!(
            us = %self.config.me,
            n_dealers = ceremony.dealers().len(),
            dealers = ?ceremony.dealers(),
            n_players = ceremony.players().len(),
            players = ?ceremony.players(),
            as_player = ceremony.is_player(),
            as_dealer = ceremony.is_dealer(),
            "started a ceremony",
        );

        self.metrics.pre_allegretto_ceremonies.inc();
        ceremony
    }

    async fn transition_to_dynamic_validator_sets<TReceiver, TSender>(
        &mut self,
        mux: &mut MuxHandle<TSender, TReceiver>,
    ) -> eyre::Result<Ceremony<ContextCell<TContext>, TReceiver, TSender>>
    where
        TReceiver: Receiver<PublicKey = PublicKey>,
        TSender: Sender<PublicKey = PublicKey>,
    {
        let epoch_state = self
            .pre_allegretto_metadatas
            .epoch_metadata
            .get(&CURRENT_EPOCH_KEY)
            .cloned()
            .expect(
                "when transitioning from pre-allegretto static validator sets to \
                post-allegretto dynamic validator sets the pre-allegretto epoch \
                state must exist",
            );

        self.transition_from_static_validator_sets(epoch_state, mux)
            .await
            .wrap_err("hand-over to post-allegretto dynamic validator set logic failed")
    }
}

pub(super) struct Metadatas<TContext>
where
    TContext: Clock + Metrics + Storage,
{
    /// Persisted information on the current epoch for DKG ceremonies that were
    /// started after the allegretto hardfork.
    epoch_metadata: Metadata<TContext, U64, EpochState>,
}

impl<TContext> Metadatas<TContext>
where
    TContext: Clock + Metrics + Storage,
{
    pub(super) async fn init(context: &TContext, partition_prefix: &str) -> Self
    where
        TContext: Metrics,
    {
        let epoch_metadata = Metadata::init(
            context.with_label("post_allegretto_epoch_metadata"),
            commonware_storage::metadata::Config {
                // XXX: the prefix of this partition must stay fixed to be
                // backward compatible with the pre-allegretto hardfork.
                partition: format!("{partition_prefix}_current_epoch"),
                codec_config: (),
            },
        )
        .await
        .expect("must be able to initialize metadata on disk to function");

        Self { epoch_metadata }
    }

    pub(super) fn dkg_outcome(&self) -> Option<PublicOutcome> {
        let epoch_state = self.current_epoch_state()?;
        Some(PublicOutcome {
            epoch: epoch_state.epoch(),
            participants: epoch_state.participants().clone(),
            public: epoch_state.public_polynomial().clone(),
        })
    }

    pub(super) fn previous_epoch_state(&self) -> Option<&EpochState> {
        self.epoch_metadata.get(&PREVIOUS_EPOCH_KEY)
    }

    pub(super) fn current_epoch_state(&self) -> Option<&EpochState> {
        self.epoch_metadata.get(&CURRENT_EPOCH_KEY)
    }

    /// Removes all pre-allegretto state from disk.
    ///
    /// Returns the current epoch state on the left-hand side, if it exists, and
    /// the previous epoch state on the right.
    async fn delete_current_epoch_state(&mut self) -> Option<EpochState> {
        let current_state = self.epoch_metadata.remove(&CURRENT_EPOCH_KEY);
        self.epoch_metadata
            .sync()
            .await
            .expect("must always be able to sync state to disk");
        current_state
    }

    pub(super) async fn delete_previous_epoch_state(&mut self) -> Option<EpochState> {
        let previous_state = self.epoch_metadata.remove(&PREVIOUS_EPOCH_KEY);
        self.epoch_metadata
            .sync()
            .await
            .expect("must always be able to sync state to disk");
        previous_state
    }
}

/// The state with all participants, public and private key share for an epoch.
#[derive(Clone)]
pub(super) struct EpochState {
    epoch: Epoch,
    participants: Ordered<PublicKey>,
    public: Public<MinSig>,
    share: Option<Share>,
}

impl std::fmt::Debug for EpochState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EpochState")
            .field("epoch", &self.epoch)
            .field("participants", &self.participants)
            .field("public", &self.public)
            .field("share", &self.share.as_ref().map(|_| "<private share>"))
            .finish()
    }
}

impl EpochState {
    pub(super) fn epoch(&self) -> Epoch {
        self.epoch
    }

    pub(super) fn participants(&self) -> &Ordered<PublicKey> {
        &self.participants
    }

    pub(super) fn public_polynomial(&self) -> &Public<MinSig> {
        &self.public
    }

    pub(super) fn private_share(&self) -> &Option<Share> {
        &self.share
    }
}

impl Write for EpochState {
    fn write(&self, buf: &mut impl bytes::BufMut) {
        UInt(self.epoch).write(buf);
        self.participants.write(buf);
        self.public.write(buf);
        self.share.write(buf);
    }
}

impl EncodeSize for EpochState {
    fn encode_size(&self) -> usize {
        UInt(self.epoch).encode_size()
            + self.participants.encode_size()
            + self.public.encode_size()
            + self.share.encode_size()
    }
}

impl Read for EpochState {
    type Cfg = ();

    fn read_cfg(
        buf: &mut impl bytes::Buf,
        _cfg: &Self::Cfg,
    ) -> Result<Self, commonware_codec::Error> {
        let epoch = UInt::read(buf)?.into();
        let participants = Ordered::read_cfg(buf, &(RangeCfg::from(0..=usize::MAX), ()))?;
        let public =
            Public::<MinSig>::read_cfg(buf, &(quorum(participants.len() as u32) as usize))?;
        let share = Option::<Share>::read_cfg(buf, &())?;
        Ok(Self {
            epoch,
            participants,
            public,
            share,
        })
    }
}
