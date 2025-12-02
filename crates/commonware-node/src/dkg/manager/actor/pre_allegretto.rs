use std::net::SocketAddr;

use commonware_codec::{EncodeSize, RangeCfg, Read, ReadExt as _, Write, varint::UInt};
use commonware_consensus::{Block as _, Reporter as _, types::Epoch, utils};
use commonware_cryptography::{
    bls12381::primitives::{group::Share, poly::Public, variant::MinSig},
    ed25519::PublicKey,
};
use commonware_p2p::{Receiver, Sender, utils::mux::MuxHandle};
use commonware_runtime::{Clock, ContextCell, Spawner, Storage};
use commonware_utils::{
    quorum,
    set::{Ordered, OrderedAssociated},
};
use eyre::WrapErr as _;
use rand_core::CryptoRngCore;
use tempo_chainspec::hardfork::TempoHardforks;
use tracing::{Span, info, instrument, warn};

use crate::{
    consensus::block::Block,
    db::{CeremonyStore, DkgEpochStore, Tx, ValidatorsStore},
    dkg::{
        HardforkRegime, RegimeEpochState,
        ceremony::{self, Ceremony},
        manager::validators::ValidatorState,
    },
    epoch,
};

impl<TContext, TPeerManager> super::Actor<TContext, TPeerManager>
where
    TContext: Clock + CryptoRngCore + commonware_runtime::Metrics + Spawner + Storage,
    TPeerManager: commonware_p2p::Manager<
            PublicKey = PublicKey,
            Peers = OrderedAssociated<PublicKey, SocketAddr>,
        > + Sync,
{
    /// Runs the pre-allegretto initialization routines.
    ///
    /// This is a no-op if post-allegretto artifacts exists on disk and there no
    /// pre-allegretto artifacts remaining. The assumption is that the last pre-
    /// allegretto ceremony deletes its state from disk.
    ///
    /// If neither pre- nor post-allegretto artifacts are found, this method
    /// assumes that the node is starting from genesis.
    pub(super) async fn pre_allegretto_init(&mut self, tx: &mut Tx<ContextCell<TContext>>) {
        let has_post = tx
            .get_epoch::<super::post_allegretto::EpochState>()
            .await
            .ok()
            .flatten()
            .is_some();

        let has_pre = tx
            .get_epoch::<EpochState>()
            .await
            .ok()
            .flatten()
            .is_some();

        if !has_post && !has_pre {
            // Genesis initialization
            tx.set_epoch(EpochState {
                epoch: 0,
                participants: self.config.initial_validators.keys().clone(),
                public: self.config.initial_public_polynomial.clone(),
                share: self.config.initial_share.clone(),
            })
            .expect("must be able to set epoch");

            tx.set_validators(
                0,
                ValidatorState::with_unknown_contract_state(
                    self.config.initial_validators.clone(),
                ),
            )
            .expect("must be able to set validators");
        }
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
        ),
    )]
    pub(super) async fn handle_finalized_pre_allegretto<TReceiver, TSender>(
        &mut self,
        cause: Span,
        block: Block,
        maybe_ceremony: &mut Option<Ceremony<TReceiver, TSender>>,
        ceremony_mux: &mut MuxHandle<TSender, TReceiver>,
        tx: &mut Tx<ContextCell<TContext>>,
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
            let epoch_state: EpochState = tx
                .get_epoch::<EpochState>()
                .await
                .expect("must be able to read epoch")
                .expect("pre-allegretto epoch state must exist");

            if block_epoch + 1 == epoch_state.epoch {
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
                        .transition_to_dynamic_validator_sets(tx, ceremony_mux)
                        .await
                    {
                        Ok(ceremony) => {
                            maybe_ceremony.replace(ceremony);
                            info!(
                                "transitioning to dynamic validator sets was successful; \
                                deleting current pre-allegretto epoch state and leaving \
                                DKG logic to the post-hardfork routines",
                            );
                            // Delete pre-allegretto current epoch state
                            tx.remove_epoch(HardforkRegime::PreAllegretto);
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

                self.config
                    .epoch_manager
                    .report(
                        epoch::Enter {
                            epoch: epoch_state.epoch,
                            public: epoch_state.public.clone(),
                            share: epoch_state.share.clone(),
                            participants: epoch_state.participants.clone(),
                        }
                        .into(),
                    )
                    .await;

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
                        .is_some_and(|ceremony| ceremony.epoch() != epoch_state.epoch)
                {
                    maybe_ceremony.replace(self.start_pre_allegretto_ceremony(tx, ceremony_mux).await);
                }

                tx.set_validators(
                    epoch_state.epoch,
                    ValidatorState::with_unknown_contract_state(
                        self.config.initial_validators.clone(),
                    ),
                )
                .expect("must be able to set validators");
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
            && let Some(old_epoch_state) = tx
                .get_previous_epoch::<EpochState>()
                .await
                .ok()
                .flatten()
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
            tx.remove_previous_epoch(HardforkRegime::PreAllegretto);
        }

        let mut ceremony = maybe_ceremony
            .take()
            .expect("a ceremony must always exist except for the last block");

        match epoch::relative_position(block.height(), self.config.epoch_length) {
            epoch::RelativePosition::FirstHalf => {
                let _ = ceremony.distribute_shares(tx).await;
                let _ = ceremony.process_messages(tx).await;
            }
            epoch::RelativePosition::Middle => {
                let _ = ceremony.process_messages(tx).await;
                let _ = ceremony.construct_intermediate_outcome(tx).await;
            }
            epoch::RelativePosition::SecondHalf => {
                let _ = ceremony.process_dealings_in_block(tx, &block).await;
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

        let old_epoch_state: EpochState = tx
            .get_epoch::<EpochState>()
            .await
            .expect("must be able to read epoch")
            .expect("there must always be a current epoch state");

        // Move current to previous
        tx.set_previous_epoch(old_epoch_state)
            .expect("must be able to set previous epoch");

        let new_epoch_state = EpochState {
            epoch: next_epoch,
            participants: ceremony_outcome.participants,
            public,
            share,
        };
        tx.set_epoch(new_epoch_state.clone())
            .expect("must be able to set epoch");

        // Prune older ceremony.
        if let Some(epoch) = new_epoch_state.epoch.checked_sub(2) {
            tx.remove_ceremony(epoch);
        }
    }

    #[instrument(skip_all)]
    pub(super) async fn start_pre_allegretto_ceremony<TReceiver, TSender>(
        &mut self,
        tx: &mut Tx<ContextCell<TContext>>,
        mux: &mut MuxHandle<TSender, TReceiver>,
    ) -> Ceremony<TReceiver, TSender>
    where
        TReceiver: Receiver<PublicKey = PublicKey>,
        TSender: Sender<PublicKey = PublicKey>,
    {
        let epoch_state: EpochState = tx
            .get_epoch::<EpochState>()
            .await
            .expect("must be able to read epoch")
            .expect("the epoch state must always exist during the lifetime of the actor");

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
            tx,
            config,
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
        tx: &mut Tx<ContextCell<TContext>>,
        mux: &mut MuxHandle<TSender, TReceiver>,
    ) -> eyre::Result<Ceremony<TReceiver, TSender>>
    where
        TReceiver: Receiver<PublicKey = PublicKey>,
        TSender: Sender<PublicKey = PublicKey>,
    {
        let epoch_state: EpochState = tx
            .get_epoch::<EpochState>()
            .await?
            .expect(
                "when transitioning from pre-allegretto static validator sets to \
                post-allegretto dynamic validator sets the pre-allegretto epoch \
                state must exist",
            );
        let validator_state =
            ValidatorState::with_unknown_contract_state(self.config.initial_validators.clone());

        self.transition_from_static_validator_sets(tx, epoch_state, validator_state, mux)
            .await
            .wrap_err("hand-over to post-allegretto dynamic validator set logic failed")
    }
}

/// The state with all participants, public and private key share for an epoch.
#[derive(Clone)]
pub struct EpochState {
    pub epoch: Epoch,
    pub participants: Ordered<PublicKey>,
    pub public: Public<MinSig>,
    pub share: Option<Share>,
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
    pub fn epoch(&self) -> Epoch {
        self.epoch
    }

    pub fn participants(&self) -> &Ordered<PublicKey> {
        &self.participants
    }

    pub fn public_polynomial(&self) -> &Public<MinSig> {
        &self.public
    }

    pub fn private_share(&self) -> &Option<Share> {
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

impl RegimeEpochState for EpochState {
    const REGIME: HardforkRegime = HardforkRegime::PreAllegretto;
}
