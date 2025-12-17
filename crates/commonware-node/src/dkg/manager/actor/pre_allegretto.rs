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
use eyre::{OptionExt as _, WrapErr as _};
use rand_core::CryptoRngCore;
use tempo_chainspec::hardfork::TempoHardforks;
use tracing::{Span, info, instrument, warn};

use crate::{
    consensus::block::Block,
    dkg::{
        HardforkRegime, RegimeEpochState,
        ceremony::{self, Ceremony},
        manager::{read_write_transaction::DkgReadWriteTransaction, validators::ValidatorState},
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
    #[instrument(skip_all, err)]
    pub(super) async fn pre_allegretto_init(
        &mut self,
        tx: &mut DkgReadWriteTransaction<ContextCell<TContext>>,
    ) -> eyre::Result<()> {
        if !tx.has_post_allegretto_state().await {
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

            if !tx.has_pre_allegretto_state().await {
                tx.set_epoch(EpochState {
                    epoch: 0,
                    participants: validators.keys().clone(),
                    public: public_polynomial,
                    share: self.config.initial_share.clone(),
                });
            }

            // Safeguard when updating from older binaries that might not yet have written
            // the validators metadata.
            //
            // Note that pre-allegretto the validator set never changes.
            let current_epoch: EpochState = tx
                .get_epoch()
                .await?
                .expect("we ensured above that the epoch state is initialized");

            // Write the validators for the *previous* epoch. This assumes
            // that after this state is written, self.register_current_epoch_state
            // is called that will set the validators for the *current* epoch.
            tx.set_validators(
                current_epoch.epoch().saturating_sub(1),
                ValidatorState::with_unknown_contract_state(validators.clone()),
            );
        }

        if self.config.delete_signing_share
            && let Some(mut epoch_state) = tx.get_epoch::<EpochState>().await?
        {
            warn!("delete-signing-share set; deleting signing share");
            epoch_state.share.take();
            tx.set_epoch(epoch_state);
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
            latest_epoch = tracing::field::Empty,
        ),
    )]
    pub(super) async fn handle_finalized_pre_allegretto<TReceiver, TSender>(
        &mut self,
        cause: Span,
        block: Block,
        ceremony: &mut Ceremony<TReceiver, TSender>,
        ceremony_mux: &mut MuxHandle<TSender, TReceiver>,
        tx: &mut DkgReadWriteTransaction<ContextCell<TContext>>,
    ) where
        TReceiver: Receiver<PublicKey = PublicKey>,
        TSender: Sender<PublicKey = PublicKey>,
    {
        let epoch_state = tx
            .get_epoch::<EpochState>()
            .await
            .expect("epoch state must be readable")
            .expect("epoch state must exist");
        Span::current().record("latest_epoch", epoch_state.epoch());

        // Special case the last height.
        if utils::is_last_block_in_epoch(self.config.epoch_length, block.height()).is_some() {
            info!("reached end of epoch - reporting new epoch and starting ceremony");

            // Finalizations happen in strictly sequential order. This means we
            // are guaranteed to have observed the parent.
            let dkg_outcome = ceremony.finalize(block.parent_digest()).expect(
                "finalizing the ceremony on the boundary using the block's \
                    parent must work - we have observed all finalized blocks up \
                    until here, so we must have observed its parent, too",
            );

            let outcome = match dkg_outcome {
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

            let (public, share) = outcome.role.into_key_pair();

            let next_epoch = epoch_state.epoch + 1;
            let new_epoch_state = EpochState {
                epoch: next_epoch,
                participants: outcome.participants,
                public,
                share,
            };

            tx.set_previous_epoch(epoch_state);
            tx.set_epoch(new_epoch_state.clone());

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
                    Ok(new_ceremony) => {
                        *ceremony = new_ceremony;
                        info!(
                            "transitioning to dynamic validator sets was successful; \
                                deleting current pre-allegretto epoch state and leaving \
                                DKG logic to the post-hardfork routines",
                        );
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

            *ceremony = self.start_pre_allegretto_ceremony(tx, ceremony_mux).await;
            // Prune older ceremony.
            if let Some(epoch) = new_epoch_state.epoch.checked_sub(2) {
                tx.remove_ceremony(epoch);
            }
            self.register_current_epoch_state(tx).await;
            return;
        }

        // Notify the epoch manager that the first height of the new epoch
        // was entered and the previous epoch can be exited.
        //
        // Recall, for an epoch length E the first heights are 0E, 1E, 2E, ...
        if block.height().is_multiple_of(self.config.epoch_length)
            && let Some(old_epoch_state) =
                tx.get_previous_epoch::<EpochState>().await.ok().flatten()
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

        match epoch::relative_position(block.height(), self.config.epoch_length) {
            epoch::RelativePosition::FirstHalf => {
                let _ = ceremony.distribute_shares(tx).await;
                let _ = ceremony.process_messages(tx).await;
            }
            epoch::RelativePosition::Middle => {
                let _ = ceremony.process_messages(tx).await;
                let _ = ceremony
                    .construct_intermediate_outcome(tx, HardforkRegime::PreAllegretto)
                    .await;
            }
            epoch::RelativePosition::SecondHalf => {
                // Nothing special happens in the second half of the epoch. All
                // blocks are checked for dealings for the entire epoch.
            }
        }

        ceremony.add_finalized_block(tx, block.clone()).await;
    }

    #[instrument(skip_all, fields(epoch = tracing::field::Empty))]
    pub(super) async fn start_pre_allegretto_ceremony<TReceiver, TSender>(
        &mut self,
        tx: &mut DkgReadWriteTransaction<ContextCell<TContext>>,
        mux: &mut MuxHandle<TSender, TReceiver>,
    ) -> Ceremony<TReceiver, TSender>
    where
        TReceiver: Receiver<PublicKey = PublicKey>,
        TSender: Sender<PublicKey = PublicKey>,
    {
        let epoch_state: EpochState = tx
            .get_epoch()
            .await
            .expect("must be able to read epoch")
            .expect("the epoch state must always exist during the lifetime of the actor");
        Span::current().record("epoch", epoch_state.epoch());

        let config = ceremony::Config {
            namespace: self.config.namespace.clone(),
            me: self.config.me.clone(),
            public: epoch_state.public.clone(),
            share: epoch_state.share.clone(),
            epoch: epoch_state.epoch,
            epoch_length: self.config.epoch_length,
            dealers: epoch_state.participants.clone(),
            players: epoch_state.participants.clone(),
            hardfork_regime: HardforkRegime::PreAllegretto,
        };

        let ceremony = ceremony::Ceremony::init(
            &mut self.context,
            mux,
            tx,
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
        tx: &mut DkgReadWriteTransaction<ContextCell<TContext>>,
        mux: &mut MuxHandle<TSender, TReceiver>,
    ) -> eyre::Result<Ceremony<TReceiver, TSender>>
    where
        TReceiver: Receiver<PublicKey = PublicKey>,
        TSender: Sender<PublicKey = PublicKey>,
    {
        let epoch_state: EpochState = tx.get_epoch().await?.expect(
            "when transitioning from pre-allegretto static validator sets to \
                post-allegretto dynamic validator sets the pre-allegretto epoch \
                state must exist",
        );

        self.transition_from_static_validator_sets(tx, epoch_state, mux)
            .await
            .wrap_err("hand-over to post-allegretto dynamic validator set logic failed")
    }
}

/// The state with all participants, public and private key share for an epoch.
#[derive(Clone)]
pub(crate) struct EpochState {
    pub(crate) epoch: Epoch,
    pub(crate) participants: Ordered<PublicKey>,
    pub(crate) public: Public<MinSig>,
    pub(crate) share: Option<Share>,
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

impl RegimeEpochState for EpochState {
    const REGIME: HardforkRegime = HardforkRegime::PreAllegretto;
}
