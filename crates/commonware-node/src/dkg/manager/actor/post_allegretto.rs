use std::net::SocketAddr;

use commonware_codec::{EncodeSize, Read, Write};
use commonware_consensus::{Block as _, Reporter as _, types::Epoch, utils};
use commonware_cryptography::{
    bls12381::primitives::{group::Share, poly::Public, variant::MinSig},
    ed25519::PublicKey,
};
use commonware_p2p::{Receiver, Sender, utils::mux::MuxHandle};
use commonware_runtime::{Clock, ContextCell, Spawner, Storage};
use commonware_utils::set::{Ordered, OrderedAssociated};
use eyre::ensure;
use rand_core::CryptoRngCore;
use tracing::{Span, info, instrument, warn};

use crate::{
    consensus::block::Block,
    db::{CeremonyStore, DkgEpochStore, DkgOutcomeStore, Tx, ValidatorsStore},
    dkg::{
        HardforkRegime, RegimeEpochState,
        ceremony::{self, Ceremony},
        manager::{
            actor::{DkgOutcome, pre_allegretto},
            validators::ValidatorState,
        },
    },
    epoch::{self, is_first_block_in_epoch},
};

impl<TContext, TPeerManager> super::Actor<TContext, TPeerManager>
where
    TContext: Clock + CryptoRngCore + commonware_runtime::Metrics + Spawner + Storage,
    TPeerManager: commonware_p2p::Manager<
            PublicKey = PublicKey,
            Peers = OrderedAssociated<PublicKey, SocketAddr>,
        > + Sync,
{
    /// Handles a finalized block.
    ///
    /// Some block heights are special cased:
    ///
    /// + first height of an epoch: notify the epoch manager that the previous
    ///   epoch can be shut down.
    /// + pre-to-last height of an epoch: finalize the ceremony and generate the
    ///   the state for the next ceremony.
    /// + last height of an epoch:
    ///     1. notify the epoch manager that a new epoch can be entered;
    ///     2. start a new ceremony by reading the validator config smart
    ///        contract
    ///
    /// The processing of all other blocks depends on which part of the epoch
    /// they fall in:
    ///
    /// + first half: if we are a dealer, distribute the generated DKG shares
    ///   to the players and collect their acks. If we are a player, receive
    ///   DKG shares and respond with an ack.
    /// + exact middle of an epoch: if we are a dealer, generate the dealing
    ///   (the intermediate outcome) of the ceremony.
    /// + second half of an epoch: if we are a dealer, send it to the application
    ///   if a request comes in (the application is supposed to add this to the
    ///   block it is proposing). Always attempt to read dealings from the blocks
    ///   and track them (if a dealer or player both).
    #[instrument(
        parent = &cause,
        skip_all,
        fields(
            block.derived_epoch = utils::epoch(self.config.epoch_length, block.height()),
            block.height = block.height(),
            ceremony.epoch = maybe_ceremony.as_ref().map(|c| c.epoch()),
        ),
    )]
    pub(super) async fn handle_finalized_post_allegretto<TReceiver, TSender>(
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
        let block_epoch = utils::epoch(self.config.epoch_length, block.height());

        // Get current epoch state
        let current_epoch_state: EpochState = match tx.get_epoch::<EpochState>().await {
            Ok(Some(state)) => state,
            Ok(None) => {
                warn!("no post-allegretto epoch state found");
                return;
            }
            Err(e) => {
                warn!(%e, "failed to read post-allegretto epoch state");
                return;
            }
        };

        // Replay protection: if the node shuts down right after the last block
        // of the outgoing epoch was processed, but before the first block of
        // the incoming epoch was processed, then we do not want to update the
        // epoch state again.
        //
        // This relies on the fact that the actor updates its tracked epoch
        // state on the last block of the epoch.
        if block_epoch != current_epoch_state.epoch() {
            info!(
                block_epoch,
                actor_epoch = current_epoch_state.epoch(),
                "block was for an epoch other than what the actor is currently tracking; ignoring",
            );
            return;
        }

        // Special case --- boundary block: report that a new epoch should be
        // entered, start a new ceremony.
        //
        // Recall, for some epoch length E, the boundary heights are
        // 1E-1, 2E-1, 3E-1, ... for epochs 0, 1, 2.
        //
        // So for E = 100, the boundary heights would be 99, 199, 299, ...
        if utils::is_last_block_in_epoch(self.config.epoch_length, block.height()).is_some() {
            self.update_and_register_current_epoch_state(tx).await;

            maybe_ceremony.replace(self.start_post_allegretto_ceremony(tx, ceremony_mux).await);
            // Early return: start driving the ceremony on the first height of
            // the next epoch.
            return;
        }

        // Recall, for an epoch length E the first heights are 0E, 1E, 2E, ...
        //
        // So for E = 100, the first heights are 0, 100, 200, ...
        if is_first_block_in_epoch(self.config.epoch_length, block.height()).is_some() {
            self.enter_current_epoch_and_remove_old_state(tx).await;

            // Similar for the validators: we only need to track the current
            // and last two epochs.
            if let Some(epoch) = current_epoch_state.epoch().checked_sub(3) {
                tx.remove_validators(epoch);
            }
        }

        let mut ceremony = maybe_ceremony.take().expect(
            "past this point a ceremony must always be defined; the only \
                time a ceremony is not permitted to exist is exactly on the \
                boundary; did the code after ensure that the ceremony is \
                returned to its Option?",
        );

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

        // XXX: Need to finalize on the pre-to-last height of the epoch so that
        // the information becomes available on the last height and can be
        // stored on chain.
        let is_one_before_boundary =
            utils::is_last_block_in_epoch(self.config.epoch_length, block.height() + 1).is_some();
        if !is_one_before_boundary {
            assert!(
                maybe_ceremony.replace(ceremony).is_none(),
                "putting back the ceremony we just took out",
            );
            return;
        }

        info!("on pre-to-last height of epoch; finalizing ceremony");

        let current_epoch = ceremony.epoch();

        let (ceremony_outcome, dkg_successful) = match ceremony.finalize() {
            Ok(outcome) => {
                self.metrics.ceremony.one_more_success();
                info!(
                    "ceremony was successful; using the new participants, polynomial and secret key"
                );
                (outcome, true)
            }
            Err(outcome) => {
                self.metrics.ceremony.one_more_failure();
                warn!(
                    "ceremony was a failure; using the old participants, polynomial and secret key"
                );
                (outcome, false)
            }
        };
        let (public, share) = ceremony_outcome.role.into_key_pair();

        tx.set_dkg_outcome(DkgOutcome {
            dkg_successful,
            epoch: current_epoch + 1,
            participants: ceremony_outcome.participants,
            public,
            share,
        })
        .expect("must always be able to persist the DKG outcome");

        // Prune older ceremony.
        if let Some(epoch) = current_epoch.checked_sub(1) {
            tx.remove_ceremony(epoch);
        }
    }

    #[instrument(skip_all)]
    pub(super) async fn transition_from_static_validator_sets<TReceiver, TSender>(
        &mut self,
        tx: &mut Tx<ContextCell<TContext>>,
        pre_allegretto_epoch_state: pre_allegretto::EpochState,
        pre_allegretto_validator_state: ValidatorState,
        mux: &mut MuxHandle<TSender, TReceiver>,
    ) -> eyre::Result<Ceremony<TReceiver, TSender>>
    where
        TReceiver: Receiver<PublicKey = PublicKey>,
        TSender: Sender<PublicKey = PublicKey>,
    {
        let on_chain_validators = super::read_validator_config_with_retry(
            &self.context,
            &self.config.execution_node,
            pre_allegretto_epoch_state.epoch(),
            self.config.epoch_length,
        )
        .await;

        ensure!(
            pre_allegretto_epoch_state.participants() == on_chain_validators.keys(),
            "ed25519 public keys of validators read from contract do not match \
            those of the last pre-allegretto static DKG ceremony; \
            DKG participants = {:?}; \
            contract = {:?}",
            pre_allegretto_epoch_state.participants(),
            on_chain_validators.keys(),
        );

        {
            let static_validators = pre_allegretto_validator_state
                .dealers()
                .iter_pairs()
                .map(|(key, val)| (key, &val.inbound))
                .collect::<OrderedAssociated<_, _>>();
            let on_chain_validators = on_chain_validators
                .iter_pairs()
                .map(|(key, val)| (key, &val.inbound))
                .collect::<OrderedAssociated<_, _>>();

            ensure!(
                static_validators == on_chain_validators,
                "static validators known to node (derived from config or \
                chainspec) do not match the validators read from the on-chain
                contract; \
                static validators = {static_validators:?}; \
                on chain validators = {on_chain_validators:?}",
            );
        }

        let mut new_validator_state = pre_allegretto_validator_state.clone();
        // NOTE: `push_on_failure` ensures that the dealers remain in the
        // validator set. This pushes the on-chain validators into the
        // validator state twice to ensure that the dealers stay around.
        new_validator_state.push_on_failure(on_chain_validators.clone());
        new_validator_state.push_on_failure(on_chain_validators);

        let new_epoch_state = EpochState {
            dkg_outcome: DkgOutcome {
                dkg_successful: true,
                epoch: pre_allegretto_epoch_state.epoch(),
                participants: pre_allegretto_epoch_state.participants().clone(),
                public: pre_allegretto_epoch_state.public_polynomial().clone(),
                share: pre_allegretto_epoch_state.private_share().clone(),
            },
            validator_state: new_validator_state.clone(),
        };

        tx.set_epoch(new_epoch_state)
            .expect("syncing state must always work");

        self.register_current_epoch_state(tx).await;

        Ok(self.start_post_allegretto_ceremony(tx, mux).await)
    }

    #[instrument(skip_all)]
    pub(super) async fn start_post_allegretto_ceremony<TReceiver, TSender>(
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
            .expect(
                "the post-allegretto epoch state must exist in order to start a ceremony for it",
            );

        let config = ceremony::Config {
            namespace: self.config.namespace.clone(),
            me: self.config.me.clone(),
            public: epoch_state.public_polynomial().clone(),
            share: epoch_state.private_share().clone(),
            epoch: epoch_state.epoch(),
            dealers: epoch_state.dealer_pubkeys(),
            players: epoch_state.player_pubkeys(),
        };
        let ceremony =
            ceremony::Ceremony::init(&mut self.context, mux, tx, config, self.metrics.ceremony.clone())
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
            n_syncing_players = epoch_state.validator_state.syncing_players().len(),
            syncing_players = ?epoch_state.validator_state.syncing_players(),
            "started a ceremony",
        );

        self.metrics
            .syncing_players
            .set(epoch_state.validator_state.syncing_players().len() as i64);

        self.metrics.post_allegretto_ceremonies.inc();

        ceremony
    }

    #[instrument(skip_all)]
    async fn update_and_register_current_epoch_state(
        &mut self,
        tx: &mut Tx<ContextCell<TContext>>,
    ) {
        let old_epoch_state: EpochState = tx
            .get_epoch::<EpochState>()
            .await
            .expect("must be able to read epoch")
            .expect("there must always exist an epoch state");

        let dkg_outcome: DkgOutcome = tx
            .get_dkg_outcome()
            .await
            .expect("must be able to read dkg outcome")
            .expect(
                "when updating the current epoch state, there must be a DKG \
                outcome of some ceremony",
            );

        assert_eq!(
            old_epoch_state.epoch() + 1,
            dkg_outcome.epoch,
            "sanity check: old outcome must be new outcome - 1"
        );

        let syncing_players = super::read_validator_config_with_retry(
            &self.context,
            &self.config.execution_node,
            dkg_outcome.epoch,
            self.config.epoch_length,
        )
        .await;

        let mut new_validator_state = old_epoch_state.validator_state.clone();
        if dkg_outcome.dkg_successful {
            new_validator_state.push_on_success(syncing_players);
        } else {
            new_validator_state.push_on_failure(syncing_players);
        }

        let new_epoch_state = EpochState {
            dkg_outcome,
            validator_state: new_validator_state.clone(),
        };

        // Move current to previous
        tx.set_previous_epoch(old_epoch_state)
            .expect("must be able to set previous epoch");

        tx.set_epoch(new_epoch_state.clone())
            .expect("must be able to set epoch");

        self.register_current_epoch_state(tx).await;
    }

    /// Reports that a new epoch was fully entered, that the previous epoch can be ended.
    async fn enter_current_epoch_and_remove_old_state(
        &mut self,
        tx: &mut Tx<ContextCell<TContext>>,
    ) {
        // Try to get and remove post-allegretto previous epoch state
        let epoch_to_shutdown =
            if let Ok(Some(old_epoch_state)) = tx.get_previous_epoch::<EpochState>().await {
                tx.remove_previous_epoch(HardforkRegime::PostAllegretto);
                Some(old_epoch_state.epoch())
            } else if let Ok(Some(old_state)) =
                tx.get_previous_epoch::<pre_allegretto::EpochState>().await
            {
                tx.remove_previous_epoch(HardforkRegime::PreAllegretto);
                Some(old_state.epoch())
            } else {
                None
            };

        if let Some(epoch) = epoch_to_shutdown {
            self.config
                .epoch_manager
                .report(epoch::Exit { epoch }.into())
                .await;
        }

        if let Some(epoch) = epoch_to_shutdown.and_then(|epoch| epoch.checked_sub(2)) {
            tx.remove_validators(epoch);
        }
    }
}

/// All state for an epoch:
///
/// + the DKG outcome containing the public key, the private key share, and the
///   participants for the epoch
/// + the validator state, containing the dealers of the epoch (corresponds to
///   the participants in the DKG outcome), the players of the next ceremony,
///   and the syncing players, who will be players in the ceremony thereafter.
#[derive(Clone, Debug)]
pub struct EpochState {
    pub dkg_outcome: DkgOutcome,
    pub validator_state: ValidatorState,
}

impl EpochState {
    pub fn epoch(&self) -> Epoch {
        self.dkg_outcome.epoch
    }

    pub fn participants(&self) -> &Ordered<PublicKey> {
        &self.dkg_outcome.participants
    }

    pub fn public_polynomial(&self) -> &Public<MinSig> {
        &self.dkg_outcome.public
    }

    pub fn private_share(&self) -> &Option<Share> {
        &self.dkg_outcome.share
    }

    pub fn dealer_pubkeys(&self) -> Ordered<PublicKey> {
        self.validator_state.dealer_pubkeys()
    }

    pub fn player_pubkeys(&self) -> Ordered<PublicKey> {
        self.validator_state.player_pubkeys()
    }
}

impl Write for EpochState {
    fn write(&self, buf: &mut impl bytes::BufMut) {
        self.dkg_outcome.write(buf);
        self.validator_state.write(buf);
    }
}

impl EncodeSize for EpochState {
    fn encode_size(&self) -> usize {
        self.dkg_outcome.encode_size() + self.validator_state.encode_size()
    }
}

impl Read for EpochState {
    type Cfg = ();

    fn read_cfg(
        buf: &mut impl bytes::Buf,
        _cfg: &Self::Cfg,
    ) -> Result<Self, commonware_codec::Error> {
        let dkg_outcome = DkgOutcome::read_cfg(buf, &())?;
        let validator_state = ValidatorState::read_cfg(buf, &())?;
        Ok(Self {
            dkg_outcome,
            validator_state,
        })
    }
}

impl RegimeEpochState for EpochState {
    const REGIME: HardforkRegime = HardforkRegime::PostAllegretto;
}
