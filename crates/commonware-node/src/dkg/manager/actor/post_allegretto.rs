use std::net::SocketAddr;

use commonware_codec::{DecodeExt as _, EncodeSize, Read, Write};
use commonware_consensus::{Block as _, Reporter as _, types::Epoch, utils};
use commonware_cryptography::{
    bls12381::primitives::{group::Share, poly::Public, variant::MinSig},
    ed25519::PublicKey,
};
use commonware_p2p::{Receiver, Sender, utils::mux::MuxHandle};
use commonware_runtime::{Clock, ContextCell, Metrics, Spawner, Storage};
use commonware_storage::metadata::Metadata;
use commonware_utils::{
    sequence::U64,
    set::{Ordered, OrderedAssociated},
};
use eyre::{WrapErr as _, ensure};
use rand_core::CryptoRngCore;
use reth_ethereum::chainspec::EthChainSpec as _;
use tempo_chainspec::hardfork::TempoHardforks as _;
use tempo_dkg_onchain_artifacts::PublicOutcome;
use tracing::{Span, info, instrument, warn};

use crate::{
    consensus::block::Block,
    dkg::{
        HardforkRegime,
        ceremony::{self, Ceremony},
        manager::{
            actor::{DkgOutcome, pre_allegretto},
            validators::{self, ValidatorState},
        },
    },
    epoch::{self, is_first_block_in_epoch},
};

const CURRENT_EPOCH_KEY: U64 = U64::new(0);
const PREVIOUS_EPOCH_KEY: U64 = U64::new(1);

const DKG_OUTCOME_KEY: U64 = U64::new(0);

impl<TContext, TPeerManager> super::Actor<TContext, TPeerManager>
where
    TContext: Clock + CryptoRngCore + commonware_runtime::Metrics + Spawner + Storage,
    TPeerManager: commonware_p2p::Manager<
            PublicKey = PublicKey,
            Peers = OrderedAssociated<PublicKey, SocketAddr>,
        >,
{
    #[instrument(skip_all, err)]
    pub(super) async fn post_allegretto_init(&mut self) -> eyre::Result<()> {
        let spec = self.config.execution_node.chain_spec();
        if !self.post_allegretto_metadatas.exists() && spec.is_allegretto_active_at_timestamp(0) {
            info!(
                "allegretto hardfork is active at timestamp 0, reading initial validators and public polynomial from genesis block"
            );

            let initial_dkg_outcome = PublicOutcome::decode(spec.genesis().extra_data.as_ref())
                .wrap_err_with(|| {
                    format!(
                        "failed decoding the genesis.extra_data field as an \
                        initial DKG outcome; this field must be set and it \
                        must be decodable; bytes = {}",
                        spec.genesis().extra_data.len(),
                    )
                })?;

            ensure!(
                initial_dkg_outcome.epoch == 0,
                "at genesis, the epoch must be zero, but genesis reported `{}`",
                initial_dkg_outcome.epoch
            );
            let initial_validators = validators::read_from_contract(
                0,
                &self.config.execution_node,
                0,
                self.config.epoch_length,
            )
            .await
            .wrap_err("validator config could not be read from genesis block validator config smart contract")?;

            // ensure that the peer set written into the smart contract matches
            // the participants as determinde by the initial DKG outcome.
            let initial_validator_state = ValidatorState::new(initial_validators);
            let peers_as_per_contract = initial_validator_state.resolve_addresses_and_merge_peers();
            ensure!(
                peers_as_per_contract.keys() == &initial_dkg_outcome.participants,
                "the DKG participants stored in the genesis extraData header \
                don't match the peers determined from the onchain contract of \
                the genesis block; \
                extraData.participants = `{:?}; \
                contract.peers = `{:?}",
                initial_dkg_outcome.participants,
                peers_as_per_contract.keys(),
            );

            info!(
                initial_public_polynomial = ?initial_dkg_outcome.public,
                initial_validators = ?peers_as_per_contract,
                "using public polynomial and validators read from contract",);

            self.post_allegretto_metadatas
                .epoch_metadata
                .put_sync(
                    CURRENT_EPOCH_KEY,
                    EpochState {
                        dkg_outcome: DkgOutcome {
                            dkg_successful: true,
                            epoch: 0,
                            participants: initial_dkg_outcome.participants,
                            public: initial_dkg_outcome.public,
                            share: self.config.initial_share.clone(),
                        },
                        validator_state: initial_validator_state.clone(),
                    },
                )
                .await
                .expect("persisting epoch state must always work");
        }
        Ok(())
    }

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
        maybe_ceremony: &mut Option<Ceremony<ContextCell<TContext>, TReceiver, TSender>>,
        ceremony_mux: &mut MuxHandle<TSender, TReceiver>,
    ) where
        TReceiver: Receiver<PublicKey = PublicKey>,
        TSender: Sender<PublicKey = PublicKey>,
    {
        let block_epoch = utils::epoch(self.config.epoch_length, block.height());
        // Replay protection: if the node shuts down right after the last block
        // of the outgoing epoch was processed, but before the first block of
        // the incoming epoch was processed, then we do not want to update the
        // epoch state again.
        //
        // This relies on the fact that the actor updates its tracked epoch
        // state on the last block of the epoch.
        if block_epoch != self.current_epoch_state().epoch() {
            info!(
                block_epoch,
                actor_epoch = self.current_epoch_state().epoch(),
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
            self.update_and_register_current_epoch_state().await;

            maybe_ceremony.replace(self.start_post_allegretto_ceremony(ceremony_mux).await);
            // Early return: start driving the ceremony on the first height of
            // the next epoch.
            return;
        }

        // Recall, for an epoch length E the first heights are 0E, 1E, 2E, ...
        //
        // So for E = 100, the first heights are 0, 100, 200, ...
        if is_first_block_in_epoch(self.config.epoch_length, block.height()).is_some() {
            self.enter_current_epoch_and_remove_old_state().await;

            // Similar for the validators: we only need to track the current
            // and last two epochs.
            if let Some(epoch) = self.current_epoch_state().epoch().checked_sub(3) {
                self.validators_metadata.remove(&epoch.into());
                self.validators_metadata
                    .sync()
                    .await
                    .expect("metadata must always be writable");
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
                let _ = ceremony.distribute_shares().await;
                let _ = ceremony.process_messages().await;
            }
            epoch::RelativePosition::Middle => {
                let _ = ceremony.process_messages().await;
                let _ = ceremony
                    .construct_intermediate_outcome(HardforkRegime::PostAllegretto)
                    .await;
            }
            epoch::RelativePosition::SecondHalf => {
                let _ = ceremony
                    .process_dealings_in_block(&block, HardforkRegime::PostAllegretto)
                    .await;
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

        self.post_allegretto_metadatas
            .dkg_outcome_metadata
            .put_sync(
                DKG_OUTCOME_KEY,
                DkgOutcome {
                    dkg_successful,
                    epoch: current_epoch + 1,
                    participants: ceremony_outcome.participants,
                    public,
                    share,
                },
            )
            .await
            .expect("must always be able to persist the DKG outcome");

        // Prune older ceremony.
        if let Some(epoch) = current_epoch.checked_sub(1) {
            let mut ceremony_metadata = self.ceremony_metadata.lock().await;
            ceremony_metadata.remove(&epoch.into());
            ceremony_metadata.sync().await.expect("metadata must sync");
        }
    }

    #[instrument(skip_all)]
    pub(super) async fn transition_from_static_validator_sets<TReceiver, TSender>(
        &mut self,
        pre_allegretto_epoch_state: pre_allegretto::EpochState,
        mux: &mut MuxHandle<TSender, TReceiver>,
    ) -> eyre::Result<Ceremony<ContextCell<TContext>, TReceiver, TSender>>
    where
        TReceiver: Receiver<PublicKey = PublicKey>,
        TSender: Sender<PublicKey = PublicKey>,
    {
        let pre_allegretto_validator_state = self
            .validators_metadata
            .get(&pre_allegretto_epoch_state.epoch().saturating_sub(1).into())
            .cloned()
            .expect("it is enforced at startup that the validator state for epoch-1 is written");

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
            self.current_epoch_state().participants(),
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

        self.post_allegretto_metadatas
            .epoch_metadata
            .put_sync(
                CURRENT_EPOCH_KEY,
                EpochState {
                    dkg_outcome: DkgOutcome {
                        dkg_successful: true,
                        epoch: pre_allegretto_epoch_state.epoch(),
                        participants: pre_allegretto_epoch_state.participants().clone(),
                        public: pre_allegretto_epoch_state.public_polynomial().clone(),
                        share: pre_allegretto_epoch_state.private_share().clone(),
                    },
                    validator_state: new_validator_state.clone(),
                },
            )
            .await
            .expect("syncing state must always work");
        self.register_current_epoch_state().await;

        Ok(self.start_post_allegretto_ceremony(mux).await)
    }

    #[instrument(skip_all, fields(epoch = self.post_allegretto_metadatas.current_epoch_state().unwrap().epoch()))]
    pub(super) async fn start_post_allegretto_ceremony<TReceiver, TSender>(
        &mut self,
        mux: &mut MuxHandle<TSender, TReceiver>,
    ) -> Ceremony<ContextCell<TContext>, TReceiver, TSender>
    where
        TReceiver: Receiver<PublicKey = PublicKey>,
        TSender: Sender<PublicKey = PublicKey>,
    {
        let epoch_state = self.post_allegretto_metadatas.current_epoch_state().expect(
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
    async fn update_and_register_current_epoch_state(&mut self) {
        let old_epoch_state = self
            .post_allegretto_metadatas
            .epoch_metadata
            .remove(&CURRENT_EPOCH_KEY)
            .expect("there must always exist an epoch state");

        // Remove it?
        let dkg_outcome = self
            .post_allegretto_metadatas
            .dkg_outcome_metadata
            .get(&DKG_OUTCOME_KEY)
            .cloned()
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

        self.post_allegretto_metadatas.epoch_metadata.put(
            CURRENT_EPOCH_KEY,
            EpochState {
                dkg_outcome,
                validator_state: new_validator_state.clone(),
            },
        );
        self.post_allegretto_metadatas
            .epoch_metadata
            .put(PREVIOUS_EPOCH_KEY, old_epoch_state);

        self.post_allegretto_metadatas
            .epoch_metadata
            .sync()
            .await
            .expect("must always be able to persists epoch state");

        self.register_current_epoch_state().await;
    }

    /// Reports that a new epoch was fully entered, that the previous epoch can be ended.
    async fn enter_current_epoch_and_remove_old_state(&mut self) {
        let epoch_to_shutdown = if let Some(old_epoch_state) = self
            .post_allegretto_metadatas
            .epoch_metadata
            .remove(&PREVIOUS_EPOCH_KEY)
        {
            self.post_allegretto_metadatas
                .epoch_metadata
                .sync()
                .await
                .expect("must always be able to persist state");
            Some(old_epoch_state.epoch())
        } else {
            self.pre_allegretto_metadatas
                .delete_previous_epoch_state()
                .await
                .map(|old_state| old_state.epoch())
        };

        if let Some(epoch) = epoch_to_shutdown {
            self.config
                .epoch_manager
                .report(epoch::Exit { epoch }.into())
                .await;
        }

        if let Some(epoch) = epoch_to_shutdown.and_then(|epoch| epoch.checked_sub(2)) {
            self.validators_metadata.remove(&epoch.into());
            self.validators_metadata
                .sync()
                .await
                .expect("must always be able to persist data");
        }
    }
}

pub(super) struct Metadatas<TContext>
where
    TContext: Clock + Metrics + Storage,
{
    /// Persisted information on the current epoch for DKG ceremonies that were
    /// started after the allegretto hardfork.
    epoch_metadata: Metadata<TContext, U64, EpochState>,

    /// The persisted DKG outcome. This is the result of latest DKG ceremony,
    /// constructed one height before the boundary height b (on b-1).
    dkg_outcome_metadata: Metadata<TContext, U64, DkgOutcome>,
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
                partition: format!("{partition_prefix}_post_allegretto_current_epoch"),
                codec_config: (),
            },
        )
        .await
        .expect("must be able to initialize metadata on disk to function");

        let dkg_outcome_metadata = Metadata::init(
            context.with_label("dkg_outcome_metadata"),
            commonware_storage::metadata::Config {
                partition: format!("{partition_prefix}_next_dkg_outcome"),
                codec_config: (),
            },
        )
        .await
        .expect("must be able to initialize metadata on disk to function");

        Self {
            epoch_metadata,
            dkg_outcome_metadata,
        }
    }

    pub(super) fn current_epoch_state(&self) -> Option<&EpochState> {
        self.epoch_metadata.get(&CURRENT_EPOCH_KEY)
    }

    pub(super) fn previous_epoch_state(&self) -> Option<&EpochState> {
        self.epoch_metadata.get(&PREVIOUS_EPOCH_KEY)
    }

    pub(super) fn dkg_outcome(&self) -> Option<PublicOutcome> {
        if let Some(dkg_outcome) = self.dkg_outcome_metadata.get(&DKG_OUTCOME_KEY) {
            Some(PublicOutcome {
                epoch: dkg_outcome.epoch,
                participants: dkg_outcome.participants.clone(),
                public: dkg_outcome.public.clone(),
            })
        } else {
            self.epoch_metadata
                .get(&CURRENT_EPOCH_KEY)
                .map(|epoch_state| PublicOutcome {
                    epoch: epoch_state.dkg_outcome.epoch,
                    participants: epoch_state.dkg_outcome.participants.clone(),
                    public: epoch_state.dkg_outcome.public.clone(),
                })
        }
    }

    pub(super) fn exists(&self) -> bool {
        self.current_epoch_state().is_some()
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
pub(super) struct EpochState {
    pub(super) dkg_outcome: DkgOutcome,
    pub(super) validator_state: ValidatorState,
}

impl EpochState {
    pub(super) fn epoch(&self) -> Epoch {
        self.dkg_outcome.epoch
    }

    pub(super) fn participants(&self) -> &Ordered<PublicKey> {
        &self.dkg_outcome.participants
    }

    pub(super) fn public_polynomial(&self) -> &Public<MinSig> {
        &self.dkg_outcome.public
    }

    pub(super) fn private_share(&self) -> &Option<Share> {
        &self.dkg_outcome.share
    }

    pub(super) fn dealer_pubkeys(&self) -> Ordered<PublicKey> {
        self.validator_state.dealer_pubkeys()
    }

    pub(super) fn player_pubkeys(&self) -> Ordered<PublicKey> {
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
