use std::net::SocketAddr;

use alloy_consensus::BlockHeader as _;
use commonware_codec::{DecodeExt as _, EncodeSize, Read, Write};
use commonware_consensus::{
    Block as _, Reporter as _,
    simplex::signing_scheme::bls12381_threshold::Scheme,
    types::{Epoch, EpochDelta},
    utils,
};
use commonware_cryptography::{
    bls12381::primitives::{group::Share, poly::Public, variant::MinSig},
    ed25519::PublicKey,
};
use commonware_p2p::{Receiver, Sender, utils::mux::MuxHandle};
use commonware_runtime::{Clock, ContextCell, Spawner, Storage};
use commonware_utils::set::{Ordered, OrderedAssociated};
use eyre::{OptionExt as _, WrapErr as _, ensure};
use rand_core::CryptoRngCore;
use reth_ethereum::chainspec::EthChainSpec as _;
use reth_primitives_traits::Block as _;
use tempo_dkg_onchain_artifacts::PublicOutcome;
use tracing::{Span, field::display, info, instrument, warn};

use crate::{
    consensus::block::Block,
    dkg::{
        HardforkRegime, RegimeEpochState,
        ceremony::{self, Ceremony, PrivateOutcome},
        manager::{
            actor::{DkgOutcome, pre_allegretto},
            read_write_transaction::DkgReadWriteTransaction,
            validators::{self, ValidatorState},
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
    #[instrument(skip_all, err)]
    pub(super) async fn post_allegretto_init(
        &mut self,
        tx: &mut DkgReadWriteTransaction<ContextCell<TContext>>,
    ) -> eyre::Result<()> {
        let spec = self.config.execution_node.chain_spec();
        let init_source: Option<PublicOutcome> = if tx.has_post_allegretto_state().await {
            if self.config.sync_floor {
                warn!("sync_floor passed but ignored; only takes effect on fresh datadirs");
            }
            None
        } else if self.config.sync_floor {
            let outcome = read_sync_floor_block(&self.config.execution_node.provider)?;
            info!("initializing from sync floor block");
            Some(outcome)
        } else {
            info!("initializing from genesis block");
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
                initial_dkg_outcome.epoch == Epoch::zero(),
                "at genesis, the epoch must be zero, but genesis reported `{}`",
                initial_dkg_outcome.epoch,
            );
            Some(initial_dkg_outcome)
        };

        if let Some(initial_dkg_outcome) = init_source {
            let expected_epoch = initial_dkg_outcome.epoch;

            let our_share = self.config.initial_share.clone();
            if let Some(our_share) = our_share.clone() {
                // XXX: explicitly check the signing key matches the public
                // polynomial. If it does not, commonware silently demotes the
                // node to a verifier.
                //
                // FIXME: replace this once commonware provides logic to not
                // degrade the node silently.
                let signer_or_verifier = Scheme::<_, MinSig>::new(
                    initial_dkg_outcome.participants.clone(),
                    &initial_dkg_outcome.public,
                    our_share,
                );
                ensure!(
                    matches!(signer_or_verifier, Scheme::Signer { .. },),
                    "incorrect signing share provided: the node would not be a \
                    signer in the ceremony"
                );
            }

            let initial_validators = validators::read_from_contract(
                0,
                &self.config.execution_node,
                expected_epoch,
                self.config.epoch_length,
            )
            .await
            .wrap_err("validator config could not be read from genesis block validator config smart contract")?;

            // ensure that the peer set written into the smart contract matches
            // the participants as determined by the initial DKG outcome.
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
                "using public polynomial and validators read from contract",
            );

            tx.set_epoch(EpochState {
                dkg_outcome: DkgOutcome {
                    dkg_successful: true,
                    epoch: expected_epoch,
                    participants: initial_dkg_outcome.participants,
                    public: initial_dkg_outcome.public,
                    share: self.config.initial_share.clone(),
                },
                validator_state: initial_validator_state,
            });
        }

        if self.config.delete_signing_share
            && let Some(mut epoch_state) = tx.get_epoch::<EpochState>().await?
        {
            warn!("delete-signing-share set; deleting signing share");
            epoch_state.dkg_outcome.share.take();
            tx.set_epoch(epoch_state);
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
            block.derived_epoch = %utils::epoch(self.config.epoch_length, block.height()),
            block.height = block.height(),
            ceremony.epoch = %ceremony.epoch(),
        ),
    )]
    pub(super) async fn handle_finalized_post_allegretto<TReceiver, TSender>(
        &mut self,
        cause: Span,
        block: &Block,
        ceremony: &mut Ceremony<TReceiver, TSender>,
        ceremony_mux: &mut MuxHandle<TSender, TReceiver>,
        tx: &mut DkgReadWriteTransaction<ContextCell<TContext>>,
    ) where
        TReceiver: Receiver<PublicKey = PublicKey>,
        TSender: Sender<PublicKey = PublicKey>,
    {
        let block_epoch = utils::epoch(self.config.epoch_length, block.height());

        let current_epoch_state: EpochState = tx
            .get_epoch()
            .await
            .expect("must be able to read epoch")
            .expect("post-allegretto epoch state must exist");

        // Replay protection: if the node shuts down right after the last block
        // of the outgoing epoch was processed, but before the first block of
        // the incoming epoch was processed, then we do not want to update the
        // epoch state again.
        //
        // This relies on the fact that the actor updates its tracked epoch
        // state on the last block of the epoch.
        if block_epoch != current_epoch_state.epoch() {
            info!(
                block_epoch = %block_epoch,
                actor_epoch = %current_epoch_state.epoch(),
                "block was for an epoch other than what the actor is currently tracking; ignoring",
            );
            return;
        }

        // Special case --- boundary block: finalize the ceremony based on the
        // parent block.
        //
        // Recall, for some epoch length E, the boundary heights are
        // 1E-1, 2E-1, 3E-1, ... for epochs 0, 1, 2.
        //
        // So for E = 100, the boundary heights would be 99, 199, 299, ...
        if let Some(block_epoch) =
            utils::is_last_block_in_epoch(self.config.epoch_length, block.height())
        {
            info!("reached end of epoch - reporting new epoch and starting ceremony");
            let block_outcome = PublicOutcome::decode(block.header().extra_data().as_ref()).expect(
                "the last block of an epoch must always contain the outcome of the DKG ceremony",
            );

            // Finalizations happen in strictly sequential order. This means we
            // are guaranteed to have observed the parent.
            let our_outcome = ceremony.finalize(block.parent_digest()).expect(
                "finalizing the ceremony on the boundary using the block's \
                    parent must work - we have observed all finalized blocks up \
                    until here, so we must have observed its parent, too",
            );

            self.update_and_register_current_epoch_state(tx, our_outcome, block_outcome)
                .await;

            // Check if we're shutting down at this epoch boundary
            if self.config.exit.args.exit_after_epoch.map(Epoch::new) == Some(block_epoch) {
                // Stop the consensus engine we just started to prevent it from running
                self.config
                    .epoch_manager
                    .report(
                        epoch::Exit {
                            epoch: block_epoch.next(),
                        }
                        .into(),
                    )
                    .await;
            }
            *ceremony = self.start_post_allegretto_ceremony(tx, ceremony_mux).await;

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
            if let Some(epoch) = current_epoch_state.epoch().checked_sub(EpochDelta::new(3)) {
                tx.remove_validators(epoch);
            }
        }

        match epoch::relative_position(block.height(), self.config.epoch_length) {
            epoch::RelativePosition::FirstHalf => {
                let _ = ceremony.distribute_shares(tx).await;
                let _ = ceremony.process_messages(tx).await;
            }
            epoch::RelativePosition::Middle => {
                let _ = ceremony.process_messages(tx).await;
                let _ = ceremony
                    .construct_intermediate_outcome(tx, HardforkRegime::PostAllegretto)
                    .await;
            }
            epoch::RelativePosition::SecondHalf => {
                // Nothing special happens in the second half of the epoch.
                // Should we use these extra blocks to process more messages?
            }
        }
    }

    #[instrument(skip_all)]
    pub(super) async fn transition_from_static_validator_sets<TReceiver, TSender>(
        &mut self,
        tx: &mut DkgReadWriteTransaction<ContextCell<TContext>>,
        pre_allegretto_epoch_state: pre_allegretto::EpochState,
        mux: &mut MuxHandle<TSender, TReceiver>,
    ) -> eyre::Result<Ceremony<TReceiver, TSender>>
    where
        TReceiver: Receiver<PublicKey = PublicKey>,
        TSender: Sender<PublicKey = PublicKey>,
    {
        let pre_allegretto_validator_state = tx
            .get_validators(
                pre_allegretto_epoch_state
                    .epoch()
                    .saturating_sub(EpochDelta::new(1)),
            )
            .await
            .expect("must be able to read validators")
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

        tx.set_epoch(new_epoch_state);

        self.register_current_epoch_state(tx).await;

        Ok(self.start_post_allegretto_ceremony(tx, mux).await)
    }

    #[instrument(skip_all, fields(epoch = tracing::field::Empty))]
    pub(super) async fn start_post_allegretto_ceremony<TReceiver, TSender>(
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
            .expect(
                "the post-allegretto epoch state must exist in order to start a ceremony for it",
            );
        Span::current().record("epoch", display(&epoch_state.epoch()));

        let config = ceremony::Config {
            namespace: self.config.namespace.clone(),
            me: self.config.me.clone(),
            public: epoch_state.public_polynomial().clone(),
            share: epoch_state.private_share().clone(),
            epoch: epoch_state.epoch(),
            epoch_length: self.config.epoch_length,
            dealers: epoch_state.dealer_pubkeys(),
            players: epoch_state.player_pubkeys(),
            hardfork_regime: HardforkRegime::PostAllegretto,
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
        tx: &mut DkgReadWriteTransaction<ContextCell<TContext>>,
        our_dkg_outcome: Result<PrivateOutcome, PrivateOutcome>,
        canonical_dkg_outcome: PublicOutcome,
    ) {
        let old_epoch_state: EpochState = tx
            .get_epoch()
            .await
            .expect("must be able to read epoch")
            .expect("there must always exist an epoch state");

        let new_epoch = our_dkg_outcome
            .as_ref()
            .map_or_else(|e| e.epoch, |o| o.epoch);

        assert_eq!(
            old_epoch_state.epoch().next(),
            new_epoch,
            "sanity check: old outcome must be new outcome - 1"
        );

        let mut dkg_outcome = match our_dkg_outcome {
            Ok(outcome) => {
                self.metrics.ceremony.one_more_success();
                info!(
                    "ceremony was successful; using the new participants, polynomial and secret key"
                );
                let (public, share) = outcome.role.into_key_pair();
                DkgOutcome {
                    dkg_successful: true,
                    epoch: new_epoch,
                    participants: outcome.participants,
                    public,
                    share,
                }
            }
            Err(outcome) => {
                self.metrics.ceremony.one_more_failure();
                warn!(
                    "ceremony was a failure; using the old participants, polynomial and secret key"
                );
                let (public, share) = outcome.role.into_key_pair();
                DkgOutcome {
                    dkg_successful: false,
                    epoch: new_epoch,
                    participants: outcome.participants,
                    public,
                    share,
                }
            }
        };

        let dkg_mismatch = canonical_dkg_outcome.public != dkg_outcome.public;
        if dkg_mismatch {
            warn!(
                "the DKG outcome committed to chain does not match our own; \
                will take the on-chain outcome instead and delete our share"
            );
            // At this point we cannot know if the public outcome was successful
            // or not so we don't change the our_dkg_outcome.dkg_successful.
            //
            // FIXME(janis): it is critical that the next set of validators and
            // players get pushed into the DKG outcome so that the we get
            // global agreement on these values.
            dkg_outcome.public = canonical_dkg_outcome.public;
            dkg_outcome.participants = canonical_dkg_outcome.participants;
            dkg_outcome.share.take();
        }

        let syncing_players = super::read_validator_config_with_retry(
            &self.context,
            &self.config.execution_node,
            new_epoch,
            self.config.epoch_length,
        )
        .await;
        let mut new_validator_state = old_epoch_state.validator_state.clone();
        match (dkg_outcome.dkg_successful, dkg_mismatch) {
            // No DKG mismatches
            (true, false) => {
                new_validator_state.push_on_success(syncing_players);
            }
            (false, false) => {
                new_validator_state.push_on_failure(syncing_players);
            }

            // DKG mismatches
            (false, true) => {
                new_validator_state.push_on_success(syncing_players);
            }

            // TODO(janis): publish the IP addresses and pubkeys to chain. Then
            // we can recover from this.
            (true, true) => {
                unreachable!(
                    "a local DKG success with an on-chain mismatch means that \
                    the node successfully read all necessary dealings from \
                    chain while a quorum of validators came to a different \
                    conclusion based off the same data; this is not something \
                    to recover from"
                );
            }
        }

        let new_epoch_state = EpochState {
            dkg_outcome,
            validator_state: new_validator_state.clone(),
        };

        tx.set_previous_epoch(old_epoch_state);

        tx.set_epoch(new_epoch_state.clone());

        self.register_current_epoch_state(tx).await;
    }

    /// Reports that a new epoch was fully entered, that the previous epoch can be ended.
    async fn enter_current_epoch_and_remove_old_state(
        &mut self,
        tx: &mut DkgReadWriteTransaction<ContextCell<TContext>>,
    ) {
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

        if let Some(epoch) =
            epoch_to_shutdown.and_then(|epoch| epoch.checked_sub(EpochDelta::new(2)))
        {
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
pub(crate) struct EpochState {
    pub(crate) dkg_outcome: DkgOutcome,
    pub(crate) validator_state: ValidatorState,
}

impl EpochState {
    pub(crate) fn epoch(&self) -> Epoch {
        self.dkg_outcome.epoch
    }

    pub(crate) fn participants(&self) -> &Ordered<PublicKey> {
        &self.dkg_outcome.participants
    }

    pub(crate) fn public_polynomial(&self) -> &Public<MinSig> {
        &self.dkg_outcome.public
    }

    pub(crate) fn private_share(&self) -> &Option<Share> {
        &self.dkg_outcome.share
    }

    pub(crate) fn dealer_pubkeys(&self) -> Ordered<PublicKey> {
        self.validator_state.dealer_pubkeys()
    }

    pub(crate) fn player_pubkeys(&self) -> Ordered<PublicKey> {
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

/// Reads the sync floor block from the execution provider and decodes its PublicOutcome.
fn read_sync_floor_block<P>(provider: &P) -> eyre::Result<PublicOutcome>
where
    P: reth_provider::BlockNumReader + reth_provider::BlockReader,
{
    let h = provider
        .best_block_number()
        .wrap_err("sync_floor: failed to get best block number")?;

    let block = provider
        .block_by_number(h)
        .wrap_err_with(|| format!("sync_floor: failed to fetch block {h}"))?
        .ok_or_eyre(format!("sync_floor: block {h} not found"))?;

    let extra_data = block.header().extra_data();

    PublicOutcome::decode(extra_data.as_ref()).wrap_err_with(|| {
        format!(
            "sync_floor: failed decoding extra_data as PublicOutcome at height {h}; bytes = {}",
            extra_data.len()
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::bytes;
    use commonware_cryptography::{
        bls12381::primitives::{group::G2, poly::Poly},
        ed25519::PublicKey,
    };
    use reth_ethereum_primitives::Block;
    use reth_provider::test_utils::MockEthProvider;

    #[test]
    fn read_sync_floor_block_backwards_compatibility() {
        // Hardcoded PublicOutcome - if encoding format changes, this test fails
        // Generated with: epoch=1, 1 participant (seed=42), threshold=1 polynomial
        let extra_data = bytes!(
            "0101" // epoch=1, participants_len=1
            "78eda21ba04a15e2000fe8810fe3e56741d23bb9ae44aa9d5bb21b76675ff34b" // ed25519 pubkey
            "8fbe20bb785531d9fb0f680dd96ecfb3eabccc4c7e672c4caf4a72e7207467081f743b469dbf18ef426770c94d7c63cc0014344e918045ac36b96b7983a69bf968bee7941d6bb895f206117b17e128dc82fa1b1e28db416c6d48b0bf977e9ae8" // bls poly
        );

        let provider = MockEthProvider::default();

        let mut block = Block::default();
        block.header.extra_data = extra_data;
        provider.add_block(block.hash_slow(), block);

        let result = read_sync_floor_block(&provider);
        assert!(
            result.is_ok(),
            "should decode valid PublicOutcome: {:?}",
            result.err()
        );

        let outcome = result.unwrap();
        assert_eq!(outcome.epoch, Epoch::new(1));
        assert_eq!(outcome.participants.len(), 1);

        // Assert ed25519 pubkey
        let expected_pubkey = PublicKey::decode(
            &bytes!("78eda21ba04a15e2000fe8810fe3e56741d23bb9ae44aa9d5bb21b76675ff34b")[..],
        )
        .unwrap();
        assert_eq!(outcome.participants[0], expected_pubkey);

        // Assert BLS polynomial (threshold=1, so 1 G2 coefficient)
        let g2 = G2::decode(
            &bytes!("8fbe20bb785531d9fb0f680dd96ecfb3eabccc4c7e672c4caf4a72e7207467081f743b469dbf18ef426770c94d7c63cc0014344e918045ac36b96b7983a69bf968bee7941d6bb895f206117b17e128dc82fa1b1e28db416c6d48b0bf977e9ae8")[..],
        )
        .unwrap();
        let expected_poly: Poly<G2> = Poly::from(vec![g2]);
        assert_eq!(outcome.public, expected_poly);
    }
}
