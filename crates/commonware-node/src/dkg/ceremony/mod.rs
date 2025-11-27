//! An actively running DKG ceremony.

use std::{collections::BTreeMap, sync::Arc};

use alloy_consensus::BlockHeader as _;
use commonware_codec::{Decode as _, Encode as _};
use commonware_consensus::{Block as _, types::Epoch};
use commonware_cryptography::{
    Signer as _,
    bls12381::{
        dkg::{self, Arbiter, Player, arbiter},
        primitives::{group, poly::Public, variant::MinSig},
    },
    ed25519::{PrivateKey, PublicKey},
};
use commonware_p2p::{
    Receiver, Recipients, Sender,
    utils::mux::{MuxHandle, SubReceiver, SubSender},
};
use commonware_runtime::{Clock, Storage};
use commonware_storage::metadata::Metadata;
use commonware_utils::{max_faults, sequence::U64, set::Ordered, union};
use eyre::{WrapErr as _, bail, ensure};
use futures::{FutureExt as _, lock::Mutex};
use indexmap::IndexSet;
use prometheus_client::metrics::gauge::Gauge;
use rand_core::CryptoRngCore;
use tracing::{Level, debug, error, info, instrument, warn};

use tempo_dkg_onchain_artifacts::{Ack, IntermediateOutcome};

use crate::{consensus::block::Block, dkg::HardforkRegime};

mod payload;
mod persisted;

pub(super) use persisted::State;

use payload::{Message, Payload, Share};
use persisted::Dealing;

const ACK_NAMESPACE: &[u8] = b"_DKG_ACK";
const OUTCOME_NAMESPACE: &[u8] = b"_DKG_OUTCOME";

/// Recovering public weights is a heavy operation. For simplicity, we use just
/// 1 thread for now.
const WEIGHT_RECOVERY_CONCURRENCY: usize = 1;

pub(super) struct Config {
    /// Prefix all signed messages to prevent replay attacks.
    pub(super) namespace: Vec<u8>,

    pub(super) me: PrivateKey,

    /// The previous public polynomial.
    pub(super) public: Public<MinSig>,

    /// Our previous share of the private polynomial. This dictates if we
    /// become a dealer in the new round: no share -> not a dealer.
    pub(super) share: Option<group::Share>,

    /// The current epoch.
    pub(super) epoch: Epoch,

    /// The dealers in the round.
    pub(super) dealers: Ordered<PublicKey>,

    /// The players in the round.
    pub(super) players: Ordered<PublicKey>,
}

#[derive(Clone)]
pub(super) struct Metrics {
    pub(super) shares_distributed: Gauge,
    pub(super) acks_received: Gauge,
    pub(super) acks_sent: Gauge,
    pub(super) dealings_read: Gauge,
    pub(super) dealings_empty: Gauge,
    pub(super) dealings_failed: Gauge,
}

pub(super) struct Ceremony<TContext, TReceiver, TSender>
where
    TContext: Clock + commonware_runtime::Metrics + Storage,
    TReceiver: Receiver,
    TSender: Sender,
{
    config: Config,

    /// The previous role of this node in the network. This contains either
    /// the polynomial (if the node was just a verifier), or the polynomial
    /// and share of the private key if the node was a signer.
    previous_role: Role,

    /// [Dealer] metadata, if this manager is also dealing.
    dealer_me: Option<Dealer>,

    /// The local [Player] for this round, if the manager is playing.
    //
    // NOTE: right now we should always be playing.
    player_me: Option<Player<PublicKey, MinSig>>,

    /// The indexed set of all players. Whereas config.players is a sorted
    /// list of unique playes, players_indexed is an actual set data structure
    /// that allows O(1) lookup of both keys and indices.
    ///
    /// It is an invariant that `players_indexed.get_index_of(players[i]) == i`.
    players_indexed: IndexSet<PublicKey>,

    /// The local [Arbiter] for this round.
    arbiter: Arbiter<PublicKey, MinSig>,

    ceremony_metadata: Arc<Mutex<Metadata<TContext, U64, State>>>,
    receiver: SubReceiver<TReceiver>,
    sender: SubSender<TSender>,
    metrics: Metrics,
}

impl<TContext, TReceiver, TSender> Ceremony<TContext, TReceiver, TSender>
where
    TContext: Clock + CryptoRngCore + commonware_runtime::Metrics + Storage,
    TReceiver: Receiver<PublicKey = PublicKey>,
    TSender: Sender<PublicKey = PublicKey>,
{
    /// Initialize a DKG ceremony.
    #[instrument(skip_all, fields(for_epoch = config.epoch), err)]
    pub(super) async fn init(
        context: &mut TContext,
        mux: &mut MuxHandle<TSender, TReceiver>,
        ceremony_metadata: Arc<Mutex<Metadata<TContext, U64, State>>>,
        config: Config,
        metrics: Metrics,
    ) -> eyre::Result<Self> {
        let (sender, receiver) = mux
            .register(config.epoch)
            .await
            .wrap_err("mux subchannel already running for epoch; this is a problem")?;

        let players_indexed: IndexSet<_> = config.players.iter().cloned().collect();
        let mut player_me = players_indexed.get(&config.me.public_key()).map(|_| {
            Player::new(
                config.me.public_key(),
                Some(config.public.clone()),
                config.dealers.clone(),
                config.players.clone(),
                WEIGHT_RECOVERY_CONCURRENCY,
            )
        });

        let mut arbiter = Arbiter::new(
            Some(config.public.clone()),
            config.dealers.clone(),
            config.players.clone(),
            WEIGHT_RECOVERY_CONCURRENCY,
        );

        let mut dealer_me = None;

        debug!("attempting to read ceremony state from disk");
        // TODO(janis): move this "recovery" logic to a function.
        // Clone in order to not hold onto the lock too long.
        let recovered = ceremony_metadata
            .lock()
            .await
            .get(&config.epoch.into())
            .cloned();

        if let Some(recovered) = recovered {
            info!("found a previous ceremony state written to disk; recovering it");
            for outcome in &recovered.outcomes {
                let ack_indices = outcome
                    .acks()
                    .iter()
                    .filter_map(|ack| {
                        let idx = players_indexed.get_index_of(ack.player());
                        if idx.is_none() {
                            warn!(
                                player = %ack.player(),
                                "ack for player recovered from disk not among players of this ceremony",
                            );
                        }
                        idx.map(|idx| idx as u32)
                    })
                    .collect::<Vec<_>>();

                if let Err(error) = arbiter
                    .commitment(
                        outcome.dealer().clone(),
                        outcome.commitment().clone(),
                        ack_indices,
                        outcome.reveals().to_vec(),
                    )
                    .wrap_err("failed to verify and track commitment")
                {
                    warn!(
                        %error,
                        "failed to update arbiter with metadata recovered from disk",
                    );
                }
            }

            if let Some(me) = &mut player_me {
                for (dealer, commitment, share) in recovered.received_shares.clone() {
                    me.share(dealer, commitment, share)
                        .wrap_err("failed updating my player information with stored metadata")?;
                }
            }

            if let Some(dealing) = recovered.dealing.clone() {
                let (mut dkg_dealer, _, _) = dkg::Dealer::<PublicKey, MinSig>::new(
                    context,
                    config.share.clone(),
                    config.players.clone(),
                );
                for ack in dealing.acks.values() {
                    dkg_dealer.ack(ack.player().clone()).wrap_err_with(|| {
                        format!(
                            "failed updating dealer information with ack for \
                             player `{player}` recovered from disk",
                            player = ack.player(),
                        )
                    })?;
                }
                dealer_me = Some(Dealer {
                    commitment: dealing.commitment,
                    shares: dealing.shares,
                    acks: dealing.acks,
                    outcome: recovered.dealing_outcome,
                });
            }
        } else {
            info!("starting a fresh ceremony");

            if let Some(share) = config.share.clone() {
                info!("we have a share, so we are a dealer in this ceremony");
                let (_, commitment, shares) = dkg::Dealer::<PublicKey, MinSig>::new(
                    context,
                    Some(share),
                    config.players.clone(),
                );
                let shares = config
                    .players
                    .iter()
                    .zip(&shares)
                    .map(|(player, share)| (player.clone(), share.clone()))
                    .collect();
                dealer_me = Some(Dealer {
                    commitment,
                    shares,
                    acks: BTreeMap::new(),
                    outcome: None,
                });
            }

            ceremony_metadata
                .lock()
                .await
                .put_sync(
                    config.epoch.into(),
                    State {
                        num_players: config
                            .players
                            .len()
                            .try_into()
                            .expect("there should never be more than u16::MAX players"),
                        dealing: dealer_me.as_ref().map(|me| Dealing {
                            commitment: me.commitment.clone(),
                            shares: me.shares.clone(),
                            acks: BTreeMap::new(),
                        }),
                        ..State::default()
                    },
                )
                .await
                .expect("must always be able to initialize the ceremony state to disk");
        };

        let previous = config.share.clone().map_or_else(
            || Role::Verifier {
                public: config.public.clone(),
            },
            |share| Role::Signer {
                public: config.public.clone(),
                share,
            },
        );
        Ok(Self {
            config,
            previous_role: previous,
            dealer_me,
            player_me,
            players_indexed,
            arbiter,
            ceremony_metadata,
            receiver,
            sender,
            metrics,
        })
    }

    /// Sends shares to all players for acknowledgements.
    ///
    /// Does not send shares if we are not a dealer in this ceremony.
    ///
    /// If we are both a dealer and a player, then we acknowledge our shares
    /// immediately without going over the p2p network.
    #[instrument(skip_all, fields(epoch = self.config.epoch), err)]
    pub(super) async fn distribute_shares(&mut self) -> eyre::Result<()> {
        let Some(dealer_me) = &mut self.dealer_me else {
            debug!("not a dealer, not distributing shares");
            return Ok(());
        };
        for player in &self.config.players {
            if dealer_me.acks.contains_key(player) {
                continue;
            }

            let share = dealer_me
                .shares
                .get(player)
                .cloned()
                .expect("invariant violated: all players must have an entry in the shares map");

            if let Some(player_me) = &mut self.player_me
                && player == &self.config.me.public_key()
            {
                player_me
                    .share(
                        self.config.me.public_key(),
                        dealer_me.commitment.clone(),
                        share.clone(),
                    )
                    .expect(
                        "must work: updating player with own dealer \
                        commitment",
                    );

                // TODO(janis): easy to mess up the fields because some of them
                // are of the same type. Better pass in a struct or create a
                // builder.
                let ack = Ack::new(
                    &union(&self.config.namespace, ACK_NAMESPACE),
                    self.config.me.clone(),
                    self.config.me.public_key(),
                    self.config.epoch,
                    &self.config.me.public_key(),
                    &dealer_me.commitment,
                );
                assert_eq!(
                    None,
                    dealer_me
                        .acks
                        .insert(self.config.me.public_key(), ack.clone()),
                    "must only insert our own ack once",
                );

                self.ceremony_metadata
                    .lock()
                    .await
                    .upsert_sync(self.config.epoch.into(), |info| {
                        if let Some(dealing) = &mut info.dealing {
                            dealing.acks.insert(self.config.me.public_key(), ack);
                        } else {
                            info.dealing = Some(Dealing {
                                commitment: dealer_me.commitment.clone(),
                                shares: dealer_me.shares.clone(),
                                acks: BTreeMap::from([(self.config.me.public_key(), ack)]),
                            });
                        }
                        info.received_shares.push((
                            self.config.me.public_key(),
                            dealer_me.commitment.clone(),
                            share,
                        ));
                    })
                    .await
                    .expect("must be able to persists acks");
                // When self-distributing, we also "receive" the share and "send" an ack to ourselves
                self.metrics.shares_distributed.inc();
                self.metrics.acks_received.inc();
                self.metrics.acks_sent.inc();
                continue;
            }

            let payload = Share {
                commitment: dealer_me.commitment.clone(),
                share,
            }
            .into();
            let success = self
                .sender
                .send(
                    Recipients::One(player.clone()),
                    Message {
                        epoch: self.config.epoch,
                        payload,
                    }
                    .encode()
                    .freeze(),
                    true,
                )
                .await
                .wrap_err("unable to forward share to p2p network")?;

            if success.is_empty() {
                warn!(%player, "failed to send share to player");
            } else {
                info!(%player, "sent share to player");
                self.metrics.shares_distributed.inc();
            }
        }
        Ok(())
    }

    /// Processes all received shares and acks on the ceremony's p2p subchannel.
    ///
    /// If we receive a share and are a player: construct an ack and return it
    /// to the sender.
    ///
    /// If we receive an ack and are a dealer: track the ack.
    #[instrument(skip_all, fields(epoch = self.epoch()), err)]
    pub(super) async fn process_messages(&mut self) -> eyre::Result<()> {
        while let Some(msg) = self.receiver.recv().now_or_never() {
            let (peer, mut msg) = msg.wrap_err("receiver p2p channel was closed")?;

            debug!(%peer, "received message from");
            let msg = Message::decode_cfg(&mut msg, &(self.config.players.len() as u32))
                .wrap_err("unable to decode message")?;
            if msg.epoch != self.epoch() {
                warn!(
                    ceremony.epoch = self.epoch(),
                    msg.epoch = msg.epoch,
                    "ignoring message for different round"
                );
                continue;
            }

            match msg.payload {
                Payload::Ack(ack) => {
                    let _: Result<_, _> = self.process_ack(peer, *ack).await;
                }
                Payload::Share(share) => {
                    let _: Result<_, _> = self.process_share(peer, share).await;
                }
            }
        }

        Ok(())
    }

    #[instrument(
        skip_all,
        fields(
            epoch = %self.epoch(),
            %peer,
            player = %ack.player(),
        ),
        err(level = Level::WARN),
        ret,
    )]
    async fn process_ack(&mut self, peer: PublicKey, ack: Ack) -> eyre::Result<&'static str> {
        let Some(dealer_me) = &mut self.dealer_me else {
            return Ok("not a dealer, dropping ack");
        };

        ensure!(
            ack.player() == &peer,
            "player recorded in ack does not match peer that sent it; dropping ack",
        );

        ensure!(
            self.players_indexed.contains(&peer),
            "peer not among players for this ceremony; dropping ack",
        );

        ensure!(
            ack.verify(
                &union(&self.config.namespace, ACK_NAMESPACE),
                &peer,
                self.config.epoch,
                &self.config.me.public_key(),
                &dealer_me.commitment,
            ),
            "failed verifying ack signature against peer",
        );

        if let std::collections::btree_map::Entry::Vacant(vacant) =
            dealer_me.acks.entry(peer.clone())
        {
            vacant.insert(ack.clone());
        } else {
            bail!("duplicate ack for peer");
        }

        self.ceremony_metadata
            .lock()
            .await
            .upsert_sync(self.config.epoch.into(), |info| {
                if let Some(dealing) = &mut info.dealing {
                    dealing.acks.insert(peer.clone(), ack);
                } else {
                    info.dealing = Some(Dealing {
                        commitment: dealer_me.commitment.clone(),
                        shares: dealer_me.shares.clone(),
                        acks: BTreeMap::from([(peer.clone(), ack)]),
                    });
                }
            })
            .await
            .expect("must always be able to persist tracked acks to disk");

        self.metrics.acks_received.inc();
        Ok("ack recorded")
    }

    #[instrument(
        skip_all,
        fields(
            epoch = %self.epoch(),
            %peer,
        ),
        err(level = Level::WARN),
        ret,
    )]
    async fn process_share(
        &mut self,
        peer: PublicKey,
        Share { commitment, share }: Share,
    ) -> eyre::Result<&'static str> {
        let Some(player_me) = &mut self.player_me else {
            return Ok("not a player, dropping share");
        };

        // This also checks peer is the correct dealer.
        player_me
            .share(peer.clone(), commitment.clone(), share.clone())
            .wrap_err("failed to record and track share")?;

        self.ceremony_metadata
            .lock()
            .await
            .upsert_sync(self.epoch().into(), |info| {
                info.received_shares
                    .push((peer.clone(), commitment.clone(), share));
            })
            .await
            .expect("must always be able to persist tracked shares to disk");

        let payload = Ack::new(
            &union(&self.config.namespace, ACK_NAMESPACE),
            self.config.me.clone(),
            self.config.me.public_key(),
            self.epoch(),
            &peer,
            &commitment,
        )
        .into();
        self.sender
            .send(
                Recipients::One(peer.clone()),
                Message {
                    epoch: self.epoch(),
                    payload,
                }
                .encode()
                .freeze(),
                true,
            )
            .await
            .wrap_err("failed returning ack to peer")?;

        self.metrics.acks_sent.inc();
        Ok("recorded share and returned signed ack to peer")
    }

    /// Process `block` by reading [`IntermediateOutcome`] from its header.
    ///
    /// If the block contains this outcome, the ceremony will verify it and
    /// track it in its arbiter.
    #[instrument(skip_all, fields(epoch = self.epoch(), block.height = block.height()), err)]
    pub(super) async fn process_dealings_in_block(
        &mut self,
        block: &Block,
        hardfork_regime: HardforkRegime,
    ) -> eyre::Result<()> {
        // Check if extra_data is empty before trying to read
        if block.header().extra_data().is_empty() {
            info!("block contained no dealing (extra_data empty)");
            self.metrics.dealings_empty.inc();
            return Ok(());
        }

        let Some(block_outcome) = block.try_read_ceremony_deal_outcome() else {
            // extra_data was not empty but decode failed
            info!("block contained dealing data but failed to decode");
            self.metrics.dealings_failed.inc();
            return Ok(());
        };

        // Ensure the outcome is for the current round.
        ensure!(
            block_outcome.epoch() == self.epoch(),
            "deal outcome in block was for epoch `{}`, but current dkg ceremony is for epoch `{}`",
            block_outcome.epoch(),
            self.epoch(),
        );

        // Verify the dealer's signature before considering processing the outcome.
        match hardfork_regime {
            HardforkRegime::PostAllegretto => {
                ensure!(
                    block_outcome.verify(&union(&self.config.namespace, OUTCOME_NAMESPACE)),
                    "invalid dealer signature; ignoring deal outcome",
                );
            }
            HardforkRegime::PreAllegretto => {
                ensure!(
                    block_outcome
                        .verify_pre_allegretto(&union(&self.config.namespace, OUTCOME_NAMESPACE)),
                    "invalid dealer signature; ignoring deal outcome",
                );
            }
        }

        // Verify all ack signatures
        if !block_outcome.acks().iter().all(|ack| {
            self.players_indexed.contains(ack.player())
                && ack.verify(
                    &union(&self.config.namespace, ACK_NAMESPACE),
                    ack.player(),
                    self.epoch(),
                    block_outcome.dealer(),
                    block_outcome.commitment(),
                )
        }) {
            self.arbiter.disqualify(block_outcome.dealer().clone());
            bail!("invalid ack signatures; disqualifying dealer");
        }

        // Check dealer commitment
        let ack_indices = block_outcome
            .acks()
            .iter()
            .filter_map(|ack| {
                let idx = self.players_indexed.get_index_of(ack.player());
                if idx.is_none() {
                    warn!(
                        player = %ack.player(),
                        "ack for player stored on disk not among players of this ceremony",
                    );
                }
                idx.map(|idx| idx as u32)
            })
            .collect::<Vec<_>>();

        self.arbiter
            .commitment(
                block_outcome.dealer().clone(),
                block_outcome.commitment().clone(),
                ack_indices,
                block_outcome.reveals().to_vec(),
            )
            .wrap_err("failed to track dealer outcome in arbiter")?;

        let block_dealer = block_outcome.dealer().clone();
        self.ceremony_metadata
            .lock()
            .await
            .upsert_sync(self.epoch().into(), |info| {
                if let Some(pos) = info
                    .outcomes
                    .iter()
                    .position(|outcome| outcome.dealer() == block_outcome.dealer())
                {
                    info.outcomes[pos] = block_outcome;
                } else {
                    info.outcomes.push(block_outcome);
                }
            })
            .await
            .expect("must persist deal outcome");

        if let Some(dealer_me) = &mut self.dealer_me
            && block_dealer == self.config.me.public_key()
        {
            let _ = dealer_me.outcome.take();

            self.ceremony_metadata
                .lock()
                .await
                .upsert_sync(self.epoch().into(), |info| {
                    let _ = info.dealing_outcome.take();
                })
                .await
                .expect("must persist deal outcome");

            info!(
                "found own dealing in a block; removed it from ceremony to \
                not include it again"
            );
        }

        self.metrics.dealings_read.inc();
        Ok(())
    }

    /// Constructs and stores the intermediate ceremony outcome.
    ///
    /// If the node is not a dealer, then this is a no-op.
    #[instrument(skip_all, fields(epoch = self.epoch()), err)]
    pub(super) async fn construct_intermediate_outcome(
        &mut self,
        hardfork_regime: HardforkRegime,
    ) -> eyre::Result<()> {
        let Some(dealer_me) = &mut self.dealer_me else {
            debug!("not a dealer; skipping construction of deal outcome");
            return Ok(());
        };
        let reveals = self
            .config
            .players
            .iter()
            .filter_map(|player| {
                (!dealer_me.acks.contains_key(player))
                    .then(|| dealer_me.shares.get(player).cloned())
                    .flatten()
            })
            .collect::<Vec<_>>();

        ensure!(
            reveals.len() as u32 <= max_faults(self.config.players.len() as u32),
            "too many reveals; skipping deal outcome construction",
        );

        let dealing_outcome = match hardfork_regime {
            HardforkRegime::PostAllegretto => Some(IntermediateOutcome::new(
                self.config
                    .players
                    .len()
                    .try_into()
                    .expect("we should never have more than u16::MAX validators/players"),
                &self.config.me,
                &union(&self.config.namespace, OUTCOME_NAMESPACE),
                self.config.epoch,
                dealer_me.commitment.clone(),
                dealer_me.acks.values().cloned().collect(),
                reveals,
            )),
            HardforkRegime::PreAllegretto => Some(IntermediateOutcome::new_pre_allegretto(
                self.config
                    .players
                    .len()
                    .try_into()
                    .expect("we should never have more than u16::MAX validators/players"),
                &self.config.me,
                &union(&self.config.namespace, OUTCOME_NAMESPACE),
                self.config.epoch,
                dealer_me.commitment.clone(),
                dealer_me.acks.values().cloned().collect(),
                reveals,
            )),
        };

        self.ceremony_metadata
            .lock()
            .await
            .upsert_sync(self.config.epoch.into(), |info| {
                info.dealing_outcome = dealing_outcome.clone();
            })
            .await
            .expect("must persist local outcome");

        dealer_me.outcome = dealing_outcome;

        Ok(())
    }

    /// Finalizes the ceremony, returning the participants and key pair for the
    /// next epoch.
    ///
    /// If the ceremony was successful, the players of the ceremony and the new
    /// public key will be returned in Ok-position. If this node was a player,
    /// it will also contain its private share.
    ///
    /// If the ceremony failed, the dealers of the ceremony and the old public
    /// key will be returned in Err-position. If this node was a dealer, this
    /// will include its old private share.
    #[instrument(skip_all, fields(epoch = self.epoch()))]
    pub(super) fn finalize(self) -> Result<PrivateOutcome, PrivateOutcome> {
        let (result, disqualified) = self.arbiter.finalize();

        let arbiter::Output {
            public,
            commitments,
            reveals,
        } = match result {
            Ok(output) => output,
            Err(error) => {
                error!(
                    error = %eyre::Report::new(error),
                    ?disqualified,
                    "failed to finalize arbiter; aborting ceremony and \
                    returning previous dealers and commitment",
                );
                return Err(PrivateOutcome {
                    participants: self.config.dealers,
                    role: self.previous_role,
                });
            }
        };

        let new_role = if let Some(player_me) = self.player_me {
            let my_index = self
                .players_indexed
                .get_index_of(&self.config.me.public_key())
                .expect("if I am a player, I must be indexed");
            let reveals = reveals
                .into_iter()
                .filter_map(|(dealer_idx, shares)| {
                    shares
                        .iter()
                        .find(|s| s.index == my_index as u32)
                        .cloned()
                        .map(|share| (dealer_idx, share))
                })
                .collect::<BTreeMap<_, _>>();

            let n_commitments = commitments.len();
            let n_reveals = reveals.len();

            let output = match player_me.finalize(commitments, reveals) {
                Ok(output) => output,
                Err(error) => {
                    error!(
                        error = %eyre::Report::new(error),
                        "failed to finalize player; aborting ceremony and \
                        returning previous dealers and commitment"
                    );
                    return Err(PrivateOutcome {
                        participants: self.config.dealers,
                        role: self.previous_role,
                    });
                }
            };

            info!(
                ?disqualified,
                n_commitments,
                n_reveals,
                "successfully finalized DKG ceremony; returning new \
                    players and commitment"
            );

            Role::Signer {
                public: output.public,
                share: output.share,
            }
        } else {
            Role::Verifier { public }
        };

        Ok(PrivateOutcome {
            participants: self.config.players,
            role: new_role,
        })
    }

    pub(super) fn epoch(&self) -> Epoch {
        self.config.epoch
    }

    pub(super) fn deal_outcome(&self) -> Option<&IntermediateOutcome> {
        let dealer_me = self.dealer_me.as_ref()?;
        dealer_me.outcome.as_ref()
    }

    pub(super) fn dealers(&self) -> &[PublicKey] {
        self.config.dealers.as_ref()
    }

    pub(super) fn players(&self) -> &[PublicKey] {
        self.config.players.as_ref()
    }

    pub(super) fn is_dealer(&self) -> bool {
        self.dealer_me.is_some()
    }

    pub(super) fn is_player(&self) -> bool {
        self.player_me.is_some()
    }
}

/// Metadata associated with a [Dealer].
struct Dealer {
    /// The [Dealer]'s commitment.
    commitment: Public<MinSig>,
    /// The dealer's shares for all players.
    shares: BTreeMap<PublicKey, group::Share>,
    /// Signed acknowledgements from contributors.
    acks: BTreeMap<PublicKey, Ack>,
    /// The constructed dealing for inclusion in a block.
    ///
    /// This is moved out once the outcome was successfully written to chain.
    outcome: Option<IntermediateOutcome>,
}

/// The outcome of the ceremony for the local node.
///
/// Called private because it potentially contains the private key share.
pub(super) struct PrivateOutcome {
    /// The participants of the new epoch. If successful, this will the players
    /// in the ceremony. If not successful, these are the dealers.
    pub(super) participants: Ordered<PublicKey>,

    /// The role the node will have in the next epoch.
    pub(super) role: Role,
}

/// The resulting keys of the round, dictating whether the node will be a
/// signer or a verifier in the next epoch.
pub(super) enum Role {
    /// The new group polynomial and the local share, if the node was a player.
    Signer {
        public: Public<MinSig>,
        share: group::Share,
    },
    /// If the node was not a player in the round it will be just a verifier.
    Verifier { public: Public<MinSig> },
}

impl Role {
    /// Splits the role into a pair of public polynomial and private share.
    ///
    /// If a signer, the share will not be unset.
    pub(super) fn into_key_pair(self) -> (Public<MinSig>, Option<group::Share>) {
        match self {
            Self::Signer {
                public: polynomial,
                share,
            } => (polynomial, Some(share)),
            Self::Verifier { public: polynomial } => (polynomial, None),
        }
    }
}
