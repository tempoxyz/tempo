//! An actively running DKG ceremony.

use std::collections::BTreeMap;

use commonware_codec::{Decode as _, Encode as _};
use commonware_consensus::{Block as _, types::Epoch};
use commonware_cryptography::{
    Signer as _,
    bls12381::{
        dkg::{self, Player, arbiter},
        primitives::{group, poly::Public, variant::MinSig},
    },
    ed25519::{PrivateKey, PublicKey},
};
use commonware_p2p::{
    Receiver, Recipients, Sender,
    utils::mux::{MuxHandle, SubReceiver, SubSender},
};
use commonware_runtime::{Clock, Metrics as RuntimeMetrics, Storage};
use commonware_utils::{max_faults, set::Ordered, union};
use eyre::{WrapErr as _, bail, ensure};
use futures::FutureExt as _;
use indexmap::IndexSet;
use prometheus_client::metrics::{counter::Counter, gauge::Gauge};
use rand_core::CryptoRngCore;
use tracing::{Level, debug, error, info, instrument, warn};

use tempo_dkg_onchain_artifacts::{Ack, IntermediateOutcome, PublicOutcome};

use crate::{
    consensus::{Digest, block::Block},
    dkg::{
        HardforkRegime, ceremony::tree::TreeOfDealings,
        manager::read_write_transaction::DkgReadWriteTransaction,
    },
};

mod payload;
mod persisted;
mod tree;

pub(super) use persisted::State;
pub(in crate::dkg) use tree::HasHoles;

use payload::{Message, Payload, Share};
use persisted::Dealing;

const ACK_NAMESPACE: &[u8] = b"_DKG_ACK";
pub(super) const OUTCOME_NAMESPACE: &[u8] = b"_DKG_OUTCOME";

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

    /// The epoch length set at genesis.
    pub(super) epoch_length: u64,

    /// The hardfork regime this ceremony runs under.
    pub(super) hardfork_regime: HardforkRegime,

    /// The dealers in the round.
    pub(super) dealers: Ordered<PublicKey>,

    /// The players in the round.
    pub(super) players: Ordered<PublicKey>,
}

pub(super) struct Ceremony<TReceiver, TSender>
where
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

    receiver: SubReceiver<TReceiver>,
    sender: SubSender<TSender>,
    metrics: Metrics,

    tree_of_dealings: TreeOfDealings,
}

impl<TReceiver, TSender> Ceremony<TReceiver, TSender>
where
    TReceiver: Receiver<PublicKey = PublicKey>,
    TSender: Sender<PublicKey = PublicKey>,
{
    /// Initialize a DKG ceremony.
    #[instrument(skip_all, fields(for_epoch = %config.epoch), err)]
    pub(super) async fn init<TContext>(
        context: &mut TContext,
        mux: &mut MuxHandle<TSender, TReceiver>,
        tx: &mut DkgReadWriteTransaction<TContext>,
        config: Config,
        metrics: Metrics,
    ) -> eyre::Result<Self>
    where
        TContext: Clock + CryptoRngCore + RuntimeMetrics + Storage,
    {
        // Reset the cumulants for the current ceremony back to zero instead
        // of creating fresh metrics: registering new metrics would just push
        // more and more into the prometheus registry without ever pruning.
        metrics.reset_per_ceremony_metrics();

        metrics.dealers.set(config.dealers.len() as i64);
        metrics.players.set(config.players.len() as i64);

        let (sender, receiver) = mux
            .register(config.epoch.get())
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

        let mut dealer_me = None;

        debug!("attempting to read ceremony state from disk");
        // TODO(janis): move this "recovery" logic to a function.
        let recovered = tx
            .get_ceremony(config.epoch)
            .await
            .wrap_err("failed to read ceremony state from disk")?;

        if let Some(recovered) = recovered {
            info!("found a previous ceremony state written to disk; recovering it");

            // Ignored recovered.outcomes now. On the next finalized block, we
            // will backfill the holes from the marshal actor.

            if let Some(me) = &mut player_me {
                for (dealer, commitment, share) in recovered.received_shares.clone() {
                    me.share(dealer, commitment, share)
                        .wrap_err("failed updating my player information with stored metadata")?;
                }
            }

            // On recovery, ignore the dealings. We will fetch the missing
            // blocks from the marshal actor
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

            tx.set_ceremony(
                config.epoch,
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
            );
        };

        metrics.how_often_player.inc_by(player_me.is_some() as u64);
        metrics.how_often_dealer.inc_by(dealer_me.is_some() as u64);

        let previous = config.share.clone().map_or_else(
            || Role::Verifier {
                public: config.public.clone(),
            },
            |share| Role::Signer {
                public: config.public.clone(),
                share,
            },
        );
        let tree_of_dealings = TreeOfDealings::new(
            config.epoch,
            config.epoch_length,
            config.public.clone(),
            config.dealers.clone(),
            config.players.clone(),
            config.hardfork_regime,
            config.namespace.clone(),
        );
        Ok(Self {
            config,
            previous_role: previous,
            dealer_me,
            player_me,
            players_indexed,
            receiver,
            sender,
            metrics,
            tree_of_dealings,
        })
    }

    #[instrument(
        skip_all,
        fields(epoch = %self.config.epoch, block.height = block.height()),
    )]
    pub(super) async fn add_finalized_block<TContext>(
        &mut self,
        tx: &mut DkgReadWriteTransaction<TContext>,
        block: Block,
    ) where
        TContext: Clock + RuntimeMetrics + Storage,
    {
        if let Some(dealer) = self.tree_of_dealings.add_finalized(block)
            && self.config.me.public_key() == dealer
            && let Some(dealer_me) = &mut self.dealer_me
        {
            let _ = dealer_me.outcome.take();
            tx.update_ceremony(self.epoch(), |info| {
                let _ = info.dealing_outcome.take();
            })
            .await
            .expect("must persist deal outcome");

            info!(
                "found own dealing in a block; removed it from ceremony to \
                not include it again"
            );
        }
    }

    #[instrument(
        skip_all,
        fields(epoch = %self.config.epoch, block.height = block.height()),
    )]
    pub(super) fn add_notarized_block(&mut self, block: Block) {
        self.tree_of_dealings.add_notarized(block);
    }

    pub(super) fn find_gaps_up_to_height(&self, height: u64) -> Vec<u64> {
        self.tree_of_dealings.find_gaps_up_to_height(height)
    }

    /// Sends shares to all players for acknowledgements.
    ///
    /// Does not send shares if we are not a dealer in this ceremony.
    ///
    /// If we are both a dealer and a player, then we acknowledge our shares
    /// immediately without going over the p2p network.
    #[instrument(skip_all, fields(epoch = %self.config.epoch), err)]
    pub(super) async fn distribute_shares<TContext>(
        &mut self,
        tx: &mut DkgReadWriteTransaction<TContext>,
    ) -> eyre::Result<()>
    where
        TContext: Clock + RuntimeMetrics + Storage,
    {
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

                tx.update_ceremony(self.config.epoch, |info| {
                    if let Some(dealing) = &mut info.dealing {
                        dealing
                            .acks
                            .insert(self.config.me.public_key(), ack.clone());
                    } else {
                        info.dealing = Some(Dealing {
                            commitment: dealer_me.commitment.clone(),
                            shares: dealer_me.shares.clone(),
                            acks: BTreeMap::from([(self.config.me.public_key(), ack.clone())]),
                        });
                    }
                    info.received_shares.push((
                        self.config.me.public_key(),
                        dealer_me.commitment.clone(),
                        share.clone(),
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
    #[instrument(skip_all, fields(epoch = %self.epoch()), err)]
    pub(super) async fn process_messages<TContext>(
        &mut self,
        tx: &mut DkgReadWriteTransaction<TContext>,
    ) -> eyre::Result<()>
    where
        TContext: Clock + RuntimeMetrics + Storage,
    {
        while let Some(msg) = self.receiver.recv().now_or_never() {
            let (peer, mut msg) = msg.wrap_err("receiver p2p channel was closed")?;

            debug!(%peer, "received message from");
            let msg = Message::decode_cfg(&mut msg, &(self.config.players.len() as u32))
                .wrap_err("unable to decode message")?;
            if msg.epoch != self.epoch() {
                warn!(
                    ceremony.epoch = %self.epoch(),
                    %msg.epoch,
                    "ignoring message for different round"
                );
                continue;
            }

            match msg.payload {
                Payload::Ack(ack) => {
                    let _: Result<_, _> = self.process_ack(tx, peer, *ack).await;
                }
                Payload::Share(share) => {
                    let _: Result<_, _> = self.process_share(tx, peer, share).await;
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
    async fn process_ack<TContext>(
        &mut self,
        tx: &mut DkgReadWriteTransaction<TContext>,
        peer: PublicKey,
        ack: Ack,
    ) -> eyre::Result<&'static str>
    where
        TContext: Clock + RuntimeMetrics + Storage,
    {
        self.metrics.acks_received.inc();
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

        tx.update_ceremony(self.config.epoch, |info| {
            if let Some(dealing) = &mut info.dealing {
                dealing.acks.insert(peer.clone(), ack.clone());
            } else {
                info.dealing = Some(Dealing {
                    commitment: dealer_me.commitment.clone(),
                    shares: dealer_me.shares.clone(),
                    acks: BTreeMap::from([(peer.clone(), ack.clone())]),
                });
            }
        })
        .await
        .expect("must always be able to persist tracked acks to disk");

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
    async fn process_share<TContext>(
        &mut self,
        tx: &mut DkgReadWriteTransaction<TContext>,
        peer: PublicKey,
        Share { commitment, share }: Share,
    ) -> eyre::Result<&'static str>
    where
        TContext: Clock + RuntimeMetrics + Storage,
    {
        self.metrics.shares_received.inc();
        let Some(player_me) = &mut self.player_me else {
            return Ok("not a player, dropping share");
        };

        // This also checks peer is the correct dealer.
        player_me
            .share(peer.clone(), commitment.clone(), share.clone())
            .wrap_err("failed to record and track share")?;

        tx.update_ceremony(self.epoch(), |info| {
            info.received_shares
                .push((peer.clone(), commitment.clone(), share.clone()));
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

    /// Constructs and stores the intermediate ceremony outcome.
    ///
    /// If the node is not a dealer, then this is a no-op.
    #[instrument(skip_all, fields(epoch = %self.epoch()), err)]
    pub(super) async fn construct_intermediate_outcome<TContext>(
        &mut self,
        tx: &mut DkgReadWriteTransaction<TContext>,
        hardfork_regime: HardforkRegime,
    ) -> eyre::Result<()>
    where
        TContext: Clock + RuntimeMetrics + Storage,
    {
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

        tx.update_ceremony(self.config.epoch, |info| {
            info.dealing_outcome = dealing_outcome.clone();
        })
        .await
        .expect("must persist local outcome");

        dealer_me.outcome = dealing_outcome;

        Ok(())
    }

    /// Returns the outcome of the DKG ceremony given the target digest.
    ///
    /// If the DKG ceremony contained all blocks leading up to the target,
    /// the DKG outcome will be in Ok-position.
    ///
    /// If the DKG ceremony did not contain all blocks leading up to the target,
    /// the missing ... will be in error position.
    #[instrument(skip_all, fields(epoch = %self.epoch()))]
    pub(super) fn finalize(
        &self,
        digest: Digest,
    ) -> Result<Result<PrivateOutcome, PrivateOutcome>, HasHoles> {
        let (result, disqualified) = self.tree_of_dealings.finalize_up_to_digest(digest)?;

        let new_epoch = self.epoch().next();

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
                    returning previous participants and polynomial",
                );
                return Ok(Err(PrivateOutcome {
                    epoch: new_epoch,
                    participants: self.config.dealers.clone(),
                    role: self.previous_role.clone(),
                }));
            }
        };

        let mut my_share = None;
        if let Some(player_me) = self.player_me.clone() {
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

            let n_reveals = reveals.len();

            match player_me.finalize(commitments, reveals) {
                Ok(output) => {
                    info!(n_reveals, "obtained a share from the DKG ceremomy");
                    my_share.replace(output.share);
                }
                Err(error) => {
                    warn!(
                        n_reveals,
                        error = %eyre::Report::new(error),
                        "failed to finalize our share even though the overall \
                        DKG ceremony was a success; will participate as a \
                        verifier since we failed to participate as a player"
                    );
                }
            };
        }

        let my_role = match my_share {
            Some(share) => Role::Signer { public, share },
            None => Role::Verifier { public },
        };
        info!(
            ?disqualified,
            "successfully finalized DKG ceremony; returning new participants polynomial"
        );

        Ok(Ok(PrivateOutcome {
            epoch: new_epoch,
            participants: self.config.players.clone(),
            role: my_role,
        }))
    }

    pub(super) fn epoch(&self) -> Epoch {
        self.config.epoch
    }

    pub(super) fn deal_outcome(&self) -> Option<&IntermediateOutcome> {
        let dealer_me = self.dealer_me.as_ref()?;
        dealer_me.outcome.as_ref()
    }

    pub(super) fn dealers(&self) -> &Ordered<PublicKey> {
        &self.config.dealers
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
    /// The epoch for which this outcome is constructed. Usually ceremony.epoch + 1.
    pub(super) epoch: Epoch,

    /// The participants of the new epoch. If successful, this will the players
    /// in the ceremony. If not successful, these are the dealers.
    pub(super) participants: Ordered<PublicKey>,

    /// The role the node will have in the next epoch.
    pub(super) role: Role,
}

impl PrivateOutcome {
    pub(super) fn to_public_outcome(&self) -> PublicOutcome {
        PublicOutcome {
            epoch: self.epoch,
            participants: self.participants.clone(),
            public: self.role.to_public_polynomial(),
        }
    }
}

/// The resulting keys of the round, dictating whether the node will be a
/// signer or a verifier in the next epoch.
#[derive(Clone)]
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

    pub(super) fn to_public_polynomial(&self) -> Public<MinSig> {
        match self {
            Self::Signer { public, .. } | Self::Verifier { public } => public.clone(),
        }
    }
}

/// Ceremony specific metrics.
#[derive(Clone)]
pub(super) struct Metrics {
    shares_distributed: Gauge,
    shares_received: Gauge,
    acks_received: Gauge,
    acks_sent: Gauge,
    dealings_read: Gauge,
    dealings_empty: Gauge,
    bad_dealings: Gauge,

    failures: Counter,
    successes: Counter,
    dealers: Gauge,
    players: Gauge,

    how_often_dealer: Counter,
    how_often_player: Counter,
}

impl Metrics {
    /// Construct and register the ceremony-related metrics on `context`.
    ///
    /// Note: because there exists no long-lived ceremony specific context,
    /// most of the metrics defined here carry a manual `ceremony` prefix.
    pub(super) fn register<C: commonware_runtime::Metrics>(context: &C) -> Self {
        let failures = Counter::default();
        let successes = Counter::default();

        let dealers = Gauge::default();
        let players = Gauge::default();

        let how_often_dealer = Counter::default();
        let how_often_player = Counter::default();

        let shares_distributed = Gauge::default();
        let shares_received = Gauge::default();
        let acks_received = Gauge::default();
        let acks_sent = Gauge::default();
        let dealings_read = Gauge::default();
        let dealings_empty = Gauge::default();
        let bad_dealings = Gauge::default();

        context.register(
            "ceremony_failures",
            "the number of failed ceremonies a node participated in",
            failures.clone(),
        );
        context.register(
            "ceremony_successes",
            "the number of successful ceremonies a node participated in",
            successes.clone(),
        );
        context.register(
            "ceremony_dealers",
            "the number of dealers in the currently running ceremony",
            dealers.clone(),
        );
        context.register(
            "ceremony_players",
            "the number of players in the currently running ceremony",
            players.clone(),
        );

        // no prefix for legacy reasons
        context.register(
            "how_often_dealer",
            "number of the times as node was active as a dealer",
            how_often_dealer.clone(),
        );
        // no prefix for for legacy reasons
        context.register(
            "how_often_player",
            "number of the times as node was active as a player",
            how_often_player.clone(),
        );

        context.register(
            "ceremony_shares_distributed",
            "the number of shares distributed by this node as a dealer in the current ceremony",
            shares_distributed.clone(),
        );
        context.register(
            "ceremony_shares_received",
            "the number of shares received by this node as a playr in the current ceremony",
            shares_received.clone(),
        );
        context.register(
            "ceremony_acks_received",
            "the number of acknowledgments received by this node as a dealer in the current ceremony",
            acks_received.clone(),
        );
        context.register(
            "ceremony_acks_sent",
            "the number of acknowledgments sent by this node as a player in the current ceremony",
            acks_sent.clone(),
        );
        context.register(
            "ceremony_dealings_read",
            "the number of dealings read from the blockchain in the current ceremony",
            dealings_read.clone(),
        );
        context.register(
            "ceremony_dealings_empty",
            "the number of blocks with empty extra_data (no dealing) in the current ceremony",
            dealings_empty.clone(),
        );
        context.register(
            "ceremony_bad_dealings",
            "the number of blocks where decoding and verifying dealings failed in the current ceremony",
            bad_dealings.clone(),
        );

        Self {
            shares_distributed,
            shares_received,
            acks_received,
            acks_sent,
            dealings_read,
            dealings_empty,
            bad_dealings,
            dealers,
            players,
            how_often_dealer,
            how_often_player,
            failures,
            successes,
        }
    }

    /// Resets per-ceremony gauges to zero. Called when a new ceremony is
    /// initialized.
    fn reset_per_ceremony_metrics(&self) {
        self.shares_distributed.set(0);
        self.shares_received.set(0);
        self.acks_received.set(0);
        self.acks_sent.set(0);
        self.dealings_read.set(0);
        self.dealings_empty.set(0);
        self.bad_dealings.set(0);
    }

    /// Increments the failed ceremonies counter.
    pub(super) fn one_more_failure(&self) {
        self.failures.inc();
    }

    /// Increments the successful ceremonies counter.
    pub(super) fn one_more_success(&self) {
        self.successes.inc();
    }
}
