//! An actively running DKG ceremony.

use std::{collections::BTreeMap, sync::Arc};

use bytes::{Buf, BufMut};
use commonware_codec::{
    Decode as _, Encode as _, EncodeSize, FixedSize as _, RangeCfg, Read, ReadExt as _, Write,
    varint::UInt,
};
use commonware_consensus::{Block as _, types::Epoch};
use commonware_cryptography::{
    Signer as _, Verifier as _,
    bls12381::{
        dkg::{Arbiter, Dealer, Player, arbiter, player::Output},
        primitives::{group, poly::Public, variant::MinSig},
    },
    ed25519::{PrivateKey, PublicKey, Signature},
};
use commonware_p2p::Recipients;
use commonware_p2p::{
    Receiver, Sender,
    utils::mux::{MuxHandle, SubReceiver, SubSender},
};
use commonware_runtime::{Clock, Metrics, Storage};
use commonware_storage::metadata::Metadata;
use commonware_utils::{max_faults, quorum, sequence::U64, set::Set, union};
use eyre::{WrapErr as _, bail, ensure};
use futures::{FutureExt as _, lock::Mutex};
use indexmap::IndexSet;
use rand_core::CryptoRngCore;
use tracing::{error, info, instrument, warn};

use crate::consensus::block::Block;

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
    //
    // TODO(janis): make this optional for those cases where we don't have a
    // public polynomial yet.
    pub(super) public: Public<MinSig>,

    /// Our previous share of the private polynomial.
    pub(super) share: Option<group::Share>,

    /// The current epoch.
    pub(super) epoch: Epoch,

    /// The dealers in the round.
    pub(super) dealers: Set<PublicKey>,

    /// The players in the round.
    pub(super) players: Set<PublicKey>,
}

pub(super) struct Ceremony<TContext, TReceiver, TSender>
where
    TContext: Clock + Metrics + Storage,
    TReceiver: Receiver,
    TSender: Sender,
{
    config: Config,

    /// The previous group polynomial and (if dealing) share.
    previous: RoundResult,

    /// [Dealer] metadata, if this manager is also dealing.
    dealer_meta: DealerMetadata,

    /// The local [Player] for this round, if the manager is playing.
    //
    // NOTE: right now we should always be playing.
    player_me: Option<Player<PublicKey, MinSig>>,

    /// The indexed set of all players. Whereas config.players is a sorted
    /// list of unique playes, players_indexed is an actual set data structure
    /// that allows O(1) lookup of both keys and indices.
    ///
    /// It is an invariant that players_indexed.get_index_of(players[i]) == i.
    players_indexed: IndexSet<PublicKey>,

    /// The local [Arbiter] for this round.
    arbiter: Arbiter<PublicKey, MinSig>,

    ceremony_metadata: Arc<Mutex<Metadata<TContext, U64, RoundInfo>>>,
    receiver: SubReceiver<TReceiver>,
    sender: SubSender<TSender>,
}

impl<TContext, TReceiver, TSender> Ceremony<TContext, TReceiver, TSender>
where
    TContext: Clock + CryptoRngCore + Metrics + Storage,
    TReceiver: Receiver<PublicKey = PublicKey>,
    TSender: Sender<PublicKey = PublicKey>,
{
    /// Initialize a DKG ceremony.
    pub(super) async fn init(
        context: &mut TContext,
        mux: &mut MuxHandle<TSender, TReceiver>,
        ceremony_metadata: Arc<Mutex<Metadata<TContext, U64, RoundInfo>>>,
        config: Config,
    ) -> eyre::Result<Self> {
        let (sender, receiver) = mux
            .register(config.epoch as u32)
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

        // TODO(janis): move this "recovery" logic to a function.
        let dealer_meta = if let Some(meta) =
            ceremony_metadata.lock().await.get(&config.epoch.into())
        {
            for outcome in &meta.outcomes {
                let ack_indices = outcome
                    .acks
                    .iter()
                    .filter_map(|ack| {
                        let idx = players_indexed.get_index_of(&ack.player);
                        if idx.is_none() {
                            warn!(
                                player = %ack.player,
                                "ack for player stored on disk not among players of this ceremony",
                            );
                        }
                        idx.map(|idx| idx as u32)
                    })
                    .collect::<Vec<_>>();

                if let Err(error) = arbiter
                    .commitment(
                        outcome.dealer.clone(),
                        outcome.commitment.clone(),
                        ack_indices,
                        outcome.reveals.clone(),
                    )
                    .wrap_err("failed to verify and track commitment")
                {
                    warn!(
                        %error,
                        "failed to update arbiter with stored metadata",
                    );
                }
            }

            if let Some(me) = &mut player_me {
                for (dealer, commitment, share) in meta.received_shares.clone() {
                    me.share(dealer, commitment, share)
                        .wrap_err("failed updating my player information with stored metadata")?;
                }
            }

            let Some(Deal {
                commitment,
                shares,
                acks,
            }) = meta.deal.clone()
            else {
                bail!(
                    "all players must currently be dealers, but no dealer \
                    information was written to disk even though some round \
                    information was; this is a problem"
                );
            };
            let (mut dealer, _, _) =
                Dealer::new(context, config.share.clone(), config.players.clone());
            for ack in acks.values() {
                dealer.ack(ack.player.clone()).wrap_err_with(|| {
                    format!(
                        "failed updating dealer information with ack for \
                         player `{player}` recovered from disk",
                        player = ack.player,
                    )
                })?;
            }
            DealerMetadata {
                dealer,
                commitment,
                shares,
                acks,
                outcome: meta.local_outcome.clone(),
            }
        } else {
            let (dealer, commitment, shares) =
                Dealer::new(context, config.share.clone(), config.players.clone());
            let shares = config
                .players
                .iter()
                .zip(&shares)
                .map(|(player, share)| (player.clone(), share.clone()))
                .collect();
            DealerMetadata {
                dealer,
                commitment,
                shares,
                acks: BTreeMap::new(),
                outcome: None,
            }
        };

        let previous = config.share.clone().map_or_else(
            || RoundResult::Polynomial(config.public.clone()),
            |share| {
                RoundResult::Output(Output {
                    public: config.public.clone(),
                    share,
                })
            },
        );
        Ok(Self {
            config,
            previous,
            dealer_meta,
            player_me,
            players_indexed,
            arbiter,
            ceremony_metadata,
            receiver,
            sender,
        })
    }

    #[instrument(skip_all, fields(epoch = self.config.epoch), err)]
    pub(super) async fn request_acks(&mut self) -> eyre::Result<()> {
        // Request acks from all players that did not yet sign theirs.

        for player in &self.config.players {
            if self.dealer_meta.acks.contains_key(player) {
                continue;
            }

            let share = self
                .dealer_meta
                .shares
                .get(player)
                .cloned()
                .expect("invariant violated: all players must have an entry in the shares map");

            if let Some(player) = &mut self.player_me {
                player
                    .share(
                        self.config.me.public_key(),
                        self.dealer_meta.commitment.clone(),
                        share.clone(),
                    )
                    .expect(
                        "must work: updating player with own dealer \
                        commmitment",
                    );

                self.dealer_meta
                    .dealer
                    .ack(self.config.me.public_key())
                    .expect("must work: updating dealer with own player ack");

                // TODO(janis): easy to mess up the fields because some of them
                // are of the same type. Better pass in a struct or create a
                // builder.
                let ack = Ack::new(
                    &union(&self.config.namespace, ACK_NAMESPACE),
                    self.config.me.clone(),
                    self.config.me.public_key(),
                    self.config.epoch,
                    &self.config.me.public_key(),
                    &self.dealer_meta.commitment,
                );
                self.dealer_meta
                    .acks
                    .insert(self.config.me.public_key(), ack.clone());

                self.ceremony_metadata
                    .lock()
                    .await
                    .upsert_sync(self.epoch().into(), |meta| {
                        if let Some(Deal { acks, .. }) = &mut meta.deal {
                            acks.insert(self.config.me.public_key(), ack);
                        } else {
                            meta.deal = Some(Deal {
                                commitment: self.dealer_meta.commitment.clone(),
                                shares: self.dealer_meta.shares.clone(),
                                acks: BTreeMap::from([(self.config.me.public_key(), ack)]),
                            });
                        }
                        meta.received_shares.push((
                            self.config.me.public_key(),
                            self.dealer_meta.commitment.clone(),
                            share,
                        ));
                    })
                    .await
                    .expect("must be able to persists acks");
                continue;
            }

            let payload = Share {
                commitment: self.dealer_meta.commitment.clone(),
                share,
            }
            .into();
            let success = self
                .sender
                .send(
                    Recipients::One(player.clone()),
                    Dkg {
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
                info!(%player, "send share to player");
            }
        }
        Ok(())
    }

    /// Processes all available messages from the [Receiver], handling both incoming shares and
    /// acknowledgements. Once the [Receiver] needs to wait for more messages, this function
    /// yields back to the caller.
    #[instrument(skip_all, fields(epoch = self.epoch()), err)]
    pub(super) async fn process_messages(&mut self) -> eyre::Result<()> {
        while let Some(msg) = self.receiver.recv().now_or_never() {
            let (peer, mut msg) = msg.wrap_err("receiver p2p channel was closed")?;

            let msg = Dkg::decode_cfg(&mut msg, &(self.config.players.len() as u32))
                .wrap_err("unable to decode message")?;
            if msg.epoch != self.epoch() {
                warn!(
                    ceremony.epoch = self.epoch(),
                    msg.epoch = msg.epoch,
                    "ignoring message for different round"
                );
                return Ok(());
            }

            match msg.payload {
                Payload::Ack(ack) => {
                    if ack.player != peer {
                        warn!(
                            ack.player = %ack.player,
                            %peer,
                            "player recorded in ack does not match peer that sent it; dropping ack",
                        );
                        continue;
                    }

                    if !self.players_indexed.contains(&peer) {
                        warn!(
                            player = %peer,
                            "player recorded in ack not known; dropping ack",
                        );
                        continue;
                    }

                    // Verify signature on incoming ack
                    if !ack.verify(
                        &union(&self.config.namespace, ACK_NAMESPACE),
                        &peer,
                        self.epoch(),
                        &self.config.me.public_key(),
                        &self.dealer_meta.commitment,
                    ) {
                        warn!(
                            player = %peer,
                            "signature of ack received from player is not valid"
                        );
                        continue;
                    }

                    // Store ack
                    if let Err(error) = self.dealer_meta.dealer.ack(peer.clone()) {
                        warn!(
                            player = %peer,
                            error = %eyre::Report::new(error),
                            "failed to record ack",
                        );
                        continue;
                    }
                    info!(
                        player = %peer,
                        "recorded ack",
                    );

                    self.dealer_meta.acks.insert(peer.clone(), ack.clone());

                    self.ceremony_metadata
                        .lock()
                        .await
                        .upsert_sync(self.epoch().into(), |meta| {
                            if let Some(Deal { acks, .. }) = &mut meta.deal {
                                acks.insert(peer.clone(), ack);
                            } else {
                                meta.deal = Some(Deal {
                                    commitment: self.dealer_meta.commitment.clone(),
                                    shares: self.dealer_meta.shares.clone(),
                                    acks: BTreeMap::from([(peer.clone(), ack)]),
                                });
                            }
                        })
                        .await
                        .expect("must persist ack");
                }
                Payload::Share(Share { commitment, share }) => {
                    let Some(player_me) = &mut self.player_me else {
                        warn!("ignoring share; not a player");
                        continue;
                    };

                    // Store share
                    if let Err(error) =
                        player_me.share(peer.clone(), commitment.clone(), share.clone())
                    {
                        warn!(
                            error = %eyre::Report::new(error),
                            "failed to record share",
                        );
                        continue;
                    }

                    // Persist the share to storage.
                    self.ceremony_metadata
                        .lock()
                        .await
                        .upsert_sync(self.epoch().into(), |meta| {
                            meta.received_shares
                                .push((peer.clone(), commitment.clone(), share));
                        })
                        .await
                        .expect("must be able to persists shares");

                    // Send ack
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
                            Dkg {
                                epoch: self.epoch(),
                                payload,
                            }
                            .encode()
                            .freeze(),
                            true,
                        )
                        .await
                        .wrap_err("unable to forward ack to p2p network")?;

                    info!(dealer = %peer, "returned ack to dealer");
                }
            }
        }

        Ok(())
    }

    /// Processes a [Block] that may contain a [DealOutcome], tracking it with the [Arbiter] if
    /// all acknowledgement signatures are valid.
    #[instrument(skip_all, fields(epoch = self.epoch(), block.height = block.height()), err)]
    pub(super) async fn process_block(&mut self, block: &Block) -> eyre::Result<()> {
        let Some(block_outcome) = block.try_read_ceremony_deal_outcome() else {
            info!("block contained no usable deal outcome");
            return Ok(());
        };

        // Ensure the outcome is for the current round.
        ensure!(
            block_outcome.epoch == self.epoch(),
            "deal outcome in block was for epoch `{}`, but current dkg ceremony is for epoch `{}`",
            block_outcome.epoch,
            self.epoch(),
        );

        // Verify the dealer's signature before considering processing the outcome.
        ensure!(
            block_outcome.verify(&union(&self.config.namespace, OUTCOME_NAMESPACE)),
            "invalid dealer signature; ignoring deal outcome",
        );

        // Verify all ack signatures
        if !block_outcome.acks.iter().all(|ack| {
            self.players_indexed.contains(&ack.player)
                && ack.verify(
                    &union(&self.config.namespace, ACK_NAMESPACE),
                    &ack.player,
                    self.epoch(),
                    &block_outcome.dealer,
                    &block_outcome.commitment,
                )
        }) {
            self.arbiter.disqualify(block_outcome.dealer.clone());
            bail!("invalid ack signatures; disqualifying dealer");
        }

        // Check dealer commitment
        let ack_indices = block_outcome
            .acks
            .iter()
            .filter_map(|ack| {
                let idx = self.players_indexed.get_index_of(&ack.player);
                if idx.is_none() {
                    warn!(
                        player = %ack.player,
                        "ack for player stored on disk not among players of this ceremony",
                    );
                }
                idx.map(|idx| idx as u32)
            })
            .collect::<Vec<_>>();

        self.arbiter
            .commitment(
                block_outcome.dealer.clone(),
                block_outcome.commitment.clone(),
                ack_indices,
                block_outcome.reveals.clone(),
            )
            .wrap_err("failed to track dealer outcome in arbiter")?;

        let block_dealer = block_outcome.dealer.clone();
        self.ceremony_metadata
            .lock()
            .await
            .upsert_sync(self.epoch().into(), |meta| {
                if let Some(pos) = meta
                    .outcomes
                    .iter()
                    .position(|outcome| outcome.dealer == block_outcome.dealer)
                {
                    meta.outcomes[pos] = block_outcome;
                } else {
                    meta.outcomes.push(block_outcome);
                }
            })
            .await
            .expect("must persist deal outcome");

        // If the block outcome is ours, remove it. This ensures that the app
        // does not include the outcome into the block again.
        if block_dealer == self.config.me.public_key() {
            let _ = self.dealer_meta.outcome.take();
        }

        Ok(())
    }

    #[instrument(skip_all, fields(epoch = self.epoch()), err)]
    pub(super) async fn construct_deal_outcome(&mut self) -> eyre::Result<()> {
        let reveals = self
            .config
            .players
            .iter()
            .filter_map(|player| {
                (!self.dealer_meta.acks.contains_key(&player))
                    .then(|| self.dealer_meta.shares.get(&player).cloned())
                    .flatten()
            })
            .collect::<Vec<_>>();

        ensure!(
            reveals.len() as u32 <= max_faults(self.config.players.len() as u32),
            "too many reveals; skipping deal outcome construction",
        );

        let local_outcome = Some(DealOutcome::new(
            &self.config.me,
            &union(&self.config.namespace, OUTCOME_NAMESPACE),
            self.epoch(),
            self.dealer_meta.commitment.clone(),
            self.dealer_meta.acks.values().cloned().collect(),
            reveals,
        ));

        self.ceremony_metadata
            .lock()
            .await
            .upsert_sync(self.epoch().into(), |meta| {
                meta.local_outcome = local_outcome.clone();
            })
            .await
            .expect("must persist local outcome");

        self.dealer_meta.outcome = local_outcome;

        Ok(())
    }

    // TODO(janis): find a better return value than a 3-tuple with a flag to
    // show failure/success.
    #[instrument(skip_all, fields(epoch = self.epoch()))]
    pub(super) async fn finalize(self) -> (Set<PublicKey>, RoundResult, bool) {
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
                return (self.config.dealers, self.previous, false);
            }
        };

        if let Some(player_me) = self.player_me {
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
                    return (self.config.dealers, self.previous, false);
                }
            };

            info!(
                ?disqualified,
                n_commitments,
                n_reveals,
                "successfully finalized DKG ceremony; returning new \
                    players and commitment"
            );

            (self.config.players, RoundResult::Output(output), true)
        } else {
            (self.config.players, RoundResult::Polynomial(public), true)
        }
    }

    pub(super) fn epoch(&self) -> Epoch {
        self.config.epoch
    }

    pub(super) fn deal_outcome(&self) -> Option<&DealOutcome> {
        self.dealer_meta.outcome.as_ref()
    }

    pub(super) fn config(&self) -> &Config {
        &self.config
    }
}

/// Metadata associated with a [Dealer].
struct DealerMetadata {
    /// The [Dealer] object.
    dealer: Dealer<PublicKey, MinSig>,
    /// The [Dealer]'s commitment.
    commitment: Public<MinSig>,
    /// The [Dealer]'s shares for all players.
    // shares: IndexMap<PublicKey, group::Share>,
    shares: BTreeMap<PublicKey, group::Share>,
    /// Signed acknowledgements from contributors.
    acks: BTreeMap<PublicKey, Ack>,
    /// The constructed dealing for inclusion in a block, if any.
    outcome: Option<DealOutcome>,
}

/// The result of a resharing operation from the local [Dealer].
///
/// [Dealer]: commonware_cryptography::bls12381::dkg::Dealer
#[derive(Clone)]
pub(crate) struct DealOutcome {
    /// The public key of the dealer.
    dealer: PublicKey,

    /// The dealer's signature over the resharing round, commitment, acks, and reveals.
    dealer_signature: Signature,

    /// The epoch of the resharing operation.
    epoch: Epoch,

    /// The new group public key polynomial.
    commitment: Public<MinSig>,

    /// All signed acknowledgements from participants.
    acks: Vec<Ack>,

    /// Any revealed secret shares.
    reveals: Vec<group::Share>,
}

impl DealOutcome {
    /// Creates a new [DealOutcome], signing its inner payload with the [commonware_cryptography::bls12381::dkg::Dealer]'s [Signer].
    pub(super) fn new(
        dealer_signer: &PrivateKey,
        namespace: &[u8],
        epoch: Epoch,
        commitment: Public<MinSig>,
        acks: Vec<Ack>,
        reveals: Vec<group::Share>,
    ) -> Self {
        // Sign the resharing outcome
        let payload = Self::signature_payload_from_parts(epoch, &commitment, &acks, &reveals);
        let dealer_signature = dealer_signer.sign(Some(namespace), payload.as_ref());

        Self {
            dealer: dealer_signer.public_key(),
            dealer_signature,
            epoch,
            commitment,
            acks,
            reveals,
        }
    }

    /// Verifies the [DealOutcome]'s signature.
    pub(super) fn verify(&self, namespace: &[u8]) -> bool {
        let payload = Self::signature_payload_from_parts(
            self.epoch,
            &self.commitment,
            &self.acks,
            &self.reveals,
        );
        self.dealer
            .verify(Some(namespace), &payload, &self.dealer_signature)
    }

    /// Returns the payload that was signed by the dealer, formed from raw parts.
    fn signature_payload_from_parts(
        epoch: Epoch,
        commitment: &Public<MinSig>,
        acks: &Vec<Ack>,
        reveals: &Vec<group::Share>,
    ) -> Vec<u8> {
        let mut buf = Vec::with_capacity(
            UInt(epoch).encode_size()
                + commitment.encode_size()
                + acks.encode_size()
                + reveals.encode_size(),
        );
        UInt(epoch).write(&mut buf);
        commitment.write(&mut buf);
        acks.write(&mut buf);
        reveals.write(&mut buf);
        buf
    }
}

impl Write for DealOutcome {
    fn write(&self, buf: &mut impl bytes::BufMut) {
        self.dealer.write(buf);
        self.dealer_signature.write(buf);
        UInt(self.epoch).write(buf);
        self.commitment.write(buf);
        self.acks.write(buf);
        self.reveals.write(buf);
    }
}

impl EncodeSize for DealOutcome {
    fn encode_size(&self) -> usize {
        self.dealer.encode_size()
            + self.dealer_signature.encode_size()
            + UInt(self.epoch).encode_size()
            + self.commitment.encode_size()
            + self.acks.encode_size()
            + self.reveals.encode_size()
    }
}

impl Read for DealOutcome {
    type Cfg = usize;

    fn read_cfg(
        buf: &mut impl bytes::Buf,
        cfg: &Self::Cfg,
    ) -> Result<Self, commonware_codec::Error> {
        Ok(Self {
            dealer: PublicKey::read(buf)?,
            dealer_signature: Signature::read(buf)?,
            epoch: UInt::read(buf)?.into(),
            commitment: Public::<MinSig>::read_cfg(buf, cfg)?,
            acks: Vec::read_cfg(buf, &(RangeCfg::from(0..=usize::MAX), ()))?,
            reveals: Vec::<group::Share>::read_cfg(buf, &(RangeCfg::from(0..=usize::MAX), ()))?,
        })
    }
}

/// Acknowledgement message sent by a [Player] node back to the [Dealer] node.
///
/// Acknowledges the receipt and verification of a [Share] message.
/// Includes a signature to authenticate the acknowledgment.
///
/// [Dealer]: crate::bls12381::dkg::Dealer
/// [Player]: crate::bls12381::dkg::Player
#[derive(Debug, Clone, PartialEq, Eq)]
struct Ack {
    /// The public key identifier of the [Player] sending the acknowledgment.
    ///
    /// [Player]: crate::bls12381::dkg::Player
    player: PublicKey,
    /// A signature covering the DKG round, dealer ID, and the [Dealer]'s commitment.
    /// This confirms the player received and validated the correct share.
    ///
    /// [Dealer]: crate::bls12381::dkg::Dealer
    signature: Signature,
}

impl Ack {
    /// Create a new [Ack] message, constructing and signing the payload with the provided [Signer].
    pub(super) fn new(
        namespace: &[u8],
        signer: PrivateKey,
        player: PublicKey,
        epoch: Epoch,
        dealer: &PublicKey,
        commitment: &Public<MinSig>,
    ) -> Self {
        let payload = Self::construct_signature_payload(epoch, dealer, commitment);
        let signature = signer.sign(Some(namespace), &payload);
        Self { player, signature }
    }

    fn construct_signature_payload(
        epoch: Epoch,
        dealer: &PublicKey,
        commitment: &Public<MinSig>,
    ) -> Vec<u8> {
        let mut payload =
            Vec::with_capacity(Epoch::SIZE + PublicKey::SIZE + commitment.encode_size());
        epoch.write(&mut payload);
        dealer.write(&mut payload);
        commitment.write(&mut payload);
        payload
    }

    fn verify(
        &self,
        namespace: &[u8],
        public_key: &PublicKey,
        epoch: Epoch,
        dealer: &PublicKey,
        commitment: &Public<MinSig>,
    ) -> bool {
        let payload = Self::construct_signature_payload(epoch, dealer, commitment);
        public_key.verify(Some(namespace), &payload, &self.signature)
    }
}

impl Write for Ack {
    fn write(&self, buf: &mut impl BufMut) {
        self.player.write(buf);
        self.signature.write(buf);
    }
}

impl EncodeSize for Ack {
    fn encode_size(&self) -> usize {
        self.player.encode_size() + self.signature.encode_size()
    }
}

impl Read for Ack {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &()) -> Result<Self, commonware_codec::Error> {
        Ok(Self {
            player: PublicKey::read(buf)?,
            signature: Signature::read(buf)?,
        })
    }
}

/// A result of a DKG/reshare round.
pub(super) enum RoundResult {
    /// The new group polynomial, if the manager is not a [Player].
    Polynomial(Public<MinSig>),
    /// The new group polynomial and the local share, if the manager is a [Player].
    Output(Output<MinSig>),
}

#[derive(Clone)]
struct Deal {
    commitment: Public<MinSig>,
    shares: BTreeMap<PublicKey, group::Share>,
    acks: BTreeMap<PublicKey, Ack>,
}

impl EncodeSize for Deal {
    fn encode_size(&self) -> usize {
        self.commitment.encode_size() + self.shares.encode_size() + self.acks.encode_size()
    }
}

impl Read for Deal {
    type Cfg = usize;

    fn read_cfg(buf: &mut impl Buf, cfg: &Self::Cfg) -> Result<Self, commonware_codec::Error> {
        let commitment = Public::<MinSig>::read_cfg(buf, cfg)?;
        let shares = BTreeMap::read_cfg(buf, &(RangeCfg::from(0..usize::MAX), ((), ())))?;
        let acks = BTreeMap::read_cfg(buf, &(RangeCfg::from(0..usize::MAX), ((), ())))?;
        Ok(Self {
            commitment,
            shares,
            acks,
        })
    }
}

impl Write for Deal {
    fn write(&self, buf: &mut impl bytes::BufMut) {
        self.commitment.write(buf);
        self.shares.write(buf);
        self.acks.write(buf);
    }
}

#[derive(Clone, Default)]
pub(super) struct RoundInfo {
    deal: Option<Deal>,
    received_shares: Vec<(PublicKey, Public<MinSig>, group::Share)>,
    local_outcome: Option<DealOutcome>,
    outcomes: Vec<DealOutcome>,
}

impl Write for RoundInfo {
    fn write(&self, buf: &mut impl bytes::BufMut) {
        self.deal.write(buf);
        self.received_shares.write(buf);
        self.local_outcome.write(buf);
        self.outcomes.write(buf);
    }
}

impl EncodeSize for RoundInfo {
    fn encode_size(&self) -> usize {
        self.deal.encode_size()
            + self.received_shares.encode_size()
            + self.local_outcome.encode_size()
            + self.outcomes.encode_size()
    }
}

impl Read for RoundInfo {
    // The consensus quorum
    type Cfg = usize;

    fn read_cfg(
        buf: &mut impl bytes::Buf,
        cfg: &Self::Cfg,
    ) -> Result<Self, commonware_codec::Error> {
        Ok(Self {
            deal: Option::<Deal>::read_cfg(buf, cfg)?,
            received_shares: Vec::<(PublicKey, Public<MinSig>, group::Share)>::read_cfg(
                buf,
                &(RangeCfg::from(0..usize::MAX), ((), *cfg, ())),
            )?,
            local_outcome: Option::<DealOutcome>::read_cfg(buf, cfg)?,
            outcomes: Vec::<DealOutcome>::read_cfg(buf, &(RangeCfg::from(0..usize::MAX), *cfg))?,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Share {
    /// The [Dealer]'s public commitment (coefficients of the polynomial).
    ///
    /// [Dealer]: crate::bls12381::dkg::Dealer
    pub(super) commitment: Public<MinSig>,
    /// The secret share evaluated for the recipient [Player].
    ///
    /// [Player]: crate::bls12381::dkg::Player
    pub(super) share: group::Share,
}

impl Write for Share {
    fn write(&self, buf: &mut impl BufMut) {
        self.commitment.write(buf);
        self.share.write(buf);
    }
}

impl EncodeSize for Share {
    fn encode_size(&self) -> usize {
        self.commitment.encode_size() + self.share.encode_size()
    }
}

impl Read for Share {
    type Cfg = u32;

    fn read_cfg(buf: &mut impl Buf, t: &u32) -> Result<Self, commonware_codec::Error> {
        let q = quorum(*t);
        Ok(Self {
            commitment: Public::<MinSig>::read_cfg(buf, &(q as usize))?,
            share: group::Share::read(buf)?,
        })
    }
}

#[derive(Clone, Debug, PartialEq)]
pub(super) enum Payload {
    /// Message sent by a dealer node to a player node.
    ///
    /// Contains the dealer's public commitment to their polynomial and the specific
    /// share calculated for the receiving player.
    Share(Share),

    /// Message sent by a player node back to the dealer node.
    ///
    /// Acknowledges the receipt and verification of a [Payload::Share] message.
    /// Includes a signature to authenticate the acknowledgment.
    Ack(Ack),
}

impl From<Ack> for Payload {
    fn from(value: Ack) -> Self {
        Payload::Ack(value)
    }
}

impl From<Share> for Payload {
    fn from(value: Share) -> Self {
        Payload::Share(value)
    }
}

impl Write for Payload {
    fn write(&self, buf: &mut impl BufMut) {
        match self {
            Payload::Share(inner) => {
                buf.put_u8(SHARE_TAG);
                inner.write(buf);
            }
            Payload::Ack(inner) => {
                buf.put_u8(ACK_TAG);
                inner.write(buf);
            }
        }
    }
}

const SHARE_TAG: u8 = 0;
const ACK_TAG: u8 = 1;

impl Read for Payload {
    type Cfg = u32;

    fn read_cfg(buf: &mut impl Buf, p: &u32) -> Result<Self, commonware_codec::Error> {
        let tag = u8::read(buf)?;
        let result = match tag {
            SHARE_TAG => Payload::Share(Share::read_cfg(buf, p)?),
            ACK_TAG => Payload::Ack(Ack::read(buf)?),
            _ => return Err(commonware_codec::Error::InvalidEnum(tag)),
        };
        Ok(result)
    }
}

impl EncodeSize for Payload {
    fn encode_size(&self) -> usize {
        u8::SIZE
            + match self {
                Payload::Share(inner) => inner.encode_size(),
                Payload::Ack(inner) => inner.encode_size(),
            }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub(super) struct Dkg {
    pub(super) epoch: Epoch,
    pub(super) payload: Payload,
}

impl Write for Dkg {
    fn write(&self, buf: &mut impl BufMut) {
        UInt(self.epoch).write(buf);
        self.payload.write(buf);
    }
}

impl Read for Dkg {
    type Cfg = u32;

    fn read_cfg(buf: &mut impl Buf, num_players: &u32) -> Result<Self, commonware_codec::Error> {
        let epoch = UInt::read(buf)?.into();
        let payload = Payload::read_cfg(buf, num_players)?;
        Ok(Self { epoch, payload })
    }
}

impl EncodeSize for Dkg {
    fn encode_size(&self) -> usize {
        UInt(self.epoch).encode_size() + self.payload.encode_size()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct PublicOutcome {
    pub(crate) participants: Set<PublicKey>,
    pub(crate) public: Public<MinSig>,
}

impl Write for PublicOutcome {
    fn write(&self, buf: &mut impl BufMut) {
        self.participants.write(buf);
        self.public.write(buf);
    }
}

impl Read for PublicOutcome {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _cfg: &Self::Cfg) -> Result<Self, commonware_codec::Error> {
        let participants = Set::read_cfg(buf, &(RangeCfg::from(0..=usize::MAX), ()))?;
        let public =
            Public::<MinSig>::read_cfg(buf, &(quorum(participants.len() as u32) as usize))?;
        Ok(Self {
            participants,
            public,
        })
    }
}

impl EncodeSize for PublicOutcome {
    fn encode_size(&self) -> usize {
        self.participants.encode_size() + self.public.encode_size()
    }
}
