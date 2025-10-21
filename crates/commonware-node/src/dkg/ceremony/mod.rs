//! An actively running DKG ceremony.

use std::{collections::BTreeMap, sync::Arc};

use bytes::{Buf, BufMut};
use commonware_codec::{EncodeSize, RangeCfg, Read, ReadExt as _, Write, varint::UInt};
use commonware_consensus::types::Epoch;
use commonware_cryptography::{
    Signer as _,
    bls12381::{
        dkg::{Arbiter, Dealer, Player, player::Output},
        primitives::{
            group::{self, Share},
            poly::Public,
            variant::MinSig,
        },
    },
    ed25519::{PrivateKey, PublicKey, Signature},
};
use commonware_p2p::utils::mux;
use commonware_p2p::{Receiver, Sender};
use commonware_runtime::{Clock, Metrics, Spawner, Storage};
use commonware_storage::metadata::Metadata;
use commonware_utils::{quorum, sequence::U64, set::Set};
use eyre::{WrapErr as _, bail, eyre};
use governor::{Quota, RateLimiter, middleware::NoOpMiddleware, state::keyed::HashMapStateStore};
use rand_core::CryptoRngCore;
use tracing::warn;

const ACK_NAMESPACE: &[u8] = b"_DKG_ACK";
const OUTCOME_NAMESPACE: &[u8] = b"_DKG_OUTCOME";

/// Recovering public weights is a heavy operation. For simplicity, we use just
/// 1 thread for now.
const WEIGHT_RECOVERY_CONCURRENCY: usize = 1;

pub(super) struct Config<TReceiver, TSender>
where
    TReceiver: Receiver,
    TSender: Sender,
{
    /// Prefix all signed messages to prevent replay attacks.
    pub(super) namespace: Vec<u8>,

    pub(super) me: PrivateKey,

    pub(super) partition_prefix: String,

    /// The previous public polynomial.
    //
    // TODO(janis): make this optional for those cases where we don't have a
    // public polynomial yet.
    pub(super) public: Public<MinSig>,

    /// Our previous share of the private polynomial.
    //
    // TODO(janis): make this optional for those cases where we don't have a
    // public polynomial yet.
    pub(super) share: group::Share,

    /// The current epoch.
    pub(super) epoch: Epoch,

    /// The dealers in the round.
    pub(super) dealers: Set<PublicKey>,

    /// The players in the round.
    pub(super) players: Set<PublicKey>,

    pub(super) send_rate_limit: Quota,
    // pub(super) store: Arc<Mutex<Metadata<E, U64, RoundInfo<V, C>>>>,
    pub(super) receiver: mux::SubReceiver<TReceiver>,
    pub(super) sender: mux::SubSender<TSender>,
}

pub(super) struct Ceremony<TContext, TReceiver, TSender>
where
    // TContext: Spawner + Metrics + CryptoRngCore + Clock + governor::clock::Clock + Storage,
    TContext: Clock + governor::clock::Clock + Metrics + Storage,
    TReceiver: Receiver,
    TSender: Sender,
{
    config: Config<TReceiver, TSender>,

    /// The previous group polynomial and (if dealing) share.
    previous: RoundResult,

    /// The rate limiter for sending messages.
    #[allow(clippy::type_complexity)]
    rate_limiter: RateLimiter<
        PublicKey,
        HashMapStateStore<PublicKey>,
        TContext,
        NoOpMiddleware<TContext::Instant>,
    >,

    /// [Dealer] metadata, if this manager is also dealing.
    dealer_meta: Option<DealerMetadata>,

    /// The local [Player] for this round, if the manager is playing.
    //
    // NOTE: right now we should always be playing.
    player_me: Option<(u32, Player<PublicKey, MinSig>)>,

    /// The local [Arbiter] for this round.
    arbiter: Arbiter<PublicKey, MinSig>,

    /// The [Metadata] store used for persisting round state.
    round_metadata: Metadata<TContext, U64, RoundInfo>,
}

impl<TContext, TReceiver, TSender> Ceremony<TContext, TReceiver, TSender>
where
    TContext: Spawner + Metrics + CryptoRngCore + Clock + governor::clock::Clock + Storage,
    TReceiver: Receiver,
    TSender: Sender,
{
    /// Initialize a DKG ceremony.
    pub(super) async fn init(
        context: &mut TContext,
        config: Config<TReceiver, TSender>,
    ) -> eyre::Result<Self> {
        // XXX: this information must be per-round since the codec-config is
        // dictated by the number of dealers (FIXME: players?).
        //
        let round_metadata: Metadata<_, U64, RoundInfo> = Metadata::init(
            context.with_label("round_metadata"),
            commonware_storage::metadata::Config {
                // TODO: should we provide a prefix on the partition?
                partition: config.partition_prefix.clone(),
                codec_config: quorum(config.dealers.len() as u32) as usize,
            },
        )
        .await
        .expect("failed to initialize dkg round metadata");

        let mut player_me = config
            .players
            .position(&config.me.public_key())
            .map(|signer_index| {
                let player = Player::new(
                    config.me.public_key(),
                    Some(config.public.clone()),
                    config.dealers.clone(),
                    config.players.clone(),
                    WEIGHT_RECOVERY_CONCURRENCY,
                );

                (signer_index as u32, player)
            });

        let mut arbiter = Arbiter::new(
            Some(config.public.clone()),
            config.dealers.clone(),
            config.players.clone(),
            WEIGHT_RECOVERY_CONCURRENCY,
        );

        // TODO(janis): move this "recovery" logic to a function.
        let dealer_meta = if let Some(meta) = round_metadata.get(&config.epoch.into()) {
            for outcome in &meta.outcomes {
                let ack_indices = outcome
                    .acks
                    .iter()
                    .map(|ack| ack.player)
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

            if let Some((_, me)) = &mut player_me {
                for (dealer, commitment, share) in meta.received_shares.clone() {
                    me.share(dealer, commitment, share)
                        .wrap_err("failed updating my player information with stored metadata")?;
                }
            }

            let Some((commitment, shares, acks)) = meta.deal.clone() else {
                bail!(
                    "all players must currently be dealers, but no dealer \
                    information was written to disk even though some round \
                    information was; this is a problem"
                );
            };
            let (mut dealer, _, _) =
                Dealer::new(context, Some(config.share.clone()), config.players.clone());
            for ack in acks.values() {
                let player_id = config
                    .players
                    .get(ack.player as usize)
                    .cloned()
                    .ok_or_else(|| eyre!(
                        "player index `{idx}` recovered from storage exceeds number of players `{num}` of this round; this is a problem",
                        idx = ack.player,
                        num = config.players.len(),
                    ))?;
                dealer.ack(player_id.clone())
                    .wrap_err_with(|| format!(
                         "failed verifying and tracking acknowledgment by player `{player_id}` read from storage"
                     ))?;
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
                Dealer::new(context, Some(config.share.clone()), config.players.clone());
            DealerMetadata {
                dealer,
                commitment,
                shares,
                acks: BTreeMap::new(),
                outcome: None,
            }
        };

        let rate_limiter = RateLimiter::hashmap_with_clock(config.send_rate_limit, &*context);

        let previous = RoundResult::Output(Output {
            public: config.public.clone(),
            share: config.share.clone(),
        });
        Ok(Self {
            config,
            previous,
            rate_limiter,
            dealer_meta: Some(dealer_meta),
            player_me,
            arbiter,
            round_metadata,
        })
    }

    pub(super) fn epoch(&self) -> Epoch {
        self.config.epoch
    }
}

/// Metadata associated with a [Dealer].
struct DealerMetadata {
    /// The [Dealer] object.
    dealer: Dealer<PublicKey, MinSig>,
    /// The [Dealer]'s commitment.
    commitment: Public<MinSig>,
    /// The [Dealer]'s shares for all players.
    shares: Set<Share>,
    /// Signed acknowledgements from contributors.
    acks: BTreeMap<u32, Ack>,
    /// The constructed dealing for inclusion in a block, if any.
    outcome: Option<DealOutcome>,
}

/// The result of a resharing operation from the local [Dealer].
///
/// [Dealer]: commonware_cryptography::bls12381::dkg::Dealer
#[derive(Clone)]
struct DealOutcome {
    /// The public key of the dealer.
    dealer: PublicKey,

    /// The dealer's signature over the resharing round, commitment, acks, and reveals.
    dealer_signature: Signature,

    /// The round of the resharing operation.
    round: u64,

    /// The new group public key polynomial.
    commitment: Public<MinSig>,

    /// All signed acknowledgements from participants.
    acks: Vec<Ack>,

    /// Any revealed secret shares.
    reveals: Vec<group::Share>,
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
    player: u32,
    /// A signature covering the DKG round, dealer ID, and the [Dealer]'s commitment.
    /// This confirms the player received and validated the correct share.
    ///
    /// [Dealer]: crate::bls12381::dkg::Dealer
    signature: Signature,
}

impl Write for Ack {
    fn write(&self, buf: &mut impl BufMut) {
        UInt(self.player).write(buf);
        self.signature.write(buf);
    }
}

impl EncodeSize for Ack {
    fn encode_size(&self) -> usize {
        UInt(self.player).encode_size() + self.signature.encode_size()
    }
}

impl Read for Ack {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &()) -> Result<Self, commonware_codec::Error> {
        Ok(Self {
            player: UInt::read(buf)?.into(),
            signature: Signature::read(buf)?,
        })
    }
}

/// A result of a DKG/reshare round.
enum RoundResult {
    /// The new group polynomial, if the manager is not a [Player].
    Polynomial(Public<MinSig>),
    /// The new group polynomial and the local share, if the manager is a [Player].
    Output(Output<MinSig>),
}

pub(super) struct RoundInfo {
    deal: Option<(Public<MinSig>, Set<Share>, BTreeMap<u32, Ack>)>,
    received_shares: Vec<(PublicKey, Public<MinSig>, Share)>,
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
            deal: Option::<(Public<MinSig>, Set<Share>, BTreeMap<u32, Ack>)>::read_cfg(
                buf,
                &(
                    *cfg,
                    (RangeCfg::from(0..usize::MAX), ()),
                    (RangeCfg::from(0..usize::MAX), ((), ())),
                ),
            )?,
            received_shares: Vec::<(PublicKey, Public<MinSig>, Share)>::read_cfg(
                buf,
                &(RangeCfg::from(0..usize::MAX), ((), *cfg, ())),
            )?,
            local_outcome: Option::<DealOutcome>::read_cfg(buf, cfg)?,
            outcomes: Vec::<DealOutcome>::read_cfg(buf, &(RangeCfg::from(0..usize::MAX), *cfg))?,
        })
    }
}

impl Write for DealOutcome {
    fn write(&self, buf: &mut impl bytes::BufMut) {
        self.dealer.write(buf);
        self.dealer_signature.write(buf);
        UInt(self.round).write(buf);
        self.commitment.write(buf);
        self.acks.write(buf);
        self.reveals.write(buf);
    }
}

impl EncodeSize for DealOutcome {
    fn encode_size(&self) -> usize {
        self.dealer.encode_size()
            + self.dealer_signature.encode_size()
            + UInt(self.round).encode_size()
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
            round: UInt::read(buf)?.into(),
            commitment: Public::<MinSig>::read_cfg(buf, cfg)?,
            acks: Vec::<Ack>::read_cfg(buf, &(RangeCfg::from(0..=usize::MAX), ()))?,
            reveals: Vec::<Share>::read_cfg(buf, &(RangeCfg::from(0..=usize::MAX), ()))?,
        })
    }
}
