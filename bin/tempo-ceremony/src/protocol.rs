//! DKG protocol implementation for the genesis ceremony.

use crate::{
    constants::{GENESIS_EPOCH, protocol::*},
    error::Error,
};
use bytes::{Buf, BufMut};
use commonware_codec::{Encode, EncodeSize, Read, ReadExt, Write};
use commonware_cryptography::{
    Signer,
    bls12381::{
        dkg::{Arbiter, Player},
        primitives::{group, poly::Public, variant::MinSig},
    },
    ed25519::{PrivateKey, PublicKey},
};
use commonware_p2p::{Recipients, Sender};
use commonware_utils::{quorum, set::Ordered, union};
use indexmap::IndexSet;
use std::collections::{BTreeMap, HashSet};
use tempo_dkg_onchain_artifacts::{Ack, IntermediateOutcome, PublicOutcome};

/// Message types for the genesis ceremony.
#[derive(Clone, Debug)]
pub enum Message {
    /// Ping to check connectivity.
    Ping,
    /// Response to Ping.
    Pong,
    /// Share from dealer to player.
    Share {
        /// The dealer's public polynomial commitment.
        commitment: Public<MinSig>,
        /// The player's secret share.
        share: group::Share,
    },
    /// Acknowledgment from player to dealer.
    Ack(Ack),
    /// Intermediate outcome broadcast by dealer.
    Dealing(IntermediateOutcome),
    /// Acknowledgment that we received a dealing.
    DealingAck {
        /// The dealer whose dealing we received.
        dealer: PublicKey,
    },
    /// Computed public outcome for verification.
    Outcome(PublicOutcome),
    /// Acknowledgment that we received an outcome. Bool indicates if it matched ours.
    OutcomeAck(bool),
}

impl Write for Message {
    fn write(&self, buf: &mut impl BufMut) {
        match self {
            Self::Ping => buf.put_u8(0),
            Self::Pong => buf.put_u8(1),
            Self::Share { commitment, share } => {
                buf.put_u8(2);
                commitment.write(buf);
                share.write(buf);
            }
            Self::Ack(ack) => {
                buf.put_u8(3);
                ack.write(buf);
            }
            Self::Dealing(dealing) => {
                buf.put_u8(4);
                dealing.write(buf);
            }
            Self::DealingAck { dealer } => {
                buf.put_u8(5);
                dealer.write(buf);
            }
            Self::Outcome(outcome) => {
                buf.put_u8(6);
                outcome.write(buf);
            }
            Self::OutcomeAck(matched) => {
                buf.put_u8(7);
                buf.put_u8(if *matched { 1 } else { 0 });
            }
        }
    }
}

impl EncodeSize for Message {
    fn encode_size(&self) -> usize {
        1 + match self {
            Self::Ping | Self::Pong => 0,
            Self::OutcomeAck(_) => 1,
            Self::Share { commitment, share } => commitment.encode_size() + share.encode_size(),
            Self::Ack(ack) => ack.encode_size(),
            Self::Dealing(dealing) => dealing.encode_size(),
            Self::DealingAck { dealer } => dealer.encode_size(),
            Self::Outcome(outcome) => outcome.encode_size(),
        }
    }
}

impl Read for Message {
    type Cfg = u32;

    fn read_cfg(buf: &mut impl Buf, n_players: &u32) -> Result<Self, commonware_codec::Error> {
        let tag = u8::read(buf)?;
        match tag {
            0 => Ok(Self::Ping),
            1 => Ok(Self::Pong),
            2 => {
                let q = quorum(*n_players);
                let commitment = Public::<MinSig>::read_cfg(buf, &(q as usize))?;
                let share = group::Share::read(buf)?;
                Ok(Self::Share { commitment, share })
            }
            3 => Ok(Self::Ack(Ack::read(buf)?)),
            4 => Ok(Self::Dealing(IntermediateOutcome::read(buf)?)),
            5 => Ok(Self::DealingAck {
                dealer: PublicKey::read(buf)?,
            }),
            6 => Ok(Self::Outcome(PublicOutcome::read(buf)?)),
            7 => Ok(Self::OutcomeAck(u8::read(buf)? != 0)),
            _ => Err(commonware_codec::Error::InvalidEnum(tag)),
        }
    }
}

/// Tracks which peers have responded to a broadcast.
struct AckTracker<T> {
    /// Map from sender public key to their response value.
    received: BTreeMap<PublicKey, T>,
}

impl<T> Default for AckTracker<T> {
    fn default() -> Self {
        Self {
            received: BTreeMap::new(),
        }
    }
}

impl<T> AckTracker<T> {
    fn insert(&mut self, from: PublicKey, value: T) {
        self.received.insert(from, value);
    }

    fn contains(&self, pk: &PublicKey) -> bool {
        self.received.contains_key(pk)
    }

    fn len(&self) -> usize {
        self.received.len()
    }

    fn values(&self) -> impl Iterator<Item = &T> {
        self.received.values()
    }

    fn missing<'a>(&'a self, all: &'a Ordered<PublicKey>) -> impl Iterator<Item = &'a PublicKey> {
        all.iter().filter(|p| !self.received.contains_key(*p))
    }

    fn iter(&self) -> impl Iterator<Item = (&PublicKey, &T)> {
        self.received.iter()
    }
}

/// Our state as a dealer (distributing shares, collecting acks).
struct DealerState {
    /// Our public polynomial commitment.
    commitment: Public<MinSig>,
    /// Shares we generated for each participant.
    shares: BTreeMap<PublicKey, group::Share>,
    /// Acks received from players for our shares.
    acks: AckTracker<Ack>,
    /// Our constructed dealing (set after all acks received).
    dealing: Option<IntermediateOutcome>,
    /// Confirmations that peers received our dealing.
    dealing_acks: AckTracker<()>,
}

/// Our state as a player (receiving shares, producing outcome).
struct PlayerState {
    /// DKG player state machine for collecting shares.
    player: Player<PublicKey, MinSig>,
    /// DKG arbiter for validating dealings.
    arbiter: Arbiter<PublicKey, MinSig>,
    /// Dealers we've received shares from.
    received_from: HashSet<PublicKey>,
    /// Collected dealings from all dealers.
    dealings: BTreeMap<PublicKey, IntermediateOutcome>,
}

/// Verification phase state.
struct VerificationState {
    /// Public outcomes received from all participants.
    outcomes: AckTracker<PublicOutcome>,
    /// Acks received confirming peers got our outcome. Bool indicates if they accepted (true) or rejected (false).
    outcome_acks: AckTracker<bool>,
    /// Our computed public outcome for comparison.
    our_outcome: Option<PublicOutcome>,
}

/// Ceremony membership and identity.
struct Membership {
    /// Our signing key.
    me: PrivateKey,
    /// Our public key (cached to avoid repeated derivation).
    my_public_key: PublicKey,
    /// Ordered list of all participants (deterministic order).
    participants: Ordered<PublicKey>,
    /// Indexed set for O(1) membership and index lookups.
    indexed: IndexSet<PublicKey>,
    /// Set of peers we've confirmed connectivity with.
    connected: HashSet<PublicKey>,
}

/// Core DKG ceremony state machine.
pub struct GenesisCeremony {
    /// Unique namespace to prevent replay attacks across ceremonies.
    namespace: Vec<u8>,
    /// Ceremony membership and our identity.
    membership: Membership,
    /// Our state as a dealer (distributing shares).
    dealer: DealerState,
    /// Our state as a player (receiving shares).
    player: PlayerState,
    /// Verification phase state (comparing outcomes).
    verification: VerificationState,
}

impl GenesisCeremony {
    /// Create a new genesis ceremony instance.
    pub fn new(
        context: &mut impl rand_core::CryptoRngCore,
        namespace: Vec<u8>,
        me: PrivateKey,
        participants: Ordered<PublicKey>,
    ) -> Result<Self, Error> {
        let my_public_key = me.public_key();
        let indexed: IndexSet<_> = participants.iter().cloned().collect();

        if !indexed.contains(&my_public_key) {
            return Err(Error::NotInParticipants);
        }

        let (_, commitment, shares) = commonware_cryptography::bls12381::dkg::Dealer::<
            PublicKey,
            MinSig,
        >::new(context, None, participants.clone());
        let shares: BTreeMap<_, _> = participants.iter().cloned().zip(shares).collect();

        Ok(Self {
            namespace,
            membership: Membership {
                me,
                my_public_key: my_public_key.clone(),
                participants: participants.clone(),
                indexed,
                connected: HashSet::new(),
            },
            dealer: DealerState {
                commitment,
                shares,
                acks: AckTracker::default(),
                dealing: None,
                dealing_acks: AckTracker::default(),
            },
            player: PlayerState {
                player: Player::new(
                    my_public_key,
                    None,
                    participants.clone(),
                    participants.clone(),
                    1,
                ),
                arbiter: Arbiter::new(None, participants.clone(), participants, 1),
                received_from: HashSet::new(),
                dealings: BTreeMap::new(),
            },
            verification: VerificationState {
                outcomes: AckTracker::default(),
                outcome_acks: AckTracker::default(),
                our_outcome: None,
            },
        })
    }

    /// Send ping messages to all unconnected peers.
    pub async fn send_pings<S: Sender<PublicKey = PublicKey>>(
        &self,
        sender: &mut S,
    ) -> eyre::Result<()> {
        for p in &self.membership.participants {
            if p == &self.membership.my_public_key || self.membership.connected.contains(p) {
                continue;
            }
            sender
                .send(
                    Recipients::One(p.clone()),
                    Message::Ping.encode().freeze(),
                    false,
                )
                .await?;
        }
        Ok(())
    }

    /// Check if all peers are connected.
    pub fn all_connected(&self) -> bool {
        self.membership.connected.len() == self.membership.participants.len() - 1
    }

    /// Get set of connected peers.
    pub fn connected_peers(&self) -> &HashSet<PublicKey> {
        &self.membership.connected
    }

    /// Get our public key.
    pub fn my_public_key(&self) -> &PublicKey {
        &self.membership.my_public_key
    }

    /// Process our own share (everyone is both dealer and player).
    fn handle_self_share(&mut self) -> eyre::Result<()> {
        self.player.player.share(
            self.membership.my_public_key.clone(),
            self.dealer.commitment.clone(),
            self.dealer
                .shares
                .get(&self.membership.my_public_key)
                .expect("self share exists")
                .clone(),
        )?;
        let self_ack = Ack::self_ack(
            &union(&self.namespace, ACK_NAMESPACE),
            self.membership.me.clone(),
            GENESIS_EPOCH,
            &self.dealer.commitment,
        );
        self.dealer
            .acks
            .insert(self.membership.my_public_key.clone(), self_ack);
        Ok(())
    }

    /// Send shares to participants who haven't acked yet.
    ///
    /// On first call, also processes our own share.
    pub async fn send_shares<S: Sender<PublicKey = PublicKey>>(
        &mut self,
        sender: &mut S,
    ) -> eyre::Result<()> {
        if !self.dealer.acks.contains(&self.membership.my_public_key) {
            self.handle_self_share()?;
        }

        for pk in self.dealer.acks.missing(&self.membership.participants) {
            if pk == &self.membership.my_public_key {
                continue;
            }
            let msg = Message::Share {
                commitment: self.dealer.commitment.clone(),
                share: self
                    .dealer
                    .shares
                    .get(pk)
                    .expect("share for participant")
                    .clone(),
            };
            sender
                .send(Recipients::One(pk.clone()), msg.encode().freeze(), true)
                .await?;
        }
        Ok(())
    }

    /// Process an incoming message.
    pub async fn process_message<S: Sender<PublicKey = PublicKey>>(
        &mut self,
        sender: &mut S,
        from: PublicKey,
        msg: Message,
    ) -> eyre::Result<()> {
        match msg {
            Message::Ping => {
                sender
                    .send(
                        Recipients::One(from),
                        Message::Pong.encode().freeze(),
                        false,
                    )
                    .await?;
            }
            Message::Pong => {
                self.membership.connected.insert(from);
            }
            Message::Share { commitment, share } => {
                self.handle_share(sender, from, commitment, share).await?;
            }
            Message::Ack(ack) => {
                self.handle_ack(ack)?;
            }
            Message::Dealing(dealing) => {
                self.handle_dealing(sender, dealing).await?;
            }
            Message::DealingAck { dealer } => {
                if dealer == self.membership.my_public_key {
                    self.dealer.dealing_acks.insert(from, ());
                }
            }
            Message::Outcome(outcome) => {
                self.handle_outcome(sender, from, outcome).await?;
            }
            Message::OutcomeAck(matched) => {
                self.verification.outcome_acks.insert(from, matched);
            }
        }
        Ok(())
    }

    async fn handle_outcome<S: Sender<PublicKey = PublicKey>>(
        &mut self,
        sender: &mut S,
        from: PublicKey,
        outcome: PublicOutcome,
    ) -> eyre::Result<()> {
        if !self.membership.indexed.contains(&from) {
            return Err(Error::UnknownParticipant(from.into()).into());
        }
        let matched = match self.verification.our_outcome {
            Some(ref ours) => &outcome == ours,
            None => true, // We haven't computed ours yet, assume it will match
        };
        // Always send ack so sender doesn't hang
        sender
            .send(
                Recipients::One(from.clone()),
                Message::OutcomeAck(matched).encode().freeze(),
                true,
            )
            .await?;
        if !matched {
            return Err(Error::OutcomeMismatch {
                from: from.into(),
                expected: self.verification.our_outcome.clone().unwrap().into(),
                got: outcome.into(),
            }
            .into());
        }
        if !self.verification.outcomes.contains(&from) {
            self.verification.outcomes.insert(from, outcome);
        }
        Ok(())
    }

    async fn handle_share<S: Sender<PublicKey = PublicKey>>(
        &mut self,
        sender: &mut S,
        from: PublicKey,
        commitment: Public<MinSig>,
        share: group::Share,
    ) -> eyre::Result<()> {
        if !self.membership.indexed.contains(&from) {
            return Err(Error::UnknownParticipant(from.into()).into());
        }
        if !self.player.received_from.contains(&from) {
            self.player
                .player
                .share(from.clone(), commitment.clone(), share)?;
            self.player.received_from.insert(from.clone());
        }
        let ack = Ack::new(
            &union(&self.namespace, ACK_NAMESPACE),
            self.membership.me.clone(),
            self.membership.my_public_key.clone(),
            GENESIS_EPOCH,
            &from,
            &commitment,
        );
        sender
            .send(
                Recipients::One(from),
                Message::Ack(ack).encode().freeze(),
                true,
            )
            .await?;
        Ok(())
    }

    fn handle_ack(&mut self, ack: Ack) -> Result<(), Error> {
        let player = ack.player().clone();
        if !self.membership.indexed.contains(&player) {
            return Err(Error::UnknownParticipant(player.into()));
        }
        if !ack.verify(
            &union(&self.namespace, ACK_NAMESPACE),
            &player,
            GENESIS_EPOCH,
            &self.membership.my_public_key,
            &self.dealer.commitment,
        ) {
            return Err(Error::InvalidAckSignature(player.into()));
        }
        self.dealer.acks.insert(player, ack);
        Ok(())
    }

    /// Validate a dealing's structure and signature.
    fn validate_dealing(&self, dealing: &IntermediateOutcome) -> Result<(), Error> {
        let dealer = dealing.dealer();
        if !self.membership.indexed.contains(dealer) {
            return Err(Error::UnknownParticipant(dealer.clone().into()));
        }
        if !dealing.verify(&union(&self.namespace, OUTCOME_NAMESPACE)) {
            return Err(Error::InvalidDealingSignature(dealer.clone().into()));
        }
        if !dealing.reveals().is_empty() {
            return Err(Error::RevealsNotAllowed {
                dealer: dealer.clone().into(),
                count: dealing.reveals().len(),
            });
        }
        if dealing.acks().len() != self.membership.participants.len() {
            return Err(Error::MissingAcksInDealing {
                dealer: dealer.clone().into(),
                expected: self.membership.participants.len(),
                got: dealing.acks().len(),
            });
        }
        Ok(())
    }

    /// Validate all acks within a dealing and return their indices.
    fn validate_dealing_acks(&self, dealing: &IntermediateOutcome) -> Result<Vec<u32>, Error> {
        let dealer = dealing.dealer();
        let mut ack_indices = Vec::with_capacity(dealing.acks().len());

        for ack in dealing.acks() {
            let acker = ack.player();
            if !self.membership.indexed.contains(acker) {
                return Err(Error::UnknownParticipant(acker.clone().into()));
            }
            if !ack.verify(
                &union(&self.namespace, ACK_NAMESPACE),
                acker,
                GENESIS_EPOCH,
                dealer,
                dealing.commitment(),
            ) {
                return Err(Error::InvalidAckInDealing {
                    dealer: dealer.clone().into(),
                    acker: acker.clone().into(),
                });
            }
            if let Some(idx) = self.membership.indexed.get_index_of(acker) {
                ack_indices.push(idx as u32);
            }
        }
        Ok(ack_indices)
    }

    async fn handle_dealing<S: Sender<PublicKey = PublicKey>>(
        &mut self,
        sender: &mut S,
        dealing: IntermediateOutcome,
    ) -> eyre::Result<()> {
        let dealer = dealing.dealer().clone();

        if !self.player.dealings.contains_key(&dealer) {
            self.validate_dealing(&dealing)?;
            let ack_indices = self.validate_dealing_acks(&dealing)?;

            self.player.arbiter.commitment(
                dealer.clone(),
                dealing.commitment().clone(),
                ack_indices,
                vec![],
            )?;
            self.player.dealings.insert(dealer.clone(), dealing);
        }

        sender
            .send(
                Recipients::One(dealer.clone()),
                Message::DealingAck { dealer }.encode().freeze(),
                true,
            )
            .await?;
        Ok(())
    }

    /// Check if we have all acks for our dealing.
    pub fn has_all_acks(&self) -> bool {
        self.dealer.acks.len() == self.membership.participants.len()
    }

    /// Get ceremony status for display.
    pub fn status(&self) -> CeremonyStatus {
        CeremonyStatus {
            missing_acks: self
                .dealer
                .acks
                .missing(&self.membership.participants)
                .cloned()
                .collect(),
            missing_dealings: self
                .membership
                .participants
                .iter()
                .filter(|p| !self.player.dealings.contains_key(*p))
                .cloned()
                .collect(),
            missing_dealing_acks: self
                .dealer
                .dealing_acks
                .missing(&self.membership.participants)
                .filter(|p| *p != &self.membership.my_public_key)
                .cloned()
                .collect(),
            missing_outcomes: self
                .verification
                .outcomes
                .missing(&self.membership.participants)
                .cloned()
                .collect(),
            missing_outcome_acks: self
                .verification
                .outcome_acks
                .missing(&self.membership.participants)
                .filter(|p| *p != &self.membership.my_public_key)
                .cloned()
                .collect(),
        }
    }

    /// Construct our dealing from collected acks.
    pub fn construct_dealing(&mut self) -> Result<&IntermediateOutcome, Error> {
        if !self.has_all_acks() {
            return Err(Error::MissingAcks);
        }
        self.dealer.dealing = Some(IntermediateOutcome::new(
            self.membership.participants.len() as u16,
            &self.membership.me,
            &union(&self.namespace, OUTCOME_NAMESPACE),
            GENESIS_EPOCH,
            self.dealer.commitment.clone(),
            self.dealer.acks.values().cloned().collect(),
            vec![],
        ));
        Ok(self.dealer.dealing.as_ref().expect("just set"))
    }

    /// Broadcast our dealing to all peers.
    pub async fn broadcast_dealing<S: Sender<PublicKey = PublicKey>>(
        &self,
        sender: &mut S,
    ) -> eyre::Result<()> {
        let dealing = self
            .dealer
            .dealing
            .as_ref()
            .ok_or_else(|| eyre::eyre!("No dealing"))?;
        for pk in self
            .dealer
            .dealing_acks
            .missing(&self.membership.participants)
        {
            if pk == &self.membership.my_public_key {
                continue;
            }
            sender
                .send(
                    Recipients::One(pk.clone()),
                    Message::Dealing(dealing.clone()).encode().freeze(),
                    true,
                )
                .await?;
        }
        Ok(())
    }

    /// Check if dealings phase is complete.
    pub fn dealings_phase_complete(&self) -> bool {
        self.player.dealings.len() == self.membership.participants.len()
            && self.dealer.dealing_acks.len() == self.membership.participants.len() - 1
    }

    /// Compute our private share and group public polynomial.
    pub fn compute_shares(&self) -> eyre::Result<FinalizedShares> {
        let (result, disqualified) = self.player.arbiter.clone().finalize();
        if !disqualified.is_empty() {
            tracing::warn!(?disqualified, "Disqualified dealers");
        }

        let arbiter_output = result?;
        let my_index = self
            .membership
            .indexed
            .get_index_of(&self.membership.my_public_key)
            .expect("in participants");

        let reveals: BTreeMap<u32, group::Share> = arbiter_output
            .reveals
            .into_iter()
            .filter_map(|(dealer_idx, shares)| {
                shares
                    .iter()
                    .find(|s| s.index == my_index as u32)
                    .cloned()
                    .map(|s| (dealer_idx, s))
            })
            .collect();

        let out = self
            .player
            .player
            .clone()
            .finalize(arbiter_output.commitments, reveals)?;
        Ok(FinalizedShares {
            public: out.public,
            share: out.share,
        })
    }

    /// Build public outcome from finalized shares.
    pub fn build_public_outcome(&self, shares: &FinalizedShares) -> PublicOutcome {
        PublicOutcome {
            epoch: GENESIS_EPOCH,
            participants: self.membership.participants.clone(),
            public: shares.public.clone(),
        }
    }

    /// Broadcast our public outcome for verification.
    pub async fn broadcast_outcome<S: Sender<PublicKey = PublicKey>>(
        &mut self,
        sender: &mut S,
        outcome: PublicOutcome,
    ) -> eyre::Result<()> {
        self.verification.our_outcome = Some(outcome.clone());
        for (pk, stored) in self.verification.outcomes.iter() {
            if stored != &outcome {
                return Err(Error::OutcomeMismatch {
                    from: pk.clone().into(),
                    expected: outcome.clone().into(),
                    got: stored.clone().into(),
                }
                .into());
            }
        }
        self.verification
            .outcomes
            .insert(self.membership.my_public_key.clone(), outcome.clone());
        // Send to all peers who haven't acked our outcome yet
        for pk in self
            .verification
            .outcome_acks
            .missing(&self.membership.participants)
        {
            if pk == &self.membership.my_public_key {
                continue;
            }
            sender
                .send(
                    Recipients::One(pk.clone()),
                    Message::Outcome(outcome.clone()).encode().freeze(),
                    true,
                )
                .await?;
        }
        Ok(())
    }

    /// Check if we have all outcomes and all peers acked ours.
    /// Returns Ok(true) if complete and all accepted.
    /// Returns Ok(false) if still waiting.
    /// Returns Err if complete but some peers rejected our outcome.
    pub fn has_all_outcomes(&self) -> eyre::Result<bool> {
        let n = self.membership.participants.len();
        let have_all_outcomes = self.verification.outcomes.len() == n;
        let have_all_acks = self.verification.outcome_acks.len() == n - 1;

        if !have_all_outcomes || !have_all_acks {
            return Ok(false);
        }

        // Check for any rejections
        let rejections: Vec<_> = self
            .verification
            .outcome_acks
            .iter()
            .filter(|(_, matched)| !**matched)
            .map(|(pk, _)| pk.clone())
            .collect();

        if !rejections.is_empty() {
            return Err(Error::OutcomeRejected(rejections.into()).into());
        }

        Ok(true)
    }

    /// Consume ceremony and produce final outcome.
    pub fn into_outcome(
        self,
        shares: FinalizedShares,
        public_outcome: PublicOutcome,
    ) -> CeremonyOutcome {
        CeremonyOutcome {
            share: shares.share,
            participants: self.membership.participants,
            public_outcome,
            dealings: self.player.dealings,
        }
    }
}

/// Intermediate result from compute_shares().
pub struct FinalizedShares {
    /// The group public polynomial.
    pub public: Public<MinSig>,
    /// Our private share.
    pub share: group::Share,
}

/// Final ceremony outcome.
pub struct CeremonyOutcome {
    /// Our private share of the group key.
    pub share: group::Share,
    /// Ordered list of participants.
    pub participants: Ordered<PublicKey>,
    /// Public outcome for genesis block.
    pub public_outcome: PublicOutcome,
    /// All dealings for audit trail.
    pub dealings: BTreeMap<PublicKey, IntermediateOutcome>,
}

/// Status information for display.
pub struct CeremonyStatus {
    /// Participants who haven't acked our shares.
    pub missing_acks: Vec<PublicKey>,
    /// Dealers whose dealings we haven't received.
    pub missing_dealings: Vec<PublicKey>,
    /// Participants who haven't acked our dealing.
    pub missing_dealing_acks: Vec<PublicKey>,
    /// Participants whose outcomes we haven't received.
    pub missing_outcomes: Vec<PublicKey>,
    /// Participants who haven't acked our outcome.
    pub missing_outcome_acks: Vec<PublicKey>,
}
