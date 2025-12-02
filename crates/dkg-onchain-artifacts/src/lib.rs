//! Items that are written to chain.

use bytes::{Buf, BufMut};
use commonware_codec::{
    EncodeSize, FixedSize as _, RangeCfg, Read, ReadExt as _, Write, varint::UInt,
};
use commonware_consensus::types::Epoch;
use commonware_cryptography::{
    Signer as _, Verifier as _,
    bls12381::primitives::{group, poly::Public, variant::MinSig},
    ed25519::{PrivateKey, PublicKey, Signature},
};
use commonware_utils::{quorum, set::Ordered};

/// A message from a player to a dealer, confirming the receipt of share.
///
/// Contains the player's public key, as well as its signature over the
/// ceremony's epoch, dealear public key, and commitment contained in the
/// share message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ack {
    /// The public key identifier of the player sending the acknowledgment.
    player: PublicKey,
    /// A signature covering the DKG round, dealer ID, and the dealer's commitment.
    /// This confirms the player received and validated the correct share.
    signature: Signature,
}

impl Ack {
    /// Create a new acknowledgment signed by `signer`.
    pub fn new(
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

    pub fn verify(
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

    pub fn player(&self) -> &PublicKey {
        &self.player
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

/// The outcome of a dkg ceremony round.
///
/// Called public because it only contains the public polynomial.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PublicOutcome {
    pub epoch: Epoch,
    pub participants: Ordered<PublicKey>,
    pub public: Public<MinSig>,
}

impl Write for PublicOutcome {
    fn write(&self, buf: &mut impl BufMut) {
        UInt(self.epoch).write(buf);
        self.participants.write(buf);
        self.public.write(buf);
    }
}

impl Read for PublicOutcome {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _cfg: &Self::Cfg) -> Result<Self, commonware_codec::Error> {
        let epoch = UInt::read(buf)?.into();
        let max_participants: usize = u16::MAX.into();
        let participants = Ordered::read_cfg(buf, &(RangeCfg::from(1..=max_participants), ()))?;
        let public =
            Public::<MinSig>::read_cfg(buf, &(quorum(participants.len() as u32) as usize))?;
        Ok(Self {
            epoch,
            participants,
            public,
        })
    }
}

impl EncodeSize for PublicOutcome {
    fn encode_size(&self) -> usize {
        UInt(self.epoch).encode_size() + self.participants.encode_size() + self.public.encode_size()
    }
}

/// The local outcome of a dealer's dealings.
///
/// This is the intermediate outcome of a ceremony, which contains a dealer's
/// generated commitment, all acks for the shares it sent to the ceremony's
/// players, and finally the revealed shares, for which it did not receive acks.
///
/// This object is persisted on-chain. Every player collects the intermediate
/// outcomes of the other dealers to create the overall outcome of the ceremony.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IntermediateOutcome {
    /// The number of players in this epoch.
    n_players: u16,

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

impl IntermediateOutcome {
    /// Creates a new intermediate ceremony outcome.
    ///
    /// This object contains, the number of players, the epoch of the ceremony,
    /// the dealer's commitment (public polynomial), the acks received by the
    /// players and the revealed shares for which no acks are received.
    ///
    /// Finally, it also includes a signature over
    /// `(namespace, epoch, commitment, acks, reveals)` signed by the dealer.
    pub fn new(
        n_players: u16,
        dealer_signer: &PrivateKey,
        namespace: &[u8],
        epoch: Epoch,
        commitment: Public<MinSig>,
        acks: Vec<Ack>,
        reveals: Vec<group::Share>,
    ) -> Self {
        // Sign the resharing outcome
        let payload =
            Self::signature_payload_from_parts(n_players, epoch, &commitment, &acks, &reveals);
        let dealer_signature = dealer_signer.sign(Some(namespace), payload.as_ref());

        Self {
            n_players,
            dealer: dealer_signer.public_key(),
            dealer_signature,
            epoch,
            commitment,
            acks,
            reveals,
        }
    }

    /// Creates a new intermediate ceremony outcome.
    ///
    /// This method constructs a signature without the number players. This is
    /// incorrect and addressed by [`Self::new`]. [`Self::new_pre_allegretto`]
    /// exists for compatibility reasons and should only be used for hardforks
    /// pre allegretto.
    ///
    /// This object contains, the number of players, the epoch of the ceremony,
    /// the dealer's commitment (public polynomial), the acks received by the
    /// players and the revealed shares for which no acks are received.
    ///
    /// Finally, it also includes a signature over
    /// `(namespace, epoch, commitment, acks, reveals)` signed by the dealer.
    pub fn new_pre_allegretto(
        n_players: u16,
        dealer_signer: &PrivateKey,
        namespace: &[u8],
        epoch: Epoch,
        commitment: Public<MinSig>,
        acks: Vec<Ack>,
        reveals: Vec<group::Share>,
    ) -> Self {
        // Sign the resharing outcome
        let payload =
            Self::signature_payload_from_parts_pre_allegretto(epoch, &commitment, &acks, &reveals);
        let dealer_signature = dealer_signer.sign(Some(namespace), payload.as_ref());

        Self {
            n_players,
            dealer: dealer_signer.public_key(),
            dealer_signature,
            epoch,
            commitment,
            acks,
            reveals,
        }
    }

    /// Verifies the intermediate outcome's signature.
    pub fn verify(&self, namespace: &[u8]) -> bool {
        let payload = Self::signature_payload_from_parts(
            self.n_players,
            self.epoch,
            &self.commitment,
            &self.acks,
            &self.reveals,
        );
        self.dealer
            .verify(Some(namespace), &payload, &self.dealer_signature)
    }

    /// Verifies the intermediate outcome's signature.
    ///
    /// This method constructs a signature without the number players. This is
    /// incorrect and addressed by [`Self::new`]. [`Self::new_pre_allegretto`]
    /// exists for compatibility reasons and should only be used for hardforks
    /// pre allegretto.
    pub fn verify_pre_allegretto(&self, namespace: &[u8]) -> bool {
        let payload = Self::signature_payload_from_parts_pre_allegretto(
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
        n_players: u16,
        epoch: Epoch,
        commitment: &Public<MinSig>,
        acks: &Vec<Ack>,
        reveals: &Vec<group::Share>,
    ) -> Vec<u8> {
        let mut buf = Vec::with_capacity(
            UInt(n_players).encode_size()
                + UInt(epoch).encode_size()
                + commitment.encode_size()
                + acks.encode_size()
                + reveals.encode_size(),
        );
        UInt(n_players).write(&mut buf);
        UInt(epoch).write(&mut buf);
        commitment.write(&mut buf);
        acks.write(&mut buf);
        reveals.write(&mut buf);
        buf
    }

    /// Returns the payload that was signed by the dealer, formed from raw parts.
    ///
    /// This method constructs a signature without the number players. This is
    /// incorrect and addressed by [`Self::new`]. [`Self::new_pre_allegretto`]
    /// exists for compatibility reasons and should only be used for hardforks
    /// pre allegretto.
    fn signature_payload_from_parts_pre_allegretto(
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

    pub fn acks(&self) -> &[Ack] {
        &self.acks
    }

    pub fn dealer(&self) -> &PublicKey {
        &self.dealer
    }

    pub fn signature(&self) -> &Signature {
        &self.dealer_signature
    }

    pub fn epoch(&self) -> Epoch {
        self.epoch
    }

    pub fn commitment(&self) -> &Public<MinSig> {
        &self.commitment
    }

    pub fn reveals(&self) -> &[group::Share] {
        &self.reveals
    }
}

impl Write for IntermediateOutcome {
    fn write(&self, buf: &mut impl bytes::BufMut) {
        UInt(self.n_players).write(buf);
        self.dealer.write(buf);
        self.dealer_signature.write(buf);
        UInt(self.epoch).write(buf);
        self.commitment.write(buf);
        self.acks.write(buf);
        self.reveals.write(buf);
    }
}

impl EncodeSize for IntermediateOutcome {
    fn encode_size(&self) -> usize {
        UInt(self.n_players).encode_size()
            + self.dealer.encode_size()
            + self.dealer_signature.encode_size()
            + UInt(self.epoch).encode_size()
            + self.commitment.encode_size()
            + self.acks.encode_size()
            + self.reveals.encode_size()
    }
}

impl Read for IntermediateOutcome {
    type Cfg = ();

    fn read_cfg(
        buf: &mut impl bytes::Buf,
        _cfg: &Self::Cfg,
    ) -> Result<Self, commonware_codec::Error> {
        let n_players: u16 = UInt::read(buf)?.into();

        // Ensure is not 0 because otherwise `quorum(0)` would panic.
        if n_players == 0 {
            return Err(commonware_codec::Error::Invalid(
                "n_players",
                "cannot be zero",
            ));
        }

        let dealer = PublicKey::read(buf)?;
        let dealer_signature = Signature::read(buf)?;
        let epoch = UInt::read(buf)?.into();
        let commitment = Public::<MinSig>::read_cfg(buf, &(quorum(n_players as u32) as usize))?;

        let acks = Vec::read_cfg(buf, &(RangeCfg::from(0..=n_players as usize), ()))?;
        let reveals =
            Vec::<group::Share>::read_cfg(buf, &(RangeCfg::from(0..=n_players as usize), ()))?;

        Ok(Self {
            n_players,
            dealer,
            dealer_signature,
            epoch,
            commitment,
            acks,
            reveals,
        })
    }
}

#[cfg(test)]
mod tests {
    use commonware_codec::{DecodeExt as _, Encode as _};
    use commonware_cryptography::{
        PrivateKeyExt as _, Signer as _,
        bls12381::{dkg, primitives::variant::MinSig},
        ed25519::{PrivateKey, PublicKey},
    };
    use commonware_utils::{set::Ordered, union};
    use rand::{SeedableRng as _, rngs::StdRng};

    const ACK_NAMESPACE: &[u8] = b"_DKG_ACK";
    const OUTCOME_NAMESPACE: &[u8] = b"_DKG_OUTCOME";

    use crate::{Ack, PublicOutcome};

    use super::IntermediateOutcome;

    fn four_private_keys() -> Ordered<PrivateKey> {
        vec![
            PrivateKey::from_seed(0),
            PrivateKey::from_seed(1),
            PrivateKey::from_seed(2),
            PrivateKey::from_seed(3),
        ]
        .into()
    }

    fn four_public_keys() -> Ordered<PublicKey> {
        vec![
            PrivateKey::from_seed(0).public_key(),
            PrivateKey::from_seed(1).public_key(),
            PrivateKey::from_seed(2).public_key(),
            PrivateKey::from_seed(3).public_key(),
        ]
        .into()
    }

    #[test]
    fn dealing_outcome_roundtrip() {
        let (_, commitment, shares) = dkg::Dealer::<_, MinSig>::new(
            &mut StdRng::from_seed([0; 32]),
            None,
            four_public_keys(),
        );

        let acks = vec![
            Ack::new(
                &union(b"test", ACK_NAMESPACE),
                four_private_keys()[0].clone(),
                four_public_keys()[0].clone(),
                42,
                &four_public_keys()[0],
                &commitment,
            ),
            Ack::new(
                &union(b"test", ACK_NAMESPACE),
                four_private_keys()[1].clone(),
                four_public_keys()[1].clone(),
                42,
                &four_public_keys()[0],
                &commitment,
            ),
            Ack::new(
                &union(b"test", ACK_NAMESPACE),
                four_private_keys()[2].clone(),
                four_public_keys()[2].clone(),
                42,
                &four_public_keys()[0],
                &commitment,
            ),
        ];
        let reveals = vec![shares[3].clone()];
        let dealing_outcome = IntermediateOutcome::new(
            4,
            &four_private_keys()[0],
            &union(b"test", OUTCOME_NAMESPACE),
            42,
            commitment,
            acks,
            reveals,
        );

        let bytes = dealing_outcome.encode();
        assert_eq!(
            IntermediateOutcome::decode(&mut bytes.as_ref()).unwrap(),
            dealing_outcome,
        );
    }

    #[test]
    fn dealing_outcome_roundtrip_without_reveals() {
        let (_, commitment, _) = dkg::Dealer::<_, MinSig>::new(
            &mut StdRng::from_seed([0; 32]),
            None,
            four_public_keys(),
        );

        let acks = vec![
            Ack::new(
                &union(b"test", ACK_NAMESPACE),
                four_private_keys()[0].clone(),
                four_public_keys()[0].clone(),
                42,
                &four_public_keys()[0],
                &commitment,
            ),
            Ack::new(
                &union(b"test", ACK_NAMESPACE),
                four_private_keys()[1].clone(),
                four_public_keys()[1].clone(),
                42,
                &four_public_keys()[0],
                &commitment,
            ),
            Ack::new(
                &union(b"test", ACK_NAMESPACE),
                four_private_keys()[2].clone(),
                four_public_keys()[2].clone(),
                42,
                &four_public_keys()[0],
                &commitment,
            ),
            Ack::new(
                &union(b"test", ACK_NAMESPACE),
                four_private_keys()[3].clone(),
                four_public_keys()[3].clone(),
                42,
                &four_public_keys()[0],
                &commitment,
            ),
        ];
        let reveals = vec![];
        let dealing_outcome = IntermediateOutcome::new(
            4,
            &four_private_keys()[0],
            &union(b"test", OUTCOME_NAMESPACE),
            42,
            commitment,
            acks,
            reveals,
        );

        let bytes = dealing_outcome.encode();
        assert_eq!(
            IntermediateOutcome::decode(&mut bytes.as_ref()).unwrap(),
            dealing_outcome,
        );
    }

    #[test]
    fn public_outcome_roundtrip() {
        let (_, commitment, _) = dkg::Dealer::<_, MinSig>::new(
            &mut StdRng::from_seed([0; 32]),
            None,
            four_public_keys(),
        );
        let public_outcome = PublicOutcome {
            epoch: 42,
            participants: four_public_keys(),
            public: commitment,
        };
        let bytes = public_outcome.encode();
        assert_eq!(
            PublicOutcome::decode(&mut bytes.as_ref()).unwrap(),
            public_outcome,
        );
    }
}
