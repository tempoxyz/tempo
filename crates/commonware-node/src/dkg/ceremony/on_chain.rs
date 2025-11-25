//! Items that are written to chain.

use bytes::{Buf, BufMut};
use commonware_codec::{EncodeSize, RangeCfg, Read, ReadExt as _, Write, varint::UInt};
use commonware_consensus::types::Epoch;
use commonware_cryptography::{
    Signer as _, Verifier as _,
    bls12381::primitives::{group, poly::Public, variant::MinSig},
    ed25519::{PrivateKey, PublicKey, Signature},
};
use commonware_utils::{quorum, set::Ordered};

use crate::dkg::ceremony::Ack;

/// The outcome of a dkg ceremony round.
///
/// Called public because it only contains the public polynomial.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct PublicOutcome {
    pub(crate) epoch: Epoch,
    pub(crate) participants: Ordered<PublicKey>,
    pub(crate) public: Public<MinSig>,
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
        let participants = Ordered::read_cfg(buf, &(RangeCfg::from(0..=usize::MAX), ()))?;
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
pub(crate) struct IntermediateOutcome {
    /// The number of players in this epoch.
    pub(super) n_players: u64,

    /// The public key of the dealer.
    pub(super) dealer: PublicKey,

    /// The dealer's signature over the resharing round, commitment, acks, and reveals.
    pub(super) dealer_signature: Signature,

    /// The epoch of the resharing operation.
    pub(super) epoch: Epoch,

    /// The new group public key polynomial.
    pub(super) commitment: Public<MinSig>,

    /// All signed acknowledgements from participants.
    pub(super) acks: Vec<Ack>,

    /// Any revealed secret shares.
    pub(super) reveals: Vec<group::Share>,
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
    pub(super) fn new(
        n_players: u64,
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
        let n_players = UInt::read(buf)?.into();
        Ok(Self {
            n_players,
            dealer: PublicKey::read(buf)?,
            dealer_signature: Signature::read(buf)?,
            epoch: UInt::read(buf)?.into(),
            commitment: Public::<MinSig>::read_cfg(buf, &(quorum(n_players as u32) as usize))?,
            acks: Vec::read_cfg(buf, &(RangeCfg::from(0..=usize::MAX), ()))?,
            reveals: Vec::<group::Share>::read_cfg(buf, &(RangeCfg::from(0..=usize::MAX), ()))?,
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

    use crate::dkg::{
        PublicOutcome,
        ceremony::{ACK_NAMESPACE, Ack, OUTCOME_NAMESPACE},
    };

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
    fn public_outcome_roundtrip() {
        use alloy_primitives::Address;
        use alloy_rlp::{Decodable, Encodable};
        use tempo_dkg_onchain_artifacts::{DecodedValidator, ValidatorState};

        let (_, commitment, _) = dkg::Dealer::<_, MinSig>::new(
            &mut StdRng::from_seed([0; 32]),
            None,
            four_public_keys(),
        );
        let validators: Vec<_> = four_public_keys()
            .into_iter()
            .enumerate()
            .map(|(i, pk)| {
                let v = DecodedValidator {
                    public_key: pk.clone(),
                    inbound: format!("127.0.0.1:{}", 8000 + i),
                    outbound: format!("127.0.0.1:{}", 9000 + i),
                    index: i as u64,
                    address: Address::default(),
                };
                (pk, v)
            })
            .collect();
        let public_outcome = PublicOutcome {
            epoch: 42,
            validator_state: ValidatorState::new(validators.into()),
            public: commitment,
        };
        let mut bytes = Vec::new();
        Encodable::encode(&public_outcome, &mut bytes);
        assert_eq!(
            <PublicOutcome as Decodable>::decode(&mut bytes.as_slice()).unwrap(),
            public_outcome,
        );
    }
}
