//! Items that are written to chain.

use bytes::{Buf, BufMut};
use commonware_codec::{EncodeSize, RangeCfg, Read, ReadExt as _, Write, varint::UInt};
use commonware_consensus::types::Epoch;
use commonware_cryptography::{
    Signer as _, Verifier as _,
    bls12381::primitives::{group, poly::Public, variant::MinSig},
    ed25519::{PrivateKey, PublicKey, Signature},
};
use commonware_utils::{quorum, set::Set};

use crate::dkg::ceremony::Ack;

/// The outcome of a dkg ceremony round.
///
/// Called public because it only contains the public polynomial.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct PublicOutcome {
    pub(crate) epoch: Epoch,
    pub(crate) participants: Set<PublicKey>,
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
        let participants = Set::read_cfg(buf, &(RangeCfg::from(0..=usize::MAX), ()))?;
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
/// This is the collection of dealer's generated commitment, as well as acks
/// it collected for its shares and revealed shares for those without acks.
///
/// This object is persisted on-chain. Every player collects the local outcomes
/// of other dealers to created a global outcome.
#[derive(Clone)]
pub(crate) struct DealingOutcome {
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

impl DealingOutcome {
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

impl Write for DealingOutcome {
    fn write(&self, buf: &mut impl bytes::BufMut) {
        self.dealer.write(buf);
        self.dealer_signature.write(buf);
        UInt(self.epoch).write(buf);
        self.commitment.write(buf);
        self.acks.write(buf);
        self.reveals.write(buf);
    }
}

impl EncodeSize for DealingOutcome {
    fn encode_size(&self) -> usize {
        self.dealer.encode_size()
            + self.dealer_signature.encode_size()
            + UInt(self.epoch).encode_size()
            + self.commitment.encode_size()
            + self.acks.encode_size()
            + self.reveals.encode_size()
    }
}

impl Read for DealingOutcome {
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
