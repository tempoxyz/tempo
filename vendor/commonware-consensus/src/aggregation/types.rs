//! Types used in [aggregation](super).

use crate::{
    aggregation::scheme,
    types::{Epoch, Height},
    Heightable,
};
use bytes::{Buf, BufMut, Bytes};
use commonware_codec::{Encode, EncodeSize, Error as CodecError, Read, ReadExt, Write};
use commonware_cryptography::{
    certificate::{Attestation, Namespace as CertificateNamespace, Scheme, Subject},
    Digest,
};
use commonware_parallel::Strategy;
use commonware_utils::{channel::oneshot, union, N3f1};
use rand_core::CryptoRng;
use std::hash::Hash;

/// Error that may be encountered when interacting with `aggregation`.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    // Proposal Errors
    /// The proposal was canceled by the application
    #[error("Application verify error: {0}")]
    AppProposeCanceled(oneshot::error::RecvError),

    // Epoch Errors
    /// The specified validator is not a participant in the epoch
    #[error("Epoch {0} has no validator {1}")]
    UnknownValidator(Epoch, String),
    /// The local node is not a signer in the scheme for the specified epoch.
    #[error("Not a signer at epoch {0}")]
    NotSigner(Epoch),

    // Peer Errors
    /// The sender's public key doesn't match the expected key
    #[error("Peer mismatch")]
    PeerMismatch,

    // Signature Errors
    /// The acknowledgment signature is invalid
    #[error("Invalid ack signature")]
    InvalidAckSignature,

    // Ignorable Message Errors
    /// The acknowledgment's epoch is outside the accepted bounds
    #[error("Invalid ack epoch {0} outside bounds {1} - {2}")]
    AckEpochOutsideBounds(Epoch, Epoch, Epoch),
    /// The acknowledgment's height is outside the accepted bounds
    #[error("Non-useful ack height {0}")]
    AckHeight(Height),
    /// The acknowledgment's digest is incorrect
    #[error("Invalid ack digest {0}")]
    AckDigest(Height),
    /// Duplicate acknowledgment for the same height
    #[error("Duplicate ack from sender {0} for height {1}")]
    AckDuplicate(String, Height),
    /// The acknowledgement is for a height that already has a certificate
    #[error("Ack for height {0} already has been certified")]
    AckCertified(Height),
    /// The epoch is unknown
    #[error("Unknown epoch {0}")]
    UnknownEpoch(Epoch),
}

impl Error {
    /// Returns true if the error represents a blockable offense by a peer.
    pub const fn blockable(&self) -> bool {
        matches!(self, Self::PeerMismatch | Self::InvalidAckSignature)
    }
}

/// Suffix used to identify an acknowledgment (ack) namespace for domain separation.
/// Used when signing and verifying acks to prevent signature reuse across different message types.
const ACK_SUFFIX: &[u8] = b"_AGG_ACK";

/// Returns a suffixed namespace for signing an ack.
///
/// This provides domain separation for signatures, preventing cross-protocol attacks
/// by ensuring signatures for acks cannot be reused for other message types.
#[inline]
fn ack_namespace(namespace: &[u8]) -> Vec<u8> {
    union(namespace, ACK_SUFFIX)
}

/// Namespace type for aggregation acknowledgments.
///
/// This type encapsulates the pre-computed namespace bytes used for signing and
/// verifying acks.
#[derive(Clone, Debug)]
pub struct Namespace(Vec<u8>);

impl CertificateNamespace for Namespace {
    fn derive(namespace: &[u8]) -> Self {
        Self(ack_namespace(namespace))
    }
}

/// Item represents a single element being aggregated in the protocol.
/// Each item has a unique height and contains a digest that validators sign.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Item<D: Digest> {
    /// Sequential position of this item within the current epoch
    pub height: Height,
    /// Cryptographic digest of the data being aggregated
    pub digest: D,
}

impl<D: Digest> Heightable for Item<D> {
    fn height(&self) -> Height {
        self.height
    }
}

impl<D: Digest> Write for Item<D> {
    fn write(&self, writer: &mut impl BufMut) {
        self.height.write(writer);
        self.digest.write(writer);
    }
}

impl<D: Digest> Read for Item<D> {
    type Cfg = ();

    fn read_cfg(reader: &mut impl Buf, _: &()) -> Result<Self, CodecError> {
        let height = Height::read(reader)?;
        let digest = D::read(reader)?;
        Ok(Self { height, digest })
    }
}

impl<D: Digest> EncodeSize for Item<D> {
    fn encode_size(&self) -> usize {
        self.height.encode_size() + self.digest.encode_size()
    }
}

/// The signed message covers only the height and digest, intentionally excluding the epoch.
/// See the [module docs](super#epoch-independent-signatures).
impl<D: Digest> Subject for &Item<D> {
    type Namespace = Namespace;

    fn namespace<'a>(&self, derived: &'a Self::Namespace) -> &'a [u8] {
        &derived.0
    }

    fn message(&self) -> Bytes {
        self.encode()
    }
}

#[cfg(feature = "arbitrary")]
impl<D: Digest> arbitrary::Arbitrary<'_> for Item<D>
where
    D: for<'a> arbitrary::Arbitrary<'a>,
{
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        let height = u.arbitrary::<Height>()?;
        let digest = u.arbitrary::<D>()?;
        Ok(Self { height, digest })
    }
}

/// Acknowledgment (ack) represents a validator's vote on an item.
/// Multiple acks can be recovered into a certificate for consensus.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Ack<S: Scheme, D: Digest> {
    /// The item being acknowledged
    pub item: Item<D>,
    /// The epoch in which this acknowledgment was created.
    ///
    /// Not part of the signed message: it selects the scheme used to verify the attestation and
    /// assemble a certificate. See the [module docs](super#epoch-independent-signatures).
    pub epoch: Epoch,
    /// Scheme-specific attestation material
    pub attestation: Attestation<S>,
}

impl<S: Scheme, D: Digest> Ack<S, D> {
    /// Verifies the attestation on this acknowledgment.
    ///
    /// Returns `true` if the attestation is valid for the given namespace and public key.
    /// Domain separation is automatically applied to prevent signature reuse.
    pub fn verify<R>(&self, rng: &mut R, scheme: &S, strategy: &impl Strategy) -> bool
    where
        R: CryptoRng,
        S: scheme::Scheme<D>,
    {
        scheme.verify_attestation::<_, D>(rng, &self.item, &self.attestation, strategy)
    }

    /// Creates a new acknowledgment by signing an item with a validator's key.
    ///
    /// The signature uses domain separation to prevent cross-protocol attacks. The epoch is
    /// carried in the ack but is not part of the signed message. See the
    /// [module docs](super#epoch-independent-signatures).
    ///
    /// # Determinism
    ///
    /// Signatures produced by this function are deterministic and safe for consensus.
    pub fn sign(scheme: &S, epoch: Epoch, item: Item<D>) -> Option<Self>
    where
        S: scheme::Scheme<D>,
    {
        let attestation = scheme.sign::<D>(&item)?;
        Some(Self {
            item,
            epoch,
            attestation,
        })
    }
}

impl<S: Scheme, D: Digest> Write for Ack<S, D> {
    fn write(&self, writer: &mut impl BufMut) {
        self.item.write(writer);
        self.epoch.write(writer);
        self.attestation.write(writer);
    }
}

impl<S: Scheme, D: Digest> Read for Ack<S, D> {
    type Cfg = ();

    fn read_cfg(reader: &mut impl Buf, _: &()) -> Result<Self, CodecError> {
        let item = Item::read(reader)?;
        let epoch = Epoch::read(reader)?;
        let attestation = Attestation::read(reader)?;
        Ok(Self {
            item,
            epoch,
            attestation,
        })
    }
}

impl<S: Scheme, D: Digest> EncodeSize for Ack<S, D> {
    fn encode_size(&self) -> usize {
        self.item.encode_size() + self.epoch.encode_size() + self.attestation.encode_size()
    }
}

#[cfg(feature = "arbitrary")]
impl<S: Scheme, D: Digest> arbitrary::Arbitrary<'_> for Ack<S, D>
where
    S::Signature: for<'a> arbitrary::Arbitrary<'a>,
    D: for<'a> arbitrary::Arbitrary<'a>,
{
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        let item = u.arbitrary::<Item<D>>()?;
        let epoch = u.arbitrary::<Epoch>()?;
        let attestation = Attestation::arbitrary(u)?;
        Ok(Self {
            item,
            epoch,
            attestation,
        })
    }
}

/// Message exchanged between peers containing an acknowledgment and tip information.
/// This combines a validator's vote with their view of consensus progress.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct TipAck<S: Scheme, D: Digest> {
    /// The peer's local view of the tip (the lowest height that is not yet confirmed).
    pub tip: Height,

    /// The peer's acknowledgement (vote) for an item.
    pub ack: Ack<S, D>,
}

impl<S: Scheme, D: Digest> Write for TipAck<S, D> {
    fn write(&self, writer: &mut impl BufMut) {
        self.tip.write(writer);
        self.ack.write(writer);
    }
}

impl<S: Scheme, D: Digest> Read for TipAck<S, D> {
    type Cfg = ();

    fn read_cfg(reader: &mut impl Buf, _: &()) -> Result<Self, CodecError> {
        let tip = Height::read(reader)?;
        let ack = Ack::read(reader)?;
        Ok(Self { tip, ack })
    }
}

impl<S: Scheme, D: Digest> EncodeSize for TipAck<S, D> {
    fn encode_size(&self) -> usize {
        self.tip.encode_size() + self.ack.encode_size()
    }
}

#[cfg(feature = "arbitrary")]
impl<S: Scheme, D: Digest> arbitrary::Arbitrary<'_> for TipAck<S, D>
where
    D: for<'a> arbitrary::Arbitrary<'a>,
    Ack<S, D>: for<'a> arbitrary::Arbitrary<'a>,
{
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        let tip = u.arbitrary::<Height>()?;
        let ack = u.arbitrary::<Ack<S, D>>()?;
        Ok(Self { tip, ack })
    }
}

/// A recovered certificate for some [Item].
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Certificate<S: Scheme, D: Digest> {
    /// The item that was recovered.
    pub item: Item<D>,
    /// The recovered certificate.
    pub certificate: S::Certificate,
}

impl<S: Scheme, D: Digest> Certificate<S, D> {
    pub fn from_acks<'a, I>(scheme: &S, acks: I, strategy: &impl Strategy) -> Option<Self>
    where
        S: scheme::Scheme<D>,
        I: IntoIterator<Item = &'a Ack<S, D>>,
        I::IntoIter: Send,
    {
        let mut iter = acks.into_iter().peekable();
        let item = iter.peek()?.item.clone();
        let attestations = iter
            .filter(|ack| ack.item == item)
            .map(|ack| ack.attestation.clone());
        let certificate = scheme.assemble::<_, N3f1>(attestations, strategy)?;

        Some(Self { item, certificate })
    }

    /// Verifies the recovered certificate for the item.
    pub fn verify<R>(&self, rng: &mut R, scheme: &S, strategy: &impl Strategy) -> bool
    where
        R: CryptoRng,
        S: scheme::Scheme<D>,
    {
        scheme.verify_certificate::<_, D, N3f1>(rng, &self.item, &self.certificate, strategy)
    }
}

impl<S: Scheme, D: Digest> Write for Certificate<S, D> {
    fn write(&self, writer: &mut impl BufMut) {
        self.item.write(writer);
        self.certificate.write(writer);
    }
}

impl<S: Scheme, D: Digest> Read for Certificate<S, D> {
    type Cfg = <S::Certificate as Read>::Cfg;

    fn read_cfg(reader: &mut impl Buf, cfg: &Self::Cfg) -> Result<Self, CodecError> {
        let item = Item::read(reader)?;
        let certificate = S::Certificate::read_cfg(reader, cfg)?;
        Ok(Self { item, certificate })
    }
}

impl<S: Scheme, D: Digest> EncodeSize for Certificate<S, D> {
    fn encode_size(&self) -> usize {
        self.item.encode_size() + self.certificate.encode_size()
    }
}

#[cfg(feature = "arbitrary")]
impl<S: Scheme, D: Digest> arbitrary::Arbitrary<'_> for Certificate<S, D>
where
    D: for<'a> arbitrary::Arbitrary<'a>,
    S::Certificate: for<'a> arbitrary::Arbitrary<'a>,
{
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        let item = u.arbitrary::<Item<D>>()?;
        let certificate = u.arbitrary::<S::Certificate>()?;
        Ok(Self { item, certificate })
    }
}

/// Used as [Reporter::Activity](crate::Reporter::Activity) to report activities that occur during
/// aggregation. Also used to journal events that are needed to initialize the aggregation engine
/// when the node restarts.
#[derive(Clone, Debug, PartialEq)]
pub enum Activity<S: Scheme, D: Digest> {
    /// Received an ack from a participant.
    Ack(Ack<S, D>),

    /// Certified an [Item].
    Certified(Certificate<S, D>),

    /// Moved the tip to a new height.
    Tip(Height),
}

impl<S: Scheme, D: Digest> Write for Activity<S, D> {
    fn write(&self, writer: &mut impl BufMut) {
        match self {
            Self::Ack(ack) => {
                0u8.write(writer);
                ack.write(writer);
            }
            Self::Certified(certificate) => {
                1u8.write(writer);
                certificate.write(writer);
            }
            Self::Tip(height) => {
                2u8.write(writer);
                height.write(writer);
            }
        }
    }
}

impl<S: Scheme, D: Digest> Read for Activity<S, D> {
    type Cfg = <S::Certificate as Read>::Cfg;

    fn read_cfg(reader: &mut impl Buf, cfg: &Self::Cfg) -> Result<Self, CodecError> {
        match u8::read(reader)? {
            0 => Ok(Self::Ack(Ack::read(reader)?)),
            1 => Ok(Self::Certified(Certificate::read_cfg(reader, cfg)?)),
            2 => Ok(Self::Tip(Height::read(reader)?)),
            _ => Err(CodecError::Invalid(
                "consensus::aggregation::Activity",
                "Invalid type",
            )),
        }
    }
}

impl<S: Scheme, D: Digest> EncodeSize for Activity<S, D> {
    fn encode_size(&self) -> usize {
        1 + match self {
            Self::Ack(ack) => ack.encode_size(),
            Self::Certified(certificate) => certificate.encode_size(),
            Self::Tip(height) => height.encode_size(),
        }
    }
}

#[cfg(feature = "arbitrary")]
impl<S: Scheme, D: Digest> arbitrary::Arbitrary<'_> for Activity<S, D>
where
    D: for<'a> arbitrary::Arbitrary<'a>,
    Ack<S, D>: for<'a> arbitrary::Arbitrary<'a>,
    Certificate<S, D>: for<'a> arbitrary::Arbitrary<'a>,
{
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        let choice = u.int_in_range(0..=2)?;
        match choice {
            0 => Ok(Self::Ack(u.arbitrary::<Ack<S, D>>()?)),
            1 => Ok(Self::Certified(u.arbitrary::<Certificate<S, D>>()?)),
            2 => Ok(Self::Tip(u.arbitrary::<Height>()?)),
            _ => unreachable!(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::aggregation::scheme::{
        bls12381_multisig, bls12381_threshold, ed25519, secp256r1, Scheme,
    };
    use bytes::BytesMut;
    use commonware_codec::{Decode, DecodeExt, Encode};
    use commonware_cryptography::{
        bls12381::primitives::variant::{MinPk, MinSig},
        certificate::mocks::Fixture,
        Hasher, Sha256,
    };
    use commonware_parallel::Sequential;
    use commonware_utils::{ordered::Quorum, test_rng, N3f1, TestRng};

    const NAMESPACE: &[u8] = b"test";

    type Sha256Digest = <Sha256 as Hasher>::Digest;

    #[test]
    fn test_ack_namespace() {
        let namespace = b"test_namespace";
        let expected = [namespace, ACK_SUFFIX].concat();
        assert_eq!(ack_namespace(namespace), expected);
    }

    fn codec<S, F>(fixture: F)
    where
        S: Scheme<Sha256Digest>,
        F: FnOnce(&mut TestRng, &[u8], u32) -> Fixture<S>,
    {
        let mut rng = test_rng();
        let fixture = fixture(&mut rng, NAMESPACE, 4);
        let schemes = &fixture.schemes;
        let item = Item {
            height: Height::new(100),
            digest: Sha256::hash(b"test_item"),
        };

        // Test Item codec
        let restored_item = Item::decode(item.encode()).unwrap();
        assert_eq!(item, restored_item);

        // Test Ack creation and codec
        let ack = Ack::sign(&schemes[0], Epoch::new(1), item.clone()).unwrap();
        let cfg = schemes[0].certificate_codec_config();
        let encoded_ack = ack.encode();
        let restored_ack: Ack<S, Sha256Digest> = Ack::decode(encoded_ack).unwrap();

        // Verify the restored ack
        assert_eq!(restored_ack.item, item);
        assert_eq!(restored_ack.epoch, Epoch::new(1));
        assert!(restored_ack.verify(&mut rng, &schemes[0], &Sequential));

        // Test TipAck codec
        let tip_ack = TipAck {
            ack: ack.clone(),
            tip: Height::new(42),
        };
        let encoded_tip_ack = tip_ack.encode();
        let restored_tip_ack: TipAck<S, Sha256Digest> = TipAck::decode(encoded_tip_ack).unwrap();
        assert_eq!(restored_tip_ack.tip, Height::new(42));
        assert_eq!(restored_tip_ack.ack.item, item);
        assert_eq!(restored_tip_ack.ack.epoch, Epoch::new(1));

        // Test Activity codec - Ack variant
        let activity_ack = Activity::Ack(ack);
        let encoded_activity = activity_ack.encode();
        let restored_activity_ack: Activity<S, Sha256Digest> =
            Activity::decode_cfg(encoded_activity, &cfg).unwrap();
        if let Activity::Ack(restored) = restored_activity_ack {
            assert_eq!(restored.item, item);
            assert_eq!(restored.epoch, Epoch::new(1));
        } else {
            panic!("Expected Activity::Ack");
        }

        // Test Activity codec - Certified variant
        // Collect enough acks for a certificate
        let acks: Vec<_> = schemes
            .iter()
            .take(schemes[0].participants().quorum::<N3f1>() as usize)
            .filter_map(|scheme| Ack::sign(scheme, Epoch::new(1), item.clone()))
            .collect();

        let certificate = Certificate::from_acks(&schemes[0], &acks, &Sequential).unwrap();
        assert!(certificate.verify(&mut rng, &schemes[0], &Sequential));

        let activity_certified = Activity::Certified(certificate.clone());
        let encoded_certified = activity_certified.encode();
        let restored_activity_certified: Activity<S, Sha256Digest> =
            Activity::decode_cfg(encoded_certified, &cfg).unwrap();
        if let Activity::Certified(restored) = restored_activity_certified {
            assert_eq!(restored.item, item);
            assert!(restored.verify(&mut rng, &schemes[0], &Sequential));
        } else {
            panic!("Expected Activity::Certified");
        }

        // Test Activity codec - Tip variant
        let activity_tip: Activity<S, Sha256Digest> = Activity::Tip(Height::new(123));
        let encoded_tip = activity_tip.encode();
        let restored_activity_tip: Activity<S, Sha256Digest> =
            Activity::decode_cfg(encoded_tip, &cfg).unwrap();
        if let Activity::Tip(height) = restored_activity_tip {
            assert_eq!(height, Height::new(123));
        } else {
            panic!("Expected Activity::Tip");
        }
    }

    #[test]
    fn test_codec() {
        codec(ed25519::fixture);
        codec(secp256r1::fixture);
        codec(bls12381_multisig::fixture::<MinPk, _>);
        codec(bls12381_multisig::fixture::<MinSig, _>);
        codec(bls12381_threshold::fixture::<MinPk, _>);
        codec(bls12381_threshold::fixture::<MinSig, _>);
    }

    fn activity_invalid_enum<S, F>(fixture: F)
    where
        S: Scheme<Sha256Digest>,
        F: FnOnce(&mut TestRng, &[u8], u32) -> Fixture<S>,
    {
        let fixture = fixture(&mut test_rng(), NAMESPACE, 4);
        let mut buf = BytesMut::new();
        3u8.write(&mut buf); // Invalid discriminant

        let cfg = fixture.schemes[0].certificate_codec_config();
        let result = Activity::<S, Sha256Digest>::read_cfg(&mut &buf[..], &cfg);
        assert!(matches!(
            result,
            Err(CodecError::Invalid(
                "consensus::aggregation::Activity",
                "Invalid type"
            ))
        ));
    }

    #[test]
    fn test_activity_invalid_enum() {
        activity_invalid_enum(ed25519::fixture);
        activity_invalid_enum(secp256r1::fixture);
        activity_invalid_enum(bls12381_multisig::fixture::<MinPk, _>);
        activity_invalid_enum(bls12381_multisig::fixture::<MinSig, _>);
        activity_invalid_enum(bls12381_threshold::fixture::<MinPk, _>);
        activity_invalid_enum(bls12381_threshold::fixture::<MinSig, _>);
    }

    #[cfg(feature = "arbitrary")]
    mod conformance {
        use super::*;
        use crate::aggregation::scheme::bls12381_threshold;
        use commonware_codec::conformance::CodecConformance;
        use commonware_cryptography::{ed25519::PublicKey, sha256::Digest as Sha256Digest};

        type Scheme = bls12381_threshold::Scheme<PublicKey, MinSig>;

        commonware_conformance::conformance_tests! {
            CodecConformance<Item<Sha256Digest>>,
            CodecConformance<Ack<Scheme, Sha256Digest>>,
            CodecConformance<TipAck<Scheme, Sha256Digest>>,
            CodecConformance<Certificate<Scheme, Sha256Digest>>,
            CodecConformance<Activity<Scheme, Sha256Digest>>,
        }
    }
}
